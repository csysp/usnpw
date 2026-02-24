#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import os
import py_compile
import shutil
import stat
import subprocess
import sys
import tarfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIST_DIR = ROOT / "dist"
PYINSTALLER_REQUIRED_VERSION = "6.16.0"

COMPILE_ROOTS: tuple[str, ...] = ("usnpw", "tools")
TESTS_ROOT = ROOT / "tests"


@dataclass(frozen=True)
class BinaryTarget:
    key: str
    entrypoint: str
    output_base: str
    windowed: bool = False
    hidden_imports: tuple[str, ...] = ()
    collect_submodules: tuple[str, ...] = ()


BINARY_TARGETS: tuple[BinaryTarget, ...] = (
    BinaryTarget(
        key="cli",
        entrypoint="usnpw/cli/usnpw_cli.py",
        output_base="usnpw-{platform}-cli",
        collect_submodules=("usnpw.cli", "usnpw.core"),
    ),
    BinaryTarget(
        key="installer",
        entrypoint="tools/cli_installer.py",
        output_base="usnpw-{platform}-installer",
        hidden_imports=("tools.release",),
    ),
)
DEFAULT_BINARY_TARGETS: tuple[str, ...] = ("cli", "installer")


def _binary_target_map() -> dict[str, BinaryTarget]:
    return {target.key: target for target in BINARY_TARGETS}


def _host_platform_tag() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _resolve_output_base(target: BinaryTarget) -> str:
    return target.output_base.format(platform=_host_platform_tag())


def discover_compile_targets() -> tuple[str, ...]:
    targets: set[str] = set()
    for rel_root in COMPILE_ROOTS:
        root = ROOT / rel_root
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if path.is_file():
                targets.add(path.relative_to(ROOT).as_posix())
    return tuple(sorted(targets))


def discover_test_modules() -> tuple[str, ...]:
    if not TESTS_ROOT.exists():
        return ()
    modules: list[str] = []
    for path in sorted(TESTS_ROOT.rglob("test_*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(ROOT).with_suffix("")
        modules.append(".".join(rel.parts))
    return tuple(modules)


def run_preflight() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    compile_targets = discover_compile_targets()
    if not compile_targets:
        raise ValueError("no compile targets discovered")

    print("[preflight] compile checks")
    for target in compile_targets:
        path = ROOT / target
        print(f"  - {target}")
        py_compile.compile(str(path), doraise=True)

    test_modules = discover_test_modules()
    if not test_modules:
        raise ValueError(f"no test modules discovered under '{TESTS_ROOT}'")

    print("[preflight] unit tests")
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for module in test_modules:
        print(f"  - {module}")
        suite.addTests(loader.loadTestsFromName(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksum(artifact: Path) -> Path:
    if not artifact.is_file():
        raise ValueError(f"artifact path must be a file: {artifact}")
    digest = sha256_file(artifact)
    sidecar = artifact.with_suffix(artifact.suffix + ".sha256")
    sidecar.write_text(f"{digest} *{artifact.name}\n", encoding="utf-8")
    print(f"[checksums] sha256={digest}")
    print(f"[checksums] wrote {sidecar}")
    return sidecar


def write_checksums(artifacts: Sequence[Path]) -> list[Path]:
    out: list[Path] = []
    for artifact in artifacts:
        out.append(write_checksum(artifact))
    return out


def _resolve_pyinstaller() -> list[str]:
    if importlib.util.find_spec("PyInstaller") is None:
        raise RuntimeError(
            "PyInstaller is required for binary builds. Install the pinned version with "
            f"`{sys.executable} -m pip install pyinstaller=={PYINSTALLER_REQUIRED_VERSION}`."
        )
    try:
        installed = importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            "PyInstaller metadata not found. Install the pinned version with "
            f"`{sys.executable} -m pip install pyinstaller=={PYINSTALLER_REQUIRED_VERSION}`."
        ) from exc
    if installed != PYINSTALLER_REQUIRED_VERSION:
        raise RuntimeError(
            "PyInstaller version mismatch. "
            f"Required: {PYINSTALLER_REQUIRED_VERSION}; installed: {installed}. "
            f"Run `{sys.executable} -m pip install pyinstaller=={PYINSTALLER_REQUIRED_VERSION}`."
        )
    return [sys.executable, "-m", "PyInstaller"]


def _target_artifact_path(bin_dir: Path, output_base: str) -> Path | None:
    candidates = (
        bin_dir / f"{output_base}.exe",
        bin_dir / output_base,
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _pyinstaller_data_separator() -> str:
    return ";" if os.name == "nt" else ":"


def _resolve_cli_artifact_for_installer(*, bin_dir: Path, built_artifacts: dict[str, Path]) -> Path:
    cli_artifact = built_artifacts.get("cli")
    if cli_artifact is not None and cli_artifact.is_file():
        return cli_artifact

    cli_target = _binary_target_map()["cli"]
    cli_output_base = _resolve_output_base(cli_target)
    discovered = _target_artifact_path(bin_dir, cli_output_base)
    if discovered is not None and discovered.is_file():
        return discovered

    raise ValueError(
        "installer target requires a host-matching CLI artifact. "
        "Build the cli target first (or in the same command), for example: "
        f"{sys.executable} .\\tools\\release.py binaries --target cli --target installer"
    )


def _remove_legacy_installer_script_artifacts(bin_dir: Path) -> None:
    cli_output_base = _resolve_output_base(_binary_target_map()["cli"])
    legacy_script = bin_dir / f"{cli_output_base}-installer.ps1"
    legacy_checksum = legacy_script.with_suffix(legacy_script.suffix + ".sha256")
    for legacy in (legacy_script, legacy_checksum):
        if not legacy.exists():
            continue
        if not legacy.is_file():
            raise ValueError(f"unexpected non-file legacy installer artifact: {legacy}")
        legacy.unlink()
        print(f"[binaries] removed legacy artifact {legacy}")


def build_binaries(dist_dir: Path, target_keys: Sequence[str]) -> list[Path]:
    targets = _binary_target_map()
    selected: list[BinaryTarget] = [targets[key] for key in target_keys]
    if not selected:
        raise ValueError("at least one binary target is required")

    pyinstaller_cmd = _resolve_pyinstaller()
    bin_dir = dist_dir / "bin"
    work_root = dist_dir / "build-pyinstaller"
    spec_dir = dist_dir / "spec"
    bin_dir.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)
    _remove_legacy_installer_script_artifacts(bin_dir)

    artifacts: list[Path] = []
    built_artifacts: dict[str, Path] = {}
    for target in selected:
        output_base = _resolve_output_base(target)
        cmd = [
            *pyinstaller_cmd,
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            output_base,
            "--distpath",
            str(bin_dir),
            "--workpath",
            str(work_root / target.key),
            "--specpath",
            str(spec_dir),
            "--paths",
            str(ROOT),
        ]
        for hidden_import in target.hidden_imports:
            cmd.extend(["--hidden-import", hidden_import])
        for package_name in target.collect_submodules:
            cmd.extend(["--collect-submodules", package_name])
        if target.key == "installer":
            cli_artifact = _resolve_cli_artifact_for_installer(bin_dir=bin_dir, built_artifacts=built_artifacts)
            add_data = f"{cli_artifact}{_pyinstaller_data_separator()}."
            cmd.extend(["--add-data", add_data])
        if target.windowed:
            cmd.append("--windowed")
        cmd.append(target.entrypoint)

        print(f"[binaries] building {target.key} -> {output_base}")
        proc = subprocess.run(cmd, cwd=ROOT)
        if proc.returncode != 0:
            raise RuntimeError(
                "PyInstaller build failed. Verify local environment is pinned to "
                f"pyinstaller=={PYINSTALLER_REQUIRED_VERSION} and retry."
            )

        artifact = _target_artifact_path(bin_dir, output_base)
        if artifact is None:
            raise RuntimeError(
                f"expected binary artifact not found for target '{target.key}' ({output_base})"
            )
        if artifact.is_dir():
            raise RuntimeError(
                f"expected one-file binary artifact, got directory: {artifact}. "
                "CLI release mode only supports single executable artifacts."
            )
        print(f"[binaries] wrote {artifact}")
        artifacts.append(artifact)
        built_artifacts[target.key] = artifact

    return artifacts


def _built_artifact_for_target(*, bin_dir: Path, target: BinaryTarget) -> Path:
    output_base = _resolve_output_base(target)
    artifact = _target_artifact_path(bin_dir, output_base)
    if artifact is None:
        raise ValueError(
            f"artifact for target '{target.key}' not found under '{bin_dir}'. "
            "Build binaries first with: "
            f"{sys.executable} .\\tools\\release.py binaries --target {target.key}"
        )
    if artifact.is_dir():
        raise ValueError(
            f"expected one-file binary artifact for target '{target.key}', got directory: {artifact}"
        )
    return artifact


def bundle_release_artifacts(dist_dir: Path, target_keys: Sequence[str]) -> list[Path]:
    targets = _binary_target_map()
    selected: list[BinaryTarget] = [targets[key] for key in target_keys]
    if not selected:
        raise ValueError("at least one bundle target is required")

    bin_dir = dist_dir / "bin"
    release_dir = dist_dir / "release"
    release_dir.mkdir(parents=True, exist_ok=True)

    packaged: list[Path] = []
    for target in selected:
        artifact = _built_artifact_for_target(bin_dir=bin_dir, target=target)
        if os.name == "nt":
            out = release_dir / artifact.name
            shutil.copy2(artifact, out)
        else:
            out = release_dir / f"{artifact.name}.tar.gz"
            with tarfile.open(out, "w:gz") as archive:
                tar_info = archive.gettarinfo(str(artifact), arcname=artifact.name)
                tar_info.mode = stat.S_IMODE(artifact.stat().st_mode) | 0o111
                with artifact.open("rb") as source:
                    archive.addfile(tar_info, source)
        print(f"[bundle] wrote {out}")
        packaged.append(out)

    write_checksums(packaged)
    return packaged


def _default_cli_binary_path(dist_dir: Path) -> Path:
    cli_target = _binary_target_map()["cli"]
    output_base = _resolve_output_base(cli_target)
    bin_dir = dist_dir / "bin"
    artifact = _target_artifact_path(bin_dir, output_base)
    if artifact is None:
        raise ValueError(
            f"CLI artifact not found under '{bin_dir}'. Build it first with: "
            f"{sys.executable} .\\tools\\release.py binaries --target cli"
        )
    return artifact


def _default_cli_install_dir() -> Path:
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            return Path(local_appdata) / "usnpw" / "bin"
        return Path.home() / "AppData" / "Local" / "usnpw" / "bin"
    return Path.home() / ".local" / "bin"


def _normalize_path_for_compare(path: str) -> str:
    expanded = Path(path).expanduser()
    return os.path.normcase(os.path.normpath(str(expanded)))


def _ensure_user_path_windows(path_entry: Path) -> bool:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        try:
            current_path_raw, reg_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current_path_raw = ""
            reg_type = winreg.REG_EXPAND_SZ

        current_path = current_path_raw if isinstance(current_path_raw, str) else ""
        parts = [part for part in current_path.split(";") if part]
        normalized_entry = _normalize_path_for_compare(str(path_entry))
        desired_parts = [
            str(path_entry),
            *[part for part in parts if _normalize_path_for_compare(part) != normalized_entry],
        ]
        current_norm = [_normalize_path_for_compare(part) for part in parts]
        desired_norm = [_normalize_path_for_compare(part) for part in desired_parts]
        if current_norm == desired_norm:
            return False

        merged = ";".join(desired_parts)
        if reg_type not in (winreg.REG_EXPAND_SZ, winreg.REG_SZ):
            reg_type = winreg.REG_EXPAND_SZ
        winreg.SetValueEx(key, "Path", 0, reg_type, merged)

    # Notify other processes that user environment variables changed.
    try:
        import ctypes

        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_ulong(0)
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            "Environment",
            SMTO_ABORTIFHUNG,
            5000,
            ctypes.byref(result),
        )
    except (AttributeError, OSError):
        pass

    return True


def _ensure_user_path_posix(path_entry: Path) -> bool:
    profile = Path.home() / ".profile"
    marker = "# Added by usnpw install-cli"
    export_line = f'export PATH="{path_entry}:$PATH"'
    existing = profile.read_text(encoding="utf-8") if profile.exists() else ""
    if export_line in existing:
        return False

    new_content = existing
    if new_content and not new_content.endswith("\n"):
        new_content += "\n"
    new_content += f"{marker}\n{export_line}\n"
    profile.write_text(new_content, encoding="utf-8")
    return True


def ensure_user_path_persistent(path_entry: Path) -> bool:
    if os.name == "nt":
        return _ensure_user_path_windows(path_entry)
    return _ensure_user_path_posix(path_entry)


def install_cli_binary(
    *,
    dist_dir: Path,
    artifact: Path | None = None,
    install_dir: Path | None = None,
    update_path: bool = True,
) -> Path:
    src = artifact.expanduser() if artifact is not None else _default_cli_binary_path(dist_dir.expanduser())
    if not src.is_file():
        raise ValueError(f"CLI artifact not found: {src}")

    target_dir = (install_dir.expanduser() if install_dir is not None else _default_cli_install_dir()).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    dest_name = "usnpw.exe" if os.name == "nt" else "usnpw"
    dest = target_dir / dest_name
    shutil.copy2(src, dest)
    if os.name != "nt":
        dest.chmod(dest.stat().st_mode | 0o111)
    digest = sha256_file(dest)
    dest_sidecar = dest.with_suffix(dest.suffix + ".sha256")
    dest_sidecar.write_text(f"{digest} *{dest.name}\n", encoding="utf-8")
    print(f"[install-cli] wrote {dest_sidecar}")

    print(f"[install-cli] wrote {dest}")
    if update_path:
        added = ensure_user_path_persistent(target_dir)
        if added:
            print(f"[install-cli] added to user PATH: {target_dir}")
            print("[install-cli] restart your shell to use `usnpw` directly.")
        else:
            print(f"[install-cli] already present in user PATH: {target_dir}")
    else:
        print(f"[install-cli] skipped PATH update; add this directory manually: {target_dir}")

    resolved = shutil.which("usnpw")
    if resolved is not None:
        resolved_norm = _normalize_path_for_compare(resolved)
        dest_norm = _normalize_path_for_compare(str(dest))
        if resolved_norm != dest_norm:
            print(f"[install-cli] warning: current shell resolves `usnpw` to: {resolved}")
            print(
                "[install-cli] open a new shell, or remove older PATH entries so "
                f"'{target_dir}' takes precedence."
            )
    return dest


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="USnPw release helper (preflight, binaries, bundle, install-cli)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("preflight", help="Run compile + unit test checks.")

    checksums = sub.add_parser("checksums", help="Write .sha256 sidecar for an artifact.")
    checksums.add_argument("--artifact", required=True)

    binaries = sub.add_parser("binaries", help="Build host-native binaries with PyInstaller.")
    binaries.add_argument("--dist-dir", default=str(DEFAULT_DIST_DIR))
    binaries.add_argument(
        "--target",
        action="append",
        choices=[t.key for t in BINARY_TARGETS],
        help="Binary target to build (repeat flag). Default: cli + installer targets.",
    )
    binaries.add_argument(
        "--no-checksums",
        action="store_true",
        help="Skip writing .sha256 files for built binaries.",
    )

    bundle = sub.add_parser(
        "bundle",
        help="Package host-native release artifacts in dist/release (tar.gz on Linux/macOS, .exe on Windows).",
    )
    bundle.add_argument("--dist-dir", default=str(DEFAULT_DIST_DIR))
    bundle.add_argument(
        "--target",
        action="append",
        choices=[t.key for t in BINARY_TARGETS],
        help="Bundle target to package (repeat flag). Default: cli + installer targets.",
    )

    install_cli = sub.add_parser(
        "install-cli",
        help="Install the CLI binary to a user-local bin directory and persist PATH.",
    )
    install_cli.add_argument("--dist-dir", default=str(DEFAULT_DIST_DIR))
    install_cli.add_argument(
        "--artifact",
        help="Optional explicit path to a CLI binary artifact. Defaults to dist/bin CLI artifact.",
    )
    install_cli.add_argument(
        "--install-dir",
        help="Optional install destination. Defaults to user-local bin (for example %%LOCALAPPDATA%%\\usnpw\\bin).",
    )
    install_cli.add_argument(
        "--no-path-update",
        action="store_true",
        help="Install binary without modifying persistent user PATH.",
    )

    all_cmd = sub.add_parser("all", help="Run preflight, then build CLI binaries and checksums.")
    all_cmd.add_argument("--dist-dir", default=str(DEFAULT_DIST_DIR))
    all_cmd.add_argument(
        "--binary-target",
        action="append",
        choices=[t.key for t in BINARY_TARGETS],
        help="Restrict binaries to these targets.",
    )
    all_cmd.add_argument(
        "--no-checksums",
        action="store_true",
        help="Skip writing .sha256 files for built binaries.",
    )

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    command = args.command

    try:
        if command == "preflight":
            return run_preflight()
        if command == "checksums":
            artifact = Path(args.artifact).expanduser()
            if not artifact.is_file():
                raise ValueError(f"artifact not found: {artifact}")
            write_checksum(artifact)
            return 0
        if command == "binaries":
            dist_dir = Path(args.dist_dir).expanduser()
            target_keys = tuple(args.target or DEFAULT_BINARY_TARGETS)
            artifacts = build_binaries(dist_dir, target_keys=target_keys)
            if not args.no_checksums:
                write_checksums(artifacts)
            return 0
        if command == "bundle":
            dist_dir = Path(args.dist_dir).expanduser()
            target_keys = tuple(args.target or DEFAULT_BINARY_TARGETS)
            bundle_release_artifacts(dist_dir, target_keys=target_keys)
            return 0
        if command == "install-cli":
            dist_dir = Path(args.dist_dir).expanduser()
            artifact = Path(args.artifact).expanduser() if args.artifact else None
            install_dir = Path(args.install_dir).expanduser() if args.install_dir else None
            install_cli_binary(
                dist_dir=dist_dir,
                artifact=artifact,
                install_dir=install_dir,
                update_path=not args.no_path_update,
            )
            return 0
        if command == "all":
            rc = run_preflight()
            if rc != 0:
                return rc
            dist_dir = Path(args.dist_dir).expanduser()
            target_keys = tuple(args.binary_target or DEFAULT_BINARY_TARGETS)
            binary_artifacts = build_binaries(dist_dir, target_keys=target_keys)
            if not args.no_checksums:
                write_checksums(binary_artifacts)
            return 0
    except (OSError, ValueError, RuntimeError, py_compile.PyCompileError) as exc:
        print(f"release tool failed: {exc}", file=sys.stderr)
        return 1

    print(f"release tool failed: unknown command {command!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
