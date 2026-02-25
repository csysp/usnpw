#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

PATH_MARKER = "# Added by usnpw install-cli"
ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "dist" / "bin"


def _host_platform_tag() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _installer_artifact_path() -> Path:
    base = f"usnpw-{_host_platform_tag()}-installer"
    if os.name == "nt":
        base += ".exe"
    path = BIN_DIR / base
    if not path.is_file():
        raise ValueError(f"installer artifact not found: {path}")
    return path


def _assert_contains(path: Path, needle: str) -> None:
    if not path.is_file():
        raise ValueError(f"expected file not found: {path}")
    content = path.read_text(encoding="utf-8")
    if needle not in content:
        raise ValueError(f"expected marker not present in {path}: {needle!r}")


def _can_write_directory(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".usnpw-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _runtime_tmp_root() -> Path:
    for key in ("RUNNER_TEMP", "TMPDIR", "TEMP", "TMP"):
        raw = os.environ.get(key, "")
        if not raw:
            continue
        candidate = Path(raw).expanduser()
        if _can_write_directory(candidate):
            return candidate

    fallback = ROOT / "dist"
    if not _can_write_directory(fallback):
        raise ValueError("no writable temporary directory available for installer smoke test")
    return fallback


def _run_installer_smoke() -> None:
    installer = _installer_artifact_path()
    tmp_root = ROOT / "dist" / f"installer-smoke-{os.getpid()}"
    runtime_tmp: Path | None = None
    if tmp_root.exists():
        shutil.rmtree(tmp_root, ignore_errors=True)
    tmp_root.mkdir(parents=True, exist_ok=True)
    try:
        env = os.environ.copy()
        runtime_tmp = _runtime_tmp_root() / f"usnpw-installer-smoke-runtime-{os.getpid()}"
        if runtime_tmp.exists():
            shutil.rmtree(runtime_tmp, ignore_errors=True)
        runtime_tmp.mkdir(parents=True, exist_ok=True)
        env["TMP"] = str(runtime_tmp)
        env["TEMP"] = str(runtime_tmp)
        env["TMPDIR"] = str(runtime_tmp)

        if os.name == "nt":
            local_appdata = tmp_root / "localappdata"
            local_appdata.mkdir(parents=True, exist_ok=True)
            env["LOCALAPPDATA"] = str(local_appdata)
            cmd = [str(installer), "--no-path-update"]
            expected_binary = local_appdata / "usnpw" / "bin" / "usnpw.exe"
            expected_home = None
            expected_profile = None
        else:
            home = tmp_root / "home"
            home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(home)
            expected_home = home
            if sys.platform == "darwin":
                env["SHELL"] = "/bin/zsh"
                expected_profile = home / ".zprofile"
            else:
                env["SHELL"] = "/bin/bash"
                expected_profile = home / ".bash_profile"
            cmd = [str(installer)]
            expected_binary = home / ".local" / "bin" / "usnpw"

        proc = subprocess.run(cmd, cwd=ROOT, env=env)
        if proc.returncode != 0:
            raise RuntimeError(f"installer smoke run failed with exit code {proc.returncode}")

        if not expected_binary.is_file():
            raise ValueError(f"installed CLI binary missing: {expected_binary}")
        expected_sidecar = expected_binary.with_suffix(expected_binary.suffix + ".sha256")
        if not expected_sidecar.is_file():
            raise ValueError(f"installed checksum sidecar missing: {expected_sidecar}")

        if os.name != "nt":
            mode = stat.S_IMODE(expected_binary.stat().st_mode)
            if mode & 0o111 == 0:
                raise ValueError(f"installed CLI binary is not executable: {expected_binary}")
            if expected_home is None:
                raise ValueError("internal error: missing expected HOME for POSIX smoke test")
            _assert_contains(expected_home / ".profile", PATH_MARKER)
            if expected_profile is not None:
                _assert_contains(expected_profile, PATH_MARKER)

        help_proc = subprocess.run([str(expected_binary), "--help"], cwd=ROOT, env=env)
        if help_proc.returncode != 0:
            raise RuntimeError(f"installed CLI help check failed with exit code {help_proc.returncode}")
    finally:
        if runtime_tmp is not None:
            shutil.rmtree(runtime_tmp, ignore_errors=True)
        shutil.rmtree(tmp_root, ignore_errors=True)


def main() -> int:
    try:
        _run_installer_smoke()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"installer smoke failed: {exc}", file=sys.stderr)
        return 1
    print("installer smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
