#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PATH_MARKER = "# Added by usnpw install-cli"


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


def _remove_user_path_windows(path_entry: Path) -> bool:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        try:
            current_path_raw, reg_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            return False

        current_path = current_path_raw if isinstance(current_path_raw, str) else ""
        parts = [part for part in current_path.split(";") if part]
        normalized_entry = _normalize_path_for_compare(str(path_entry))
        kept_parts = [part for part in parts if _normalize_path_for_compare(part) != normalized_entry]
        if len(kept_parts) == len(parts):
            return False

        merged = ";".join(kept_parts)
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


def _remove_user_path_posix(path_entry: Path) -> bool:
    profile = Path.home() / ".profile"
    if not profile.exists():
        return False

    export_line = f'export PATH="{path_entry}:$PATH"'
    lines = profile.read_text(encoding="utf-8").splitlines()
    kept_lines: list[str] = []
    removed = False
    for line in lines:
        if line == PATH_MARKER or line == export_line:
            removed = True
            continue
        kept_lines.append(line)

    if not removed:
        return False

    new_content = "\n".join(kept_lines)
    if new_content:
        new_content += "\n"
    profile.write_text(new_content, encoding="utf-8")
    return True


def _remove_user_path(path_entry: Path) -> bool:
    if os.name == "nt":
        return _remove_user_path_windows(path_entry)
    return _remove_user_path_posix(path_entry)


def uninstall_cli(*, install_dir: Path | None, remove_path: bool, keep_install_dir: bool) -> None:
    target_dir = (install_dir.expanduser() if install_dir is not None else _default_cli_install_dir()).resolve()
    if target_dir.exists() and not target_dir.is_dir():
        raise ValueError(f"install path is not a directory: {target_dir}")

    dest_name = "usnpw.exe" if os.name == "nt" else "usnpw"
    binary = target_dir / dest_name
    sidecar = binary.with_suffix(binary.suffix + ".sha256")

    for path in (binary, sidecar):
        if not path.exists():
            print(f"[uninstall-cli] not found {path}")
            continue
        if not path.is_file():
            raise ValueError(f"expected file, found non-file path: {path}")
        path.unlink()
        print(f"[uninstall-cli] removed {path}")

    if remove_path:
        removed = _remove_user_path(target_dir)
        if removed:
            print(f"[uninstall-cli] removed PATH entry: {target_dir}")
        else:
            print(f"[uninstall-cli] PATH entry not present: {target_dir}")
    else:
        print("[uninstall-cli] skipped PATH cleanup (use --remove-path to remove persistent PATH entry).")

    if keep_install_dir:
        return
    if target_dir.exists():
        try:
            target_dir.rmdir()
            print(f"[uninstall-cli] removed empty directory {target_dir}")
        except OSError:
            print(f"[uninstall-cli] kept non-empty directory {target_dir}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Uninstall the user-local usnpw CLI binary for iterative testing."
    )
    parser.add_argument(
        "--install-dir",
        help="Optional install directory override. Defaults to the same user-local path as install-cli.",
    )
    parser.add_argument(
        "--remove-path",
        action="store_true",
        help="Also remove the install directory from persistent user PATH.",
    )
    parser.add_argument(
        "--keep-install-dir",
        action="store_true",
        help="Keep install directory even if it becomes empty after uninstall.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    install_dir = Path(args.install_dir).expanduser() if args.install_dir else None
    try:
        uninstall_cli(
            install_dir=install_dir,
            remove_path=bool(args.remove_path),
            keep_install_dir=bool(args.keep_install_dir),
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"uninstall-cli failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
