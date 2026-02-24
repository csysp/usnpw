#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.release import DEFAULT_DIST_DIR, install_cli_binary


def _host_platform_tag() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _default_cli_artifact_name() -> str:
    base = f"usnpw-{_host_platform_tag()}-cli"
    if os.name == "nt":
        return f"{base}.exe"
    return base


def _runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return ROOT


def _bundle_dir() -> Path | None:
    if not getattr(sys, "frozen", False):
        return None
    base = getattr(sys, "_MEIPASS", "")
    if not base:
        return None
    return Path(base)


def _resolve_default_artifact(dist_dir: Path) -> Path:
    artifact_name = _default_cli_artifact_name()

    bundled_root = _bundle_dir()
    if bundled_root is not None:
        bundled = bundled_root / artifact_name
        if bundled.is_file():
            return bundled

    sibling = _runtime_dir() / artifact_name
    if sibling.is_file():
        return sibling

    dist_candidate = dist_dir.expanduser() / "bin" / artifact_name
    if dist_candidate.is_file():
        return dist_candidate

    raise ValueError(
        "CLI artifact not found in bundled payload, next to installer, or under dist/bin. "
        "Use --artifact to provide a CLI binary path explicitly."
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install host-native usnpw CLI binary and persist user PATH."
    )
    parser.add_argument(
        "--dist-dir",
        default=str(DEFAULT_DIST_DIR),
        help="Optional dist directory for fallback artifact lookup (default: ./dist).",
    )
    parser.add_argument(
        "--artifact",
        help=(
            "Optional explicit path to a CLI artifact. "
            "Defaults to bundled or sibling usnpw-<platform>-cli binary."
        ),
    )
    parser.add_argument(
        "--install-dir",
        help="Optional install destination override (defaults to user-local bin path).",
    )
    parser.add_argument(
        "--no-path-update",
        action="store_true",
        help="Install binary without modifying persistent user PATH.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    dist_dir = Path(args.dist_dir).expanduser()
    install_dir = Path(args.install_dir).expanduser() if args.install_dir else None
    artifact = Path(args.artifact).expanduser() if args.artifact else None

    try:
        resolved_artifact = artifact or _resolve_default_artifact(dist_dir)
        print(f"[installer] using artifact: {resolved_artifact}")
        install_cli_binary(
            dist_dir=dist_dir,
            artifact=resolved_artifact,
            install_dir=install_dir,
            update_path=not args.no_path_update,
        )
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"installer failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
