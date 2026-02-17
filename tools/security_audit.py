from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str]) -> int:
    proc = subprocess.run(cmd, cwd=ROOT)
    return int(proc.returncode)


def _print_env() -> None:
    print(f"[env] python={sys.version.split()[0]} exe={sys.executable}")
    print(f"[env] os.name={os.name} platform={sys.platform}")

    dockerfile = ROOT / "Dockerfile"
    if dockerfile.is_file():
        text = dockerfile.read_text(encoding="utf-8", errors="ignore")
        base = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("FROM "):
                base = line.split(None, 1)[1]
                break
        if base:
            print(f"[env] docker_base={base}")


def _maybe_run_external_scanners() -> int:
    # Best-effort only: keep stdlib-only project constraints; do not auto-install tooling.
    for tool in ("trivy", "grype", "pip-audit", "bandit"):
        if shutil.which(tool):
            print(f"[scanner] found {tool} (not auto-run by default)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local security audit runner (stdlib-only).")
    parser.add_argument("--fuzz-iterations", type=int, default=5000)
    parser.add_argument("--fuzz-seed", type=int, default=0)
    parser.add_argument(
        "--allow-ci",
        action="store_true",
        help="Allow running in CI environments (local-only by default).",
    )
    args = parser.parse_args(argv)

    ci_markers = (
        os.environ.get("CI", ""),
        os.environ.get("GITHUB_ACTIONS", ""),
        os.environ.get("TF_BUILD", ""),
        os.environ.get("BUILD_BUILDID", ""),
    )
    if not args.allow_ci and any(marker.strip() for marker in ci_markers):
        print(
            "[run] security audit is local-only; refusing to run in CI. "
            "Use --allow-ci to override.",
            file=sys.stderr,
        )
        return 2

    _print_env()
    _maybe_run_external_scanners()

    steps: list[tuple[str, list[str]]] = [
        ("preflight", [sys.executable, "tools/release.py", "preflight"]),
        (
            "fuzz_gui_adapters",
            [
                sys.executable,
                "tools/fuzz_gui_adapters.py",
                "--iterations",
                str(args.fuzz_iterations),
                "--seed",
                str(args.fuzz_seed),
            ],
        ),
        (
            "fuzz_api_adapters",
            [
                sys.executable,
                "tools/fuzz_api_adapters.py",
                "--iterations",
                str(args.fuzz_iterations),
                "--seed",
                str(args.fuzz_seed),
            ],
        ),
        ("pentest_api", [sys.executable, "tools/pentest_api.py"]),
    ]

    for name, cmd in steps:
        print(f"[run] {name}: {' '.join(cmd)}")
        rc = _run(cmd)
        if rc != 0:
            print(f"[run] {name} failed rc={rc}", file=sys.stderr)
            return rc

    print("[run] security audit ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
