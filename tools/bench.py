from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Allow running as `py .\\tools\\bench.py` without installing the package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames


def _bench_passwords(count: int, length: int) -> None:
    req = PasswordRequest(count=count, length=length)
    t0 = time.perf_counter()
    result = generate_passwords(req)
    dt = time.perf_counter() - t0
    rate = (len(result.outputs) / dt) if dt > 0 else 0.0
    print(f"[passwords] count={len(result.outputs)} length={length} seconds={dt:.4f} rate={rate:.1f}/s")


def _bench_usernames(count: int, profile: str, allow_token_reuse: bool) -> None:
    req = UsernameRequest(
        count=count,
        profile=profile,
        block_tokens=not allow_token_reuse,
        show_meta=False,
    )
    t0 = time.perf_counter()
    result = generate_usernames(req)
    dt = time.perf_counter() - t0
    rate = (len(result.records) / dt) if dt > 0 else 0.0
    mode = "token-reuse" if allow_token_reuse else "token-block"
    print(
        f"[usernames] count={len(result.records)} profile={profile} mode={mode} "
        f"seconds={dt:.4f} rate={rate:.1f}/s"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="USnPw baseline benchmark (stdlib-only).")
    parser.add_argument("--passwords", type=int, default=0, help="Number of passwords to generate.")
    parser.add_argument("--length", type=int, default=24, help="Password length for password bench.")
    parser.add_argument("--usernames", type=int, default=0, help="Number of usernames to generate.")
    parser.add_argument("--profile", type=str, default="reddit", help="Username profile for username bench.")
    parser.add_argument(
        "--allow-token-reuse",
        action="store_true",
        help="Disable token blocking for higher-throughput benchmarking.",
    )
    args = parser.parse_args(argv)

    if args.passwords <= 0 and args.usernames <= 0:
        parser.error("Set --passwords and/or --usernames to a value > 0")

    if args.passwords > 0:
        _bench_passwords(count=args.passwords, length=args.length)
    if args.usernames > 0:
        _bench_usernames(count=args.usernames, profile=args.profile, allow_token_reuse=args.allow_token_reuse)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
