from __future__ import annotations

import argparse
import time

from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames


def _bench_passwords(count: int, length: int) -> None:
    req = PasswordRequest(count=count, length=length)
    t0 = time.perf_counter()
    result = generate_passwords(req)
    dt = time.perf_counter() - t0
    rate = (len(result.passwords) / dt) if dt > 0 else 0.0
    print(f"[passwords] count={len(result.passwords)} length={length} seconds={dt:.4f} rate={rate:.1f}/s")


def _bench_usernames(count: int, profile: str, uniqueness_mode: str) -> None:
    # Benchmark posture: avoid persistence and disable token blocking to prevent saturation in large runs.
    req = UsernameRequest(
        count=count,
        profile=profile,
        uniqueness_mode=uniqueness_mode,
        safe_mode=False,
        no_save=True,
        no_token_save=True,
        no_token_block=True,
        stream_save_tokens=False,
        stream_state_persist=False,
        stream_state="",
        allow_plaintext_stream_state=False,
        show_meta=False,
    )
    t0 = time.perf_counter()
    result = generate_usernames(req)
    dt = time.perf_counter() - t0
    rate = (len(result.records) / dt) if dt > 0 else 0.0
    print(
        f"[usernames] count={len(result.records)} profile={profile} mode={uniqueness_mode} "
        f"seconds={dt:.4f} rate={rate:.1f}/s"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="USnPw baseline benchmark (stdlib-only).")
    parser.add_argument("--passwords", type=int, default=0, help="Number of passwords to generate.")
    parser.add_argument("--length", type=int, default=24, help="Password length for password bench.")
    parser.add_argument("--usernames", type=int, default=0, help="Number of usernames to generate.")
    parser.add_argument("--profile", type=str, default="reddit", help="Username profile for username bench.")
    parser.add_argument(
        "--uniqueness-mode",
        type=str,
        default="stream",
        choices=("stream", "blacklist"),
        help="Username uniqueness mode for bench.",
    )
    args = parser.parse_args(argv)

    if args.passwords <= 0 and args.usernames <= 0:
        parser.error("Set --passwords and/or --usernames to a value > 0")

    if args.passwords > 0:
        _bench_passwords(count=args.passwords, length=args.length)
    if args.usernames > 0:
        _bench_usernames(count=args.usernames, profile=args.profile, uniqueness_mode=args.uniqueness_mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

