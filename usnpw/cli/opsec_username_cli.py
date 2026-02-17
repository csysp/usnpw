#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from usnpw.core.error_dialect import format_error_text
from usnpw.core.models import (
    DEFAULT_USERNAME_BLACKLIST,
    DEFAULT_USERNAME_TOKENS,
    USERNAME_DEFAULT_HISTORY,
    USERNAME_DEFAULT_INITIALS_WEIGHT,
    USERNAME_DEFAULT_MAX_SCHEME_PCT,
    USERNAME_DEFAULT_NO_LEADING_DIGIT,
    USERNAME_DEFAULT_NO_SAVE,
    USERNAME_DEFAULT_NO_TOKEN_SAVE,
    USERNAME_DEFAULT_POOL_SCALE,
    USERNAME_DEFAULT_UNIQUENESS_MODE,
    UsernameRequest,
)
from usnpw.core.username_policies import PLATFORM_POLICIES
from usnpw.core.username_service import generate_usernames


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OPSEC-ish random username generator (v4).")

    parser.add_argument("-n", "--count", type=int, default=10, help="How many usernames to generate.")
    parser.add_argument("--min-len", type=int, default=8, help="Minimum username length (re-roll if shorter).")
    parser.add_argument("--max-len", type=int, default=16, help="Maximum username length.")
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="Apply and lock recommended hardening defaults (stream mode, no-save, no-token-save, no-leading-digit, tuned anti-fingerprint knobs).",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PLATFORM_POLICIES.keys()),
        default="generic",
        help="Platform profile for canonicalization and length bounds.",
    )
    parser.add_argument(
        "--uniqueness-mode",
        choices=["blacklist", "stream"],
        default=USERNAME_DEFAULT_UNIQUENESS_MODE,
        help="blacklist = persistent historical list, stream = no name ledger (secret+counter state).",
    )
    parser.add_argument(
        "--blacklist",
        type=str,
        default=DEFAULT_USERNAME_BLACKLIST,
        help="Path to username blacklist file.",
    )
    parser.add_argument(
        "--no-save",
        dest="no_save",
        action="store_true",
        default=USERNAME_DEFAULT_NO_SAVE,
        help="Do not write generated names to username blacklist (default: on).",
    )
    parser.add_argument(
        "--save",
        dest="no_save",
        action="store_false",
        help="Allow username blacklist persistence in blacklist mode.",
    )

    parser.add_argument(
        "--token-blacklist",
        type=str,
        default=DEFAULT_USERNAME_TOKENS,
        help="Path to token blacklist file (blocks reuse of components).",
    )
    parser.add_argument(
        "--no-token-save",
        dest="no_token_save",
        action="store_true",
        default=USERNAME_DEFAULT_NO_TOKEN_SAVE,
        help="Do not write used tokens to token blacklist (default: on).",
    )
    parser.add_argument(
        "--token-save",
        dest="no_token_save",
        action="store_false",
        help="Allow token persistence to token blacklist.",
    )
    parser.add_argument("--no-token-block", action="store_true", help="Disable token blocking (not recommended).")
    parser.add_argument(
        "--stream-save-tokens",
        action="store_true",
        help="Allow token blacklist persistence in stream mode (disabled by default for lower artifact footprint).",
    )
    parser.add_argument(
        "--stream-state",
        type=str,
        default="",
        help="(stream mode) path to local stream state file. Default: ~/.opsec_username_stream_<profile>.json",
    )
    parser.add_argument(
        "--no-stream-state-persist",
        action="store_true",
        help="(stream mode) force in-memory stream state for this run (no state-file persistence).",
    )
    parser.add_argument(
        "--allow-plaintext-stream-state",
        action="store_true",
        help="Allow plaintext stream state storage when secure storage is unavailable (not recommended).",
    )

    parser.add_argument("--disallow-prefix", action="append", default=[], help="Disallow usernames starting with prefix.")
    parser.add_argument("--disallow-substring", action="append", default=[], help="Disallow usernames containing substring.")
    parser.add_argument(
        "--no-leading-digit",
        dest="no_leading_digit",
        action="store_true",
        default=USERNAME_DEFAULT_NO_LEADING_DIGIT,
        help="Reject usernames that start with a digit (default: on).",
    )
    parser.add_argument(
        "--allow-leading-digit",
        dest="no_leading_digit",
        action="store_false",
        help="Allow usernames to start with digits.",
    )

    parser.add_argument(
        "--max-scheme-pct",
        type=float,
        default=USERNAME_DEFAULT_MAX_SCHEME_PCT,
        help="Max fraction any scheme may occupy (default 0.28).",
    )
    parser.add_argument(
        "--history",
        type=int,
        default=USERNAME_DEFAULT_HISTORY,
        help="Recent history window for anti-repeat (default 10).",
    )
    parser.add_argument(
        "--pool-scale",
        type=int,
        default=USERNAME_DEFAULT_POOL_SCALE,
        help="Per-run sub-pool diversity (1..6). Higher = less vocabulary repetition (default 4).",
    )
    parser.add_argument(
        "--initials-weight",
        type=float,
        default=USERNAME_DEFAULT_INITIALS_WEIGHT,
        help="Weight for initials_style scheme (0 disables it). Default 0.",
    )
    parser.add_argument("--show-meta", action="store_true", help="Print scheme/sep/case metadata per username.")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    request = UsernameRequest(
        count=args.count,
        min_len=args.min_len,
        max_len=args.max_len,
        profile=args.profile,
        safe_mode=args.safe_mode,
        uniqueness_mode=args.uniqueness_mode,
        blacklist=args.blacklist,
        no_save=args.no_save,
        token_blacklist=args.token_blacklist,
        no_token_save=args.no_token_save,
        no_token_block=args.no_token_block,
        stream_save_tokens=args.stream_save_tokens,
        stream_state=args.stream_state,
        stream_state_persist=not args.no_stream_state_persist,
        allow_plaintext_stream_state=args.allow_plaintext_stream_state,
        disallow_prefix=tuple(args.disallow_prefix),
        disallow_substring=tuple(args.disallow_substring),
        no_leading_digit=args.no_leading_digit,
        max_scheme_pct=args.max_scheme_pct,
        history=args.history,
        pool_scale=args.pool_scale,
        initials_weight=args.initials_weight,
        show_meta=args.show_meta,
    )

    try:
        result = generate_usernames(request)
    except ValueError as exc:
        print(format_error_text(exc), file=sys.stderr)
        return 2

    for line in result.as_lines(show_meta=request.show_meta):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
