#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from usnpw.core.error_dialect import format_error_text
from usnpw.core.models import (
    USERNAME_DEFAULT_HISTORY,
    USERNAME_DEFAULT_INITIALS_WEIGHT,
    USERNAME_DEFAULT_MAX_SCHEME_PCT,
    USERNAME_DEFAULT_NO_LEADING_DIGIT,
    USERNAME_DEFAULT_POOL_SCALE,
    UsernameRequest,
)
from usnpw.core.username_policies import PLATFORM_POLICIES
from usnpw.core.username_service import generate_usernames


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Private, offline username generator.")

    parser.add_argument("-n", "--count", type=int, default=10, help="How many usernames to generate.")
    parser.add_argument("--min-len", type=int, default=8, help="Minimum username length.")
    parser.add_argument("--max-len", type=int, default=16, help="Maximum username length.")
    parser.add_argument(
        "--profile",
        choices=sorted(PLATFORM_POLICIES.keys()),
        default="generic",
        help="Platform profile for canonicalization and length bounds.",
    )
    parser.add_argument(
        "--disallow-prefix",
        action="append",
        default=[],
        help="Disallow usernames starting with prefix (repeat flag to add more).",
    )
    parser.add_argument(
        "--disallow-substring",
        action="append",
        default=[],
        help="Disallow usernames containing substring (repeat flag to add more).",
    )
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
    parser.add_argument(
        "--allow-token-reuse",
        action="store_true",
        help="Disable token blocking to increase throughput at the cost of output reuse.",
    )
    parser.add_argument("--show-meta", action="store_true", help="Print scheme/sep/case metadata per username.")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        request = UsernameRequest(
            count=args.count,
            min_len=args.min_len,
            max_len=args.max_len,
            profile=args.profile,
            block_tokens=not args.allow_token_reuse,
            disallow_prefix=tuple(args.disallow_prefix),
            disallow_substring=tuple(args.disallow_substring),
            no_leading_digit=args.no_leading_digit,
            max_scheme_pct=args.max_scheme_pct,
            history=args.history,
            pool_scale=args.pool_scale,
            initials_weight=args.initials_weight,
            show_meta=args.show_meta,
        )
        result = generate_usernames(request)
    except ValueError as exc:
        print(format_error_text(exc), file=sys.stderr)
        return 2

    for line in result.as_lines(show_meta=request.show_meta):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
