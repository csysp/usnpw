#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from usnpw.core.error_dialect import format_error_text
from usnpw.core.models import PasswordRequest
from usnpw.core.password_engine import FORMAT_CHOICES, OUT_ENC_CHOICES
from usnpw.core.password_service import generate_passwords


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Password / token generator using os.urandom")

    # Password mode args
    parser.add_argument("-l", "--length", type=int, default=20, help="password length")
    parser.add_argument("-n", "--count", type=int, default=1, help="number of outputs to print")
    parser.add_argument("--charset", default="", help="custom character set (overrides other options)")
    parser.add_argument(
        "--symbols",
        default="!@#$%^&*()-_=+[]{};:,?/",
        help="symbol set to include (ignored with --charset)",
    )
    parser.add_argument("--no-symbols", action="store_true", help="exclude symbols from the generated passwords")
    parser.add_argument(
        "--max-entropy",
        action="store_true",
        help="hardened preset: force 512-bit base64url output for post-quantum margin",
    )

    # Token/hash args
    parser.add_argument("--format", choices=FORMAT_CHOICES, default="password", help="output format")
    parser.add_argument(
        "--bytes",
        type=int,
        default=0,
        help="bytes of entropy for token/hash formats (if 0, defaults or --bits will be used)",
    )
    parser.add_argument(
        "--bits",
        type=int,
        default=0,
        help="convenience: set entropy size in bits (overrides --bytes when --bytes is 0). Common: 128, 192, 256",
    )
    parser.add_argument(
        "--out-enc",
        choices=OUT_ENC_CHOICES,
        default="hex",
        help="(hash formats) encoding of digest output",
    )

    # Grouping
    parser.add_argument("--group", type=int, default=0, help="group output into chunks of N characters")
    parser.add_argument("--group-sep", default="-", help="separator used with --group (default: -)")
    parser.add_argument("--group-pad", default="", help="optional: right-pad final group with this character")

    # BIP39
    parser.add_argument("--words", type=int, default=24, choices=[12, 18, 24], help="(bip39) number of words")
    parser.add_argument("--delim", default=" ", help="(bip39) delimiter between words (default: space)")
    parser.add_argument("--bip39-wordlist", default="", help="(bip39) path to 2048-word English wordlist file")
    parser.add_argument(
        "--show-meta",
        "--meta",
        action="store_true",
        help="Print estimated entropy metadata per output.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    request = PasswordRequest(
        count=args.count,
        length=args.length,
        charset=args.charset,
        symbols=args.symbols,
        no_symbols=args.no_symbols,
        max_entropy=args.max_entropy,
        format=args.format,
        entropy_bytes=args.bytes,
        bits=args.bits,
        out_enc=args.out_enc,
        group=args.group,
        group_sep=args.group_sep,
        group_pad=args.group_pad,
        words=args.words,
        delim=args.delim,
        bip39_wordlist=args.bip39_wordlist,
    )
    try:
        result = generate_passwords(request)
    except ValueError as exc:
        print(format_error_text(exc), file=sys.stderr)
        return 2
    for line in result.as_lines(show_meta=args.show_meta):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
