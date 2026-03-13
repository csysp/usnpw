#!/usr/bin/env python3
from __future__ import annotations

import sys

from usnpw.cli.opsec_username_cli import main as username_main
from usnpw.cli.pwgen_cli import main as password_main

_PASSWORD_ALIASES = frozenset({"password", "pass", "pw"})
_USERNAME_ALIASES = frozenset({"username", "user", "users", "uname"})


def _print_help() -> None:
    print(
        "USnPw unified CLI\n"
        "\n"
        "Usage:\n"
        "  usnpw                          generate one username + one password\n"
        "  usnpw password [password flags]\n"
        "  usnpw username [username flags]\n"
        "\n"
        "Examples:\n"
        "  usnpw\n"
        "  usnpw -n 5 -l 24\n"
        "  usnpw username -n 20 --profile reddit\n"
    )


def _generate_pair() -> int:
    """Generate one username and one password with hardened defaults."""
    from usnpw.core.error_dialect import format_error_text
    from usnpw.core.models import PasswordRequest, UsernameRequest
    from usnpw.core.password_service import generate_passwords
    from usnpw.core.username_service import generate_usernames

    try:
        un_result = generate_usernames(UsernameRequest(count=1))
        pw_result = generate_passwords(PasswordRequest(count=1))
    except ValueError as exc:
        print(format_error_text(exc), file=sys.stderr)
        return 2

    username = un_result.records[0].username
    password = pw_result.outputs[0]
    print(f"username: {username}")
    print(f"password: {password}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _generate_pair()

    command = args[0].lower()
    tail = args[1:]

    if command in ("-h", "--help", "help"):
        _print_help()
        return 0
    if command in _PASSWORD_ALIASES:
        return password_main(tail)
    if command in _USERNAME_ALIASES:
        return username_main(tail)
    if command.startswith("-"):
        return password_main(args)
    print(
        f"unknown command: {args[0]!r}. Use 'usnpw --help' for usage.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
