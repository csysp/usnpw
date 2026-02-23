from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from usnpw.cli.opsec_username_cli import (
    main as username_main,
    parse_args as parse_username_args,
)
from usnpw.cli.pwgen_cli import main as password_main, parse_args as parse_password_args
from usnpw.cli.usnpw_cli import main as usnpw_main


class CliArgTests(unittest.TestCase):
    def test_username_cli_token_reuse_flag(self) -> None:
        args = parse_username_args(["-n", "1", "--allow-token-reuse"])
        self.assertTrue(args.allow_token_reuse)

    def test_username_cli_token_reuse_default(self) -> None:
        args = parse_username_args(["-n", "1"])
        self.assertFalse(args.allow_token_reuse)

    def test_password_cli_max_entropy_flag(self) -> None:
        args = parse_password_args(["--max-entropy"])
        self.assertTrue(args.max_entropy)

    def test_password_cli_max_entropy_default(self) -> None:
        args = parse_password_args([])
        self.assertFalse(args.max_entropy)

    def test_username_cli_main_rejects_invalid_count(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = username_main(["-n", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("count must be > 0", stderr.getvalue())

    def test_username_cli_main_rejects_non_positive_history(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = username_main(["-n", "1", "--history", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("history must be > 0", stderr.getvalue())

    def test_password_cli_main_rejects_negative_bytes(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = password_main(["--format", "hex", "--bytes", "-1"])
        self.assertEqual(rc, 2)
        self.assertIn("bytes must be >= 0", stderr.getvalue())

    def test_usnpw_cli_defaults_to_password_mode(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = usnpw_main(["-n", "1", "-l", "8", "--charset", "ab"])
        self.assertEqual(rc, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(lines[0]), 8)
        self.assertTrue(set(lines[0]).issubset({"a", "b"}))

    def test_usnpw_cli_username_subcommand_dispatch(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = usnpw_main(
                [
                    "username",
                    "-n",
                    "1",
                    "--profile",
                    "reddit",
                ]
            )
        self.assertEqual(rc, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)

    def test_usnpw_cli_help(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            rc = usnpw_main(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("USnPw unified CLI", stdout.getvalue())

    def test_usnpw_cli_unknown_subcommand_hard_fails(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = usnpw_main(["usernmae", "-n", "1"])
        self.assertEqual(rc, 2)
        self.assertIn("unknown command", stderr.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
