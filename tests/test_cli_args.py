from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from usnpw.cli.opsec_username_cli import (
    main as username_main,
    parse_args as parse_username_args,
    validate_safe_mode_args,
)
from usnpw.cli.pwgen_cli import parse_args as parse_password_args
from usnpw.cli.usnpw_cli import main as usnpw_main


class CliArgTests(unittest.TestCase):
    def test_username_cli_stream_state_persist_flag(self) -> None:
        args = parse_username_args(["-n", "1", "--no-stream-state-persist"])
        self.assertTrue(args.no_stream_state_persist)

    def test_username_cli_stream_state_persist_default(self) -> None:
        args = parse_username_args(["-n", "1"])
        self.assertFalse(args.no_stream_state_persist)

    def test_password_cli_max_entropy_flag(self) -> None:
        args = parse_password_args(["--max-entropy"])
        self.assertTrue(args.max_entropy)

    def test_password_cli_max_entropy_default(self) -> None:
        args = parse_password_args([])
        self.assertFalse(args.max_entropy)

    def test_username_cli_safe_mode_conflict_validation(self) -> None:
        args = parse_username_args(["--safe-mode", "--allow-leading-digit"])
        with self.assertRaisesRegex(ValueError, "safe-mode cannot be combined with conflicting options"):
            validate_safe_mode_args(args)

    def test_username_cli_safe_mode_non_conflicting_args_are_allowed(self) -> None:
        args = parse_username_args(["--safe-mode", "-n", "1"])
        validate_safe_mode_args(args)

    def test_username_cli_main_hard_fails_on_safe_mode_conflict(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = username_main(["--safe-mode", "--allow-leading-digit", "-n", "1"])
        self.assertEqual(rc, 2)
        self.assertIn("safe-mode cannot be combined with conflicting options", stderr.getvalue())

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
                    "--blacklist",
                    ".tmp_username_blacklist.txt",
                    "--token-blacklist",
                    ".tmp_username_tokens.txt",
                    "--no-stream-state-persist",
                    "--no-save",
                    "--no-token-save",
                    "--no-token-block",
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


if __name__ == "__main__":
    unittest.main()
