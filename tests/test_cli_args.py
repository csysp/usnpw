from __future__ import annotations

import unittest

from usnpw.cli.opsec_username_cli import parse_args as parse_username_args
from usnpw.cli.pwgen_cli import parse_args as parse_password_args


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


if __name__ == "__main__":
    unittest.main()
