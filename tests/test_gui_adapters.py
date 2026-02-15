from __future__ import annotations

import unittest

from pathlib import Path

from usnpw.gui.adapters import (
    SAFE_MODE_LOCKED_VALUES,
    build_export_warning,
    build_password_request,
    build_username_request,
    effective_stream_state_path,
    format_error_status,
    is_unusual_delete_target,
    stream_state_lock_path,
)


class GuiAdapterTests(unittest.TestCase):
    def test_build_password_request_maps_fields(self) -> None:
        req = build_password_request(
            {
                "count": "2",
                "length": "24",
                "charset": "abc123",
                "symbols": "!@#",
                "no_symbols": True,
                "max_entropy": True,
                "format": "password",
                "entropy_bytes": "0",
                "bits": "0",
                "out_enc": "hex",
                "group": "0",
                "group_sep": "-",
                "group_pad": "",
                "words": "24",
                "delim": " ",
                "bip39_wordlist": "",
            }
        )
        self.assertEqual(req.count, 2)
        self.assertEqual(req.length, 24)
        self.assertTrue(req.no_symbols)
        self.assertTrue(req.max_entropy)
        self.assertEqual(req.charset, "abc123")

    def test_build_username_request_maps_fields(self) -> None:
        req = build_username_request(
            {
                "count": "5",
                "min_len": "8",
                "max_len": "16",
                "profile": "reddit",
                "safe_mode": True,
                "uniqueness_mode": "stream",
                "blacklist": "bl.txt",
                "no_save": True,
                "token_blacklist": "tok.txt",
                "no_token_save": True,
                "no_token_block": False,
                "stream_save_tokens": False,
                "stream_state": "state.json",
                "stream_state_persist": False,
                "allow_plaintext_stream_state": False,
                "disallow_prefix": "admin,mod",
                "disallow_substring": "test,bot",
                "no_leading_digit": True,
                "max_scheme_pct": "0.28",
                "history": "10",
                "pool_scale": "4",
                "initials_weight": "0",
                "show_meta": False,
            }
        )
        self.assertEqual(req.count, 5)
        self.assertEqual(req.profile, "reddit")
        self.assertTrue(req.safe_mode)
        self.assertEqual(req.disallow_prefix, ("admin", "mod"))
        self.assertEqual(req.disallow_substring, ("test", "bot"))
        self.assertTrue(req.no_leading_digit)
        self.assertFalse(req.stream_state_persist)

    def test_build_username_request_uses_hardened_defaults(self) -> None:
        req = build_username_request({})
        self.assertEqual(req.uniqueness_mode, "stream")
        self.assertTrue(req.no_save)
        self.assertTrue(req.no_token_save)
        self.assertTrue(req.no_leading_digit)
        self.assertEqual(req.history, 10)
        self.assertEqual(req.pool_scale, 4)
        self.assertEqual(req.initials_weight, 0.0)

    def test_build_request_validation_errors(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid integer for count"):
            build_password_request({"count": "abc"})
        with self.assertRaisesRegex(ValueError, "Invalid number for max-scheme-pct"):
            build_username_request({"max_scheme_pct": "x"})

    def test_error_status_format(self) -> None:
        self.assertEqual(format_error_status("boom"), "Error: boom")

    def test_safe_mode_defaults(self) -> None:
        self.assertEqual(SAFE_MODE_LOCKED_VALUES["uniqueness_mode"], "stream")

    def test_export_warning_text(self) -> None:
        plain = build_export_warning("username data", encrypted=False)
        enc = build_export_warning("username data", encrypted=True)
        self.assertIn("recoverable local artifact", plain)
        self.assertNotIn("passphrase-encrypted", plain)
        self.assertIn("passphrase-encrypted", enc)

    def test_stream_state_path_helpers(self) -> None:
        custom = effective_stream_state_path("reddit", "./custom_state.json")
        self.assertEqual(custom.name, "custom_state.json")
        default = effective_stream_state_path("reddit", "")
        self.assertEqual(default.name, ".opsec_username_stream_reddit.json")
        lock = stream_state_lock_path(Path("state.json"))
        self.assertEqual(lock.name, "state.json.lock")

    def test_delete_target_heuristics(self) -> None:
        self.assertFalse(is_unusual_delete_target(Path("tokens.txt"), "token blacklist"))
        self.assertTrue(is_unusual_delete_target(Path("tokens.dat"), "token blacklist"))
        self.assertFalse(is_unusual_delete_target(Path("state.json"), "stream state"))
        self.assertTrue(is_unusual_delete_target(Path("state.txt"), "stream state"))
        self.assertFalse(is_unusual_delete_target(Path("state.json.lock"), "stream state lock"))
        self.assertTrue(is_unusual_delete_target(Path("state.lock"), "stream state lock"))


if __name__ == "__main__":
    unittest.main()
