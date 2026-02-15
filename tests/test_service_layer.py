from __future__ import annotations

import unittest
from unittest.mock import patch

from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import apply_safe_mode_overrides, generate_usernames


class ServiceLayerTests(unittest.TestCase):
    def test_password_service_generates_expected_count(self) -> None:
        request = PasswordRequest(count=4, length=12, charset="abc123", format="password")
        result = generate_passwords(request)
        self.assertEqual(len(result.outputs), 4)
        for value in result.outputs:
            self.assertEqual(len(value), 12)
            self.assertTrue(set(value).issubset(set("abc123")))

    def test_password_service_bits_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "bits must be a multiple of 8"):
            generate_passwords(PasswordRequest(count=1, format="hex", bits=130))

    def test_password_service_bip39_requires_wordlist_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "no wordlist path set"):
            generate_passwords(PasswordRequest(count=1, format="bip39", words=24, bip39_wordlist=""))

    def test_password_service_max_entropy_preset(self) -> None:
        result = generate_passwords(
            PasswordRequest(
                count=2,
                format="password",
                length=6,
                bits=130,
                max_entropy=True,
            )
        )
        self.assertEqual(len(result.outputs), 2)
        for value in result.outputs:
            self.assertEqual(len(value), 86)  # base64url for 64 bytes (no padding)
            self.assertRegex(value, r"^[A-Za-z0-9_-]+$")

    def test_username_service_count_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "count must be > 0"):
            generate_usernames(UsernameRequest(count=0))

    def test_username_service_generates_records(self) -> None:
        request = UsernameRequest(
            count=5,
            min_len=5,
            max_len=12,
            profile="telegram",
            uniqueness_mode="blacklist",
            blacklist=".tmp_nonexistent_blacklist.txt",
            token_blacklist=".tmp_nonexistent_tokens.txt",
            no_save=True,
            no_token_save=True,
            no_token_block=True,
        )
        result = generate_usernames(request)
        self.assertEqual(len(result.records), 5)
        for row in result.records:
            self.assertGreaterEqual(len(row.username), 5)
            self.assertLessEqual(len(row.username), 12)

    def test_username_request_defaults_are_hardened(self) -> None:
        request = UsernameRequest()
        self.assertEqual(request.uniqueness_mode, "stream")
        self.assertTrue(request.no_save)
        self.assertTrue(request.no_token_save)
        self.assertTrue(request.stream_state_persist)
        self.assertTrue(request.no_leading_digit)
        self.assertEqual(request.history, 10)
        self.assertEqual(request.pool_scale, 4)
        self.assertEqual(request.initials_weight, 0.0)

    def test_stream_mode_non_windows_ephemeral_without_plaintext(self) -> None:
        request = UsernameRequest(
            count=2,
            min_len=5,
            max_len=12,
            profile="reddit",
            uniqueness_mode="stream",
            stream_state=".tmp_stream_state.json",
            allow_plaintext_stream_state=False,
            no_save=True,
            no_token_save=True,
            no_token_block=True,
        )
        with (
            patch("usnpw.core.username_service.os.name", "posix"),
            patch("usnpw.core.username_service.engine.acquire_stream_state_lock") as lock_state,
            patch("usnpw.core.username_service.engine.load_or_init_stream_state") as load_state,
            patch("usnpw.core.username_service.engine.save_stream_state") as save_state,
            patch("usnpw.core.username_service.engine.release_stream_state_lock") as release_lock,
        ):
            result = generate_usernames(request)

        self.assertEqual(len(result.records), 2)
        lock_state.assert_not_called()
        load_state.assert_not_called()
        save_state.assert_not_called()
        release_lock.assert_not_called()

    def test_stream_mode_windows_ephemeral_when_persist_disabled(self) -> None:
        request = UsernameRequest(
            count=2,
            min_len=5,
            max_len=12,
            profile="reddit",
            uniqueness_mode="stream",
            stream_state=".tmp_stream_state.json",
            stream_state_persist=False,
            allow_plaintext_stream_state=False,
            no_save=True,
            no_token_save=True,
            no_token_block=True,
        )
        with (
            patch("usnpw.core.username_service.os.name", "nt"),
            patch("usnpw.core.username_service.engine.acquire_stream_state_lock") as lock_state,
            patch("usnpw.core.username_service.engine.load_or_init_stream_state") as load_state,
            patch("usnpw.core.username_service.engine.save_stream_state") as save_state,
            patch("usnpw.core.username_service.engine.release_stream_state_lock") as release_lock,
        ):
            result = generate_usernames(request)

        self.assertEqual(len(result.records), 2)
        lock_state.assert_not_called()
        load_state.assert_not_called()
        save_state.assert_not_called()
        release_lock.assert_not_called()

    def test_safe_mode_overrides(self) -> None:
        original = UsernameRequest(
            safe_mode=True,
            uniqueness_mode="blacklist",
            no_save=False,
            no_token_save=False,
            no_token_block=True,
            stream_save_tokens=True,
            allow_plaintext_stream_state=True,
            no_leading_digit=False,
            max_scheme_pct=0.5,
            history=4,
            pool_scale=2,
            initials_weight=0.7,
            show_meta=True,
        )
        hardened = apply_safe_mode_overrides(original)
        self.assertEqual(hardened.uniqueness_mode, "stream")
        self.assertTrue(hardened.no_save)
        self.assertTrue(hardened.no_token_save)
        self.assertFalse(hardened.no_token_block)
        self.assertFalse(hardened.stream_save_tokens)
        self.assertFalse(hardened.allow_plaintext_stream_state)
        self.assertTrue(hardened.no_leading_digit)
        self.assertEqual(hardened.max_scheme_pct, 0.28)
        self.assertEqual(hardened.history, 10)
        self.assertEqual(hardened.pool_scale, 4)
        self.assertEqual(hardened.initials_weight, 0.0)
        self.assertFalse(hardened.show_meta)


if __name__ == "__main__":
    unittest.main()
