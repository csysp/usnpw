from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from usnpw.core import username_storage
from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import apply_safe_mode_overrides, generate_usernames
from usnpw.core.username_lexicon import RunPools


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
        with self.assertRaisesRegex(ValueError, "bip39_wordlist is required when format is bip39"):
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

    def test_username_service_rejects_oversize_blacklist_file(self) -> None:
        suffix = f"{os.getpid()}_{time.time_ns()}"
        blacklist_path = Path(f".tmp_names_oversize_{suffix}.txt")
        try:
            with blacklist_path.open("wb") as handle:
                handle.truncate(username_storage.MAX_LINESET_FILE_BYTES + 1)
            request = UsernameRequest(
                count=1,
                min_len=5,
                max_len=12,
                profile="reddit",
                uniqueness_mode="blacklist",
                blacklist=str(blacklist_path),
                no_save=True,
                no_token_save=True,
                no_token_block=True,
            )
            with self.assertRaisesRegex(ValueError, "username blacklist file is too large"):
                generate_usernames(request)
        finally:
            try:
                blacklist_path.unlink()
            except OSError:
                pass

    def test_username_service_token_cap_does_not_hard_fail_on_soft_scheme_pct(self) -> None:
        pools = RunPools(
            adjectives=["a0", "a1", "a2", "a3"],
            nouns=["n0", "n1", "n2"],
            verbs=["v0", "v1", "v2", "v3", "v4"],
            pseudos=[f"pseudo{i}" for i in range(20)],
            tags=[f"tag{i}" for i in range(20)],
        )
        request = UsernameRequest(
            count=8,
            min_len=5,
            max_len=20,
            profile="reddit",
            uniqueness_mode="blacklist",
            no_save=True,
            no_token_save=True,
            no_token_block=False,
            max_scheme_pct=0.10,
        )

        def _fake_generate_unique(  # type: ignore[no-untyped-def]
            username_blacklist_keys,
            token_blacklist,
            max_len,
            min_len,
            policy,
            disallow_prefixes,
            disallow_substrings,
            state,
            schemes,
            pools,
            history_n,
            block_tokens,
            attempts=80_000,
            push_state=True,
        ):
            del username_blacklist_keys, policy, disallow_prefixes, disallow_substrings, state, schemes, history_n, attempts
            del push_state, block_tokens
            for token in pools.pseudos:
                if token in token_blacklist:
                    continue
                username = token[:max_len]
                if len(username) < min_len:
                    continue
                return username, "pseudoword_pair", "", "lower", {token}
            raise RuntimeError("exhausted")

        with (
            patch("usnpw.core.username_service.username_lexicon.build_run_pools", return_value=pools),
            patch("usnpw.core.username_service.username_generation.generate_unique", side_effect=_fake_generate_unique),
        ):
            result = generate_usernames(request)

        self.assertEqual(len(result.records), 8)

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
            patch("usnpw.core.username_service.username_stream_state.acquire_stream_state_lock") as lock_state,
            patch("usnpw.core.username_service.username_stream_state.load_or_init_stream_state") as load_state,
            patch("usnpw.core.username_service.username_stream_state.save_stream_state") as save_state,
            patch("usnpw.core.username_service.username_stream_state.release_stream_state_lock") as release_lock,
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
            patch("usnpw.core.username_service.username_stream_state.acquire_stream_state_lock") as lock_state,
            patch("usnpw.core.username_service.username_stream_state.load_or_init_stream_state") as load_state,
            patch("usnpw.core.username_service.username_stream_state.save_stream_state") as save_state,
            patch("usnpw.core.username_service.username_stream_state.release_stream_state_lock") as release_lock,
        ):
            result = generate_usernames(request)

        self.assertEqual(len(result.records), 2)
        lock_state.assert_not_called()
        load_state.assert_not_called()
        save_state.assert_not_called()
        release_lock.assert_not_called()

    def test_blacklist_mode_save_acquires_and_releases_lock(self) -> None:
        suffix = f"{os.getpid()}_{time.time_ns()}"
        blacklist_path = Path(f".tmp_names_{suffix}.txt")
        token_path = Path(f".tmp_tokens_{suffix}.txt")
        try:
            request = UsernameRequest(
                count=2,
                min_len=5,
                max_len=12,
                profile="reddit",
                uniqueness_mode="blacklist",
                blacklist=str(blacklist_path),
                token_blacklist=str(token_path),
                no_save=False,
                no_token_save=True,
                no_token_block=True,
            )
            lock_obj = object()
            with (
                patch(
                    "usnpw.core.username_service.username_stream_state.acquire_stream_state_lock",
                    return_value=lock_obj,
                ) as acquire_lock,
                patch("usnpw.core.username_service.username_stream_state.release_stream_state_lock") as release_lock,
            ):
                result = generate_usernames(request)

            self.assertEqual(len(result.records), 2)
            acquire_lock.assert_called_once_with(blacklist_path)
            release_lock.assert_called_once_with(lock_obj)
            self.assertTrue(blacklist_path.exists())
        finally:
            for path in (
                blacklist_path,
                token_path,
                blacklist_path.with_name(blacklist_path.name + ".lock"),
                token_path.with_name(token_path.name + ".lock"),
            ):
                try:
                    path.unlink()
                except OSError:
                    pass

    def test_blacklist_mode_no_save_skips_lock(self) -> None:
        suffix = f"{os.getpid()}_{time.time_ns()}"
        blacklist_path = Path(f".tmp_names_{suffix}.txt")
        token_path = Path(f".tmp_tokens_{suffix}.txt")
        try:
            request = UsernameRequest(
                count=2,
                min_len=5,
                max_len=12,
                profile="reddit",
                uniqueness_mode="blacklist",
                blacklist=str(blacklist_path),
                token_blacklist=str(token_path),
                no_save=True,
                no_token_save=True,
                no_token_block=True,
            )
            with (
                patch("usnpw.core.username_service.username_stream_state.acquire_stream_state_lock") as acquire_lock,
                patch("usnpw.core.username_service.username_stream_state.release_stream_state_lock") as release_lock,
            ):
                result = generate_usernames(request)

            self.assertEqual(len(result.records), 2)
            acquire_lock.assert_not_called()
            release_lock.assert_not_called()
        finally:
            for path in (
                blacklist_path,
                token_path,
                blacklist_path.with_name(blacklist_path.name + ".lock"),
                token_path.with_name(token_path.name + ".lock"),
            ):
                try:
                    path.unlink()
                except OSError:
                    pass

    def test_blacklist_mode_token_save_acquires_token_lock(self) -> None:
        suffix = f"{os.getpid()}_{time.time_ns()}"
        blacklist_path = Path(f".tmp_names_{suffix}.txt")
        token_path = Path(f".tmp_tokens_{suffix}.txt")
        try:
            request = UsernameRequest(
                count=2,
                min_len=5,
                max_len=12,
                profile="reddit",
                uniqueness_mode="blacklist",
                blacklist=str(blacklist_path),
                token_blacklist=str(token_path),
                no_save=True,
                no_token_save=False,
                no_token_block=False,
            )
            token_lock = object()
            with (
                patch(
                    "usnpw.core.username_service.username_stream_state.acquire_stream_state_lock",
                    return_value=token_lock,
                ) as acquire_lock,
                patch("usnpw.core.username_service.username_stream_state.release_stream_state_lock") as release_lock,
            ):
                result = generate_usernames(request)

            self.assertEqual(len(result.records), 2)
            acquire_lock.assert_called_once_with(token_path)
            release_lock.assert_called_once_with(token_lock)
            self.assertTrue(token_path.exists())
        finally:
            for path in (
                blacklist_path,
                token_path,
                blacklist_path.with_name(blacklist_path.name + ".lock"),
                token_path.with_name(token_path.name + ".lock"),
            ):
                try:
                    path.unlink()
                except OSError:
                    pass

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
