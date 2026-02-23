from __future__ import annotations

import string
import unittest
from unittest.mock import patch

from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_lexicon import RunPools
from usnpw.core.username_service import generate_usernames


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

    def test_password_service_rejects_negative_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "bytes must be >= 0"):
            generate_passwords(PasswordRequest(count=1, format="hex", entropy_bytes=-1))

    def test_password_service_rejects_negative_bits(self) -> None:
        with self.assertRaisesRegex(ValueError, "bits must be >= 0"):
            generate_passwords(PasswordRequest(count=1, format="hex", bits=-8))

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
            self.assertEqual(len(value), 86)
            self.assertRegex(value, r"^[A-Za-z0-9_-]+$")

    def test_username_service_count_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "count must be > 0"):
            generate_usernames(UsernameRequest(count=0))

    def test_username_service_history_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "history must be > 0"):
            generate_usernames(UsernameRequest(history=0))

    def test_username_service_initials_weight_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "initials_weight must be >= 0"):
            generate_usernames(UsernameRequest(initials_weight=-1.0))

    def test_username_service_generates_records(self) -> None:
        request = UsernameRequest(
            count=6,
            min_len=5,
            max_len=12,
            profile="telegram",
        )
        result = generate_usernames(request)
        self.assertEqual(len(result.records), 6)
        for row in result.records:
            self.assertGreaterEqual(len(row.username), 5)
            self.assertLessEqual(len(row.username), 12)

    def test_username_request_defaults_are_hardened(self) -> None:
        request = UsernameRequest()
        self.assertTrue(request.block_tokens)
        self.assertTrue(request.no_leading_digit)
        self.assertEqual(request.history, 10)
        self.assertEqual(request.pool_scale, 4)
        self.assertEqual(request.initials_weight, 0.0)

    def test_username_service_is_stream_only_and_never_touches_state_files(self) -> None:
        request = UsernameRequest(
            count=2,
            min_len=5,
            max_len=12,
            profile="reddit",
        )
        result = generate_usernames(request)
        self.assertEqual(len(result.records), 2)

    def test_stream_mode_block_tokens_does_not_misreport_token_saturation(self) -> None:
        impossible_prefixes = tuple(string.ascii_lowercase + string.digits)
        request = UsernameRequest(
            count=1,
            min_len=8,
            max_len=16,
            profile="reddit",
            disallow_prefix=impossible_prefixes,
        )
        with self.assertRaises(ValueError) as ctx:
            generate_usernames(request)
        msg = str(ctx.exception)
        self.assertIn("Failed to generate a stream-unique username", msg)
        self.assertNotIn("Token-block saturation reached", msg)

    def test_token_specific_runtime_maps_to_saturation_message(self) -> None:
        pools = RunPools(
            adjectives=["able", "agile"],
            nouns=["node", "token"],
            verbs=["build", "trace"],
            pseudos=["keko", "mavu"],
            tags=["xx", "yy"],
        )
        request = UsernameRequest(
            count=1,
            min_len=5,
            max_len=12,
            profile="reddit",
            block_tokens=True,
        )

        with (
            patch("usnpw.core.username_service.username_lexicon.build_run_pools", return_value=pools),
            patch(
                "usnpw.core.username_service.username_generation.generate_stream_unique",
                side_effect=RuntimeError("Token-block candidate space exhausted within attempt budget."),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "Token-block saturation reached before target count"):
                generate_usernames(request)

    def test_token_block_mode_filters_to_viable_schemes_under_budget_pressure(self) -> None:
        pools = RunPools(
            adjectives=[],
            nouns=[],
            verbs=[],
            pseudos=["keko", "mavu"],
            tags=["xx"],
        )
        request = UsernameRequest(
            count=1,
            min_len=5,
            max_len=16,
            profile="reddit",
            block_tokens=True,
        )

        captured_scheme_names: list[list[str]] = []

        def _fake_stream_unique(  # type: ignore[no-untyped-def]
            *,
            stream_key,
            stream_tag_map,
            stream_counter,
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
            attempts=2000,
            existing_username_keys=None,
        ):
            del (
                stream_key,
                stream_tag_map,
                token_blacklist,
                max_len,
                min_len,
                policy,
                disallow_prefixes,
                disallow_substrings,
                state,
                pools,
                history_n,
                block_tokens,
                attempts,
                existing_username_keys,
            )
            captured_scheme_names.append([s.name for s in schemes])
            return "kekoabc", "pseudoword_pair", "", "lower", {"keko"}, stream_counter + 1

        with (
            patch("usnpw.core.username_service.username_lexicon.build_run_pools", return_value=pools),
            patch("usnpw.core.username_service.username_generation.generate_stream_unique", side_effect=_fake_stream_unique),
        ):
            result = generate_usernames(request)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(captured_scheme_names, [["pseudoword_pair"]])

    def test_no_viable_token_block_schemes_fails_closed(self) -> None:
        pools = RunPools(
            adjectives=[],
            nouns=[],
            verbs=[],
            pseudos=[],
            tags=[],
        )
        request = UsernameRequest(
            count=1,
            min_len=5,
            max_len=16,
            profile="reddit",
            block_tokens=True,
        )

        with (
            patch("usnpw.core.username_service.username_lexicon.build_run_pools", return_value=pools),
            patch("usnpw.core.username_service.username_schemes.max_token_block_count", return_value=None),
        ):
            with self.assertRaisesRegex(ValueError, "Token-block saturation reached before target count"):
                generate_usernames(request)

    def test_allow_token_reuse_disables_token_saturation_remap(self) -> None:
        request = UsernameRequest(
            count=1,
            min_len=5,
            max_len=12,
            profile="reddit",
            block_tokens=False,
        )
        with patch(
            "usnpw.core.username_service.username_generation.generate_stream_unique",
            side_effect=RuntimeError("Token-block candidate space exhausted within attempt budget."),
        ):
            with self.assertRaisesRegex(ValueError, "Token-block candidate space exhausted"):
                generate_usernames(request)

    def test_count_above_token_cap_fails_with_actionable_message(self) -> None:
        request = UsernameRequest(
            count=12,
            min_len=5,
            max_len=16,
            profile="reddit",
            block_tokens=True,
        )
        with patch(
            "usnpw.core.username_service.username_schemes.max_token_block_count",
            return_value=3,
        ):
            with self.assertRaisesRegex(ValueError, "--allow-token-reuse"):
                generate_usernames(request)


if __name__ == "__main__":
    unittest.main()
