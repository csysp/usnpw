from __future__ import annotations

import re
import subprocess
import sys
import unittest
from unittest.mock import patch

from usnpw.core.password_engine import generate_password

from usnpw.core import (
    username_generation,
    username_lexicon,
    username_schemes,
    username_stream_state,
    username_uniqueness,
)
from usnpw.core.username_generation import normalize_for_platform
from usnpw.core.username_policies import PLATFORM_POLICIES, PlatformPolicy


class CoreSmokeTests(unittest.TestCase):
    def test_password_generation_length_and_charset(self) -> None:
        alphabet = "abc123"
        out = generate_password(32, alphabet)
        self.assertEqual(len(out), 32)
        self.assertTrue(set(out).issubset(set(alphabet)))

    def test_password_generation_large_charset_does_not_hang(self) -> None:
        # Regression test: prior _choice_uniform() implementation could hang forever for len(alphabet) > 256.
        probe = "\n".join(
            [
                "from usnpw.core.password_engine import generate_password",
                "alphabet = ''.join(chr(0x1000 + i) for i in range(257))",
                "out = generate_password(64, alphabet)",
                "print(int(len(out) == 64 and set(out).issubset(set(alphabet))))",
            ]
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            check=True,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        self.assertEqual(proc.stdout.strip(), "1")

    def test_platform_normalization_telegram(self) -> None:
        policy = PLATFORM_POLICIES["telegram"]
        out = normalize_for_platform("A!B.C__D-", policy=policy, max_len=32)
        self.assertEqual(out, "abc_d")

    def test_stream_generation_state_is_only_updated_for_emitted_usernames(self) -> None:
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        stream_key = b"\x01" * 32
        tag_map = {ch: ch for ch in base36}

        # Force at least one stream-tag re-roll by disallowing the first tag character.
        tag0 = username_stream_state.stream_tag(tag_map, 0, scramble_key=stream_key)
        tag1 = username_stream_state.stream_tag(tag_map, 1, scramble_key=stream_key)
        self.assertNotEqual(tag0, tag1)

        policy = PlatformPolicy(
            min_len=1,
            max_len=32,
            lowercase=True,
            case_insensitive=True,
            disallow_re=re.compile(re.escape(tag0)),
            collapse_re=None,
            trim_chars="",
            separators=("", "_", "-", "."),
        )

        pools = username_lexicon.RunPools(
            adjectives=["able", "brisk", "clean"],
            nouns=["node", "token", "buffer"],
            verbs=["build", "trace", "encode"],
            pseudos=["keko", "mavu", "nori"],
            tags=["xx", "yy", "zz"],
        )
        schemes = [username_schemes.Scheme("adj_noun", 1.0, username_schemes.scheme_adj_noun)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        username, scheme_name, sep_used, case_style_used, used_tokens, stream_counter = username_generation.generate_stream_unique(
            stream_key=stream_key,
            stream_tag_map=tag_map,
            stream_counter=0,
            token_blacklist=set(),
            max_len=32,
            min_len=1,
            policy=policy,
            disallow_prefixes=tuple(),
            disallow_substrings=tuple(),
            state=state,
            schemes=schemes,
            pools=pools,
            history_n=10,
            block_tokens=False,
            attempts=50,
        )
        self.assertTrue(username)
        self.assertGreaterEqual(stream_counter, 2, "expected at least one tag re-roll")
        self.assertEqual(len(state.recent_schemes), 1)
        self.assertEqual(state.scheme_counts.get(scheme_name), 1)
        self.assertEqual(state.recent_schemes[-1], scheme_name)
        self.assertEqual(state.recent_seps[-1], sep_used)
        self.assertEqual(state.recent_case_styles[-1], case_style_used)

    def test_stream_generation_accepts_large_counter_values(self) -> None:
        stream_key = b"\x02" * 32
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        tag_map = {ch: ch for ch in base36}
        start_counter = 1 << 64

        policy = PLATFORM_POLICIES["reddit"]
        pools = username_lexicon.RunPools(
            adjectives=["able", "brisk", "clean"],
            nouns=["node", "token", "buffer"],
            verbs=["build", "trace", "encode"],
            pseudos=["keko", "mavu", "nori"],
            tags=["xx", "yy", "zz"],
        )
        schemes = [username_schemes.Scheme("adj_noun", 1.0, username_schemes.scheme_adj_noun)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        username, _, _, _, _, stream_counter = username_generation.generate_stream_unique(
            stream_key=stream_key,
            stream_tag_map=tag_map,
            stream_counter=start_counter,
            token_blacklist=set(),
            max_len=32,
            min_len=policy.min_len,
            policy=policy,
            disallow_prefixes=tuple(),
            disallow_substrings=tuple(),
            state=state,
            schemes=schemes,
            pools=pools,
            history_n=10,
            block_tokens=False,
            attempts=50,
        )
        self.assertTrue(username)
        self.assertGreater(stream_counter, start_counter)

    def test_stream_generation_is_unique_with_duplicate_guard_at_small_max_len(self) -> None:
        stream_key = b"\x03" * 32
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        tag_map = {ch: ch for ch in base36}

        policy = PLATFORM_POLICIES["reddit"]

        def _fixed_builder(state, pools, history_n):  # type: ignore[no-untyped-def]
            del state, pools, history_n
            return "a", "", "lower", {"a"}

        pools = username_lexicon.RunPools(
            adjectives=["a"],
            nouns=["a"],
            verbs=["a"],
            pseudos=["a"],
            tags=["a"],
        )
        schemes = [username_schemes.Scheme("fixed", 1.0, _fixed_builder)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1000,
            max_scheme_pct=1.0,
        )

        seen: set[str] = set()
        counter = 0
        for _ in range(1000):
            before = len(seen)
            username, _, _, _, _, counter = username_generation.generate_stream_unique(
                stream_key=stream_key,
                stream_tag_map=tag_map,
                stream_counter=counter,
                token_blacklist=set(),
                max_len=3,
                min_len=3,
                policy=policy,
                disallow_prefixes=tuple(),
                disallow_substrings=tuple(),
                state=state,
                schemes=schemes,
                pools=pools,
                history_n=1,
                block_tokens=False,
                attempts=200,
                existing_username_keys=seen,
            )
            self.assertIn(username, seen)
            self.assertEqual(len(seen), before + 1)
        self.assertEqual(len(seen), 1000)

    def test_stream_generation_rejects_unrepresentable_counter_space(self) -> None:
        stream_key = b"\x04" * 32
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        tag_map = {ch: ch for ch in base36}
        policy = PLATFORM_POLICIES["reddit"]

        pools = username_lexicon.RunPools(
            adjectives=["able"],
            nouns=["node"],
            verbs=["build"],
            pseudos=["keko"],
            tags=["xx"],
        )
        schemes = [username_schemes.Scheme("adj_noun", 1.0, username_schemes.scheme_adj_noun)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        with self.assertRaisesRegex(RuntimeError, "exceeded representable space"):
            username_generation.generate_stream_unique(
                stream_key=stream_key,
                stream_tag_map=tag_map,
                stream_counter=36**3,
                token_blacklist=set(),
                max_len=3,
                min_len=3,
                policy=policy,
                disallow_prefixes=tuple(),
                disallow_substrings=tuple(),
                state=state,
                schemes=schemes,
                pools=pools,
                history_n=1,
                block_tokens=False,
                attempts=10,
            )

    def test_stream_generation_rechecks_repeated_patterns_after_tagging(self) -> None:
        stream_key = b"\x05" * 32
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        tag_map = {ch: ch for ch in base36}
        policy = PLATFORM_POLICIES["reddit"]

        pools = username_lexicon.RunPools(
            adjectives=["able"],
            nouns=["node"],
            verbs=["build"],
            pseudos=["keko"],
            tags=["xx"],
        )
        schemes = [username_schemes.Scheme("adj_noun", 1.0, username_schemes.scheme_adj_noun)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        with (
            patch("usnpw.core.username_generation.stream_state.stream_tag", return_value="axis"),
            patch("usnpw.core.username_generation.uniqueness.apply_stream_tag", return_value="axisaxis"),
        ):
            with self.assertRaisesRegex(RuntimeError, "stream-unique username"):
                username_generation.generate_stream_unique(
                    stream_key=stream_key,
                    stream_tag_map=tag_map,
                    stream_counter=0,
                    token_blacklist=set(),
                    max_len=16,
                    min_len=3,
                    policy=policy,
                    disallow_prefixes=tuple(),
                    disallow_substrings=tuple(),
                    state=state,
                    schemes=schemes,
                    pools=pools,
                    history_n=1,
                    block_tokens=False,
                    attempts=3,
                )

    def test_stream_generation_retries_after_transient_inner_failure(self) -> None:
        stream_key = b"\x06" * 32
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        tag_map = {ch: ch for ch in base36}
        policy = PLATFORM_POLICIES["reddit"]

        pools = username_lexicon.RunPools(
            adjectives=["able"],
            nouns=["node"],
            verbs=["build"],
            pseudos=["keko"],
            tags=["xx"],
        )
        schemes = [username_schemes.Scheme("adj_noun", 1.0, username_schemes.scheme_adj_noun)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        with patch(
            "usnpw.core.username_generation.generate_unique",
            side_effect=[
                RuntimeError("Failed to generate a unique username within attempt budget."),
                ("able_node", "adj_noun", "_", "lower", {"able", "node"}),
            ],
        ):
            username, scheme_name, sep_used, case_style_used, used_tokens, stream_counter = username_generation.generate_stream_unique(
                stream_key=stream_key,
                stream_tag_map=tag_map,
                stream_counter=0,
                token_blacklist=set(),
                max_len=16,
                min_len=policy.min_len,
                policy=policy,
                disallow_prefixes=tuple(),
                disallow_substrings=tuple(),
                state=state,
                schemes=schemes,
                pools=pools,
                history_n=1,
                block_tokens=True,
                attempts=4,
            )
        self.assertTrue(username)
        self.assertEqual(scheme_name, "adj_noun")
        self.assertEqual(sep_used, "_")
        self.assertEqual(case_style_used, "lower")
        self.assertEqual(used_tokens, {"able", "node"})
        self.assertEqual(stream_counter, 1)
        self.assertEqual(state.scheme_counts.get("adj_noun"), 1)

    def test_stream_generation_propagates_token_exhaustion_after_inner_windows(self) -> None:
        stream_key = b"\x07" * 32
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        tag_map = {ch: ch for ch in base36}
        policy = PLATFORM_POLICIES["reddit"]

        pools = username_lexicon.RunPools(
            adjectives=["able"],
            nouns=["node"],
            verbs=["build"],
            pseudos=["keko"],
            tags=["xx"],
        )
        schemes = [username_schemes.Scheme("adj_noun", 1.0, username_schemes.scheme_adj_noun)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        with patch(
            "usnpw.core.username_generation.generate_unique",
            side_effect=RuntimeError(username_generation.TOKEN_BLOCK_EXHAUSTION_ERROR),
        ):
            with self.assertRaisesRegex(RuntimeError, "Token-block candidate space exhausted"):
                username_generation.generate_stream_unique(
                    stream_key=stream_key,
                    stream_tag_map=tag_map,
                    stream_counter=0,
                    token_blacklist=set(),
                    max_len=16,
                    min_len=policy.min_len,
                    policy=policy,
                    disallow_prefixes=tuple(),
                    disallow_substrings=tuple(),
                    state=state,
                    schemes=schemes,
                    pools=pools,
                    history_n=1,
                    block_tokens=True,
                    attempts=3,
                )

    def test_core_package_import_is_lightweight(self) -> None:
        probe = (
            "import sys; import usnpw.core; "
            "print(int('usnpw.core.username_generation' in sys.modules)); "
            "print(int('usnpw.core.username_service' in sys.modules))"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            check=True,
            capture_output=True,
            text=True,
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(lines, ["0", "0"])

    def test_uniqueness_helpers_are_consistent(self) -> None:
        policy = PLATFORM_POLICIES["reddit"]
        normalize_token = username_lexicon.normalize_token
        tokens = username_uniqueness.extract_component_tokens("Alpha_Beta-123", normalize_token=normalize_token)
        self.assertEqual(tokens, {"alpha", "beta", "123"})
        self.assertTrue(username_uniqueness.has_repeated_component_pattern("axisaxis", normalize_token=normalize_token))
        self.assertEqual(username_uniqueness.apply_stream_tag("samplecore", "abc", policy, 16, 3), "samplecore-abc")
        self.assertIn("Token-block saturation reached", username_uniqueness.token_saturation_message(10, 7, 8))

    def test_generate_unique_skips_component_extraction_when_token_blocking_disabled(self) -> None:
        policy = PLATFORM_POLICIES["reddit"]

        def _fixed_builder(state, pools, history_n):  # type: ignore[no-untyped-def]
            del state, pools, history_n
            return "alpha_node", "_", "lower", {"alpha", "node"}

        pools = username_lexicon.RunPools(
            adjectives=["alpha"],
            nouns=["node"],
            verbs=["build"],
            pseudos=["keko"],
            tags=["xx"],
        )
        schemes = [username_schemes.Scheme("fixed", 1.0, _fixed_builder)]
        state = username_schemes.GenState(
            recent_schemes=[],
            recent_seps=[],
            recent_case_styles=[],
            scheme_counts={},
            total_target=1,
            max_scheme_pct=1.0,
        )

        with patch(
            "usnpw.core.username_generation.uniqueness.extract_component_tokens",
            side_effect=AssertionError("extract_component_tokens should not run when block_tokens is False"),
        ):
            username, _, _, _, used_tokens = username_generation.generate_unique(
                username_blacklist_keys=set(),
                token_blacklist=set(),
                max_len=20,
                min_len=3,
                policy=policy,
                disallow_prefixes=tuple(),
                disallow_substrings=tuple(),
                state=state,
                schemes=schemes,
                pools=pools,
                history_n=1,
                block_tokens=False,
                attempts=5,
            )
        self.assertTrue(username)
        self.assertEqual(used_tokens, set())

    def test_lexicon_and_scheme_modules_are_consistent(self) -> None:
        self.assertEqual(username_lexicon.normalize_token("Alpha_Beta-123"), "alphabeta123")
        self.assertEqual(
            username_generation.normalize_username_key("Alpha_Beta-123"),
            "alpha_beta-123",
        )
        policy = PLATFORM_POLICIES["telegram"]
        self.assertEqual(
            username_generation.normalize_for_platform("A!B.C__D-", policy=policy, max_len=32),
            "abc_d",
        )

    def test_token_cap_math_uses_soft_quota_upper_bound(self) -> None:
        pools = username_lexicon.RunPools(
            adjectives=["a0", "a1", "a2", "a3"],
            nouns=["n0", "n1", "n2"],
            verbs=["v0", "v1", "v2", "v3", "v4"],
            pseudos=[f"p{i}" for i in range(12)],
            tags=[f"t{i}" for i in range(12)],
        )
        schemes = [s for s in username_schemes.DEFAULT_SCHEMES if s.name != "initials_style"]
        cap_low = username_schemes.max_token_block_count(pools, schemes, max_scheme_pct=0.10)
        cap_high = username_schemes.max_token_block_count(pools, schemes, max_scheme_pct=0.80)
        self.assertEqual(cap_low, cap_high)
        self.assertGreaterEqual(cap_low, 12)

if __name__ == "__main__":
    unittest.main()
