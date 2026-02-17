from __future__ import annotations

import re
import subprocess
import sys
import os
import time
import unittest

from usnpw.core.password_engine import generate_password
from pathlib import Path

from usnpw.core import (
    username_engine,
    username_generation,
    username_lexicon,
    username_schemes,
    username_storage,
    username_stream_state,
    username_uniqueness,
)
from usnpw.core.username_engine import StreamStateLock, normalize_for_platform, release_stream_state_lock
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

    def test_core_package_import_is_lightweight(self) -> None:
        probe = (
            "import sys; import usnpw.core; "
            "print(int('usnpw.core.username_engine' in sys.modules)); "
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

    def test_release_stream_lock_respects_owner_token(self) -> None:
        path = Path(".tmp_test_state.json.lock")
        try:
            with path.open("wb+") as handle:
                handle.write(b"123 0 token-a\n")
                handle.flush()
                fd = os.dup(handle.fileno())
            lock = StreamStateLock(path=path, fd=fd, owner_pid=123, owner_token="token-b")
            release_stream_state_lock(lock)
            self.assertTrue(path.exists(), "lock file with mismatched token should not be removed")
        finally:
            try:
                path.unlink()
            except OSError:
                pass

    def test_acquire_stream_lock_reclaims_stale_file(self) -> None:
        suffix = f"{os.getpid()}_{time.time_ns()}"
        state_path = Path(f".tmp_stream_state_{suffix}.json")
        lock_path = state_path.with_name(state_path.name + ".lock")
        try:
            lock_path.write_text(f"{os.getpid()} 0 stale-token\n", encoding="ascii")
            stale_time = time.time() - 7200
            os.utime(lock_path, (stale_time, stale_time))

            lock = username_stream_state.acquire_stream_state_lock(state_path, timeout_sec=0.5)
            try:
                self.assertEqual(lock.path, lock_path)
                token = lock_path.read_text(encoding="ascii").split()[2]
                self.assertEqual(token, lock.owner_token)
            finally:
                username_stream_state.release_stream_state_lock(lock)

            self.assertFalse(lock_path.exists())
        finally:
            for path in (state_path, lock_path):
                try:
                    path.unlink()
                except OSError:
                    pass

    def test_stream_api_reexports_are_stable(self) -> None:
        self.assertIs(username_engine.StreamStateLock, username_stream_state.StreamStateLock)
        self.assertIs(username_engine.acquire_stream_state_lock, username_stream_state.acquire_stream_state_lock)
        self.assertIs(username_engine.release_stream_state_lock, username_stream_state.release_stream_state_lock)
        self.assertIs(username_engine.touch_stream_state_lock, username_stream_state.touch_stream_state_lock)
        self.assertIs(username_engine.load_or_init_stream_state, username_stream_state.load_or_init_stream_state)
        self.assertIs(username_engine.save_stream_state, username_stream_state.save_stream_state)
        self.assertIs(username_engine.derive_stream_profile_key, username_stream_state.derive_stream_profile_key)
        self.assertIs(username_engine.derive_stream_tag_map, username_stream_state.derive_stream_tag_map)
        self.assertIs(username_engine.scramble_stream_counter, username_stream_state.scramble_stream_counter)
        self.assertIs(username_engine.stream_tag, username_stream_state.stream_tag)

    def test_uniqueness_helpers_match_engine_wrappers(self) -> None:
        policy = PLATFORM_POLICIES["reddit"]
        self.assertEqual(
            username_engine.extract_component_tokens("Alpha_Beta-123"),
            username_uniqueness.extract_component_tokens("Alpha_Beta-123", normalize_token=username_engine.normalize_token),
        )
        self.assertEqual(
            username_engine.has_repeated_component_pattern("axisaxis"),
            username_uniqueness.has_repeated_component_pattern("axisaxis", normalize_token=username_engine.normalize_token),
        )
        self.assertEqual(
            username_engine.apply_stream_tag("samplecore", "abc", policy, 16, 3),
            username_uniqueness.apply_stream_tag("samplecore", "abc", policy, 16, 3),
        )
        self.assertEqual(
            username_engine.token_saturation_message(10, 7, 8),
            username_uniqueness.token_saturation_message(10, 7, 8),
        )

    def test_lexicon_and_scheme_api_reexports_are_stable(self) -> None:
        self.assertIs(username_engine.RunPools, username_lexicon.RunPools)
        self.assertIs(username_engine.build_run_pools, username_lexicon.build_run_pools)
        self.assertEqual(username_engine.normalize_token("Alpha_Beta-123"), username_lexicon.normalize_token("Alpha_Beta-123"))
        self.assertEqual(
            username_engine.normalize_username_key("Alpha_Beta-123"),
            username_generation.normalize_username_key("Alpha_Beta-123"),
        )
        policy = PLATFORM_POLICIES["reddit"]
        self.assertEqual(
            username_engine.normalize_for_platform("A!B.C__D-", policy=policy, max_len=32),
            username_generation.normalize_for_platform("A!B.C__D-", policy=policy, max_len=32),
        )

        self.assertIs(username_engine.GenState, username_schemes.GenState)
        self.assertIs(username_engine.Scheme, username_schemes.Scheme)
        self.assertIs(username_engine.DEFAULT_SCHEMES, username_schemes.DEFAULT_SCHEMES)
        self.assertIs(username_engine.pick_scheme, username_schemes.pick_scheme)
        self.assertIs(username_engine.max_token_block_count, username_schemes.max_token_block_count)

    def test_storage_api_reexports_are_stable(self) -> None:
        self.assertIs(username_engine.load_lineset, username_storage.load_lineset)
        self.assertIs(username_engine.fsync_parent_directory, username_storage.fsync_parent_directory)
        self.assertIs(username_engine.append_line, username_storage.append_line)
        self.assertIs(username_engine.append_lines, username_storage.append_lines)


if __name__ == "__main__":
    unittest.main()
