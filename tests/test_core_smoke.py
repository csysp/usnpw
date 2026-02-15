from __future__ import annotations

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
from usnpw.core.username_policies import PLATFORM_POLICIES


class CoreSmokeTests(unittest.TestCase):
    def test_password_generation_length_and_charset(self) -> None:
        alphabet = "abc123"
        out = generate_password(32, alphabet)
        self.assertEqual(len(out), 32)
        self.assertTrue(set(out).issubset(set(alphabet)))

    def test_platform_normalization_telegram(self) -> None:
        policy = PLATFORM_POLICIES["telegram"]
        out = normalize_for_platform("A!B.C__D-", policy=policy, max_len=32)
        self.assertEqual(out, "abc_d")

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


if __name__ == "__main__":
    unittest.main()
