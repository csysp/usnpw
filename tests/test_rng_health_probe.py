from __future__ import annotations

import unittest
from unittest.mock import patch

from tools import rng_health_probe


class RngHealthProbeTests(unittest.TestCase):
    def test_run_probe_accepts_healthy_sample_set(self) -> None:
        samples = [b"\x00", b"\xff", b"\x0f", b"\xf0"]
        with (
            patch("tools.rng_health_probe.assert_csprng_ready"),
            patch("tools.rng_health_probe.secure_random_bytes", side_effect=samples),
        ):
            unique_ratio, ones_ratio, collisions, collision_bound = rng_health_probe._run_probe(
                samples=4,
                chunk_bytes=1,
                min_unique_ratio=1.0,
                min_ones_ratio=0.2,
                max_ones_ratio=0.8,
            )
        self.assertEqual(unique_ratio, 1.0)
        self.assertEqual(ones_ratio, 0.5)
        self.assertEqual(collisions, 0)
        self.assertGreaterEqual(collision_bound, 2)

    def test_run_probe_rejects_low_unique_ratio(self) -> None:
        with (
            patch("tools.rng_health_probe.assert_csprng_ready"),
            patch("tools.rng_health_probe.secure_random_bytes", return_value=b"\x00"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unique ratio"):
                rng_health_probe._run_probe(
                    samples=8,
                    chunk_bytes=1,
                    min_unique_ratio=0.9,
                    min_ones_ratio=0.0,
                    max_ones_ratio=1.0,
                )

    def test_run_probe_rejects_bad_one_bit_ratio(self) -> None:
        with (
            patch("tools.rng_health_probe.assert_csprng_ready"),
            patch("tools.rng_health_probe.secure_random_bytes", return_value=b"\x00"),
        ):
            with self.assertRaisesRegex(RuntimeError, "one-bit ratio"):
                rng_health_probe._run_probe(
                    samples=8,
                    chunk_bytes=1,
                    min_unique_ratio=0.0 + 1e-9,
                    min_ones_ratio=0.4,
                    max_ones_ratio=0.6,
                )


if __name__ == "__main__":
    unittest.main()
