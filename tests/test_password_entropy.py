from __future__ import annotations

import math
import unittest

from usnpw.core.password_entropy import (
    estimate_pattern_aware_entropy_bits,
    estimate_theoretical_password_bits,
    quality_from_entropy_bits,
)


class PasswordEntropyTests(unittest.TestCase):
    def test_quality_bands_match_keepassxc_thresholds(self) -> None:
        self.assertEqual(quality_from_entropy_bits(0.0), "bad")
        self.assertEqual(quality_from_entropy_bits(39.999), "poor")
        self.assertEqual(quality_from_entropy_bits(40.0), "weak")
        self.assertEqual(quality_from_entropy_bits(74.999), "weak")
        self.assertEqual(quality_from_entropy_bits(75.0), "good")
        self.assertEqual(quality_from_entropy_bits(99.999), "good")
        self.assertEqual(quality_from_entropy_bits(100.0), "excellent")

    def test_theoretical_entropy_uses_alphabet_space(self) -> None:
        self.assertEqual(estimate_theoretical_password_bits(12, "ab"), 12.0)

    def test_pattern_aware_entropy_penalizes_repeated_block_patterns(self) -> None:
        alphabet = "ab"
        repeated = "abababab"
        repeated_bits = estimate_pattern_aware_entropy_bits(repeated, alphabet)
        theoretical_bits = estimate_theoretical_password_bits(len(repeated), alphabet)
        self.assertGreaterEqual(repeated_bits, 0.0)
        self.assertLess(repeated_bits, theoretical_bits)

    def test_pattern_aware_entropy_penalizes_obvious_sequences(self) -> None:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        seq = "abcd1234"
        seq_bits = estimate_pattern_aware_entropy_bits(seq, alphabet)
        theoretical_bits = estimate_theoretical_password_bits(len(seq), alphabet)
        self.assertGreaterEqual(seq_bits, 0.0)
        self.assertLess(seq_bits, theoretical_bits)

    def test_pattern_aware_entropy_keeps_irregular_values_near_theoretical(self) -> None:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        value = "hG7qL2zA"
        observed_bits = estimate_pattern_aware_entropy_bits(value, alphabet)
        theoretical_bits = estimate_theoretical_password_bits(len(value), alphabet)
        self.assertTrue(math.isclose(observed_bits, theoretical_bits, rel_tol=0.0, abs_tol=0.001))

    def test_pattern_aware_entropy_long_input_uses_bounded_analysis(self) -> None:
        value = "a" * 256
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        observed_bits = estimate_pattern_aware_entropy_bits(value, alphabet)
        theoretical_bits = estimate_theoretical_password_bits(len(value), alphabet)
        self.assertGreaterEqual(observed_bits, 0.0)
        self.assertLess(observed_bits, theoretical_bits)


if __name__ == "__main__":
    unittest.main()
