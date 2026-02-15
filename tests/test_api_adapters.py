from __future__ import annotations

import unittest

from usnpw.api.adapters import build_password_request, build_username_request


class APIAdapterTests(unittest.TestCase):
    def test_build_password_request_maps_fields(self) -> None:
        request = build_password_request(
            {
                "count": 2,
                "length": 24,
                "charset": "abc123",
                "no_symbols": True,
                "format": "password",
            },
            max_count=10,
        )
        self.assertEqual(request.count, 2)
        self.assertEqual(request.length, 24)
        self.assertEqual(request.charset, "abc123")
        self.assertTrue(request.no_symbols)

    def test_password_request_rejects_unknown_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            build_password_request({"count": 1, "bad_field": "x"})

    def test_password_request_enforces_count_cap(self) -> None:
        with self.assertRaisesRegex(ValueError, "count must be <= 2"):
            build_password_request({"count": 3}, max_count=2)

    def test_username_request_enforces_hardened_fields(self) -> None:
        request = build_username_request(
            {
                "count": 2,
                "profile": "reddit",
                "safe_mode": False,
                "no_save": False,
                "no_token_save": False,
                "no_leading_digit": False,
                "show_meta": True,
                "disallow_prefix": ["admin", "mod"],
            },
            max_count=10,
        )
        self.assertEqual(request.count, 2)
        self.assertEqual(request.disallow_prefix, ("admin", "mod"))
        self.assertTrue(request.safe_mode)
        self.assertTrue(request.no_save)
        self.assertTrue(request.no_token_save)
        self.assertTrue(request.no_leading_digit)
        self.assertFalse(request.show_meta)
        self.assertFalse(request.allow_plaintext_stream_state)
        self.assertFalse(request.stream_state_persist)

    def test_username_request_rejects_unknown_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            build_username_request({"count": 1, "bad_field": "x"})

    def test_username_request_enforces_count_cap(self) -> None:
        with self.assertRaisesRegex(ValueError, "count must be <= 2"):
            build_username_request({"count": 3}, max_count=2)

    def test_payload_must_be_json_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "payload must be a JSON object"):
            build_password_request(["not", "an", "object"])


if __name__ == "__main__":
    unittest.main()
