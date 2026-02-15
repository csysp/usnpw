from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from usnpw.api.server import APIConfig, create_server


class APIServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._config = APIConfig(
            host="127.0.0.1",
            port=0,
            token="test-token",
            max_body_bytes=1024,
            max_password_count=20,
            max_username_count=20,
        )
        cls._server = create_server(cls._config)
        cls._port = int(cls._server.server_address[1])
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._server.shutdown()
        cls._server.server_close()
        cls._thread.join(timeout=2)

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | bytes | None = None,
        token: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        url = f"http://127.0.0.1:{self._port}{path}"
        headers: dict[str, str] = {}
        body: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            if isinstance(payload, bytes):
                body = payload
            else:
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                data = response.read().decode("utf-8")
                return response.status, json.loads(data)
        except urllib.error.HTTPError as exc:
            data = exc.read().decode("utf-8")
            return exc.code, json.loads(data)

    def test_healthz_is_open(self) -> None:
        status, payload = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_passwords_requires_auth(self) -> None:
        status, payload = self._request("POST", "/v1/passwords", payload={"count": 1})
        self.assertEqual(status, 401)
        self.assertEqual(payload.get("error"), "unauthorized")

    def test_password_generation_endpoint(self) -> None:
        status, payload = self._request(
            "POST",
            "/v1/passwords",
            payload={"count": 2, "length": 12, "format": "password"},
            token="test-token",
        )
        self.assertEqual(status, 200)
        outputs = payload.get("outputs")
        self.assertIsInstance(outputs, list)
        self.assertEqual(len(outputs), 2)

    def test_username_generation_endpoint(self) -> None:
        status, payload = self._request(
            "POST",
            "/v1/usernames",
            payload={"count": 3, "profile": "reddit"},
            token="test-token",
        )
        self.assertEqual(status, 200)
        usernames = payload.get("usernames")
        self.assertIsInstance(usernames, list)
        self.assertEqual(len(usernames), 3)
        self.assertIn("effective_min_len", payload)
        self.assertIn("effective_max_len", payload)

    def test_invalid_json_returns_400(self) -> None:
        status, payload = self._request(
            "POST",
            "/v1/passwords",
            payload=b"{",
            token="test-token",
        )
        self.assertEqual(status, 400)
        self.assertIn("error", payload)

    def test_oversize_payload_returns_413(self) -> None:
        status, payload = self._request(
            "POST",
            "/v1/passwords",
            payload=(b"{" + (b"a" * 2048) + b"}"),
            token="test-token",
        )
        self.assertEqual(status, 413)
        self.assertIn("error", payload)

    def test_internal_error_returns_json_500(self) -> None:
        with patch("usnpw.api.server.generate_passwords", side_effect=RuntimeError("boom")):
            status, payload = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1, "length": 12, "format": "password"},
                token="test-token",
            )
        self.assertEqual(status, 500)
        self.assertEqual(payload.get("error"), "internal_error")


if __name__ == "__main__":
    unittest.main()
