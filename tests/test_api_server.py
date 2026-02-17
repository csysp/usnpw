from __future__ import annotations

import argparse
import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from usnpw.api.server import APIConfig, AuthThrottle, _build_config, create_server


class APIServerTests(unittest.TestCase):
    @staticmethod
    def _error_code(payload: dict[str, object]) -> str:
        error_obj = payload.get("error")
        if isinstance(error_obj, dict):
            code = error_obj.get("code")
            if isinstance(code, str):
                return code
        return ""

    @staticmethod
    def _error_message(payload: dict[str, object]) -> str:
        error_obj = payload.get("error")
        if isinstance(error_obj, dict):
            message = error_obj.get("message")
            if isinstance(message, str):
                return message
        return ""

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
        content_type: str = "application/json",
        port: int | None = None,
    ) -> tuple[int, dict[str, object]]:
        status, payload, _ = self._request_with_headers(
            method,
            path,
            payload=payload,
            token=token,
            content_type=content_type,
            port=port,
        )
        return status, payload

    def _request_with_headers(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | bytes | None = None,
        token: str | None = None,
        content_type: str = "application/json",
        port: int | None = None,
    ) -> tuple[int, dict[str, object], dict[str, str]]:
        target_port = self._port if port is None else port
        url = f"http://127.0.0.1:{target_port}{path}"
        headers: dict[str, str] = {}
        body: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = content_type
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
                return response.status, json.loads(data), dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            data = exc.read().decode("utf-8")
            return exc.code, json.loads(data), dict(exc.headers.items())

    def test_healthz_is_open(self) -> None:
        status, payload = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_passwords_requires_auth(self) -> None:
        status, payload = self._request("POST", "/v1/passwords", payload={"count": 1})
        self.assertEqual(status, 401)
        self.assertEqual(self._error_code(payload), "unauthorized")

    def test_unauthorized_post_closes_connection(self) -> None:
        status, payload, headers = self._request_with_headers(
            "POST",
            "/v1/passwords",
            payload={"count": 1},
            token="wrong-token",
        )
        self.assertEqual(status, 401)
        self.assertEqual(self._error_code(payload), "unauthorized")
        normalized_headers = {k.lower(): v.lower() for k, v in headers.items()}
        self.assertEqual(normalized_headers.get("connection"), "close")

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

    def test_strict_content_type_rejects_jsonx(self) -> None:
        status, payload = self._request(
            "POST",
            "/v1/passwords",
            payload={"count": 1},
            token="test-token",
            content_type="application/jsonx",
        )
        self.assertEqual(status, 400)
        self.assertEqual(self._error_code(payload), "invalid_request")
        self.assertEqual(self._error_message(payload), "Content-Type must be application/json")

    def test_get_on_post_endpoint_returns_json_405(self) -> None:
        status, payload = self._request("GET", "/v1/passwords")
        self.assertEqual(status, 405)
        self.assertEqual(self._error_code(payload), "method_not_allowed")

    def test_unsupported_method_returns_json_405(self) -> None:
        status, payload, headers = self._request_with_headers(
            "PUT",
            "/v1/passwords",
            payload={"count": 1},
            token="test-token",
        )
        self.assertEqual(status, 405)
        self.assertEqual(self._error_code(payload), "method_not_allowed")
        normalized_headers = {k.lower(): v.lower() for k, v in headers.items()}
        self.assertEqual(normalized_headers.get("connection"), "close")

    def test_auth_throttle_uses_composite_route_and_token_keying(self) -> None:
        config = APIConfig(
            host="127.0.0.1",
            port=0,
            token="rate-token",
            max_body_bytes=1024,
            max_password_count=20,
            max_username_count=20,
            auth_fail_limit=2,
            auth_fail_window_seconds=60,
            auth_block_seconds=60,
        )
        server = create_server(config)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status1, _ = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1},
                token="wrong-token",
                port=port,
            )
            status2, _ = self._request(
                "POST",
                "/v1/usernames",
                payload={"count": 1, "profile": "reddit"},
                token="wrong-token",
                port=port,
            )
            status3, payload3 = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1},
                token="wrong-token",
                port=port,
            )
            status4, payload4 = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1},
                token="rate-token",
                port=port,
            )
            self.assertEqual(status1, 401)
            self.assertEqual(status2, 401)
            self.assertEqual(status3, 429)
            self.assertEqual(self._error_code(payload3), "too_many_auth_failures")
            self.assertEqual(status4, 200)
            self.assertIn("outputs", payload4)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_auth_throttle_blocks_token_spray_per_route(self) -> None:
        config = APIConfig(
            host="127.0.0.1",
            port=0,
            token="spray-token",
            max_body_bytes=1024,
            max_password_count=20,
            max_username_count=20,
            auth_fail_limit=2,
            auth_fail_window_seconds=60,
            auth_block_seconds=60,
        )
        server = create_server(config)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status1, _ = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1},
                token="wrong-token-1",
                port=port,
            )
            status2, payload2 = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1},
                token="wrong-token-2",
                port=port,
            )
            status3, payload3 = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1},
                token="spray-token",
                port=port,
            )
            self.assertEqual(status1, 401)
            self.assertEqual(status2, 429)
            self.assertEqual(self._error_code(payload2), "too_many_auth_failures")
            self.assertEqual(status3, 200)
            self.assertIn("outputs", payload3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_request_rate_throttle_blocks_healthz_and_is_route_scoped(self) -> None:
        config = APIConfig(
            host="127.0.0.1",
            port=0,
            token="rate-token",
            max_body_bytes=1024,
            max_password_count=20,
            max_username_count=20,
            request_rate_limit=2,
            request_rate_window_seconds=60,
            request_rate_block_seconds=60,
        )
        server = create_server(config)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status1, _ = self._request("GET", "/healthz", port=port)
            status2, _ = self._request("GET", "/healthz", port=port)
            status3, payload3, headers3 = self._request_with_headers("GET", "/healthz", port=port)
            status4, payload4 = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1, "length": 12, "format": "password"},
                token="rate-token",
                port=port,
            )
            self.assertEqual(status1, 200)
            self.assertEqual(status2, 200)
            self.assertEqual(status3, 429)
            self.assertEqual(self._error_code(payload3), "too_many_requests")
            normalized_headers = {k.lower(): v for k, v in headers3.items()}
            self.assertIn("retry-after", normalized_headers)
            self.assertEqual(status4, 200)
            self.assertIn("outputs", payload4)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_per_client_concurrency_limit_returns_429(self) -> None:
        config = APIConfig(
            host="127.0.0.1",
            port=0,
            token="concurrency-token",
            max_body_bytes=1024,
            max_password_count=20,
            max_username_count=20,
            max_concurrent_requests=2,
            max_concurrent_requests_per_client=1,
            request_rate_limit=100,
            request_rate_window_seconds=60,
            request_rate_block_seconds=60,
        )
        server = create_server(config)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        entered = threading.Event()
        release = threading.Event()
        try:
            from usnpw.api import server as api_server_mod

            real_generate_passwords = api_server_mod.generate_passwords

            def _slow_generate_passwords(req):  # type: ignore[no-untyped-def]
                entered.set()
                if not release.wait(2.0):
                    raise RuntimeError("test timeout waiting for release")
                return real_generate_passwords(req)

            with patch("usnpw.api.server.generate_passwords", side_effect=_slow_generate_passwords):
                out: list[tuple[int, dict[str, object]]] = []

                def _first_call() -> None:
                    out.append(
                        self._request(
                            "POST",
                            "/v1/passwords",
                            payload={"count": 1, "length": 12, "format": "password"},
                            token="concurrency-token",
                            port=port,
                        )
                    )

                t1 = threading.Thread(target=_first_call, daemon=True)
                t1.start()
                self.assertTrue(entered.wait(1.0), "slow handler not entered")

                # Use a body-less request for the contending call to avoid a Windows-specific
                # client send-abort race when the server rejects at accept-time.
                status2, payload2 = self._request(
                    "GET",
                    "/healthz",
                    port=port,
                )
                self.assertEqual(status2, 429)
                self.assertEqual(self._error_code(payload2), "too_many_requests")

                release.set()
                t1.join(timeout=3.0)
                self.assertTrue(out, "first request did not complete")
                self.assertEqual(out[0][0], 200)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_build_config_reads_token_file(self) -> None:
        token_file = Path(".tmp_api_token_file.txt")
        try:
            token_file.write_text("file-token\n", encoding="utf-8")
            args = argparse.Namespace(
                host="127.0.0.1",
                port=8080,
                token="",
                token_file=str(token_file),
                max_body_bytes=1024,
                max_password_count=10,
                max_username_count=10,
                max_concurrent_requests=32,
                socket_timeout_seconds=5.0,
                auth_fail_limit=5,
                auth_fail_window_seconds=60,
                auth_block_seconds=120,
                request_rate_limit=240,
                request_rate_window_seconds=10,
                request_rate_block_seconds=30,
                tls_cert_file="",
                tls_key_file="",
                allow_env_token=False,
                allow_cli_token=False,
            )
            config = _build_config(args)
            self.assertEqual(config.token, "file-token")
        finally:
            token_file.unlink(missing_ok=True)

    def test_build_config_rejects_env_token_without_opt_in(self) -> None:
        with patch.dict(os.environ, {"USNPW_API_TOKEN": "env-token"}, clear=False):
            args = argparse.Namespace(
                host="127.0.0.1",
                port=8080,
                token="",
                token_file="",
                max_body_bytes=1024,
                max_password_count=10,
                max_username_count=10,
                max_concurrent_requests=32,
                socket_timeout_seconds=5.0,
                auth_fail_limit=5,
                auth_fail_window_seconds=60,
                auth_block_seconds=120,
                request_rate_limit=240,
                request_rate_window_seconds=10,
                request_rate_block_seconds=30,
                tls_cert_file="",
                tls_key_file="",
                allow_env_token=False,
                allow_cli_token=False,
            )
            with self.assertRaisesRegex(ValueError, "USNPW_API_TOKEN is disabled by default"):
                _build_config(args)

    def test_build_config_allows_env_token_with_opt_in(self) -> None:
        with patch.dict(os.environ, {"USNPW_API_TOKEN": "env-token"}, clear=False):
            args = argparse.Namespace(
                host="127.0.0.1",
                port=8080,
                token="",
                token_file="",
                max_body_bytes=1024,
                max_password_count=10,
                max_username_count=10,
                max_concurrent_requests=32,
                socket_timeout_seconds=5.0,
                auth_fail_limit=5,
                auth_fail_window_seconds=60,
                auth_block_seconds=120,
                request_rate_limit=240,
                request_rate_window_seconds=10,
                request_rate_block_seconds=30,
                tls_cert_file="",
                tls_key_file="",
                allow_env_token=True,
                allow_cli_token=False,
            )
            config = _build_config(args)
            self.assertEqual(config.token, "env-token")

    def test_build_config_rejects_cli_token_without_opt_in(self) -> None:
        args = argparse.Namespace(
            host="127.0.0.1",
            port=8080,
            token="cli-token",
            token_file="",
            max_body_bytes=1024,
            max_password_count=10,
            max_username_count=10,
            max_concurrent_requests=32,
            socket_timeout_seconds=5.0,
            auth_fail_limit=5,
            auth_fail_window_seconds=60,
            auth_block_seconds=120,
            request_rate_limit=240,
            request_rate_window_seconds=10,
            request_rate_block_seconds=30,
            tls_cert_file="",
            tls_key_file="",
            allow_env_token=False,
            allow_cli_token=False,
        )
        with self.assertRaisesRegex(ValueError, "--token is disabled by default"):
            _build_config(args)

    def test_build_config_allows_cli_token_with_opt_in(self) -> None:
        args = argparse.Namespace(
            host="127.0.0.1",
            port=8080,
            token="cli-token",
            token_file="",
            max_body_bytes=1024,
            max_password_count=10,
            max_username_count=10,
            max_concurrent_requests=32,
            socket_timeout_seconds=5.0,
            auth_fail_limit=5,
            auth_fail_window_seconds=60,
            auth_block_seconds=120,
            request_rate_limit=240,
            request_rate_window_seconds=10,
            request_rate_block_seconds=30,
            tls_cert_file="",
            tls_key_file="",
            allow_env_token=False,
            allow_cli_token=True,
        )
        config = _build_config(args)
        self.assertEqual(config.token, "cli-token")

    def test_build_config_rejects_per_client_concurrency_over_global(self) -> None:
        args = argparse.Namespace(
            host="127.0.0.1",
            port=8080,
            token="cli-token",
            token_file="",
            max_body_bytes=1024,
            max_password_count=10,
            max_username_count=10,
            max_concurrent_requests=4,
            max_concurrent_requests_per_client=5,
            socket_timeout_seconds=5.0,
            auth_fail_limit=5,
            auth_fail_window_seconds=60,
            auth_block_seconds=120,
            request_rate_limit=240,
            request_rate_window_seconds=10,
            request_rate_block_seconds=30,
            tls_cert_file="",
            tls_key_file="",
            allow_env_token=False,
            allow_cli_token=True,
        )
        with self.assertRaisesRegex(ValueError, "max-concurrent-requests-per-client must be <= max-concurrent-requests"):
            _build_config(args)

    def test_internal_error_returns_json_500(self) -> None:
        with patch("usnpw.api.server.generate_passwords", side_effect=RuntimeError("boom")):
            status, payload = self._request(
                "POST",
                "/v1/passwords",
                payload={"count": 1, "length": 12, "format": "password"},
                token="test-token",
            )
        self.assertEqual(status, 500)
        self.assertEqual(self._error_code(payload), "internal_error")

    def test_auth_throttle_caps_tracked_key_cardinality(self) -> None:
        throttle = AuthThrottle(
            fail_limit=4,
            window_seconds=120,
            block_seconds=120,
            max_tracked_keys=8,
        )
        for i in range(64):
            throttle.record_failure(f"k{i}", now=float(i))
        self.assertLessEqual(len(throttle._last_seen), 8)


if __name__ == "__main__":
    unittest.main()
