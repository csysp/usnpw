from __future__ import annotations

import argparse
import hmac
import json
import os
import socket
import ssl
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Type

from usnpw.api.adapters import build_password_request, build_username_request
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_MAX_BODY_BYTES = 16 * 1024
DEFAULT_MAX_PASSWORD_COUNT = 512
DEFAULT_MAX_USERNAME_COUNT = 512
DEFAULT_MAX_CONCURRENT_REQUESTS = 256
DEFAULT_SOCKET_TIMEOUT_SECONDS = 5.0
DEFAULT_AUTH_FAIL_LIMIT = 16
DEFAULT_AUTH_FAIL_WINDOW_SECONDS = 60
DEFAULT_AUTH_BLOCK_SECONDS = 300
DEFAULT_REQUEST_QUEUE_SIZE = 256


class PayloadTooLargeError(ValueError):
    pass


@dataclass(frozen=True)
class APIConfig:
    host: str
    port: int
    token: str
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_password_count: int = DEFAULT_MAX_PASSWORD_COUNT
    max_username_count: int = DEFAULT_MAX_USERNAME_COUNT
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS
    socket_timeout_seconds: float = DEFAULT_SOCKET_TIMEOUT_SECONDS
    auth_fail_limit: int = DEFAULT_AUTH_FAIL_LIMIT
    auth_fail_window_seconds: int = DEFAULT_AUTH_FAIL_WINDOW_SECONDS
    auth_block_seconds: int = DEFAULT_AUTH_BLOCK_SECONDS
    tls_cert_file: str = ""
    tls_key_file: str = ""


def _parse_int(value: str, field: str) -> int:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{field} must be a non-empty integer")
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer") from exc


def _parse_float(value: str, field: str) -> float:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{field} must be a non-empty number")
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be a number") from exc


def _parse_bool(value: str, field: str) -> bool:
    raw = value.strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"{field} must be a boolean")


class AuthThrottle:
    def __init__(self, *, fail_limit: int, window_seconds: int, block_seconds: int) -> None:
        self._fail_limit = fail_limit
        self._window_seconds = window_seconds
        self._block_seconds = block_seconds
        self._failures: dict[str, deque[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune_failures_locked(self, key: str, now: float) -> deque[float]:
        events = self._failures.get(key)
        if events is None:
            events = deque()
            self._failures[key] = events
            return events
        threshold = now - float(self._window_seconds)
        while events and events[0] < threshold:
            events.popleft()
        if not events:
            self._failures[key] = deque()
            return self._failures[key]
        return events

    def is_blocked(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            blocked_until = self._blocked_until.get(key)
            if blocked_until is None:
                return False
            if blocked_until > current:
                return True
            self._blocked_until.pop(key, None)
            return False

    def record_failure(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            blocked_until = self._blocked_until.get(key)
            if blocked_until is not None and blocked_until > current:
                return True
            if blocked_until is not None and blocked_until <= current:
                self._blocked_until.pop(key, None)
            events = self._prune_failures_locked(key, current)
            events.append(current)
            if len(events) >= self._fail_limit:
                self._blocked_until[key] = current + float(self._block_seconds)
                self._failures.pop(key, None)
                return True
            return False

    def reset(self, key: str) -> None:
        with self._lock:
            self._blocked_until.pop(key, None)
            self._failures.pop(key, None)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = DEFAULT_REQUEST_QUEUE_SIZE

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: Type[BaseHTTPRequestHandler],
        *,
        max_concurrent_requests: int,
        socket_timeout_seconds: float,
    ) -> None:
        self._slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._socket_timeout_seconds = socket_timeout_seconds
        super().__init__(server_address, handler_class)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(self._socket_timeout_seconds)
        return request, client_address

    @staticmethod
    def _try_send_overloaded_response(request: socket.socket) -> None:
        body = b"{\"error\":\"server_overloaded\"}"
        try:
            request.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                + body
            )
        except OSError:
            return

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._slots.acquire(blocking=False):
            self._try_send_overloaded_response(request)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def _read_token_file(path: str) -> str:
    token_path = Path(path).expanduser()
    if not token_path.is_file():
        raise ValueError(f"token file not found: {token_path}")
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"unable to read token file '{token_path}': {exc}") from exc
    if not token:
        raise ValueError(f"token file is empty: {token_path}")
    return token


def _build_config(args: argparse.Namespace) -> APIConfig:
    token = (args.token or "").strip()
    token_file = (args.token_file or "").strip()
    env_token = (os.environ.get("USNPW_API_TOKEN", "") or "").strip()
    if token and token_file:
        raise ValueError("set either USNPW_API_TOKEN or USNPW_API_TOKEN_FILE, not both")
    if token_file:
        token = _read_token_file(token_file)
    elif not token and env_token:
        if not args.allow_env_token:
            raise ValueError(
                "USNPW_API_TOKEN is disabled by default; use USNPW_API_TOKEN_FILE or set USNPW_API_ALLOW_ENV_TOKEN=true"
            )
        token = env_token
    if not token:
        raise ValueError("USNPW_API_TOKEN_FILE is required (or pass --token / --allow-env-token)")

    if args.port <= 0:
        raise ValueError("port must be > 0")
    if args.max_body_bytes <= 0:
        raise ValueError("max-body-bytes must be > 0")
    if args.max_password_count <= 0:
        raise ValueError("max-password-count must be > 0")
    if args.max_username_count <= 0:
        raise ValueError("max-username-count must be > 0")
    if args.max_concurrent_requests <= 0:
        raise ValueError("max-concurrent-requests must be > 0")
    if args.socket_timeout_seconds <= 0:
        raise ValueError("socket-timeout-seconds must be > 0")
    if args.auth_fail_limit <= 0:
        raise ValueError("auth-fail-limit must be > 0")
    if args.auth_fail_window_seconds <= 0:
        raise ValueError("auth-fail-window-seconds must be > 0")
    if args.auth_block_seconds <= 0:
        raise ValueError("auth-block-seconds must be > 0")

    tls_cert_file = (args.tls_cert_file or "").strip()
    tls_key_file = (args.tls_key_file or "").strip()
    if bool(tls_cert_file) != bool(tls_key_file):
        raise ValueError("tls-cert-file and tls-key-file must be set together")
    if tls_cert_file:
        cert_path = Path(tls_cert_file).expanduser()
        key_path = Path(tls_key_file).expanduser()
        if not cert_path.is_file():
            raise ValueError(f"tls cert file not found: {cert_path}")
        if not key_path.is_file():
            raise ValueError(f"tls key file not found: {key_path}")
        tls_cert_file = str(cert_path)
        tls_key_file = str(key_path)

    return APIConfig(
        host=args.host,
        port=args.port,
        token=token,
        max_body_bytes=args.max_body_bytes,
        max_password_count=args.max_password_count,
        max_username_count=args.max_username_count,
        max_concurrent_requests=args.max_concurrent_requests,
        socket_timeout_seconds=args.socket_timeout_seconds,
        auth_fail_limit=args.auth_fail_limit,
        auth_fail_window_seconds=args.auth_fail_window_seconds,
        auth_block_seconds=args.auth_block_seconds,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
    )


def _handler_factory(config: APIConfig) -> Type[BaseHTTPRequestHandler]:
    auth_throttle = AuthThrottle(
        fail_limit=config.auth_fail_limit,
        window_seconds=config.auth_fail_window_seconds,
        block_seconds=config.auth_block_seconds,
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "UsnPwAPI/1.0"
        sys_version = ""

        def log_message(self, fmt: str, *args: object) -> None:
            # Keep request logging metadata-only and opt-in to reduce sensitive trail risk.
            if os.environ.get("USNPW_API_ACCESS_LOG", "").strip().lower() in ("1", "true", "yes", "on"):
                sys.stderr.write(f"{self.address_string()} - - [{self.log_date_time_string()}] {fmt % args}\n")

        def _write_json(self, code: int, payload: Mapping[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_internal_error(self) -> None:
            try:
                self._write_json(500, {"error": "internal_error"})
            except OSError:
                # Client may have disconnected before receiving the response.
                return

        def _require_auth(self) -> bool:
            auth_header = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not auth_header.startswith(prefix):
                return False
            presented = auth_header[len(prefix) :].strip()
            return hmac.compare_digest(presented, config.token)

        def _client_identity(self) -> str:
            try:
                return str(self.client_address[0])
            except Exception:
                return "unknown"

        @staticmethod
        def _is_json_content_type(content_type: str) -> bool:
            media_type = content_type.split(";", 1)[0].strip().lower()
            return media_type == "application/json"

        def _read_json_payload(self) -> Mapping[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            if not self._is_json_content_type(content_type):
                raise ValueError("Content-Type must be application/json")

            length_header = self.headers.get("Content-Length")
            if length_header is None:
                raise ValueError("Content-Length header is required")
            try:
                length = int(length_header)
            except ValueError as exc:
                raise ValueError("Content-Length must be an integer") from exc
            if length <= 0:
                raise ValueError("request body must not be empty")
            if length > config.max_body_bytes:
                raise PayloadTooLargeError(f"request body too large (>{config.max_body_bytes} bytes)")

            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("incomplete request body")
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("request body must be valid UTF-8 JSON") from exc
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON payload") from exc
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            return payload

        def do_GET(self) -> None:
            try:
                if self.path == "/healthz":
                    self._write_json(200, {"status": "ok"})
                    return
                self._write_json(404, {"error": "not_found"})
            except Exception:
                self._write_internal_error()

        def do_POST(self) -> None:
            try:
                if self.path not in ("/v1/passwords", "/v1/usernames"):
                    self._write_json(404, {"error": "not_found"})
                    return

                client_key = self._client_identity()
                if auth_throttle.is_blocked(client_key):
                    self._write_json(429, {"error": "too_many_auth_failures"})
                    return

                if not self._require_auth():
                    if auth_throttle.record_failure(client_key):
                        self._write_json(429, {"error": "too_many_auth_failures"})
                    else:
                        self._write_json(401, {"error": "unauthorized"})
                    return

                auth_throttle.reset(client_key)

                try:
                    payload = self._read_json_payload()
                except PayloadTooLargeError as exc:
                    self._write_json(413, {"error": str(exc)})
                    return
                except ValueError as exc:
                    self._write_json(400, {"error": str(exc)})
                    return

                if self.path == "/v1/passwords":
                    try:
                        request = build_password_request(payload, max_count=config.max_password_count)
                        result = generate_passwords(request)
                    except ValueError as exc:
                        self._write_json(400, {"error": str(exc)})
                        return
                    self._write_json(200, {"outputs": list(result.outputs)})
                    return

                try:
                    request = build_username_request(payload, max_count=config.max_username_count)
                    result = generate_usernames(request)
                except ValueError as exc:
                    self._write_json(400, {"error": str(exc)})
                    return

                self._write_json(
                    200,
                    {
                        "usernames": [record.username for record in result.records],
                        "effective_min_len": result.effective_min_len,
                        "effective_max_len": result.effective_max_len,
                        "token_cap": result.token_cap,
                    },
                )
                return
            except Exception:
                self._write_internal_error()

    return Handler


def create_server(config: APIConfig) -> ThreadingHTTPServer:
    handler = _handler_factory(config)
    server = BoundedThreadingHTTPServer(
        (config.host, config.port),
        handler,
        max_concurrent_requests=config.max_concurrent_requests,
        socket_timeout_seconds=config.socket_timeout_seconds,
    )
    if config.tls_cert_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=config.tls_cert_file, keyfile=config.tls_key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def run_server(config: APIConfig) -> int:
    with create_server(config) as server:
        server.serve_forever()
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="USnPw hardened API server (private network use).")
    parser.add_argument("--host", default=os.environ.get("USNPW_API_HOST", DEFAULT_HOST))
    parser.add_argument(
        "--port",
        type=int,
        default=_parse_int(os.environ.get("USNPW_API_PORT", str(DEFAULT_PORT)), "USNPW_API_PORT"),
    )
    parser.add_argument("--token", default="")
    parser.add_argument("--token-file", default=os.environ.get("USNPW_API_TOKEN_FILE", ""))
    parser.add_argument(
        "--allow-env-token",
        action="store_true",
        default=_parse_bool(os.environ.get("USNPW_API_ALLOW_ENV_TOKEN", "false"), "USNPW_API_ALLOW_ENV_TOKEN"),
        help="Allow reading bearer token from USNPW_API_TOKEN (less secure than token-file).",
    )
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)),
            "USNPW_API_MAX_BODY_BYTES",
        ),
    )
    parser.add_argument(
        "--max-password-count",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_MAX_PASSWORD_COUNT", str(DEFAULT_MAX_PASSWORD_COUNT)),
            "USNPW_API_MAX_PASSWORD_COUNT",
        ),
    )
    parser.add_argument(
        "--max-username-count",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_MAX_USERNAME_COUNT", str(DEFAULT_MAX_USERNAME_COUNT)),
            "USNPW_API_MAX_USERNAME_COUNT",
        ),
    )
    parser.add_argument(
        "--max-concurrent-requests",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_MAX_CONCURRENT_REQUESTS", str(DEFAULT_MAX_CONCURRENT_REQUESTS)),
            "USNPW_API_MAX_CONCURRENT_REQUESTS",
        ),
    )
    parser.add_argument(
        "--socket-timeout-seconds",
        type=float,
        default=_parse_float(
            os.environ.get("USNPW_API_SOCKET_TIMEOUT_SECONDS", str(DEFAULT_SOCKET_TIMEOUT_SECONDS)),
            "USNPW_API_SOCKET_TIMEOUT_SECONDS",
        ),
    )
    parser.add_argument(
        "--auth-fail-limit",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_AUTH_FAIL_LIMIT", str(DEFAULT_AUTH_FAIL_LIMIT)),
            "USNPW_API_AUTH_FAIL_LIMIT",
        ),
    )
    parser.add_argument(
        "--auth-fail-window-seconds",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_AUTH_FAIL_WINDOW_SECONDS", str(DEFAULT_AUTH_FAIL_WINDOW_SECONDS)),
            "USNPW_API_AUTH_FAIL_WINDOW_SECONDS",
        ),
    )
    parser.add_argument(
        "--auth-block-seconds",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_AUTH_BLOCK_SECONDS", str(DEFAULT_AUTH_BLOCK_SECONDS)),
            "USNPW_API_AUTH_BLOCK_SECONDS",
        ),
    )
    parser.add_argument("--tls-cert-file", default=os.environ.get("USNPW_API_TLS_CERT_FILE", ""))
    parser.add_argument("--tls-key-file", default=os.environ.get("USNPW_API_TLS_KEY_FILE", ""))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        config = _build_config(_parse_args(argv))
        return run_server(config)
    except (OSError, ValueError) as exc:
        print(f"api server failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
