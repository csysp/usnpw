from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import socket
import ssl
import stat
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from usnpw.api.adapters import build_password_request, build_username_request
from usnpw.core.error_dialect import error_payload, error_payload_from_exception, format_error_text
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_MAX_BODY_BYTES = 16 * 1024
DEFAULT_MAX_PASSWORD_COUNT = 512
DEFAULT_MAX_USERNAME_COUNT = 512
DEFAULT_MAX_CONCURRENT_REQUESTS = 256
DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CLIENT = 32
DEFAULT_SOCKET_TIMEOUT_SECONDS = 5.0
DEFAULT_AUTH_FAIL_LIMIT = 16
DEFAULT_AUTH_FAIL_WINDOW_SECONDS = 60
DEFAULT_AUTH_BLOCK_SECONDS = 300
DEFAULT_REQUEST_RATE_LIMIT = 240
DEFAULT_REQUEST_RATE_WINDOW_SECONDS = 10
DEFAULT_REQUEST_RATE_BLOCK_SECONDS = 30
DEFAULT_REQUEST_QUEUE_SIZE = 256
DEFAULT_AUTH_TRACKED_KEYS_MAX = 8192
DEFAULT_AUTH_CLEANUP_INTERVAL_SECONDS = 30.0
DEFAULT_MIN_TOKEN_LENGTH = 24
DEFAULT_MAX_TOKEN_FILE_BYTES = 16 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
KNOWN_ENDPOINT_METHODS: dict[str, tuple[str, ...]] = {
    "/healthz": ("GET",),
    "/v1/passwords": ("POST",),
    "/v1/usernames": ("POST",),
}


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
    max_concurrent_requests_per_client: int = DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CLIENT
    socket_timeout_seconds: float = DEFAULT_SOCKET_TIMEOUT_SECONDS
    auth_fail_limit: int = DEFAULT_AUTH_FAIL_LIMIT
    auth_fail_window_seconds: int = DEFAULT_AUTH_FAIL_WINDOW_SECONDS
    auth_block_seconds: int = DEFAULT_AUTH_BLOCK_SECONDS
    request_rate_limit: int = DEFAULT_REQUEST_RATE_LIMIT
    request_rate_window_seconds: int = DEFAULT_REQUEST_RATE_WINDOW_SECONDS
    request_rate_block_seconds: int = DEFAULT_REQUEST_RATE_BLOCK_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    tls_cert_file: str = ""
    tls_key_file: str = ""
    allow_insecure_no_tls: bool = False


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


def _is_loopback_host(host: str) -> bool:
    raw = host.strip().lower()
    if not raw:
        return False
    if raw == "localhost":
        return True
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return False


def _is_visible_ascii(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if code < 33 or code > 126:
            return False
    return True


class AuthThrottle:
    def __init__(
        self,
        *,
        fail_limit: int,
        window_seconds: int,
        block_seconds: int,
        max_tracked_keys: int = DEFAULT_AUTH_TRACKED_KEYS_MAX,
    ) -> None:
        self._fail_limit = fail_limit
        self._window_seconds = window_seconds
        self._block_seconds = block_seconds
        self._max_tracked_keys = max_tracked_keys
        self._failures: dict[str, deque[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._last_seen: dict[str, float] = {}
        self._next_cleanup_at = 0.0
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

    def _touch_locked(self, key: str, now: float) -> None:
        self._last_seen[key] = now
        self._enforce_key_cap_locked()

    def _enforce_key_cap_locked(self) -> None:
        overflow = len(self._last_seen) - self._max_tracked_keys
        if overflow <= 0:
            return
        oldest_keys = sorted(self._last_seen.items(), key=lambda kv: kv[1])[:overflow]
        for stale_key, _ in oldest_keys:
            self._last_seen.pop(stale_key, None)
            self._failures.pop(stale_key, None)
            self._blocked_until.pop(stale_key, None)

    def _cleanup_locked(self, now: float) -> None:
        tracked = len(self._last_seen)
        if now < self._next_cleanup_at and tracked <= self._max_tracked_keys:
            return

        # Prune expired block entries and stale failure windows.
        threshold = now - float(self._window_seconds)
        for key in list(self._blocked_until):
            if self._blocked_until[key] <= now:
                self._blocked_until.pop(key, None)
        for key in list(self._failures):
            events = self._failures.get(key)
            if events is None:
                continue
            while events and events[0] < threshold:
                events.popleft()
            if not events:
                self._failures.pop(key, None)

        active_keys = set(self._failures) | set(self._blocked_until)
        for key in list(self._last_seen):
            if key not in active_keys:
                self._last_seen.pop(key, None)

        # Bound memory growth from high-cardinality auth probes.
        self._enforce_key_cap_locked()

        self._next_cleanup_at = now + DEFAULT_AUTH_CLEANUP_INTERVAL_SECONDS

    def is_blocked(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._cleanup_locked(current)
            blocked_until = self._blocked_until.get(key)
            if blocked_until is None:
                return False
            self._touch_locked(key, current)
            if blocked_until > current:
                return True
            self._blocked_until.pop(key, None)
            self._last_seen.pop(key, None)
            return False

    def record_failure(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._cleanup_locked(current)
            blocked_until = self._blocked_until.get(key)
            if blocked_until is not None and blocked_until > current:
                self._touch_locked(key, current)
                return True
            if blocked_until is not None and blocked_until <= current:
                self._blocked_until.pop(key, None)
            events = self._prune_failures_locked(key, current)
            events.append(current)
            self._touch_locked(key, current)
            if len(events) >= self._fail_limit:
                self._blocked_until[key] = current + float(self._block_seconds)
                self._failures.pop(key, None)
                return True
            return False

    def reset(self, key: str) -> None:
        with self._lock:
            self._blocked_until.pop(key, None)
            self._failures.pop(key, None)
            self._last_seen.pop(key, None)


class RequestRateThrottle:
    def __init__(
        self,
        *,
        request_limit: int,
        window_seconds: int,
        block_seconds: int,
        max_tracked_keys: int = DEFAULT_AUTH_TRACKED_KEYS_MAX,
    ) -> None:
        self._request_limit = request_limit
        self._window_seconds = window_seconds
        self._block_seconds = block_seconds
        self._max_tracked_keys = max_tracked_keys
        self._events: dict[str, deque[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._last_seen: dict[str, float] = {}
        self._next_cleanup_at = 0.0
        self._lock = threading.Lock()

    def _prune_events_locked(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            events = deque()
            self._events[key] = events
            return events
        threshold = now - float(self._window_seconds)
        while events and events[0] < threshold:
            events.popleft()
        if not events:
            self._events[key] = deque()
            return self._events[key]
        return events

    def _touch_locked(self, key: str, now: float) -> None:
        self._last_seen[key] = now
        self._enforce_key_cap_locked()

    def _enforce_key_cap_locked(self) -> None:
        overflow = len(self._last_seen) - self._max_tracked_keys
        if overflow <= 0:
            return
        oldest_keys = sorted(self._last_seen.items(), key=lambda kv: kv[1])[:overflow]
        for stale_key, _ in oldest_keys:
            self._last_seen.pop(stale_key, None)
            self._events.pop(stale_key, None)
            self._blocked_until.pop(stale_key, None)

    def _cleanup_locked(self, now: float) -> None:
        tracked = len(self._last_seen)
        if now < self._next_cleanup_at and tracked <= self._max_tracked_keys:
            return

        threshold = now - float(self._window_seconds)
        for key in list(self._blocked_until):
            if self._blocked_until[key] <= now:
                self._blocked_until.pop(key, None)
        for key in list(self._events):
            events = self._events.get(key)
            if events is None:
                continue
            while events and events[0] < threshold:
                events.popleft()
            if not events:
                self._events.pop(key, None)

        active_keys = set(self._events) | set(self._blocked_until)
        for key in list(self._last_seen):
            if key not in active_keys:
                self._last_seen.pop(key, None)

        self._enforce_key_cap_locked()
        self._next_cleanup_at = now + DEFAULT_AUTH_CLEANUP_INTERVAL_SECONDS

    def retry_after_seconds(self, key: str, *, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            blocked_until = self._blocked_until.get(key)
            if blocked_until is None or blocked_until <= current:
                return 0
            remaining = blocked_until - current
            return max(1, int(remaining) + (0 if remaining.is_integer() else 1))

    def check_and_record(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._cleanup_locked(current)
            blocked_until = self._blocked_until.get(key)
            if blocked_until is not None and blocked_until > current:
                self._touch_locked(key, current)
                return True
            if blocked_until is not None and blocked_until <= current:
                self._blocked_until.pop(key, None)

            events = self._prune_events_locked(key, current)
            events.append(current)
            self._touch_locked(key, current)
            if len(events) > self._request_limit:
                self._blocked_until[key] = current + float(self._block_seconds)
                self._events.pop(key, None)
                return True
            return False


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = DEFAULT_REQUEST_QUEUE_SIZE

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        max_concurrent_requests: int,
        max_concurrent_requests_per_client: int,
        socket_timeout_seconds: float,
    ) -> None:
        self._slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._max_concurrent_requests_per_client = max_concurrent_requests_per_client
        self._active_client_counts: dict[str, int] = {}
        self._client_counts_lock = threading.Lock()
        self._socket_timeout_seconds = socket_timeout_seconds
        super().__init__(server_address, handler_class)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(self._socket_timeout_seconds)
        return request, client_address

    @staticmethod
    def _try_send_overloaded_response(request: socket.socket) -> None:
        body = json.dumps(
            error_payload("server_overloaded", "server is overloaded; retry later"),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
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

    @staticmethod
    def _try_send_client_limited_response(request: socket.socket) -> None:
        body = json.dumps(
            error_payload("too_many_requests", "too many concurrent requests from this client"),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        try:
            request.sendall(
                b"HTTP/1.1 429 Too Many Requests\r\n"
                b"Content-Type: application/json; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"Retry-After: 1\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                + body
            )
        except OSError:
            return

    @staticmethod
    def _client_id(client_address: tuple[str, int]) -> str:
        try:
            return str(client_address[0])
        except (IndexError, TypeError):
            return "unknown"

    def _try_acquire_client_slot(self, client_address: tuple[str, int]) -> bool:
        client_id = self._client_id(client_address)
        with self._client_counts_lock:
            current = self._active_client_counts.get(client_id, 0)
            if current >= self._max_concurrent_requests_per_client:
                return False
            self._active_client_counts[client_id] = current + 1
            return True

    def _release_client_slot(self, client_address: tuple[str, int]) -> None:
        client_id = self._client_id(client_address)
        with self._client_counts_lock:
            current = self._active_client_counts.get(client_id, 0)
            if current <= 1:
                self._active_client_counts.pop(client_id, None)
                return
            self._active_client_counts[client_id] = current - 1

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._try_acquire_client_slot(client_address):
            self._try_send_client_limited_response(request)
            self.shutdown_request(request)
            return
        if not self._slots.acquire(blocking=False):
            self._release_client_slot(client_address)
            self._try_send_overloaded_response(request)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except (OSError, RuntimeError) as exc:
            self._slots.release()
            self._release_client_slot(client_address)
            raise RuntimeError("failed to dispatch request handler thread") from exc

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
            self._release_client_slot(client_address)


def _read_token_file(path: str) -> str:
    token_path = Path(path).expanduser()
    flags = os.O_RDONLY
    if os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(token_path), flags)
    except FileNotFoundError as exc:
        raise ValueError(f"token file not found: {token_path}") from exc
    except OSError as exc:
        raise ValueError(f"unable to open token file '{token_path}': {exc}") from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise ValueError(f"unable to stat token file '{token_path}': {exc}") from exc
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"token file must be a regular file: {token_path}")
        if os.name != "nt":
            if st.st_mode & 0o077:
                raise ValueError(
                    f"token file permissions are too broad: {token_path}. "
                    "Use owner-only permissions (chmod 600)."
                )
            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise ValueError(f"token file must be owned by the current user: {token_path}")
        data = bytearray()
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > DEFAULT_MAX_TOKEN_FILE_BYTES:
                raise ValueError(
                    f"token file is too large: {token_path} "
                    f"(max {DEFAULT_MAX_TOKEN_FILE_BYTES} bytes)"
                )
        try:
            token = bytes(data).decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ValueError(f"token file must be valid UTF-8 text: {token_path}") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if not token:
        raise ValueError(f"token file is empty: {token_path}")
    return token


def _validate_api_config(config: APIConfig) -> None:
    if not config.host.strip():
        raise ValueError("host must be non-empty")
    if not config.token:
        raise ValueError("token must be non-empty")
    if len(config.token) < DEFAULT_MIN_TOKEN_LENGTH:
        raise ValueError(
            f"token must be at least {DEFAULT_MIN_TOKEN_LENGTH} characters; use a random 32+ character token"
        )
    if any(ch.isspace() for ch in config.token):
        raise ValueError("token must not contain whitespace")
    if not _is_visible_ascii(config.token):
        raise ValueError("token must use visible ASCII characters only")
    if config.port < 0:
        raise ValueError("port must be >= 0")
    if config.max_body_bytes <= 0:
        raise ValueError("max-body-bytes must be > 0")
    if config.max_password_count <= 0:
        raise ValueError("max-password-count must be > 0")
    if config.max_username_count <= 0:
        raise ValueError("max-username-count must be > 0")
    if config.max_concurrent_requests <= 0:
        raise ValueError("max-concurrent-requests must be > 0")
    if config.max_concurrent_requests_per_client <= 0:
        raise ValueError("max-concurrent-requests-per-client must be > 0")
    if config.max_concurrent_requests_per_client > config.max_concurrent_requests:
        raise ValueError("max-concurrent-requests-per-client must be <= max-concurrent-requests")
    if config.socket_timeout_seconds <= 0:
        raise ValueError("socket-timeout-seconds must be > 0")
    if config.auth_fail_limit <= 0:
        raise ValueError("auth-fail-limit must be > 0")
    if config.auth_fail_window_seconds <= 0:
        raise ValueError("auth-fail-window-seconds must be > 0")
    if config.auth_block_seconds <= 0:
        raise ValueError("auth-block-seconds must be > 0")
    if config.request_rate_limit <= 0:
        raise ValueError("request-rate-limit must be > 0")
    if config.request_rate_window_seconds <= 0:
        raise ValueError("request-rate-window-seconds must be > 0")
    if config.request_rate_block_seconds <= 0:
        raise ValueError("request-rate-block-seconds must be > 0")
    if config.max_response_bytes <= 0:
        raise ValueError("max-response-bytes must be > 0")
    if bool(config.tls_cert_file) != bool(config.tls_key_file):
        raise ValueError("tls-cert-file and tls-key-file must be set together")
    if config.tls_cert_file:
        cert_path = Path(config.tls_cert_file).expanduser()
        key_path = Path(config.tls_key_file).expanduser()
        if not cert_path.is_file():
            raise ValueError(f"tls cert file not found: {cert_path}")
        if not key_path.is_file():
            raise ValueError(f"tls key file not found: {key_path}")
    elif not _is_loopback_host(config.host) and not config.allow_insecure_no_tls:
        raise ValueError(
            "TLS is required when binding a non-loopback host. "
            "Set --tls-cert-file/--tls-key-file, or pass --allow-insecure-no-tls to opt in."
        )


def _build_config(args: argparse.Namespace) -> APIConfig:
    cli_token = (args.token or "").strip()
    allow_cli_token = bool(getattr(args, "allow_cli_token", False))
    token_file = (args.token_file or "").strip()
    env_token = (os.environ.get("USNPW_API_TOKEN", "") or "").strip()
    if cli_token and not allow_cli_token:
        raise ValueError(
            "--token is disabled by default for privacy. "
            "Use --token-file, or set --allow-cli-token to opt in."
        )
    if cli_token and token_file:
        raise ValueError("set either --token or --token-file, not both")
    token = ""
    if token_file:
        token = _read_token_file(token_file)
    elif cli_token:
        token = cli_token
    elif env_token:
        if not args.allow_env_token:
            raise ValueError(
                "USNPW_API_TOKEN is disabled by default; use USNPW_API_TOKEN_FILE or set USNPW_API_ALLOW_ENV_TOKEN=true"
            )
        token = env_token
    if not token:
        raise ValueError(
            "USNPW_API_TOKEN_FILE is required "
            "(or use USNPW_API_TOKEN with --allow-env-token, or opt in to --token with --allow-cli-token)"
        )

    if args.port <= 0:
        raise ValueError("port must be > 0")
    if args.max_body_bytes <= 0:
        raise ValueError("max-body-bytes must be > 0")
    if args.max_password_count <= 0:
        raise ValueError("max-password-count must be > 0")
    if args.max_username_count <= 0:
        raise ValueError("max-username-count must be > 0")
    max_concurrent_requests = int(getattr(args, "max_concurrent_requests", DEFAULT_MAX_CONCURRENT_REQUESTS))
    max_concurrent_requests_per_client = int(
        getattr(args, "max_concurrent_requests_per_client", DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CLIENT)
    )
    request_rate_limit = int(getattr(args, "request_rate_limit", DEFAULT_REQUEST_RATE_LIMIT))
    request_rate_window_seconds = int(getattr(args, "request_rate_window_seconds", DEFAULT_REQUEST_RATE_WINDOW_SECONDS))
    request_rate_block_seconds = int(getattr(args, "request_rate_block_seconds", DEFAULT_REQUEST_RATE_BLOCK_SECONDS))
    max_response_bytes = int(getattr(args, "max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES))

    if max_concurrent_requests <= 0:
        raise ValueError("max-concurrent-requests must be > 0")
    if max_concurrent_requests_per_client <= 0:
        raise ValueError("max-concurrent-requests-per-client must be > 0")
    if max_concurrent_requests_per_client > max_concurrent_requests:
        raise ValueError("max-concurrent-requests-per-client must be <= max-concurrent-requests")
    if args.socket_timeout_seconds <= 0:
        raise ValueError("socket-timeout-seconds must be > 0")
    if args.auth_fail_limit <= 0:
        raise ValueError("auth-fail-limit must be > 0")
    if args.auth_fail_window_seconds <= 0:
        raise ValueError("auth-fail-window-seconds must be > 0")
    if args.auth_block_seconds <= 0:
        raise ValueError("auth-block-seconds must be > 0")
    if request_rate_limit <= 0:
        raise ValueError("request-rate-limit must be > 0")
    if request_rate_window_seconds <= 0:
        raise ValueError("request-rate-window-seconds must be > 0")
    if request_rate_block_seconds <= 0:
        raise ValueError("request-rate-block-seconds must be > 0")
    if max_response_bytes <= 0:
        raise ValueError("max-response-bytes must be > 0")

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

    config = APIConfig(
        host=args.host,
        port=args.port,
        token=token,
        max_body_bytes=args.max_body_bytes,
        max_password_count=args.max_password_count,
        max_username_count=args.max_username_count,
        max_concurrent_requests=max_concurrent_requests,
        max_concurrent_requests_per_client=max_concurrent_requests_per_client,
        socket_timeout_seconds=args.socket_timeout_seconds,
        auth_fail_limit=args.auth_fail_limit,
        auth_fail_window_seconds=args.auth_fail_window_seconds,
        auth_block_seconds=args.auth_block_seconds,
        request_rate_limit=request_rate_limit,
        request_rate_window_seconds=request_rate_window_seconds,
        request_rate_block_seconds=request_rate_block_seconds,
        max_response_bytes=max_response_bytes,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
        allow_insecure_no_tls=bool(getattr(args, "allow_insecure_no_tls", False)),
    )
    _validate_api_config(config)
    return config


def _handler_factory(config: APIConfig) -> type[BaseHTTPRequestHandler]:
    auth_throttle = AuthThrottle(
        fail_limit=config.auth_fail_limit,
        window_seconds=config.auth_fail_window_seconds,
        block_seconds=config.auth_block_seconds,
    )
    request_throttle = RequestRateThrottle(
        request_limit=config.request_rate_limit,
        window_seconds=config.request_rate_window_seconds,
        block_seconds=config.request_rate_block_seconds,
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "UsnPwAPI/1.0"
        sys_version = ""

        def log_message(self, fmt: str, *args: object) -> None:
            # Keep request logging metadata-only and opt-in to reduce sensitive trail risk.
            if os.environ.get("USNPW_API_ACCESS_LOG", "").strip().lower() in ("1", "true", "yes", "on"):
                sys.stderr.write(f"{self.address_string()} - - [{self.log_date_time_string()}] {fmt % args}\n")

        def _write_json(
            self,
            code: int,
            payload: Mapping[str, Any],
            *,
            close: bool = False,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            if len(body) > config.max_response_bytes:
                code = 413
                close = True
                body = json.dumps(
                    error_payload(
                        "response_too_large",
                        f"response body too large (>{config.max_response_bytes} bytes)",
                    ),
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if headers:
                for name, value in headers.items():
                    self.send_header(name, value)
            if close:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _write_internal_error(self, exc: BaseException | None = None) -> None:
            try:
                if exc is not None:
                    if os.environ.get("USNPW_API_VERBOSE_ERRORS", "").strip().lower() in ("1", "true", "yes", "on"):
                        sys.stderr.write(
                            format_error_text(
                                exc,
                                default_code="internal_error",
                                default_message="internal server error",
                            )
                            + "\n"
                        )
                    else:
                        sys.stderr.write(f"internal_error: {exc.__class__.__name__}\n")
                self._write_json(500, error_payload("internal_error", "internal server error"))
            except OSError:
                # Client may have disconnected before receiving the response.
                return

        def _request_path(self) -> str:
            return urlsplit(self.path).path

        def _request_throttle_key(self, *, path: str) -> str:
            route = self._route_throttle_key(path)
            return f"{self._client_identity()}|{route}"

        def _enforce_request_rate(self, *, path: str) -> bool:
            throttle_key = self._request_throttle_key(path=path)
            if not request_throttle.check_and_record(throttle_key):
                return True
            retry_after = request_throttle.retry_after_seconds(throttle_key)
            self._write_json(
                429,
                error_payload("too_many_requests", "request rate exceeded; retry later"),
                close=True,
                headers={"Retry-After": str(max(1, retry_after))},
            )
            return False

        def _presented_bearer_token(self) -> str | None:
            auth_header = self.headers.get("Authorization", "")
            parts = auth_header.split(None, 1)
            if len(parts) != 2:
                return None
            scheme, token = parts
            if scheme.lower() != "bearer":
                return None
            presented = token.strip()
            return presented or None

        @staticmethod
        def _route_throttle_key(path: str) -> str:
            if path in ("/v1/passwords", "/v1/usernames"):
                return path
            if path == "/healthz":
                return path
            return "__other__"

        def _auth_throttle_key(self, *, path: str, presented_token: str | None) -> str:
            route = self._route_throttle_key(path)
            if presented_token is None:
                token_fp = "missing"
            else:
                token_fp = hmac.new(
                    config.token.encode("utf-8"),
                    presented_token.encode("utf-8"),
                    digestmod="sha256",
                ).hexdigest()[:24]
            return f"{self._client_identity()}|{route}|{token_fp}"

        def _auth_route_key(self, *, path: str) -> str:
            route = self._route_throttle_key(path)
            return f"{self._client_identity()}|{route}|__route__"

        @staticmethod
        def _is_authorized(presented_token: str | None, *, expected_token: str) -> bool:
            if presented_token is None:
                return False
            return hmac.compare_digest(presented_token, expected_token)

        def _client_identity(self) -> str:
            try:
                return str(self.client_address[0])
            except (IndexError, TypeError):
                return "unknown"

        @staticmethod
        def _is_json_content_type(content_type: str) -> bool:
            media_type = content_type.split(";", 1)[0].strip().lower()
            return media_type == "application/json"

        def _write_not_found(self, *, close: bool = False) -> None:
            self._write_json(404, error_payload("not_found", "endpoint not found"), close=close)

        def _write_method_not_allowed(self, path: str, *, close: bool = False) -> None:
            allowed = KNOWN_ENDPOINT_METHODS.get(path)
            if not allowed:
                self._write_not_found(close=close)
                return
            self._write_json(
                405,
                error_payload("method_not_allowed", "method not allowed"),
                close=close,
                headers={"Allow": ", ".join(allowed)},
            )

        def _handle_non_get_post(self) -> None:
            try:
                path = self._request_path()
                if not self._enforce_request_rate(path=path):
                    return
                if path in KNOWN_ENDPOINT_METHODS:
                    self._write_method_not_allowed(path, close=True)
                    return
                self._write_not_found(close=True)
            except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
                self._write_internal_error(exc)

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
                path = self._request_path()
                if not self._enforce_request_rate(path=path):
                    return
                if path == "/healthz":
                    self._write_json(200, {"status": "ok"})
                    return
                if path in KNOWN_ENDPOINT_METHODS:
                    self._write_method_not_allowed(path)
                    return
                self._write_not_found()
            except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
                self._write_internal_error(exc)

        def do_POST(self) -> None:
            try:
                path = self._request_path()
                if not self._enforce_request_rate(path=path):
                    return
                if path not in ("/v1/passwords", "/v1/usernames"):
                    if path in KNOWN_ENDPOINT_METHODS:
                        self._write_method_not_allowed(path)
                    else:
                        self._write_not_found()
                    return

                presented_token = self._presented_bearer_token()
                client_key = self._auth_throttle_key(path=path, presented_token=presented_token)
                route_key = self._auth_route_key(path=path)
                is_authorized = self._is_authorized(presented_token, expected_token=config.token)

                if not is_authorized:
                    if auth_throttle.is_blocked(client_key) or auth_throttle.is_blocked(route_key):
                        self._write_json(
                            429,
                            error_payload(
                                "too_many_auth_failures",
                                "authentication temporarily blocked after repeated failures",
                            ),
                            close=True,
                        )
                        return
                    blocked_client = auth_throttle.record_failure(client_key)
                    blocked_route = auth_throttle.record_failure(route_key)
                    if blocked_client or blocked_route:
                        self._write_json(
                            429,
                            error_payload(
                                "too_many_auth_failures",
                                "authentication temporarily blocked after repeated failures",
                            ),
                            close=True,
                        )
                        return
                    self._write_json(
                        401,
                        error_payload("unauthorized", "missing or invalid bearer token"),
                        close=True,
                    )
                    return

                auth_throttle.reset(client_key)
                auth_throttle.reset(route_key)

                try:
                    payload = self._read_json_payload()
                except PayloadTooLargeError as exc:
                    # Do not keep-alive when the request body was not drained.
                    self._write_json(
                        413,
                        error_payload_from_exception(
                            exc,
                            default_code="payload_too_large",
                            default_message="request body too large",
                        ),
                        close=True,
                    )
                    return
                except ValueError as exc:
                    # Close on parse/validation failures to avoid leaving unread bytes on keep-alive sockets.
                    self._write_json(
                        400,
                        error_payload_from_exception(
                            exc,
                            default_code="invalid_request",
                            default_message="invalid request payload",
                        ),
                        close=True,
                    )
                    return

                if path == "/v1/passwords":
                    try:
                        request = build_password_request(payload, max_count=config.max_password_count)
                        result = generate_passwords(request)
                    except ValueError as exc:
                        self._write_json(
                            400,
                            error_payload_from_exception(
                                exc,
                                default_code="invalid_request",
                                default_message="invalid password request",
                            ),
                        )
                        return
                    self._write_json(200, {"outputs": list(result.outputs)})
                    return

                try:
                    request = build_username_request(payload, max_count=config.max_username_count)
                    result = generate_usernames(request)
                except ValueError as exc:
                    self._write_json(
                        400,
                        error_payload_from_exception(
                            exc,
                            default_code="invalid_request",
                            default_message="invalid username request",
                        ),
                    )
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
            except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
                self._write_internal_error(exc)

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_PUT(self) -> None:
            self._handle_non_get_post()

        def do_DELETE(self) -> None:
            self._handle_non_get_post()

        def do_PATCH(self) -> None:
            self._handle_non_get_post()

        def do_OPTIONS(self) -> None:
            self._handle_non_get_post()

        def do_TRACE(self) -> None:
            self._handle_non_get_post()

        def do_CONNECT(self) -> None:
            self._handle_non_get_post()

    return Handler


def create_server(config: APIConfig) -> ThreadingHTTPServer:
    _validate_api_config(config)
    handler = _handler_factory(config)
    server = BoundedThreadingHTTPServer(
        (config.host, config.port),
        handler,
        max_concurrent_requests=config.max_concurrent_requests,
        max_concurrent_requests_per_client=config.max_concurrent_requests_per_client,
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
    parser.add_argument(
        "--token",
        default="",
        help="Bearer token value (disabled unless --allow-cli-token is set).",
    )
    parser.add_argument(
        "--allow-cli-token",
        action="store_true",
        default=_parse_bool(os.environ.get("USNPW_API_ALLOW_CLI_TOKEN", "false"), "USNPW_API_ALLOW_CLI_TOKEN"),
        help="Allow reading bearer token from --token (less secure than token-file).",
    )
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
        "--max-concurrent-requests-per-client",
        type=int,
        default=_parse_int(
            os.environ.get(
                "USNPW_API_MAX_CONCURRENT_REQUESTS_PER_CLIENT",
                str(DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CLIENT),
            ),
            "USNPW_API_MAX_CONCURRENT_REQUESTS_PER_CLIENT",
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
    parser.add_argument(
        "--request-rate-limit",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_REQUEST_RATE_LIMIT", str(DEFAULT_REQUEST_RATE_LIMIT)),
            "USNPW_API_REQUEST_RATE_LIMIT",
        ),
    )
    parser.add_argument(
        "--request-rate-window-seconds",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_REQUEST_RATE_WINDOW_SECONDS", str(DEFAULT_REQUEST_RATE_WINDOW_SECONDS)),
            "USNPW_API_REQUEST_RATE_WINDOW_SECONDS",
        ),
    )
    parser.add_argument(
        "--request-rate-block-seconds",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_REQUEST_RATE_BLOCK_SECONDS", str(DEFAULT_REQUEST_RATE_BLOCK_SECONDS)),
            "USNPW_API_REQUEST_RATE_BLOCK_SECONDS",
        ),
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=_parse_int(
            os.environ.get("USNPW_API_MAX_RESPONSE_BYTES", str(DEFAULT_MAX_RESPONSE_BYTES)),
            "USNPW_API_MAX_RESPONSE_BYTES",
        ),
    )
    parser.add_argument("--tls-cert-file", default=os.environ.get("USNPW_API_TLS_CERT_FILE", ""))
    parser.add_argument("--tls-key-file", default=os.environ.get("USNPW_API_TLS_KEY_FILE", ""))
    parser.add_argument(
        "--allow-insecure-no-tls",
        action="store_true",
        default=_parse_bool(
            os.environ.get("USNPW_API_ALLOW_INSECURE_NO_TLS", "false"),
            "USNPW_API_ALLOW_INSECURE_NO_TLS",
        ),
        help="Allow binding non-loopback host without TLS (not recommended).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        config = _build_config(_parse_args(argv))
        return run_server(config)
    except (OSError, ValueError) as exc:
        print(
            format_error_text(
                exc,
                default_code="startup_error",
                default_message="api server startup failed",
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
