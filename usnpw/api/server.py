from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping, Type

from usnpw.api.adapters import build_password_request, build_username_request
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_MAX_BODY_BYTES = 16 * 1024
DEFAULT_MAX_PASSWORD_COUNT = 512
DEFAULT_MAX_USERNAME_COUNT = 512


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


def _parse_int(value: str, field: str) -> int:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{field} must be a non-empty integer")
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer") from exc


def _build_config(args: argparse.Namespace) -> APIConfig:
    token = (args.token or "").strip()
    if not token:
        raise ValueError("USNPW_API_TOKEN is required")

    if args.port <= 0:
        raise ValueError("port must be > 0")
    if args.max_body_bytes <= 0:
        raise ValueError("max-body-bytes must be > 0")
    if args.max_password_count <= 0:
        raise ValueError("max-password-count must be > 0")
    if args.max_username_count <= 0:
        raise ValueError("max-username-count must be > 0")

    return APIConfig(
        host=args.host,
        port=args.port,
        token=token,
        max_body_bytes=args.max_body_bytes,
        max_password_count=args.max_password_count,
        max_username_count=args.max_username_count,
    )


def _handler_factory(config: APIConfig) -> Type[BaseHTTPRequestHandler]:
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

        def _read_json_payload(self) -> Mapping[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
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

                if not self._require_auth():
                    self._write_json(401, {"error": "unauthorized"})
                    return

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
    server = ThreadingHTTPServer((config.host, config.port), handler)
    server.daemon_threads = True
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
    parser.add_argument("--token", default=os.environ.get("USNPW_API_TOKEN", ""))
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
