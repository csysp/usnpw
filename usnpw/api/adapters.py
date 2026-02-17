from __future__ import annotations

from dataclasses import fields, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from usnpw.core.models import (
    PasswordRequest,
    UsernameRequest,
)


def _allowed_field_names(model_type: type[Any]) -> set[str]:
    return {field.name for field in fields(model_type)}


_PASSWORD_FIELDS = _allowed_field_names(PasswordRequest)
_USERNAME_FIELDS = _allowed_field_names(UsernameRequest)
API_DEFAULT_USERNAME_BLACKLIST = str(Path(".usnpw_api_usernames.txt"))
API_DEFAULT_TOKEN_BLACKLIST = str(Path(".usnpw_api_tokens.txt"))
API_RESTRICTED_PASSWORD_FIELDS = ("bip39_wordlist", "words", "delim")
API_RESTRICTED_USERNAME_FIELDS = (
    "safe_mode",
    "uniqueness_mode",
    "blacklist",
    "no_save",
    "token_blacklist",
    "no_token_save",
    "no_token_block",
    "stream_save_tokens",
    "stream_state",
    "stream_state_persist",
    "allow_plaintext_stream_state",
    "no_leading_digit",
    "max_scheme_pct",
    "history",
    "pool_scale",
    "initials_weight",
    "show_meta",
)
API_MAX_PASSWORD_LENGTH = 4096
API_MAX_PASSWORD_ENTROPY_BYTES = 1024
API_MAX_PASSWORD_BITS = API_MAX_PASSWORD_ENTROPY_BYTES * 8


def _ensure_object(payload: Mapping[str, Any] | Any, label: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} payload must be a JSON object")
    return payload


def _reject_unknown_fields(payload: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(payload.keys()) - allowed)
    if unknown:
        raise ValueError(f"{label} payload has unknown fields: {', '.join(unknown)}")


def _parse_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError(f"{field} must be an integer")
        try:
            return int(raw)
        except ValueError as exc:
            raise ValueError(f"{field} must be an integer") from exc
    raise ValueError(f"{field} must be an integer")


def _parse_float(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError(f"{field} must be a number")
        try:
            return float(raw)
        except ValueError as exc:
            raise ValueError(f"{field} must be a number") from exc
    raise ValueError(f"{field} must be a number")


def _parse_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off"):
            return False
    raise ValueError(f"{field} must be a boolean")


def _parse_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _parse_str_tuple(value: Any, field: str) -> tuple[str, ...]:
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
        return tuple(part for part in parts if part)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{field} entries must be strings")
            text = item.strip()
            if text:
                out.append(text)
        return tuple(out)
    raise ValueError(f"{field} must be a comma-separated string or string list")


def _require_count_limit(count: int, *, field: str, max_count: int) -> None:
    if count <= 0:
        raise ValueError(f"{field} must be > 0")
    if count > max_count:
        raise ValueError(f"{field} must be <= {max_count}")


def _reject_restricted_fields(payload: Mapping[str, Any], *, label: str, fields: Sequence[str]) -> None:
    disallowed = [field for field in fields if field in payload]
    if not disallowed:
        return
    joined = ", ".join(disallowed)
    raise ValueError(f"{label} payload fields are not configurable in API mode: {joined}")


def build_password_request(payload: Mapping[str, Any] | Any, *, max_count: int = 512) -> PasswordRequest:
    data = _ensure_object(payload, "password")
    _reject_unknown_fields(data, _PASSWORD_FIELDS, "password")
    _reject_restricted_fields(data, label="password", fields=API_RESTRICTED_PASSWORD_FIELDS)

    request_format = _parse_str(data.get("format", "password"), "format")
    if request_format == "bip39":
        raise ValueError("password format 'bip39' is disabled in API mode")

    request = PasswordRequest(
        count=_parse_int(data.get("count", 1), "count"),
        length=_parse_int(data.get("length", 20), "length"),
        charset=_parse_str(data.get("charset", ""), "charset"),
        symbols=_parse_str(data.get("symbols", "!@#$%^&*()-_=+[]{};:,?/"), "symbols"),
        no_symbols=_parse_bool(data.get("no_symbols", False), "no_symbols"),
        max_entropy=_parse_bool(data.get("max_entropy", False), "max_entropy"),
        format=request_format,
        entropy_bytes=_parse_int(data.get("entropy_bytes", 0), "entropy_bytes"),
        bits=_parse_int(data.get("bits", 0), "bits"),
        out_enc=_parse_str(data.get("out_enc", "hex"), "out_enc"),
        group=_parse_int(data.get("group", 0), "group"),
        group_sep=_parse_str(data.get("group_sep", "-"), "group_sep"),
        group_pad=_parse_str(data.get("group_pad", ""), "group_pad"),
        words=_parse_int(data.get("words", 24), "words"),
        delim=_parse_str(data.get("delim", " "), "delim"),
        bip39_wordlist="",
    )
    _require_count_limit(request.count, field="count", max_count=max_count)
    if request.length <= 0:
        raise ValueError("length must be > 0")
    if request.length > API_MAX_PASSWORD_LENGTH:
        raise ValueError(f"length must be <= {API_MAX_PASSWORD_LENGTH}")
    if request.entropy_bytes < 0:
        raise ValueError("entropy_bytes must be >= 0")
    if request.entropy_bytes > API_MAX_PASSWORD_ENTROPY_BYTES:
        raise ValueError(f"entropy_bytes must be <= {API_MAX_PASSWORD_ENTROPY_BYTES}")
    if request.bits < 0:
        raise ValueError("bits must be >= 0")
    if request.bits > API_MAX_PASSWORD_BITS:
        raise ValueError(f"bits must be <= {API_MAX_PASSWORD_BITS}")
    return request


def build_username_request(payload: Mapping[str, Any] | Any, *, max_count: int = 512) -> UsernameRequest:
    data = _ensure_object(payload, "username")
    _reject_unknown_fields(data, _USERNAME_FIELDS, "username")
    _reject_restricted_fields(data, label="username", fields=API_RESTRICTED_USERNAME_FIELDS)

    request = UsernameRequest(
        count=_parse_int(data.get("count", 10), "count"),
        min_len=_parse_int(data.get("min_len", 8), "min_len"),
        max_len=_parse_int(data.get("max_len", 16), "max_len"),
        profile=_parse_str(data.get("profile", "generic"), "profile"),
        safe_mode=_parse_bool(data.get("safe_mode", False), "safe_mode"),
        uniqueness_mode=_parse_str(data.get("uniqueness_mode", "stream"), "uniqueness_mode"),
        blacklist=API_DEFAULT_USERNAME_BLACKLIST,
        no_save=_parse_bool(data.get("no_save", True), "no_save"),
        token_blacklist=API_DEFAULT_TOKEN_BLACKLIST,
        no_token_save=_parse_bool(data.get("no_token_save", True), "no_token_save"),
        no_token_block=_parse_bool(data.get("no_token_block", False), "no_token_block"),
        stream_save_tokens=_parse_bool(data.get("stream_save_tokens", False), "stream_save_tokens"),
        stream_state="",
        stream_state_persist=_parse_bool(data.get("stream_state_persist", True), "stream_state_persist"),
        allow_plaintext_stream_state=_parse_bool(
            data.get("allow_plaintext_stream_state", False),
            "allow_plaintext_stream_state",
        ),
        disallow_prefix=_parse_str_tuple(data.get("disallow_prefix", ()), "disallow_prefix"),
        disallow_substring=_parse_str_tuple(data.get("disallow_substring", ()), "disallow_substring"),
        no_leading_digit=_parse_bool(data.get("no_leading_digit", True), "no_leading_digit"),
        max_scheme_pct=_parse_float(data.get("max_scheme_pct", 0.28), "max_scheme_pct"),
        history=_parse_int(data.get("history", 10), "history"),
        pool_scale=_parse_int(data.get("pool_scale", 4), "pool_scale"),
        initials_weight=_parse_float(data.get("initials_weight", 0.0), "initials_weight"),
        show_meta=_parse_bool(data.get("show_meta", False), "show_meta"),
    )
    _require_count_limit(request.count, field="count", max_count=max_count)

    # API mode enforces hardened defaults by policy.
    return replace(
        request,
        safe_mode=True,
        no_save=True,
        no_token_save=True,
        stream_state_persist=False,
        stream_state="",
        no_leading_digit=True,
        allow_plaintext_stream_state=False,
        show_meta=False,
    )


__all__ = [
    "build_password_request",
    "build_username_request",
]
