from __future__ import annotations

from dataclasses import fields
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
API_HARDENED_UNIQUENESS_MODE = "stream"
API_HARDENED_MAX_SCHEME_PCT = 0.28
API_HARDENED_HISTORY = 10
API_HARDENED_POOL_SCALE = 4
API_HARDENED_INITIALS_WEIGHT = 0.0
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
API_MAX_PASSWORD_CHARSET_LENGTH = 512
API_MAX_PASSWORD_SYMBOLS_LENGTH = 128
API_MAX_PASSWORD_GROUP_SEP_LENGTH = 16
API_MAX_PASSWORD_GROUP_PAD_LENGTH = 1
API_MAX_PASSWORD_TOTAL_CHARS = 4 * 1024 * 1024
API_MAX_USERNAME_PROFILE_LENGTH = 64
API_MAX_USERNAME_FILTER_ITEM_LENGTH = 64
API_MAX_USERNAME_FILTER_ITEMS = 128


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


def _parse_bounded_str(value: Any, field: str, *, max_len: int) -> str:
    text = _parse_str(value, field)
    if len(text) > max_len:
        raise ValueError(f"{field} must be <= {max_len} characters")
    return text


def _parse_str_tuple(
    value: Any,
    field: str,
    *,
    max_items: int | None = None,
    max_item_len: int | None = None,
) -> tuple[str, ...]:
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
        items = tuple(part for part in parts if part)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{field} entries must be strings")
            text = item.strip()
            if text:
                out.append(text)
        items = tuple(out)
    else:
        raise ValueError(f"{field} must be a comma-separated string or string list")

    if max_items is not None and len(items) > max_items:
        raise ValueError(f"{field} must contain <= {max_items} entries")
    if max_item_len is not None:
        for item in items:
            if len(item) > max_item_len:
                raise ValueError(f"{field} entries must be <= {max_item_len} characters")
    return items


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
        charset=_parse_bounded_str(data.get("charset", ""), "charset", max_len=API_MAX_PASSWORD_CHARSET_LENGTH),
        symbols=_parse_bounded_str(
            data.get("symbols", "!@#$%^&*()-_=+[]{};:,?/"),
            "symbols",
            max_len=API_MAX_PASSWORD_SYMBOLS_LENGTH,
        ),
        no_symbols=_parse_bool(data.get("no_symbols", False), "no_symbols"),
        max_entropy=_parse_bool(data.get("max_entropy", False), "max_entropy"),
        format=request_format,
        entropy_bytes=_parse_int(data.get("entropy_bytes", 0), "entropy_bytes"),
        bits=_parse_int(data.get("bits", 0), "bits"),
        out_enc=_parse_str(data.get("out_enc", "hex"), "out_enc"),
        group=_parse_int(data.get("group", 0), "group"),
        group_sep=_parse_bounded_str(
            data.get("group_sep", "-"),
            "group_sep",
            max_len=API_MAX_PASSWORD_GROUP_SEP_LENGTH,
        ),
        group_pad=_parse_bounded_str(
            data.get("group_pad", ""),
            "group_pad",
            max_len=API_MAX_PASSWORD_GROUP_PAD_LENGTH,
        ),
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
    if request.group < 0:
        raise ValueError("group must be >= 0")
    if request.format == "password":
        projected_line_len = request.length
        if request.group > 0 and request.length > 0:
            projected_line_len += ((request.length - 1) // request.group) * len(request.group_sep)
        projected_total_chars = request.count * projected_line_len
        if projected_total_chars > API_MAX_PASSWORD_TOTAL_CHARS:
            raise ValueError(
                f"projected password output is too large; reduce count/length/grouping "
                f"(max total chars {API_MAX_PASSWORD_TOTAL_CHARS})"
            )
    return request


def build_username_request(payload: Mapping[str, Any] | Any, *, max_count: int = 512) -> UsernameRequest:
    data = _ensure_object(payload, "username")
    _reject_unknown_fields(data, _USERNAME_FIELDS, "username")
    _reject_restricted_fields(data, label="username", fields=API_RESTRICTED_USERNAME_FIELDS)

    request = UsernameRequest(
        count=_parse_int(data.get("count", 10), "count"),
        min_len=_parse_int(data.get("min_len", 8), "min_len"),
        max_len=_parse_int(data.get("max_len", 16), "max_len"),
        profile=_parse_bounded_str(
            data.get("profile", "generic"),
            "profile",
            max_len=API_MAX_USERNAME_PROFILE_LENGTH,
        ),
        safe_mode=True,
        uniqueness_mode=API_HARDENED_UNIQUENESS_MODE,
        blacklist=API_DEFAULT_USERNAME_BLACKLIST,
        no_save=True,
        token_blacklist=API_DEFAULT_TOKEN_BLACKLIST,
        no_token_save=True,
        no_token_block=False,
        stream_save_tokens=False,
        stream_state="",
        stream_state_persist=False,
        allow_plaintext_stream_state=False,
        disallow_prefix=_parse_str_tuple(
            data.get("disallow_prefix", ()),
            "disallow_prefix",
            max_items=API_MAX_USERNAME_FILTER_ITEMS,
            max_item_len=API_MAX_USERNAME_FILTER_ITEM_LENGTH,
        ),
        disallow_substring=_parse_str_tuple(
            data.get("disallow_substring", ()),
            "disallow_substring",
            max_items=API_MAX_USERNAME_FILTER_ITEMS,
            max_item_len=API_MAX_USERNAME_FILTER_ITEM_LENGTH,
        ),
        no_leading_digit=True,
        max_scheme_pct=API_HARDENED_MAX_SCHEME_PCT,
        history=API_HARDENED_HISTORY,
        pool_scale=API_HARDENED_POOL_SCALE,
        initials_weight=API_HARDENED_INITIALS_WEIGHT,
        show_meta=False,
    )
    _require_count_limit(request.count, field="count", max_count=max_count)
    return request


__all__ = [
    "build_password_request",
    "build_username_request",
]
