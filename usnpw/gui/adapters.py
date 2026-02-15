from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Tuple

from usnpw.core.models import (
    DEFAULT_USERNAME_BLACKLIST,
    DEFAULT_USERNAME_TOKENS,
    USERNAME_DEFAULT_HISTORY,
    USERNAME_DEFAULT_INITIALS_WEIGHT,
    USERNAME_DEFAULT_MAX_SCHEME_PCT,
    USERNAME_DEFAULT_NO_LEADING_DIGIT,
    USERNAME_DEFAULT_NO_SAVE,
    USERNAME_DEFAULT_NO_TOKEN_SAVE,
    USERNAME_DEFAULT_POOL_SCALE,
    USERNAME_DEFAULT_UNIQUENESS_MODE,
    PasswordRequest,
    UsernameRequest,
)

SAFE_MODE_LOCKED_VALUES: dict[str, Any] = {
    "uniqueness_mode": USERNAME_DEFAULT_UNIQUENESS_MODE,
    "no_save": USERNAME_DEFAULT_NO_SAVE,
    "no_token_save": USERNAME_DEFAULT_NO_TOKEN_SAVE,
    "no_token_block": False,
    "stream_save_tokens": False,
    "allow_plaintext_stream_state": False,
    "no_leading_digit": USERNAME_DEFAULT_NO_LEADING_DIGIT,
    "max_scheme_pct": str(USERNAME_DEFAULT_MAX_SCHEME_PCT),
    "history": str(USERNAME_DEFAULT_HISTORY),
    "pool_scale": str(USERNAME_DEFAULT_POOL_SCALE),
    "initials_weight": str(USERNAME_DEFAULT_INITIALS_WEIGHT),
    "show_meta": False,
}


def split_csv(value: str) -> Tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def parse_int(value: str, field: str) -> int:
    try:
        return int(value.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid integer for {field}: {value!r}") from exc


def parse_float(value: str, field: str) -> float:
    try:
        return float(value.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid number for {field}: {value!r}") from exc


def format_error_status(message: str) -> str:
    return f"Error: {message}"


def build_export_warning(label: str, encrypted: bool) -> str:
    return (
        f"You are about to export generated {label} to disk.\n\n"
        "This may create a recoverable local artifact.\n"
        + ("Export will be passphrase-encrypted.\n" if encrypted else "")
        + "Continue?"
    )


def effective_stream_state_path(profile: str, stream_state: str) -> Path:
    custom = stream_state.strip()
    if custom:
        return Path(custom).expanduser()
    return Path.home() / f".opsec_username_stream_{profile}.json"


def stream_state_lock_path(state_path: Path) -> Path:
    return state_path.with_name(state_path.name + ".lock")


def is_unusual_delete_target(path: Path, label: str) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if label == "token blacklist":
        return suffix != ".txt"
    if label == "stream state":
        return suffix != ".json"
    if label == "stream state lock":
        return suffix != ".lock" or not name.endswith(".json.lock")
    return True


def build_password_request(fields: Mapping[str, Any]) -> PasswordRequest:
    return PasswordRequest(
        count=parse_int(str(fields.get("count", "1")), "count"),
        length=parse_int(str(fields.get("length", "20")), "length"),
        charset=str(fields.get("charset", "")),
        symbols=str(fields.get("symbols", "")),
        no_symbols=bool(fields.get("no_symbols", False)),
        max_entropy=bool(fields.get("max_entropy", False)),
        format=str(fields.get("format", "password")),
        entropy_bytes=parse_int(str(fields.get("entropy_bytes", "0")), "bytes"),
        bits=parse_int(str(fields.get("bits", "0")), "bits"),
        out_enc=str(fields.get("out_enc", "hex")),
        group=parse_int(str(fields.get("group", "0")), "group"),
        group_sep=str(fields.get("group_sep", "-")),
        group_pad=str(fields.get("group_pad", "")),
        words=parse_int(str(fields.get("words", "24")), "words"),
        delim=str(fields.get("delim", " ")),
        bip39_wordlist=str(fields.get("bip39_wordlist", "")).strip(),
    )


def build_username_request(fields: Mapping[str, Any]) -> UsernameRequest:
    return UsernameRequest(
        count=parse_int(str(fields.get("count", "10")), "count"),
        min_len=parse_int(str(fields.get("min_len", "8")), "min-len"),
        max_len=parse_int(str(fields.get("max_len", "16")), "max-len"),
        profile=str(fields.get("profile", "generic")),
        safe_mode=bool(fields.get("safe_mode", False)),
        uniqueness_mode=str(fields.get("uniqueness_mode", USERNAME_DEFAULT_UNIQUENESS_MODE)),
        blacklist=str(fields.get("blacklist", DEFAULT_USERNAME_BLACKLIST)).strip(),
        no_save=bool(fields.get("no_save", USERNAME_DEFAULT_NO_SAVE)),
        token_blacklist=str(fields.get("token_blacklist", DEFAULT_USERNAME_TOKENS)).strip(),
        no_token_save=bool(fields.get("no_token_save", USERNAME_DEFAULT_NO_TOKEN_SAVE)),
        no_token_block=bool(fields.get("no_token_block", False)),
        stream_save_tokens=bool(fields.get("stream_save_tokens", False)),
        stream_state=str(fields.get("stream_state", "")).strip(),
        stream_state_persist=bool(fields.get("stream_state_persist", True)),
        allow_plaintext_stream_state=bool(fields.get("allow_plaintext_stream_state", False)),
        disallow_prefix=split_csv(str(fields.get("disallow_prefix", ""))),
        disallow_substring=split_csv(str(fields.get("disallow_substring", ""))),
        no_leading_digit=bool(fields.get("no_leading_digit", USERNAME_DEFAULT_NO_LEADING_DIGIT)),
        max_scheme_pct=parse_float(
            str(fields.get("max_scheme_pct", str(USERNAME_DEFAULT_MAX_SCHEME_PCT))),
            "max-scheme-pct",
        ),
        history=parse_int(str(fields.get("history", str(USERNAME_DEFAULT_HISTORY))), "history"),
        pool_scale=parse_int(str(fields.get("pool_scale", str(USERNAME_DEFAULT_POOL_SCALE))), "pool-scale"),
        initials_weight=parse_float(
            str(fields.get("initials_weight", str(USERNAME_DEFAULT_INITIALS_WEIGHT))),
            "initials-weight",
        ),
        show_meta=bool(fields.get("show_meta", False)),
    )
