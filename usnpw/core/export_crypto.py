from __future__ import annotations

import base64
import json
import os

from usnpw.core.dpapi import dpapi_protect, dpapi_unprotect

_HEADER = "USNPW-ENC-1"
_MODE = "dpapi"
_ENTROPY_PREFIX = b"usnpw-export-v1:"


def _entropy(passphrase: str) -> bytes:
    if not passphrase:
        raise ValueError("export passphrase is required when encryption is enabled")
    return _ENTROPY_PREFIX + passphrase.encode("utf-8")


def _require_windows() -> None:
    if os.name != "nt":
        raise ValueError("encrypted export is only supported on Windows in stdlib mode")


def encrypt_text(plaintext: str, passphrase: str) -> str:
    _require_windows()
    data = plaintext.encode("utf-8")
    try:
        protected = dpapi_protect(data, _entropy(passphrase))
    except OSError as exc:
        raise ValueError(f"encrypted export failed: {exc}") from exc

    payload = {
        "v": 1,
        "mode": _MODE,
        "ct_b64": base64.b64encode(protected).decode("ascii"),
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _HEADER + "\n" + body


def decrypt_text(serialized: str, passphrase: str) -> str:
    _require_windows()
    if not serialized.startswith(_HEADER + "\n"):
        raise ValueError("invalid encrypted export header")

    body = serialized[len(_HEADER) + 1 :]
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid encrypted export payload") from exc

    if payload.get("v") != 1 or payload.get("mode") != _MODE:
        raise ValueError("unsupported encrypted export format")
    ct_b64 = payload.get("ct_b64")
    if not isinstance(ct_b64, str) or not ct_b64:
        raise ValueError("invalid encrypted export payload")

    try:
        protected = base64.b64decode(ct_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid encrypted export payload") from exc

    try:
        plaintext = dpapi_unprotect(protected, _entropy(passphrase))
    except OSError as exc:
        raise ValueError(f"decryption failed: {exc}") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("decryption failed: invalid utf-8 payload") from exc
