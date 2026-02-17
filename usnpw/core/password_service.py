from __future__ import annotations

from dataclasses import replace
import string

from usnpw.core import password_engine as engine
from usnpw.core.models import PasswordRequest, PasswordResult

MAX_ENTROPY_BYTES = 64
MAX_ENTROPY_FORMAT = "base64url"


def _apply_max_entropy_preset(request: PasswordRequest) -> PasswordRequest:
    if not request.max_entropy:
        return request
    # 64 bytes = 512 bits of entropy to preserve a wide Grover-resistant margin.
    return replace(
        request,
        format=MAX_ENTROPY_FORMAT,
        entropy_bytes=MAX_ENTROPY_BYTES,
        bits=0,
        group=0,
    )


def generate_passwords(request: PasswordRequest) -> PasswordResult:
    request = _apply_max_entropy_preset(request)

    if request.count <= 0:
        raise ValueError("count must be > 0")
    if request.format == "bip39" and not request.bip39_wordlist.strip():
        raise ValueError("bip39_wordlist is required when format is bip39")

    outputs = []
    if request.format == "password":
        if request.length <= 0:
            raise ValueError("length must be > 0")
        if request.charset:
            alphabet = request.charset
        else:
            alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
            if not request.no_symbols:
                alphabet += request.symbols
        if not alphabet:
            raise ValueError("character set is empty")
        for _ in range(request.count):
            outputs.append(engine.generate_password(request.length, alphabet))
        return PasswordResult(outputs=tuple(outputs))

    nbytes = request.entropy_bytes
    if nbytes <= 0:
        if request.bits:
            if request.bits % 8 != 0:
                raise ValueError("bits must be a multiple of 8")
            nbytes = request.bits // 8
        else:
            nbytes = 32

    if nbytes <= 0:
        raise ValueError("bytes must be > 0")

    for _ in range(request.count):
        try:
            out = engine.token_from_format(
                request.format,
                nbytes,
                request.out_enc,
                request.words,
                request.bip39_wordlist,
                request.delim,
            )
            if request.group and request.format not in ("bip39", "uuid"):
                out = engine.group_string(out, request.group, request.group_sep, request.group_pad)
            outputs.append(out)
        except (OSError, UnicodeError, ValueError) as e:
            raise ValueError(str(e)) from e

    return PasswordResult(outputs=tuple(outputs))
