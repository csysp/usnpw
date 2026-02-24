from __future__ import annotations

from dataclasses import replace
import string

from usnpw.core import password_engine as engine
from usnpw.core.password_entropy import (
    estimate_pattern_aware_entropy_bits,
    estimate_theoretical_password_bits,
    quality_from_entropy_bits,
)
from usnpw.core.models import PasswordRequest, PasswordResult

MAX_ENTROPY_BYTES = 64
MAX_ENTROPY_FORMAT = "base64url"
UUID4_ENTROPY_BITS = 122
_BIP39_ENTROPY_BITS = {12: 128, 18: 192, 24: 256}
_HASH_DIGEST_BITS = {
    "sha256": 256,
    "sha512": 512,
    "sha3_256": 256,
    "sha3_512": 512,
    "blake2b": 512,
    "blake2s": 256,
}


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


def _validate_password_alphabet(alphabet: str) -> None:
    if not alphabet:
        raise ValueError("character set is empty")
    unique_count = len(set(alphabet))
    if unique_count < 2:
        raise ValueError("character set must contain at least 2 distinct characters")
    if unique_count != len(alphabet):
        raise ValueError("character set contains duplicate characters, which biases selection probabilities")


def _resolve_entropy_bytes(request: PasswordRequest) -> int:
    nbytes = request.entropy_bytes
    if nbytes == 0:
        if request.bits:
            if request.bits % 8 != 0:
                raise ValueError("bits must be a multiple of 8")
            nbytes = request.bits // 8
        else:
            nbytes = 32
    if nbytes <= 0:
        raise ValueError("bytes must be > 0")
    return nbytes


def _estimate_entropy_bits_for_token(request: PasswordRequest, nbytes: int) -> float:
    if request.format == "uuid":
        return float(UUID4_ENTROPY_BITS)
    if request.format == "bip39":
        bits = _BIP39_ENTROPY_BITS.get(request.words)
        if bits is None:
            raise ValueError("BIP39 words must be 12, 18, or 24")
        return float(bits)

    raw_bits = nbytes * 8
    digest_bits = _HASH_DIGEST_BITS.get(request.format)
    if digest_bits is not None:
        return float(min(raw_bits, digest_bits))
    return float(raw_bits)


def generate_passwords(request: PasswordRequest) -> PasswordResult:
    request = _apply_max_entropy_preset(request)

    if request.count <= 0:
        raise ValueError("count must be > 0")
    if request.entropy_bytes < 0:
        raise ValueError("bytes must be >= 0")
    if request.bits < 0:
        raise ValueError("bits must be >= 0")
    if request.format == "bip39" and not request.bip39_wordlist.strip():
        raise ValueError("bip39_wordlist is required when format is bip39")
    try:
        engine.assert_csprng_ready()
    except OSError as e:
        raise ValueError(str(e)) from e

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
        _validate_password_alphabet(alphabet)
        entropy_bits = 0.0
        if request.show_meta:
            entropy_bits = estimate_theoretical_password_bits(request.length, alphabet)
        entropy_by_output: list[float] = []
        quality_by_output: list[str] = []
        for _ in range(request.count):
            try:
                generated = engine.generate_password(request.length, alphabet)
            except OSError as e:
                raise ValueError(str(e)) from e
            outputs.append(generated)
            if request.show_meta:
                observed_bits = estimate_pattern_aware_entropy_bits(generated, alphabet)
                entropy_by_output.append(observed_bits)
                quality_by_output.append(quality_from_entropy_bits(observed_bits))
        return PasswordResult(
            outputs=tuple(outputs),
            estimated_entropy_bits=entropy_bits,
            entropy_bits_by_output=tuple(entropy_by_output),
            entropy_quality_by_output=tuple(quality_by_output),
        )

    nbytes = _resolve_entropy_bytes(request)
    entropy_bits = 0.0
    quality = ""
    if request.show_meta:
        entropy_bits = _estimate_entropy_bits_for_token(request, nbytes)
        quality = quality_from_entropy_bits(entropy_bits)
    entropy_by_output: list[float] = []
    quality_by_output: list[str] = []

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
            if request.show_meta:
                entropy_by_output.append(entropy_bits)
                quality_by_output.append(quality)
        except (OSError, UnicodeError, ValueError) as e:
            raise ValueError(str(e)) from e

    return PasswordResult(
        outputs=tuple(outputs),
        estimated_entropy_bits=entropy_bits,
        entropy_bits_by_output=tuple(entropy_by_output),
        entropy_quality_by_output=tuple(quality_by_output),
    )
