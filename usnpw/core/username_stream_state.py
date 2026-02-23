from __future__ import annotations

import hashlib
import hmac
import math
from functools import lru_cache
from typing import Dict, Optional, Tuple

_BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _encode_base36_uint(n: int) -> str:
    if n < 0:
        raise ValueError("base36 input must be non-negative")
    if n == 0:
        return "0"
    out = []
    while n > 0:
        n, rem = divmod(n, 36)
        out.append(_BASE36[rem])
    return "".join(reversed(out))


def derive_stream_profile_key(root_secret: bytes, profile: str) -> bytes:
    return hmac.new(root_secret, f"profile:{profile}".encode("utf-8"), hashlib.sha256).digest()


def derive_stream_tag_map(profile_key: bytes) -> Dict[str, str]:
    ranked = []
    for ch in _BASE36:
        digest = hmac.new(profile_key, f"tag-map:{ch}".encode("utf-8"), hashlib.sha256).digest()
        ranked.append((digest, ch))
    ranked.sort(key=lambda item: item[0])
    perm = "".join(ch for _, ch in ranked)
    return {src: perm[i] for i, src in enumerate(_BASE36)}


@lru_cache(maxsize=256)
def _stream_scramble_params_for_digits(profile_key: bytes, digits: int) -> Tuple[int, int, int, int]:
    if digits <= 0:
        raise ValueError("digits must be positive")

    if digits == 1:
        start = 0
        span = 36
    else:
        start = 36 ** (digits - 1)
        span = 35 * start

    digest = hmac.new(profile_key, f"scramble:{digits}".encode("utf-8"), hashlib.sha256).digest()
    a = int.from_bytes(digest[:16], "big") % span
    if a == 0:
        a = 1
    while math.gcd(a, span) != 1:
        a += 1
        if a >= span:
            a = 1
    b = int.from_bytes(digest[16:], "big") % span
    return start, span, a, b


def scramble_stream_counter(counter: int, profile_key: bytes) -> int:
    if counter < 0:
        raise ValueError("counter must be non-negative")
    digits = len(_encode_base36_uint(counter))
    start, span, a, b = _stream_scramble_params_for_digits(profile_key, digits)
    offset = counter - start
    return start + ((a * offset + b) % span)


def stream_tag(tag_map: Dict[str, str], counter: int, scramble_key: Optional[bytes] = None) -> str:
    if scramble_key is not None:
        counter = scramble_stream_counter(counter, scramble_key)
    raw = _encode_base36_uint(counter)
    return "".join(tag_map[ch] for ch in raw)


__all__ = [
    "derive_stream_profile_key",
    "derive_stream_tag_map",
    "scramble_stream_counter",
    "stream_tag",
]
