#!/usr/bin/env python3
r"""
pwgen.py — high-entropy password / token generator (os.urandom)

Formats:
  - password: unbiased random characters from a charset (default)
  - raw token encodings: hex, base64, base64url, crock32, crock32check, base58, base58check, uuid
  - hash tokens: sha256, sha512, sha3_256, sha3_512, blake2b, blake2s (digest encoded via --out-enc)
  - bip39: mnemonic word tokens (12/18/24 words) using user-provided BIP39 wordlists (2048 words)

"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import uuid
from pathlib import Path


# ---------------- Password mode (unbiased selection) ----------------

def generate_password(length: int, alphabet: str) -> str:
    if not alphabet:
        raise ValueError("alphabet is empty")
    # `secrets.choice` is unbiased and supports arbitrary alphabet lengths.
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------- Encodings ----------------

def encode_hex(b: bytes) -> str:
    return b.hex()


def encode_base64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def encode_base64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# Crockford Base32 (human-friendly)
_CROCK32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCK32_CHECK_ALPHABET = _CROCK32_ALPHABET + "*~$=U"  # mod 37
_CROCK32_VALUE = {ch: i for i, ch in enumerate(_CROCK32_ALPHABET)}


def encode_crock32(data: bytes) -> str:
    """Crockford Base32, no checksum, no padding."""
    if not data:
        return ""
    bits = "".join(f"{byte:08b}" for byte in data)
    pad_len = (-len(bits)) % 5
    if pad_len:
        bits += "0" * pad_len
    out = []
    for i in range(0, len(bits), 5):
        out.append(_CROCK32_ALPHABET[int(bits[i:i+5], 2)])
    return "".join(out)


def crock32_checksum(payload_str: str) -> str:
    """Rolling checksum mod 37 over crock32 payload string."""
    vals = []
    for ch in payload_str:
        if ch in "-_ ":
            continue
        ch = ch.upper()
        if ch not in _CROCK32_ALPHABET:
            raise ValueError(f"invalid crock32 char for checksum: {ch}")
        vals.append(_CROCK32_VALUE[ch])
    c = 0
    for v in vals:
        c = (c * 32 + v) % 37
    return _CROCK32_CHECK_ALPHABET[c]


def encode_crock32check(data: bytes) -> str:
    payload = encode_crock32(data)
    return payload + crock32_checksum(payload)


# Base58 (Bitcoin alphabet) + Base58Check
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(data: bytes) -> str:
    """Base58 encode (no checksum). Preserves leading zero bytes as '1'."""
    if not data:
        return ""
    zeros = 0
    for b in data:
        if b == 0:
            zeros += 1
        else:
            break
    n = int.from_bytes(data, "big", signed=False)
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_BASE58_ALPHABET[rem])
    out = "".join(reversed(out)) if out else ""
    return ("1" * zeros) + out


def _double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def encode_base58check(payload: bytes) -> str:
    """Base58Check: payload + 4-byte checksum (double SHA-256), then Base58."""
    chk = _double_sha256(payload)[:4]
    return encode_base58(payload + chk)


def encode_bytes_by_name(b: bytes, enc: str) -> str:
    if enc == "hex":
        return encode_hex(b)
    if enc == "base64":
        return encode_base64(b)
    if enc == "base64url":
        return encode_base64url(b)
    if enc == "crock32":
        return encode_crock32(b)
    if enc == "crock32check":
        return encode_crock32check(b)
    if enc == "base58":
        return encode_base58(b)
    if enc == "base58check":
        return encode_base58check(b)
    raise ValueError(f"unsupported encoding: {enc}")


def group_string(s: str, size: int, sep: str = "-", pad_char: str = "") -> str:
    """Group string into chunks of `size` separated by `sep`.
    If pad_char is set (one character), right-pad the final group to full length.
    """
    if size <= 0:
        return s
    parts = [s[i:i+size] for i in range(0, len(s), size)]
    if pad_char:
        if len(pad_char) != 1:
            raise ValueError("group-pad must be a single character")
        if parts and len(parts[-1]) < size:
            parts[-1] = parts[-1] + (pad_char * (size - len(parts[-1])))
    return sep.join(parts)


# ---------------- BIP39 (requires wordlist file) ----------------

def load_bip39_wordlist(path: str) -> list[str]:
    p = Path(path).expanduser()
    try:
        st = p.stat()
    except FileNotFoundError as exc:
        raise ValueError(f"BIP39 wordlist file not found: {p}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to stat BIP39 wordlist file '{p}': {exc}") from exc

    if not p.is_file():
        raise ValueError(f"BIP39 wordlist path is not a file: {p}")

    # Prevent pathological inputs (BIP39 wordlists are small).
    if st.st_size > 512 * 1024:
        raise ValueError(f"BIP39 wordlist file too large: {p} ({st.st_size} bytes)")

    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Unable to read BIP39 wordlist file '{p}': {exc}") from exc

    words: list[str] = []
    seen: set[str] = set()
    dupes: list[str] = []
    for raw_line in text.splitlines():
        w = raw_line.strip()
        if not w:
            continue
        # Tolerate UTF-8 BOM if present at file start.
        w = w.lstrip("\ufeff")
        if any(ch.isspace() for ch in w):
            raise ValueError(f"Invalid BIP39 word contains whitespace: {w!r}")
        if len(w) > 64:
            raise ValueError(f"Invalid BIP39 word too long: {w!r}")
        words.append(w)
        if w in seen and w not in dupes:
            dupes.append(w)
        seen.add(w)

    if len(words) != 2048:
        raise ValueError(f"BIP39 wordlist must have 2048 words, got {len(words)}")
    if dupes:
        sample = ", ".join(repr(w) for w in dupes[:5])
        raise ValueError(f"BIP39 wordlist must contain 2048 unique words; found duplicates (sample): {sample}")
    return words


def bip39_mnemonic(num_words: int, wordlist: list[str]) -> str:
    if num_words not in (12, 18, 24):
        raise ValueError("BIP39 words must be 12, 18, or 24")
    ent_bits = {12: 128, 18: 192, 24: 256}[num_words]
    ent = os.urandom(ent_bits // 8)
    checksum_len = ent_bits // 32
    h = hashlib.sha256(ent).digest()
    ent_bitstr = "".join(f"{b:08b}" for b in ent)
    chk_bitstr = "".join(f"{b:08b}" for b in h)[:checksum_len]
    bits = ent_bitstr + chk_bitstr
    idxs = [int(bits[i:i+11], 2) for i in range(0, len(bits), 11)]
    return " ".join(wordlist[i] for i in idxs)


# ---------------- Formats ----------------

FORMAT_CHOICES = [
    "password",
    "hex",
    "base64",
    "base64url",
    "crock32",
    "crock32check",
    "base58",
    "base58check",
    "uuid",
    "bip39",
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake2s",
]

OUT_ENC_CHOICES = ["hex", "base64", "base64url", "crock32", "crock32check", "base58", "base58check"]


def token_from_format(
    fmt: str,
    nbytes: int,
    out_enc: str,
    bip39_words: int,
    bip39_wordlist_path: str,
    bip39_delim: str,
) -> str:
    if fmt == "uuid":
        return str(uuid.UUID(bytes=os.urandom(16), version=4))

    if fmt == "bip39":
        if not bip39_wordlist_path:
            raise ValueError("bip39 requires --bip39-wordlist pointing to the 2048-word English list")
        wl = load_bip39_wordlist(bip39_wordlist_path)
        phrase = bip39_mnemonic(bip39_words, wl)
        return phrase.replace(" ", bip39_delim)

    raw = os.urandom(nbytes)

    if fmt in ("hex", "base64", "base64url", "crock32", "crock32check", "base58", "base58check"):
        return encode_bytes_by_name(raw, fmt)

    if fmt in ("sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"):
        h = hashlib.new(fmt)
        h.update(raw)
        digest = h.digest()
        return encode_bytes_by_name(digest, out_enc)

    raise ValueError(f"unsupported format: {fmt}")
