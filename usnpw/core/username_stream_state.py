from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

from usnpw.core.dpapi import dpapi_protect, dpapi_unprotect

_STREAM_STATE_VERSION = 2
_STREAM_LOCK_TIMEOUT_SEC = 15.0
_STREAM_LOCK_POLL_SEC = 0.1
_STREAM_LOCK_STALE_SEC = 600.0
_STREAM_DPAPI_ENTROPY = b"UsnPw.opsec_username_gen.stream.v2"
_BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


@dataclass
class StreamStateLock:
    path: Path
    fd: int
    owner_pid: int
    owner_token: str


def _lock_metadata(pid: int, token: str) -> bytes:
    return f"{pid} {int(time.time())} {token}\n".encode("ascii")


def _lock_owner_token(path: Path) -> Optional[str]:
    try:
        raw = path.read_text(encoding="ascii", errors="ignore").strip()
    except OSError:
        return None
    parts = raw.split()
    if len(parts) < 3:
        return None
    return parts[2]


def touch_stream_state_lock(lock: StreamStateLock) -> None:
    try:
        os.lseek(lock.fd, 0, os.SEEK_SET)
        os.ftruncate(lock.fd, 0)
        os.write(lock.fd, _lock_metadata(lock.owner_pid, lock.owner_token))
        os.fsync(lock.fd)
    except OSError as exc:
        raise ValueError(f"Unable to refresh stream state lock '{lock.path}': {exc}") from exc


def acquire_stream_state_lock(state_path: Path, timeout_sec: float = _STREAM_LOCK_TIMEOUT_SEC) -> StreamStateLock:
    lock_path = state_path.with_name(state_path.name + ".lock")
    deadline = time.monotonic() + timeout_sec

    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            owner_pid = os.getpid()
            owner_token = secrets.token_hex(16)
            try:
                os.write(fd, _lock_metadata(owner_pid, owner_token))
                os.fsync(fd)
            except OSError as exc:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                raise ValueError(f"Unable to initialize stream state lock '{lock_path}': {exc}") from exc
            return StreamStateLock(path=lock_path, fd=fd, owner_pid=owner_pid, owner_token=owner_token)
        except FileExistsError:
            try:
                lock_age = time.time() - lock_path.stat().st_mtime
                if lock_age > _STREAM_LOCK_STALE_SEC:
                    # Staleness is governed by heartbeat age, not PID checks, to avoid
                    # deadlocks from PID reuse across process lifecycles.
                    try:
                        lock_path.unlink()
                    except FileNotFoundError:
                        continue
                    except OSError:
                        pass
                    else:
                        continue
            except OSError:
                pass

            if time.monotonic() >= deadline:
                raise ValueError(f"Timed out waiting for stream state lock '{lock_path}'.")

            time.sleep(_STREAM_LOCK_POLL_SEC)


def release_stream_state_lock(lock: StreamStateLock) -> None:
    should_unlink = False
    token = _lock_owner_token(lock.path)
    if token is not None and token == lock.owner_token:
        should_unlink = True
    try:
        os.close(lock.fd)
    except OSError:
        pass
    if should_unlink:
        try:
            lock.path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


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


def _fsync_parent_directory(path: Path) -> None:
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def load_or_init_stream_state(path: Path, allow_plaintext: bool = False) -> Tuple[bytes, int]:
    if not path.exists():
        secret = os.urandom(32)
        counter = 0
        save_stream_state(path, secret, counter, allow_plaintext=allow_plaintext)
        return secret, counter

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Unable to read stream state file '{path}': {e}") from e

    if not isinstance(raw, dict):
        raise ValueError(f"Invalid stream state format in '{path}' (expected JSON object).")

    version = raw.get("version")
    counter = raw.get("counter")
    if not isinstance(counter, int):
        raise ValueError(f"Invalid stream state counter in '{path}'.")
    if counter < 0:
        raise ValueError(f"Invalid stream counter in '{path}': must be non-negative.")

    if version == 1:
        secret_hex = raw.get("secret_hex")
        if not isinstance(secret_hex, str):
            raise ValueError(f"Invalid legacy stream state fields in '{path}'.")
        try:
            secret = bytes.fromhex(secret_hex)
        except ValueError as e:
            raise ValueError(f"Invalid secret_hex in legacy stream state file '{path}': {e}") from e
        if os.name != "nt" and not allow_plaintext:
            raise ValueError(
                "Legacy plaintext stream state is blocked on this OS by default. "
                "Pass --allow-plaintext-stream-state to proceed."
            )
        return secret, counter

    if version != _STREAM_STATE_VERSION:
        raise ValueError(
            f"Unsupported stream state version in '{path}': {version} (expected {_STREAM_STATE_VERSION})."
        )

    secret_format = raw.get("secret_format")
    if secret_format == "dpapi":
        secret_b64 = raw.get("secret_b64")
        if not isinstance(secret_b64, str):
            raise ValueError(f"Invalid DPAPI stream state fields in '{path}'.")
        try:
            protected = base64.b64decode(secret_b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeError) as e:
            raise ValueError(f"Invalid secret_b64 in stream state file '{path}': {e}") from e
        try:
            secret = dpapi_unprotect(protected, _STREAM_DPAPI_ENTROPY)
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Unable to decrypt stream secret from '{path}': {e}") from e
    elif secret_format == "plaintext":
        secret_hex = raw.get("secret_hex")
        if not isinstance(secret_hex, str):
            raise ValueError(f"Invalid plaintext stream state fields in '{path}'.")
        try:
            secret = bytes.fromhex(secret_hex)
        except ValueError as e:
            raise ValueError(f"Invalid secret_hex in stream state file '{path}': {e}") from e
        if os.name != "nt" and not allow_plaintext:
            raise ValueError(
                "Plaintext stream state is blocked on this OS by default. "
                "Pass --allow-plaintext-stream-state to proceed."
            )
    else:
        raise ValueError(f"Invalid stream secret format in '{path}': {secret_format}")

    if len(secret) < 16:
        raise ValueError(f"Invalid stream secret length in '{path}': expected at least 16 bytes.")

    return secret, counter


def save_stream_state(path: Path, secret: bytes, counter: int, allow_plaintext: bool = False) -> None:
    if counter < 0:
        raise ValueError("counter must be non-negative")
    if len(secret) < 16:
        raise ValueError("stream secret must be at least 16 bytes")

    payload: Dict[str, object] = {
        "version": _STREAM_STATE_VERSION,
        "counter": counter,
    }

    if os.name == "nt":
        try:
            protected = dpapi_protect(secret, _STREAM_DPAPI_ENTROPY)
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Unable to encrypt stream secret for '{path}': {e}") from e
        payload["secret_format"] = "dpapi"
        payload["secret_b64"] = base64.b64encode(protected).decode("ascii")
    else:
        if not allow_plaintext:
            raise ValueError(
                "Secure stream state storage is unavailable on this OS. "
                "Pass --allow-plaintext-stream-state to permit plaintext state."
            )
        payload["secret_format"] = "plaintext"
        payload["secret_hex"] = secret.hex()

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_parent_directory(path)
    except OSError as e:
        raise ValueError(f"Unable to write stream state file '{path}': {e}") from e
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def derive_stream_profile_key(root_secret: bytes, profile: str) -> bytes:
    return hmac.new(root_secret, f"profile:{profile}".encode("utf-8"), hashlib.sha256).digest()


def derive_stream_tag_map(profile_key: bytes) -> Dict[str, str]:
    ranked = []
    for ch in _BASE36:
        d = hmac.new(profile_key, f"tag-map:{ch}".encode("utf-8"), hashlib.sha256).digest()
        ranked.append((d, ch))
    ranked.sort(key=lambda x: x[0])
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
    "StreamStateLock",
    "acquire_stream_state_lock",
    "release_stream_state_lock",
    "touch_stream_state_lock",
    "load_or_init_stream_state",
    "save_stream_state",
    "derive_stream_profile_key",
    "derive_stream_tag_map",
    "scramble_stream_counter",
    "stream_tag",
]
