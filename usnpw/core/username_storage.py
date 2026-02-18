from __future__ import annotations

import hmac
import hashlib
import os
import stat
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Set, TextIO

from usnpw.core.file_hardening import enforce_private_file_permissions

MAX_LINESET_FILE_BYTES = 64 * 1024 * 1024
USERNAME_HASH_PREFIX = "h1:"
USERNAME_HASH_KEY_HEX_LEN = 64


def username_hash_key_path(path: Path) -> Path:
    return path.with_name(path.name + ".key")


def hash_username_key(username_key: str, key: bytes) -> str:
    digest = hmac.new(key, username_key.encode("utf-8"), hashlib.sha256).hexdigest()
    return USERNAME_HASH_PREFIX + digest


def parse_hashed_username_entry(line: str) -> str | None:
    if not line.startswith(USERNAME_HASH_PREFIX):
        return None
    digest = line[len(USERNAME_HASH_PREFIX) :].lower()
    if len(digest) != 64:
        return None
    if any(ch not in "0123456789abcdef" for ch in digest):
        return None
    return USERNAME_HASH_PREFIX + digest


def load_username_hash_key(
    blacklist_path: Path,
    *,
    create_if_missing: bool,
    strict_windows_acl: bool = False,
) -> bytes | None:
    key_path = username_hash_key_path(blacklist_path)
    if key_path.exists():
        try:
            enforce_private_file_permissions(key_path, strict_windows_acl=strict_windows_acl)
        except ValueError as exc:
            raise ValueError(
                f"Unable to enforce private permissions on username hash key '{key_path}': {exc}"
            ) from exc
        try:
            raw = key_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"Unable to read username hash key '{key_path}': {exc}") from exc
        if len(raw) != USERNAME_HASH_KEY_HEX_LEN:
            raise ValueError(
                f"Invalid username hash key length in '{key_path}' "
                f"(expected {USERNAME_HASH_KEY_HEX_LEN} hex chars)."
            )
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError(f"Invalid username hash key format in '{key_path}': {exc}") from exc

    if not create_if_missing:
        return None

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_bytes = secrets.token_bytes(32)
    fd = os.open(str(key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(key_bytes.hex())
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        enforce_private_file_permissions(key_path, strict_windows_acl=strict_windows_acl)
        fsync_parent_directory(key_path)
    except OSError as exc:
        raise ValueError(f"Unable to initialize username hash key '{key_path}': {exc}") from exc
    return key_bytes


def load_lineset(path: Path, label: str) -> Set[str]:
    if not path.exists():
        return set()
    try:
        st = path.stat()
    except OSError as e:
        raise ValueError(f"Unable to stat {label} file '{path}': {e}") from e
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{label} path is not a regular file: {path}")
    if st.st_size > MAX_LINESET_FILE_BYTES:
        raise ValueError(
            f"{label} file is too large: {path} "
            f"(max {MAX_LINESET_FILE_BYTES} bytes)"
        )
    try:
        return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except (OSError, UnicodeError) as e:
        raise ValueError(f"Unable to read {label} file '{path}': {e}") from e


def fsync_parent_directory(path: Path) -> None:
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


@contextmanager
def _open_append_private(path: Path, *, strict_windows_acl: bool = False) -> Iterator[TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        # Threat model: persisted username/token files should remain private-by-default,
        # with optional strict ACL hardening on Windows.
        enforce_private_file_permissions(path, strict_windows_acl=strict_windows_acl)
    except ValueError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ValueError(str(exc)) from exc
    with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as handle:
        yield handle


def append_line(path: Path, line: str, *, strict_windows_acl: bool = False) -> None:
    append_lines(path, (line,), strict_windows_acl=strict_windows_acl)


def append_lines(path: Path, lines: Iterable[str], *, strict_windows_acl: bool = False) -> None:
    iterator = iter(lines)
    try:
        first = next(iterator)
    except StopIteration:
        return

    with _open_append_private(path, strict_windows_acl=strict_windows_acl) as handle:
        handle.write(first + "\n")
        for line in iterator:
            handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    fsync_parent_directory(path)


def replace_lines(path: Path, lines: Iterable[str], *, strict_windows_acl: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for line in lines:
                handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        enforce_private_file_permissions(tmp_path, strict_windows_acl=strict_windows_acl)
        os.replace(tmp_path, path)
        enforce_private_file_permissions(path, strict_windows_acl=strict_windows_acl)
        fsync_parent_directory(path)
    except OSError as exc:
        raise ValueError(f"Unable to rewrite lineset file '{path}': {exc}") from exc
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass


__all__ = [
    "MAX_LINESET_FILE_BYTES",
    "USERNAME_HASH_PREFIX",
    "load_lineset",
    "username_hash_key_path",
    "hash_username_key",
    "parse_hashed_username_entry",
    "load_username_hash_key",
    "fsync_parent_directory",
    "append_line",
    "append_lines",
    "replace_lines",
]
