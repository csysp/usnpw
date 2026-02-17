from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Set, TextIO

from usnpw.core.file_hardening import enforce_private_file_permissions

MAX_LINESET_FILE_BYTES = 64 * 1024 * 1024


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


__all__ = [
    "MAX_LINESET_FILE_BYTES",
    "load_lineset",
    "fsync_parent_directory",
    "append_line",
    "append_lines",
]
