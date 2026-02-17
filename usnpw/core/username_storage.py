from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Set, TextIO


def load_lineset(path: Path, label: str) -> Set[str]:
    if not path.exists():
        return set()
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
def _open_append_private(path: Path) -> Iterator[TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    if os.name != "nt":
        # Create with restrictive permissions on POSIX; prevents leaking persisted usernames/tokens.
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            try:
                os.close(fd)
            except OSError:
                pass
            raise ValueError(f"Unable to enforce private permissions on '{path}': {exc}") from exc
    else:
        # Best-effort private mode normalization on Windows; ACL behavior is OS-managed.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as handle:
        yield handle


def append_line(path: Path, line: str) -> None:
    append_lines(path, (line,))


def append_lines(path: Path, lines: Iterable[str]) -> None:
    iterator = iter(lines)
    try:
        first = next(iterator)
    except StopIteration:
        return

    with _open_append_private(path) as handle:
        handle.write(first + "\n")
        for line in iterator:
            handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    fsync_parent_directory(path)


__all__ = [
    "load_lineset",
    "fsync_parent_directory",
    "append_line",
    "append_lines",
]
