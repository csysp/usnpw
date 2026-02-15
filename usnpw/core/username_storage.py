from __future__ import annotations

import os
from pathlib import Path
from typing import Set


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


def append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    fsync_parent_directory(path)


__all__ = [
    "load_lineset",
    "fsync_parent_directory",
    "append_line",
]
