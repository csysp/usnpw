from __future__ import annotations

import sys
from pathlib import Path


def _resolve_repo_root(script_file: str | Path) -> Path:
    script_path = Path(script_file).resolve()
    repo_root = script_path.parent.parent
    if not (repo_root / "usnpw").is_dir():
        raise RuntimeError(
            "unable to resolve repository root from wrapper location; "
            "expected wrapper under '<repo>/scripts/' with '<repo>/usnpw/' present"
        )
    return repo_root


def bootstrap_repo_path(script_file: str | Path | None = None) -> None:
    source_file = __file__ if script_file is None else script_file
    root = str(_resolve_repo_root(source_file))
    if root not in sys.path:
        sys.path.insert(0, root)
