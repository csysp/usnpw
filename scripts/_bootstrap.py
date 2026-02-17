from __future__ import annotations

import sys
from pathlib import Path


def bootstrap_repo_path() -> None:
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "usnpw").is_dir():
            root = str(candidate)
            if root not in sys.path:
                sys.path.insert(0, root)
            return
