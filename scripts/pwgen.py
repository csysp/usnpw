#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_repo_path() -> None:
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "usnpw").is_dir():
            s = str(candidate)
            if s not in sys.path:
                sys.path.insert(0, s)
            return


_bootstrap_repo_path()

from usnpw.cli.pwgen_cli import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
