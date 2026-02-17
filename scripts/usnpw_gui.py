#!/usr/bin/env python3
from __future__ import annotations

from _bootstrap import bootstrap_repo_path


bootstrap_repo_path()

from usnpw.gui.app import main


if __name__ == "__main__":
    raise SystemExit(main())
