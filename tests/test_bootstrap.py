from __future__ import annotations

import importlib.util
import shutil
import sys
import unittest
import uuid
from pathlib import Path

_BOOTSTRAP_PATH = Path(__file__).resolve().parents[1] / "scripts" / "_bootstrap.py"
_BOOTSTRAP_SPEC = importlib.util.spec_from_file_location("usnpw_bootstrap", _BOOTSTRAP_PATH)
if _BOOTSTRAP_SPEC is None or _BOOTSTRAP_SPEC.loader is None:
    raise RuntimeError(f"unable to import bootstrap helper from {_BOOTSTRAP_PATH}")
_BOOTSTRAP_MODULE = importlib.util.module_from_spec(_BOOTSTRAP_SPEC)
_BOOTSTRAP_SPEC.loader.exec_module(_BOOTSTRAP_MODULE)


class BootstrapTests(unittest.TestCase):
    @staticmethod
    def _case_root() -> Path:
        root = Path(".tmp_test_bootstrap") / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=True)
        return root.resolve()

    def test_bootstrap_repo_path_inserts_direct_parent_only(self) -> None:
        case_root = self._case_root()
        try:
            repo_root = case_root / "repo"
            scripts_dir = repo_root / "scripts"
            package_dir = repo_root / "usnpw"
            scripts_dir.mkdir(parents=True)
            package_dir.mkdir()
            script_path = scripts_dir / "entry.py"
            script_path.write_text("# wrapper", encoding="utf-8")

            original_sys_path = list(sys.path)
            expected_root = str(repo_root.resolve())
            try:
                sys.path = [entry for entry in sys.path if entry != expected_root]
                _BOOTSTRAP_MODULE.bootstrap_repo_path(script_file=script_path)
                self.assertEqual(sys.path[0], expected_root)
                before = sys.path.count(expected_root)
                _BOOTSTRAP_MODULE.bootstrap_repo_path(script_file=script_path)
                self.assertEqual(sys.path.count(expected_root), before)
            finally:
                sys.path[:] = original_sys_path
        finally:
            shutil.rmtree(case_root, ignore_errors=True)

    def test_bootstrap_repo_path_rejects_ancestor_shadow_package(self) -> None:
        case_root = self._case_root()
        try:
            top_root = case_root / "root"
            (top_root / "usnpw").mkdir(parents=True)
            nested_scripts = top_root / "nested" / "scripts"
            nested_scripts.mkdir(parents=True)
            script_path = nested_scripts / "entry.py"
            script_path.write_text("# wrapper", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "unable to resolve repository root"):
                _BOOTSTRAP_MODULE.bootstrap_repo_path(script_file=script_path)
        finally:
            shutil.rmtree(case_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
