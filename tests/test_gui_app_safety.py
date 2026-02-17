from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from usnpw.core.models import (
    USERNAME_DEFAULT_HISTORY,
    USERNAME_DEFAULT_INITIALS_WEIGHT,
    USERNAME_DEFAULT_MAX_SCHEME_PCT,
    USERNAME_DEFAULT_NO_LEADING_DIGIT,
    USERNAME_DEFAULT_NO_SAVE,
    USERNAME_DEFAULT_NO_TOKEN_SAVE,
    USERNAME_DEFAULT_POOL_SCALE,
    USERNAME_DEFAULT_UNIQUENESS_MODE,
)

tk = None
USnPwApp = None


def _is_tkinter_dependency_error(exc: ImportError) -> bool:
    name = getattr(exc, "name", "") or ""
    msg = str(exc).lower()
    if name in {"tkinter", "_tkinter"}:
        return True
    if name.startswith("tkinter."):
        return True
    return any(token in msg for token in ("tkinter", "_tkinter", "libtk", "libtcl"))


def _load_gui_test_deps() -> tuple[object, object]:
    try:
        import tkinter as tk_mod
        from usnpw.gui.app import USnPwApp as app_cls
    except ImportError as exc:
        if _is_tkinter_dependency_error(exc):
            raise unittest.SkipTest(f"Tkinter GUI dependencies unavailable: {exc}") from exc
        raise
    return tk_mod, app_cls


class _Var:
    def __init__(self, value: object) -> None:
        self._value = value

    def get(self) -> object:
        return self._value

    def set(self, value: object) -> None:
        self._value = value


class _Status:
    def __init__(self) -> None:
        self.value = ""

    def set(self, value: str) -> None:
        self.value = value


class _Widget:
    def __init__(self) -> None:
        self.config: dict[str, object] = {}

    def configure(self, **kwargs: object) -> None:
        self.config.update(kwargs)


def _bind_path_safety_methods(dummy: object) -> None:
    dummy._canonicalize_for_risk = USnPwApp._canonicalize_for_risk.__get__(dummy, object)
    dummy._normalized_path_value = USnPwApp._normalized_path_value
    dummy._is_noncanonical_path = USnPwApp._is_noncanonical_path.__get__(dummy, object)
    dummy._ensure_safe_path = USnPwApp._ensure_safe_path.__get__(dummy, object)


class GuiAppSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global tk, USnPwApp
        tk, USnPwApp = _load_gui_test_deps()

    def test_is_risky_path_blocks_home_with_parent_segments(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy._canonicalize_for_risk = USnPwApp._canonicalize_for_risk.__get__(dummy, object)
        dummy._normalized_path_value = USnPwApp._normalized_path_value

        home = Path.home()
        traversed_home = home.parent / ".." / home.parent.name / home.name
        self.assertTrue(USnPwApp._is_risky_path(dummy, traversed_home))

    def test_is_risky_path_blocks_home_parent_with_parent_segments(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy._canonicalize_for_risk = USnPwApp._canonicalize_for_risk.__get__(dummy, object)
        dummy._normalized_path_value = USnPwApp._normalized_path_value

        home = Path.home()
        traversed_home_parent = home.parent / ".." / home.parent.name
        self.assertTrue(USnPwApp._is_risky_path(dummy, traversed_home_parent))

    def test_copy_guard_requires_prompt_when_enabled(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.copy_guard = _Var(True)
        dummy.strict_opsec_lock = _Var(True)
        dummy.u_safe_mode = _Var(True)

        self.assertTrue(USnPwApp._copy_guard_required(dummy))

        dummy.copy_guard.set(False)
        self.assertFalse(USnPwApp._copy_guard_required(dummy))

    def test_apply_strict_opsec_values_enforces_hardened_defaults(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.u_uniqueness_mode = _Var("blacklist")
        dummy.u_no_save = _Var(False)
        dummy.u_no_token_save = _Var(False)
        dummy.u_no_token_block = _Var(True)
        dummy.u_stream_save_tokens = _Var(True)
        dummy.u_no_leading_digit = _Var(False)
        dummy.u_max_scheme_pct = _Var("0.5")
        dummy.u_history = _Var("2")
        dummy.u_pool_scale = _Var("1")
        dummy.u_initials_weight = _Var("0.9")
        dummy.u_show_meta = _Var(True)
        dummy.u_allow_plaintext = _Var(True)

        USnPwApp._apply_strict_opsec_values(dummy)

        self.assertEqual(dummy.u_uniqueness_mode.get(), USERNAME_DEFAULT_UNIQUENESS_MODE)
        self.assertEqual(dummy.u_no_save.get(), USERNAME_DEFAULT_NO_SAVE)
        self.assertEqual(dummy.u_no_token_save.get(), USERNAME_DEFAULT_NO_TOKEN_SAVE)
        self.assertFalse(dummy.u_no_token_block.get())
        self.assertFalse(dummy.u_stream_save_tokens.get())
        self.assertEqual(dummy.u_no_leading_digit.get(), USERNAME_DEFAULT_NO_LEADING_DIGIT)
        self.assertEqual(dummy.u_max_scheme_pct.get(), str(USERNAME_DEFAULT_MAX_SCHEME_PCT))
        self.assertEqual(dummy.u_history.get(), str(USERNAME_DEFAULT_HISTORY))
        self.assertEqual(dummy.u_pool_scale.get(), str(USERNAME_DEFAULT_POOL_SCALE))
        self.assertEqual(dummy.u_initials_weight.get(), str(USERNAME_DEFAULT_INITIALS_WEIGHT))
        self.assertFalse(dummy.u_show_meta.get())
        self.assertFalse(dummy.u_allow_plaintext.get())

    def test_apply_username_lock_state_locks_hardened_controls_under_strict(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.u_uniqueness_combo = _Widget()
        dummy.u_safe_mode = _Var(False)
        dummy.strict_opsec_lock = _Var(True)
        dummy.chk_u_no_save = _Widget()
        dummy.chk_u_no_token_save = _Widget()
        dummy.chk_u_allow_plaintext = _Widget()
        dummy.chk_u_no_leading_digit = _Widget()
        dummy.chk_u_show_meta = _Widget()
        dummy.chk_u_no_token_block = _Widget()
        dummy.chk_u_stream_save_tokens = _Widget()
        dummy.u_max_scheme_pct_entry = _Widget()
        dummy.u_history_entry = _Widget()
        dummy.u_pool_scale_entry = _Widget()
        dummy.u_initials_weight_entry = _Widget()

        USnPwApp._apply_username_lock_state(dummy)

        self.assertEqual(dummy.u_uniqueness_combo.config["state"], "disabled")
        self.assertEqual(dummy.chk_u_no_save.config["state"], tk.DISABLED)
        self.assertEqual(dummy.chk_u_no_token_save.config["state"], tk.DISABLED)
        self.assertEqual(dummy.chk_u_allow_plaintext.config["state"], tk.DISABLED)
        self.assertEqual(dummy.chk_u_no_leading_digit.config["state"], tk.DISABLED)
        self.assertEqual(dummy.chk_u_show_meta.config["state"], tk.DISABLED)
        self.assertEqual(dummy.chk_u_no_token_block.config["state"], tk.DISABLED)
        self.assertEqual(dummy.chk_u_stream_save_tokens.config["state"], tk.DISABLED)
        self.assertEqual(dummy.u_max_scheme_pct_entry.config["state"], tk.DISABLED)
        self.assertEqual(dummy.u_history_entry.config["state"], tk.DISABLED)
        self.assertEqual(dummy.u_pool_scale_entry.config["state"], tk.DISABLED)
        self.assertEqual(dummy.u_initials_weight_entry.config["state"], tk.DISABLED)

    def test_apply_runtime_username_safety_fields_enforces_strict_defaults(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.strict_opsec_lock = _Var(True)
        dummy.session_only_mode = _Var(False)
        dummy.unsafe_path_block = _Var(False)
        dummy._is_risky_path = lambda _path: False
        _bind_path_safety_methods(dummy)
        base = Path(tempfile.gettempdir())

        fields = {
            "profile": "reddit",
            "uniqueness_mode": "blacklist",
            "no_save": False,
            "no_token_save": False,
            "no_token_block": True,
            "stream_save_tokens": True,
            "no_leading_digit": False,
            "max_scheme_pct": 0.7,
            "history": 1,
            "pool_scale": 1,
            "initials_weight": 0.8,
            "show_meta": True,
            "allow_plaintext_stream_state": True,
            "blacklist": str(base / "tmp_blacklist.txt"),
            "token_blacklist": str(base / "tmp_tokens.txt"),
            "stream_state": str(base / "tmp_state.json"),
        }

        updated = USnPwApp._apply_runtime_username_safety_fields(dummy, fields)

        self.assertEqual(updated["uniqueness_mode"], USERNAME_DEFAULT_UNIQUENESS_MODE)
        self.assertEqual(updated["no_save"], USERNAME_DEFAULT_NO_SAVE)
        self.assertEqual(updated["no_token_save"], USERNAME_DEFAULT_NO_TOKEN_SAVE)
        self.assertFalse(updated["no_token_block"])
        self.assertFalse(updated["stream_save_tokens"])
        self.assertEqual(updated["no_leading_digit"], USERNAME_DEFAULT_NO_LEADING_DIGIT)
        self.assertEqual(updated["max_scheme_pct"], USERNAME_DEFAULT_MAX_SCHEME_PCT)
        self.assertEqual(updated["history"], USERNAME_DEFAULT_HISTORY)
        self.assertEqual(updated["pool_scale"], USERNAME_DEFAULT_POOL_SCALE)
        self.assertEqual(updated["initials_weight"], USERNAME_DEFAULT_INITIALS_WEIGHT)
        self.assertFalse(updated["show_meta"])
        self.assertFalse(updated["allow_plaintext_stream_state"])

    def test_session_only_does_not_weaken_strict_token_block_hardening(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.strict_opsec_lock = _Var(True)
        dummy.session_only_mode = _Var(True)
        dummy.unsafe_path_block = _Var(False)
        dummy._is_risky_path = lambda _path: False
        _bind_path_safety_methods(dummy)
        base = Path(tempfile.gettempdir())

        fields = {
            "profile": "reddit",
            "uniqueness_mode": "stream",
            "blacklist": str(base / "tmp_blacklist.txt"),
            "token_blacklist": str(base / "tmp_tokens.txt"),
            "stream_state": str(base / "tmp_state.json"),
        }
        updated = USnPwApp._apply_runtime_username_safety_fields(dummy, fields)

        self.assertFalse(updated["no_token_block"])
        self.assertFalse(updated["stream_save_tokens"])
        self.assertFalse(updated["stream_state_persist"])

    def test_apply_runtime_username_safety_fields_blocks_noncanonical_targets(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.strict_opsec_lock = _Var(False)
        dummy.session_only_mode = _Var(False)
        dummy.unsafe_path_block = _Var(False)
        dummy._is_risky_path = lambda _path: False
        _bind_path_safety_methods(dummy)

        fields = {
            "profile": "reddit",
            "uniqueness_mode": "blacklist",
            "blacklist": "relative_blacklist.txt",
            "token_blacklist": str(Path(tempfile.gettempdir()) / "tmp_tokens.txt"),
        }

        with self.assertRaisesRegex(ValueError, "non-canonical path blocked for username blacklist"):
            USnPwApp._apply_runtime_username_safety_fields(dummy, fields)

    def test_confirm_and_delete_file_blocks_risky_delete_targets(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.unsafe_path_block = _Var(True)
        dummy._is_risky_path = lambda _path: True
        dummy._status_var = _Status()
        _bind_path_safety_methods(dummy)

        handle = tempfile.NamedTemporaryFile(delete=False)
        try:
            handle.close()
            target = Path(handle.name)
            with patch("usnpw.gui.app.messagebox.askyesno") as ask_yesno:
                deleted = USnPwApp._confirm_and_delete_file(dummy, target, "token blacklist")

            self.assertFalse(deleted)
            self.assertTrue(target.exists())
            self.assertIn("unsafe path blocked for token blacklist", dummy._status_var.value)
            ask_yesno.assert_not_called()
        finally:
            try:
                Path(handle.name).unlink()
            except OSError:
                pass

    def test_confirm_and_delete_file_blocks_unusual_targets_without_prompt(self) -> None:
        dummy = type("Dummy", (), {})()
        dummy.unsafe_path_block = _Var(False)
        dummy._is_risky_path = lambda _path: False
        dummy._status_var = _Status()
        _bind_path_safety_methods(dummy)

        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".dat")
        try:
            handle.close()
            target = Path(handle.name)
            with patch("usnpw.gui.app.messagebox.askyesno") as ask_yesno:
                deleted = USnPwApp._confirm_and_delete_file(dummy, target, "token blacklist")

            self.assertFalse(deleted)
            self.assertTrue(target.exists())
            self.assertIn("unusual path blocked for token blacklist", dummy._status_var.value)
            ask_yesno.assert_not_called()
        finally:
            try:
                Path(handle.name).unlink()
            except OSError:
                pass

    def test_copy_text_preserves_output_whitespace(self) -> None:
        dummy = type("Dummy", (), {})()
        widget = object()
        dummy._output_cache = {widget: ("  alpha", "beta  ", "")}
        dummy._status_var = _Status()
        dummy.auto_clear_clipboard = _Var(False)
        dummy._confirm_sensitive_action = lambda _action: True

        copied: dict[str, object] = {"text": None, "cleared": False}

        def _clear() -> None:
            copied["cleared"] = True

        def _append(text: str) -> None:
            copied["text"] = text

        dummy.clipboard_clear = _clear
        dummy.clipboard_append = _append
        dummy._schedule_clipboard_clear = lambda: None

        USnPwApp._copy_text(dummy, widget)

        self.assertTrue(copied["cleared"])
        self.assertEqual(copied["text"], "  alpha\nbeta  \n")
        self.assertEqual(dummy._status_var.value, "Copied output to clipboard.")

    def test_export_text_preserves_output_whitespace(self) -> None:
        dummy = type("Dummy", (), {})()
        widget = object()
        dummy._output_cache = {widget: ("  alpha", "beta  ")}
        dummy._status_var = _Status()
        dummy.encrypt_exports = _Var(False)
        dummy.export_passphrase = _Var("")
        dummy.unsafe_path_block = _Var(False)
        dummy._is_risky_path = lambda _path: False
        dummy._confirm_sensitive_action = lambda _action: True
        dummy.windows_acl_hardening = _Var(False)
        _bind_path_safety_methods(dummy)
        dummy._validate_export_path = USnPwApp._validate_export_path.__get__(dummy, object)

        exported: dict[str, object] = {}
        out_path = Path(tempfile.gettempdir()) / "out.txt"

        def _atomic_write(path: Path, text: str, *, strict_windows_acl: bool = False) -> None:
            exported["path"] = path
            exported["text"] = text
            exported["strict_windows_acl"] = strict_windows_acl

        dummy._atomic_write_text = _atomic_write

        with (
            patch("usnpw.gui.app.messagebox.askyesno", return_value=True),
            patch("usnpw.gui.app.filedialog.asksaveasfilename", return_value=str(out_path)),
        ):
            USnPwApp._export_text(dummy, widget, "username data")

        self.assertEqual(exported["path"], out_path)
        self.assertEqual(exported["text"], "  alpha\nbeta  \n")
        self.assertFalse(exported["strict_windows_acl"])
        self.assertEqual(dummy._status_var.value, "Exported output.")


if __name__ == "__main__":
    unittest.main()
