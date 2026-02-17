from __future__ import annotations

import os
import queue
import sys
import tempfile
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable, Iterable

from usnpw.core.export_crypto import encrypt_text
from usnpw.core.error_dialect import make_error
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
from usnpw.core.password_engine import FORMAT_CHOICES, OUT_ENC_CHOICES
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_policies import PLATFORM_POLICIES
from usnpw.core.username_service import generate_usernames
from usnpw.gui.adapters import (
    SAFE_MODE_LOCKED_VALUES,
    build_export_warning,
    build_password_request,
    build_username_request,
    effective_stream_state_path,
    format_error_status,
    is_unusual_delete_target,
    parse_int,
    stream_state_lock_path,
)


class USnPwApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("USnPw")
        self.geometry("1080x800")
        self.minsize(980, 720)

        self._events: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._busy = False
        self._status_var = tk.StringVar(value="Ready.")
        self._clipboard_timer_id: str | None = None
        self._output_timer_ids: dict[ScrolledText, str] = {}
        self._output_cache: dict[ScrolledText, tuple[str, ...]] = {}
        self._mask_rehide_timer_id: str | None = None
        self.dark_mode = tk.BooleanVar(value=False)
        self._style = ttk.Style(self)
        self._text_widgets: list[ScrolledText] = []
        self._windows_only_label: ttk.Label | None = None

        self._build_ui()
        self._apply_theme(dark=self.dark_mode.get())
        self.after(100, self._poll_events)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        self._build_safety_panel(root)

        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.password_tab = ttk.Frame(notebook, padding=10)
        self.username_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.password_tab, text="Passwords")
        notebook.add(self.username_tab, text="Usernames")

        self._build_password_tab(self.password_tab)
        self._build_username_tab(self.username_tab)

        status = ttk.Label(root, textvariable=self._status_var, anchor="w")
        status.pack(fill=tk.X, pady=(8, 0))

    def _on_theme_toggled(self) -> None:
        dark = self.dark_mode.get()
        self._apply_theme(dark=dark)
        self._status_var.set("Dark mode enabled." if dark else "Dark mode disabled.")

    def _on_strict_opsec_toggled(self) -> None:
        if self.strict_opsec_lock.get():
            self._apply_strict_opsec_values()
            self._status_var.set("Strict OPSEC lock enabled.")
        else:
            self._status_var.set("Strict OPSEC lock disabled.")
        self._apply_username_lock_state()

    def _apply_strict_opsec_values(self) -> None:
        if not hasattr(self, "u_uniqueness_mode"):
            return
        self.u_uniqueness_mode.set(USERNAME_DEFAULT_UNIQUENESS_MODE)
        self.u_no_save.set(USERNAME_DEFAULT_NO_SAVE)
        self.u_no_token_save.set(USERNAME_DEFAULT_NO_TOKEN_SAVE)
        self.u_no_token_block.set(False)
        self.u_stream_save_tokens.set(False)
        self.u_no_leading_digit.set(USERNAME_DEFAULT_NO_LEADING_DIGIT)
        self.u_max_scheme_pct.set(str(USERNAME_DEFAULT_MAX_SCHEME_PCT))
        self.u_history.set(str(USERNAME_DEFAULT_HISTORY))
        self.u_pool_scale.set(str(USERNAME_DEFAULT_POOL_SCALE))
        self.u_initials_weight.set(str(USERNAME_DEFAULT_INITIALS_WEIGHT))
        self.u_show_meta.set(False)
        self.u_allow_plaintext.set(False)

    def _apply_username_lock_state(self) -> None:
        if not hasattr(self, "u_uniqueness_combo"):
            return

        safe_locked = self.u_safe_mode.get()
        strict_locked = self.strict_opsec_lock.get()

        combo_state = "disabled" if (safe_locked or strict_locked) else "readonly"
        self.u_uniqueness_combo.configure(state=combo_state)

        sensitive_lock_state = tk.DISABLED if (safe_locked or strict_locked) else tk.NORMAL
        self.chk_u_no_save.configure(state=sensitive_lock_state)
        self.chk_u_no_token_save.configure(state=sensitive_lock_state)
        self.chk_u_allow_plaintext.configure(state=sensitive_lock_state)
        self.chk_u_no_leading_digit.configure(state=sensitive_lock_state)
        self.chk_u_show_meta.configure(state=sensitive_lock_state)

        hardened_lock_state = tk.DISABLED if (safe_locked or strict_locked) else tk.NORMAL
        entry_state = tk.DISABLED if (safe_locked or strict_locked) else tk.NORMAL
        self.chk_u_no_token_block.configure(state=hardened_lock_state)
        self.chk_u_stream_save_tokens.configure(state=hardened_lock_state)
        self.u_max_scheme_pct_entry.configure(state=entry_state)
        self.u_history_entry.configure(state=entry_state)
        self.u_pool_scale_entry.configure(state=entry_state)
        self.u_initials_weight_entry.configure(state=entry_state)

    def _on_session_only_toggled(self) -> None:
        if self.session_only_mode.get():
            self._status_var.set("Session-only mode enabled.")
        else:
            self._status_var.set("Session-only mode disabled.")

    def _on_output_auto_clear_toggled(self) -> None:
        if not self.output_auto_clear.get():
            for timer_id in list(self._output_timer_ids.values()):
                self.after_cancel(timer_id)
            self._output_timer_ids.clear()

    def _on_shoulder_surf_toggled(self) -> None:
        masked = self.shoulder_surf_mask.get()
        self.btn_reveal_mask.configure(state=tk.NORMAL if masked else tk.DISABLED)
        if masked:
            self._status_var.set("Shoulder-surf mask enabled.")
        else:
            if self._mask_rehide_timer_id is not None:
                self.after_cancel(self._mask_rehide_timer_id)
                self._mask_rehide_timer_id = None
            self._status_var.set("Shoulder-surf mask disabled.")
        for widget in self._text_widgets:
            self._render_output(widget, reveal=not masked)

    def _reveal_output_temporarily(self) -> None:
        if not self.shoulder_surf_mask.get():
            return
        if self._mask_rehide_timer_id is not None:
            self.after_cancel(self._mask_rehide_timer_id)
            self._mask_rehide_timer_id = None
        for widget in self._text_widgets:
            self._render_output(widget, reveal=True)
        self._mask_rehide_timer_id = self.after(5000, self._rehide_masked_output)
        self._status_var.set("Output revealed for 5 seconds.")

    def _rehide_masked_output(self) -> None:
        self._mask_rehide_timer_id = None
        if not self.shoulder_surf_mask.get():
            return
        for widget in self._text_widgets:
            self._render_output(widget, reveal=False)

    def _render_output(self, widget: ScrolledText, reveal: bool = False) -> None:
        lines = self._output_cache.get(widget, ())
        if self.shoulder_surf_mask.get() and not reveal:
            masked_lines = tuple(("*" * len(line)) if line else "" for line in lines)
            display_lines = masked_lines
        else:
            display_lines = lines
        widget.delete("1.0", tk.END)
        for line in display_lines:
            widget.insert(tk.END, line + "\n")

    @staticmethod
    def _normalized_path_value(path: Path) -> str:
        return os.path.normcase(os.path.normpath(str(path)))

    def _canonicalize_for_risk(self, path: Path) -> Path:
        expanded = path.expanduser()
        try:
            return expanded.resolve(strict=False)
        except OSError:
            return Path(os.path.abspath(os.path.normpath(str(expanded))))

    def _is_risky_path(self, path: Path) -> bool:
        raw_input = str(path).strip()
        if raw_input in ("", ".", ".."):
            return True

        canonical = self._canonicalize_for_risk(path)
        canonical_value = self._normalized_path_value(canonical)
        if canonical_value.startswith("\\\\"):
            return True

        anchor = canonical.anchor
        if anchor and canonical_value == self._normalized_path_value(Path(anchor)):
            return True

        home = self._canonicalize_for_risk(Path.home())
        home_value = self._normalized_path_value(home)
        home_parent_value = self._normalized_path_value(home.parent)
        return canonical_value in (home_value, home_parent_value)

    def _ensure_safe_path(self, path: Path, label: str) -> None:
        if not self.unsafe_path_block.get():
            return
        if self._is_risky_path(path):
            raise ValueError(f"unsafe path blocked for {label}: {path}")

    def _apply_runtime_username_safety_fields(self, fields: dict[str, object]) -> dict[str, object]:
        strict_locked = self.strict_opsec_lock.get()
        if strict_locked:
            fields["uniqueness_mode"] = "stream"
            fields["no_save"] = True
            fields["no_token_save"] = True
            fields["no_token_block"] = False
            fields["stream_save_tokens"] = False
            fields["no_leading_digit"] = True
            fields["max_scheme_pct"] = USERNAME_DEFAULT_MAX_SCHEME_PCT
            fields["history"] = USERNAME_DEFAULT_HISTORY
            fields["pool_scale"] = USERNAME_DEFAULT_POOL_SCALE
            fields["initials_weight"] = USERNAME_DEFAULT_INITIALS_WEIGHT
            fields["show_meta"] = False
            fields["allow_plaintext_stream_state"] = False

        if self.session_only_mode.get():
            fields["uniqueness_mode"] = "stream"
            fields["no_save"] = True
            fields["no_token_save"] = True
            fields["no_token_block"] = False if strict_locked else True
            fields["stream_save_tokens"] = False
            fields["stream_state_persist"] = False
            fields["stream_state"] = ""
            fields["allow_plaintext_stream_state"] = False

        profile = str(fields.get("profile", "generic"))
        blacklist = Path(str(fields.get("blacklist", "")).strip()).expanduser()
        token_blacklist = Path(str(fields.get("token_blacklist", "")).strip()).expanduser()
        self._ensure_safe_path(blacklist, "username blacklist")
        self._ensure_safe_path(token_blacklist, "token blacklist")

        if fields.get("uniqueness_mode") == "stream":
            stream_state_path = effective_stream_state_path(profile, str(fields.get("stream_state", "")))
            self._ensure_safe_path(stream_state_path, "stream state")

        return fields

    def _copy_guard_required(self) -> bool:
        return bool(self.copy_guard.get())

    def _confirm_sensitive_action(self, action: str) -> bool:
        if not self._copy_guard_required():
            return True
        return messagebox.askyesno(
            title="Copy Guard",
            message=f"{action} contains sensitive output. Continue?",
            icon=messagebox.WARNING,
            default=messagebox.NO,
        )

    def _schedule_output_clear(self, widget: ScrolledText) -> None:
        if widget in self._output_timer_ids:
            self.after_cancel(self._output_timer_ids[widget])
            self._output_timer_ids.pop(widget, None)
        seconds = parse_int(self.output_ttl_seconds.get(), "output auto-clear seconds")
        if seconds <= 0:
            raise ValueError("output auto-clear seconds must be > 0")
        timer_id = self.after(seconds * 1000, lambda w=widget: self._clear_output_from_timer(w))
        self._output_timer_ids[widget] = timer_id

    def _clear_output_from_timer(self, widget: ScrolledText) -> None:
        self._output_timer_ids.pop(widget, None)
        self._output_cache[widget] = ()
        self._render_output(widget, reveal=True)
        self._status_var.set("Output auto-cleared.")

    def _delete_file_if_exists(self, path: Path, label: str) -> bool:
        if not path.exists() or path.is_dir():
            return False
        if self.unsafe_path_block.get() and self._is_risky_path(path):
            self._status_var.set(format_error_status(f"panic clear blocked unsafe {label} path: {path}"))
            return False
        try:
            path.unlink()
            return True
        except OSError as exc:
            self._status_var.set(format_error_status(f"panic clear failed for {label}: {exc}"))
            return False

    def _panic_clear(self) -> None:
        proceed = messagebox.askyesno(
            title="Panic Clear",
            message="Clear outputs, clipboard, and selected runtime files now?",
            icon=messagebox.WARNING,
            default=messagebox.NO,
        )
        if not proceed:
            self._status_var.set("Panic clear canceled.")
            return

        for timer_id in list(self._output_timer_ids.values()):
            self.after_cancel(timer_id)
        self._output_timer_ids.clear()
        if self._mask_rehide_timer_id is not None:
            self.after_cancel(self._mask_rehide_timer_id)
            self._mask_rehide_timer_id = None

        self._clear_text(self.password_output)
        self._clear_text(self.username_output)
        self._clear_clipboard_now()

        removed: list[str] = []
        token_path = Path(self.u_token_blacklist.get().strip()).expanduser()
        if self._delete_file_if_exists(token_path, "token blacklist"):
            removed.append("token blacklist")

        stream_state_path = effective_stream_state_path(self.u_profile.get(), self.u_stream_state.get())
        if self._delete_file_if_exists(stream_state_path, "stream state"):
            removed.append("stream state")
        stream_lock_path = stream_state_lock_path(stream_state_path)
        if self._delete_file_if_exists(stream_lock_path, "stream state lock"):
            removed.append("stream state lock")

        if removed:
            self._status_var.set(f"Panic clear completed ({', '.join(removed)} removed).")
        else:
            self._status_var.set("Panic clear completed.")

    def _apply_theme(self, dark: bool) -> None:
        self._style.theme_use("clam")
        if dark:
            colors = {
                "bg": "#11161d",
                "field": "#0f141b",
                "fg": "#e8eef6",
                "muted": "#9fb0c3",
                "select": "#2d3a4a",
                "border": "#3a4556",
            }
        else:
            colors = {
                "bg": "#f4f6f8",
                "field": "#ffffff",
                "fg": "#111827",
                "muted": "#5b6675",
                "select": "#dbeafe",
                "border": "#c7d0db",
            }

        self.configure(background=colors["bg"])
        self._style.configure(".", background=colors["bg"], foreground=colors["fg"])
        self._style.configure("TFrame", background=colors["bg"])
        self._style.configure("TLabel", background=colors["bg"], foreground=colors["fg"])
        self._style.configure("TLabelframe", background=colors["bg"], bordercolor=colors["border"])
        self._style.configure("TLabelframe.Label", background=colors["bg"], foreground=colors["fg"])
        self._style.configure("TButton", background=colors["bg"], foreground=colors["fg"], bordercolor=colors["border"])
        self._style.map("TButton", background=[("active", colors["select"])])
        self._style.configure("TCheckbutton", background=colors["bg"], foreground=colors["fg"])
        self._style.map("TCheckbutton", background=[("active", colors["bg"])])
        self._style.configure(
            "TEntry",
            fieldbackground=colors["field"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
        )
        self._style.configure(
            "TCombobox",
            fieldbackground=colors["field"],
            foreground=colors["fg"],
            background=colors["bg"],
            arrowcolor=colors["fg"],
            bordercolor=colors["border"],
        )
        self._style.map(
            "TCombobox",
            fieldbackground=[("readonly", colors["field"])],
            foreground=[("readonly", colors["fg"])],
            selectbackground=[("readonly", colors["select"])],
            selectforeground=[("readonly", colors["fg"])],
        )
        self._style.configure("TNotebook", background=colors["bg"], bordercolor=colors["border"])
        self._style.configure("TNotebook.Tab", background=colors["bg"], foreground=colors["fg"])
        self._style.map(
            "TNotebook.Tab",
            background=[("selected", colors["select"])],
            foreground=[("selected", colors["fg"])],
        )
        self._style.configure("TSeparator", background=colors["border"])

        for widget in self._text_widgets:
            widget.configure(
                background=colors["field"],
                foreground=colors["fg"],
                insertbackground=colors["fg"],
                selectbackground=colors["select"],
                selectforeground=colors["fg"],
                highlightthickness=1,
                highlightbackground=colors["border"],
                highlightcolor=colors["border"],
            )

        if self._windows_only_label is not None:
            self._windows_only_label.configure(foreground=colors["muted"])

    def _build_safety_panel(self, parent: ttk.Frame) -> None:
        panel = ttk.LabelFrame(parent, text="Safety Controls", padding=8)
        panel.pack(fill=tk.X, pady=(8, 0), anchor="w")
        row1 = ttk.Frame(panel)
        row1.pack(fill=tk.X, anchor="w")
        row2 = ttk.Frame(panel)
        row2.pack(fill=tk.X, anchor="w", pady=(6, 0))
        row3 = ttk.Frame(panel)
        row3.pack(fill=tk.X, anchor="w", pady=(6, 0))
        row4 = ttk.Frame(panel)
        row4.pack(fill=tk.X, anchor="w", pady=(6, 0))

        self.strict_opsec_lock = tk.BooleanVar(value=False)
        self.session_only_mode = tk.BooleanVar(value=False)
        self.copy_guard = tk.BooleanVar(value=False)
        self.unsafe_path_block = tk.BooleanVar(value=True)
        self.shoulder_surf_mask = tk.BooleanVar(value=False)
        self.auto_clear_clipboard = tk.BooleanVar(value=True)
        self.clipboard_ttl_seconds = tk.StringVar(value="30")
        self.output_auto_clear = tk.BooleanVar(value=False)
        self.output_ttl_seconds = tk.StringVar(value="30")
        self.encrypt_exports = tk.BooleanVar(value=False)
        self.export_passphrase = tk.StringVar(value="")

        ttk.Checkbutton(
            row1, text="Strict OPSEC lock", variable=self.strict_opsec_lock, command=self._on_strict_opsec_toggled
        ).pack(side=tk.LEFT)
        ttk.Checkbutton(
            row1, text="Session-only mode", variable=self.session_only_mode, command=self._on_session_only_toggled
        ).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Checkbutton(row1, text="Copy guard", variable=self.copy_guard).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Checkbutton(
            row1,
            text="Unsafe path block",
            variable=self.unsafe_path_block,
        ).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Checkbutton(row1, text="Dark mode", variable=self.dark_mode, command=self._on_theme_toggled).pack(
            side=tk.LEFT
        )
        ttk.Checkbutton(
            row1, text="Shoulder-surf mask", variable=self.shoulder_surf_mask, command=self._on_shoulder_surf_toggled
        ).pack(side=tk.LEFT, padx=(10, 0))
        self.btn_reveal_mask = ttk.Button(
            row1,
            text="Reveal 5s",
            command=self._reveal_output_temporarily,
            state=tk.DISABLED,
        )
        self.btn_reveal_mask.pack(side=tk.LEFT, padx=(8, 0))

        ttk.Checkbutton(row2, text="Auto-clear clipboard", variable=self.auto_clear_clipboard).pack(side=tk.LEFT)
        ttk.Label(row2, text="after").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Entry(row2, textvariable=self.clipboard_ttl_seconds, width=6).pack(side=tk.LEFT)
        ttk.Label(row2, text="seconds").pack(side=tk.LEFT, padx=(4, 12))
        ttk.Button(row2, text="Clear Clipboard Now", command=self._clear_clipboard_now).pack(side=tk.LEFT)
        ttk.Separator(row2, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=12)
        ttk.Checkbutton(
            row2, text="Auto-clear output", variable=self.output_auto_clear, command=self._on_output_auto_clear_toggled
        ).pack(side=tk.LEFT)
        ttk.Label(row2, text="after").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Entry(row2, textvariable=self.output_ttl_seconds, width=6).pack(side=tk.LEFT)
        ttk.Label(row2, text="seconds").pack(side=tk.LEFT, padx=(4, 12))

        self.chk_encrypt_exports = ttk.Checkbutton(row3, text="Encrypt exports", variable=self.encrypt_exports)
        self.chk_encrypt_exports.pack(side=tk.LEFT)
        ttk.Label(row3, text="passphrase").pack(side=tk.LEFT, padx=(10, 4))
        self.entry_export_passphrase = ttk.Entry(row3, textvariable=self.export_passphrase, show="*", width=20)
        self.entry_export_passphrase.pack(side=tk.LEFT)

        ttk.Button(row4, text="Panic Clear", command=self._panic_clear).pack(side=tk.LEFT)

        if os.name != "nt":
            self.encrypt_exports.set(False)
            self.chk_encrypt_exports.configure(state=tk.DISABLED)
            self.entry_export_passphrase.configure(state=tk.DISABLED)
            self._windows_only_label = ttk.Label(row3, text="(Windows only)")
            self._windows_only_label.pack(side=tk.LEFT, padx=(8, 0))

    def _build_password_tab(self, parent: ttk.Frame) -> None:
        self.p_count = tk.StringVar(value="1")
        self.p_length = tk.StringVar(value="20")
        self.p_format = tk.StringVar(value="password")
        self.p_charset = tk.StringVar(value="")
        self.p_symbols = tk.StringVar(value="!@#$%^&*()-_=+[]{};:,?/")
        self.p_no_symbols = tk.BooleanVar(value=False)
        self.p_max_entropy = tk.BooleanVar(value=False)
        self.p_bytes = tk.StringVar(value="0")
        self.p_bits = tk.StringVar(value="0")
        self.p_out_enc = tk.StringVar(value="hex")
        self.p_group = tk.StringVar(value="0")
        self.p_group_sep = tk.StringVar(value="-")
        self.p_group_pad = tk.StringVar(value="")
        self.p_words = tk.StringVar(value="24")
        self.p_delim = tk.StringVar(value=" ")
        self.p_bip39_wordlist = tk.StringVar(value="")

        form = ttk.LabelFrame(parent, text="Options", padding=8)
        form.pack(fill=tk.X, anchor="n")

        self._add_entry(form, 0, "Count", self.p_count, width=10)
        self._add_combo(form, 0, "Format", self.p_format, list(FORMAT_CHOICES), width=16, col=2)
        self._add_entry(form, 1, "Length", self.p_length, width=10)
        self._add_entry(form, 1, "Charset", self.p_charset, width=30, col=2)
        self._add_entry(form, 2, "Symbols", self.p_symbols, width=30)
        ttk.Checkbutton(form, text="No symbols", variable=self.p_no_symbols).grid(
            row=2, column=3, sticky="w", padx=6, pady=4
        )
        ttk.Checkbutton(form, text="Max entropy (PQ-512 preset)", variable=self.p_max_entropy).grid(
            row=2, column=4, sticky="w", padx=6, pady=4
        )
        self._add_entry(form, 3, "Bytes", self.p_bytes, width=10)
        self._add_entry(form, 3, "Bits", self.p_bits, width=10, col=2)
        self._add_combo(form, 3, "Out enc", self.p_out_enc, list(OUT_ENC_CHOICES), width=16, col=4)
        self._add_entry(form, 4, "Group", self.p_group, width=10)
        self._add_entry(form, 4, "Group sep", self.p_group_sep, width=10, col=2)
        self._add_entry(form, 4, "Group pad", self.p_group_pad, width=10, col=4)
        self._add_combo(form, 5, "BIP39 words", self.p_words, ["12", "18", "24"], width=10)
        self._add_entry(form, 5, "BIP39 delim", self.p_delim, width=10, col=2)
        self._add_entry(form, 6, "BIP39 wordlist", self.p_bip39_wordlist, width=54)
        ttk.Button(form, text="Browse", command=self._browse_bip39).grid(row=6, column=3, sticky="w", padx=6, pady=4)

        actions = ttk.Frame(parent)
        actions.pack(fill=tk.X, pady=(8, 4))
        self.btn_password_generate = ttk.Button(actions, text="Generate Passwords", command=self._generate_passwords)
        self.btn_password_generate.pack(side=tk.LEFT)
        ttk.Button(actions, text="Copy Output", command=lambda: self._copy_text(self.password_output)).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(
            actions,
            text="Export...",
            command=lambda: self._export_text(self.password_output, "password data"),
        ).pack(side=tk.LEFT)
        ttk.Button(
            actions,
            text="Clear",
            command=lambda: self._clear_text(self.password_output),
        ).pack(side=tk.LEFT, padx=6)

        self.password_output = ScrolledText(parent, height=20, wrap=tk.NONE)
        self.password_output.pack(fill=tk.BOTH, expand=True)
        self._text_widgets.append(self.password_output)

    def _build_username_tab(self, parent: ttk.Frame) -> None:
        profiles = sorted(PLATFORM_POLICIES.keys())

        self.u_count = tk.StringVar(value="10")
        self.u_min_len = tk.StringVar(value="8")
        self.u_max_len = tk.StringVar(value="16")
        self.u_profile = tk.StringVar(value="generic")
        self.u_safe_mode = tk.BooleanVar(value=False)
        self.u_uniqueness_mode = tk.StringVar(value=USERNAME_DEFAULT_UNIQUENESS_MODE)
        self.u_blacklist = tk.StringVar(value=str(Path.home() / ".opsec_username_blacklist.txt"))
        self.u_no_save = tk.BooleanVar(value=USERNAME_DEFAULT_NO_SAVE)
        self.u_token_blacklist = tk.StringVar(value=str(Path.home() / ".opsec_username_tokens.txt"))
        self.u_no_token_save = tk.BooleanVar(value=USERNAME_DEFAULT_NO_TOKEN_SAVE)
        self.u_no_token_block = tk.BooleanVar(value=False)
        self.u_stream_save_tokens = tk.BooleanVar(value=False)
        self.u_stream_state = tk.StringVar(value="")
        self.u_allow_plaintext = tk.BooleanVar(value=False)
        self.u_disallow_prefix = tk.StringVar(value="")
        self.u_disallow_substring = tk.StringVar(value="")
        self.u_no_leading_digit = tk.BooleanVar(value=USERNAME_DEFAULT_NO_LEADING_DIGIT)
        self.u_max_scheme_pct = tk.StringVar(value=str(USERNAME_DEFAULT_MAX_SCHEME_PCT))
        self.u_history = tk.StringVar(value=str(USERNAME_DEFAULT_HISTORY))
        self.u_pool_scale = tk.StringVar(value=str(USERNAME_DEFAULT_POOL_SCALE))
        self.u_initials_weight = tk.StringVar(value=str(USERNAME_DEFAULT_INITIALS_WEIGHT))
        self.u_show_meta = tk.BooleanVar(value=False)

        form = ttk.LabelFrame(parent, text="Options", padding=8)
        form.pack(fill=tk.X, anchor="n")

        self._add_entry(form, 0, "Count", self.u_count, width=10)
        self._add_combo(form, 0, "Profile", self.u_profile, profiles, width=16, col=2)
        self.u_uniqueness_combo = self._add_combo(
            form, 0, "Uniqueness", self.u_uniqueness_mode, ["blacklist", "stream"], width=12, col=4
        )
        self._add_entry(form, 1, "Min len", self.u_min_len, width=10)
        self._add_entry(form, 1, "Max len", self.u_max_len, width=10, col=2)
        self.u_max_scheme_pct_entry = self._add_entry(form, 1, "Max scheme pct", self.u_max_scheme_pct, width=10, col=4)
        self.u_history_entry = self._add_entry(form, 2, "History", self.u_history, width=10)
        self.u_pool_scale_entry = self._add_entry(form, 2, "Pool scale", self.u_pool_scale, width=10, col=2)
        self.u_initials_weight_entry = self._add_entry(
            form,
            2,
            "Initials weight",
            self.u_initials_weight,
            width=10,
            col=4,
        )
        self._add_entry(form, 3, "Blacklist file", self.u_blacklist, width=54)
        ttk.Button(form, text="Browse", command=lambda: self._browse_path(self.u_blacklist)).grid(
            row=3, column=3, sticky="w", padx=6, pady=4
        )
        self._add_entry(form, 4, "Token blacklist", self.u_token_blacklist, width=54)
        ttk.Button(form, text="Browse", command=lambda: self._browse_path(self.u_token_blacklist)).grid(
            row=4, column=3, sticky="w", padx=6, pady=4
        )
        self._add_entry(form, 5, "Stream state", self.u_stream_state, width=54)
        ttk.Button(form, text="Browse", command=lambda: self._browse_path(self.u_stream_state)).grid(
            row=5, column=3, sticky="w", padx=6, pady=4
        )
        self._add_entry(form, 6, "Disallow prefix (csv)", self.u_disallow_prefix, width=54)
        self._add_entry(form, 7, "Disallow substring (csv)", self.u_disallow_substring, width=54)

        toggles = ttk.Frame(form)
        toggles.grid(row=8, column=0, columnspan=6, sticky="w", pady=(4, 2))
        self.chk_u_safe_mode = ttk.Checkbutton(
            toggles, text="Safe mode", variable=self.u_safe_mode, command=self._on_safe_mode_toggled
        )
        self.chk_u_safe_mode.pack(side=tk.LEFT, padx=(0, 8))
        self.chk_u_no_save = ttk.Checkbutton(toggles, text="No save", variable=self.u_no_save)
        self.chk_u_no_save.pack(side=tk.LEFT, padx=(0, 8))
        self.chk_u_no_token_save = ttk.Checkbutton(toggles, text="No token save", variable=self.u_no_token_save)
        self.chk_u_no_token_save.pack(side=tk.LEFT, padx=8)
        self.chk_u_no_token_block = ttk.Checkbutton(toggles, text="No token block", variable=self.u_no_token_block)
        self.chk_u_no_token_block.pack(side=tk.LEFT, padx=8)
        self.chk_u_stream_save_tokens = ttk.Checkbutton(
            toggles, text="Stream save tokens", variable=self.u_stream_save_tokens
        )
        self.chk_u_stream_save_tokens.pack(side=tk.LEFT, padx=8)
        self.chk_u_allow_plaintext = ttk.Checkbutton(
            toggles, text="Allow plaintext stream state", variable=self.u_allow_plaintext
        )
        self.chk_u_allow_plaintext.pack(side=tk.LEFT, padx=8)
        self.chk_u_no_leading_digit = ttk.Checkbutton(
            toggles, text="No leading digit", variable=self.u_no_leading_digit
        )
        self.chk_u_no_leading_digit.pack(side=tk.LEFT, padx=8)
        self.chk_u_show_meta = ttk.Checkbutton(toggles, text="Show meta", variable=self.u_show_meta)
        self.chk_u_show_meta.pack(side=tk.LEFT, padx=8)

        maintenance = ttk.LabelFrame(parent, text="Maintenance", padding=8)
        maintenance.pack(fill=tk.X, pady=(4, 4))
        ttk.Button(maintenance, text="Clear Token Blacklist", command=self._clear_token_blacklist).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(maintenance, text="Clear Stream State", command=self._clear_stream_state).pack(side=tk.LEFT)

        actions = ttk.Frame(parent)
        actions.pack(fill=tk.X, pady=(8, 4))
        self.btn_username_generate = ttk.Button(actions, text="Generate Usernames", command=self._generate_usernames)
        self.btn_username_generate.pack(side=tk.LEFT)
        ttk.Button(actions, text="Copy Output", command=lambda: self._copy_text(self.username_output)).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(
            actions,
            text="Export...",
            command=lambda: self._export_text(self.username_output, "username data"),
        ).pack(side=tk.LEFT)
        ttk.Button(
            actions,
            text="Clear",
            command=lambda: self._clear_text(self.username_output),
        ).pack(side=tk.LEFT, padx=6)

        self.username_output = ScrolledText(parent, height=20, wrap=tk.NONE)
        self.username_output.pack(fill=tk.BOTH, expand=True)
        self._text_widgets.append(self.username_output)
        self._on_safe_mode_toggled()

    def _on_safe_mode_toggled(self) -> None:
        locked = self.u_safe_mode.get()
        if locked:
            self.u_uniqueness_mode.set(str(SAFE_MODE_LOCKED_VALUES["uniqueness_mode"]))
            self.u_no_save.set(bool(SAFE_MODE_LOCKED_VALUES["no_save"]))
            self.u_no_token_save.set(bool(SAFE_MODE_LOCKED_VALUES["no_token_save"]))
            self.u_no_token_block.set(bool(SAFE_MODE_LOCKED_VALUES["no_token_block"]))
            self.u_stream_save_tokens.set(bool(SAFE_MODE_LOCKED_VALUES["stream_save_tokens"]))
            self.u_allow_plaintext.set(bool(SAFE_MODE_LOCKED_VALUES["allow_plaintext_stream_state"]))
            self.u_no_leading_digit.set(bool(SAFE_MODE_LOCKED_VALUES["no_leading_digit"]))
            self.u_max_scheme_pct.set(str(SAFE_MODE_LOCKED_VALUES["max_scheme_pct"]))
            self.u_history.set(str(SAFE_MODE_LOCKED_VALUES["history"]))
            self.u_pool_scale.set(str(SAFE_MODE_LOCKED_VALUES["pool_scale"]))
            self.u_initials_weight.set(str(SAFE_MODE_LOCKED_VALUES["initials_weight"]))
            self.u_show_meta.set(bool(SAFE_MODE_LOCKED_VALUES["show_meta"]))
            self._status_var.set("Safe mode enabled: hardened defaults are locked.")
        else:
            if self.strict_opsec_lock.get():
                self._status_var.set("Strict OPSEC lock enabled.")
            else:
                self._status_var.set("Safe mode disabled.")

        if self.strict_opsec_lock.get():
            self._apply_strict_opsec_values()
        self._apply_username_lock_state()

    def _confirm_and_delete_file(self, path: Path, label: str) -> bool:
        if not path.exists():
            self._status_var.set(f"{label} not found: {path}")
            return False
        if path.is_dir():
            self._status_var.set(format_error_status(f"refusing to delete directory for {label}: {path}"))
            return False
        if self.unsafe_path_block.get() and self._is_risky_path(path):
            self._status_var.set(format_error_status(f"unsafe delete path blocked for {label}: {path}"))
            return False

        if is_unusual_delete_target(path, label):
            unusual_confirm = messagebox.askyesno(
                title="Unusual Target Warning",
                message=(
                    f"Path looks unusual for {label}:\n{path}\n\n"
                    "Proceed anyway?"
                ),
                icon=messagebox.WARNING,
                default=messagebox.NO,
            )
            if not unusual_confirm:
                self._status_var.set(f"Canceled deletion of {label}.")
                return False

        confirm = messagebox.askyesno(
            title=f"Delete {label}",
            message=f"Delete {label} at:\n{path}\n\nThis action cannot be undone.",
            icon=messagebox.WARNING,
            default=messagebox.NO,
        )
        if not confirm:
            self._status_var.set(f"Canceled deletion of {label}.")
            return False
        try:
            path.unlink()
        except OSError as exc:
            self._status_var.set(format_error_status(f"failed to delete {label}: {exc}"))
            return False
        self._status_var.set(f"Deleted {label}: {path}")
        return True

    def _clear_token_blacklist(self) -> None:
        target = self.u_token_blacklist.get().strip()
        if not target:
            self._status_var.set(format_error_status("token blacklist path is empty"))
            return
        self._confirm_and_delete_file(Path(target).expanduser(), "token blacklist")

    def _clear_stream_state(self) -> None:
        state_path = effective_stream_state_path(self.u_profile.get(), self.u_stream_state.get())
        removed_state = self._confirm_and_delete_file(state_path, "stream state")
        lock_path = stream_state_lock_path(state_path)
        if lock_path.exists():
            self._confirm_and_delete_file(lock_path, "stream state lock")
        elif removed_state:
            self._status_var.set(f"Stream state cleared for profile '{self.u_profile.get()}'.")

    def _add_entry(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        var: tk.StringVar,
        width: int = 12,
        col: int = 0,
    ) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=(0, 6), pady=4)
        entry = ttk.Entry(parent, textvariable=var, width=width)
        entry.grid(
            row=row, column=col + 1, sticky="w", padx=(0, 16), pady=4
        )
        return entry

    def _add_combo(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        var: tk.StringVar,
        values: Iterable[str],
        width: int = 12,
        col: int = 0,
    ) -> ttk.Combobox:
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=(0, 6), pady=4)
        combo = ttk.Combobox(parent, textvariable=var, values=list(values), width=width, state="readonly")
        combo.grid(
            row=row, column=col + 1, sticky="w", padx=(0, 16), pady=4
        )
        return combo

    def _browse_bip39(self) -> None:
        path = filedialog.askopenfilename(title="Select BIP39 Wordlist")
        if path:
            self.p_bip39_wordlist.set(path)

    def _browse_path(self, target: tk.StringVar) -> None:
        path = filedialog.askopenfilename(title="Select File")
        if not path:
            path = filedialog.asksaveasfilename(title="Choose Path")
        if path:
            target.set(path)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.btn_password_generate.configure(state=state)
        self.btn_username_generate.configure(state=state)

    def _start_job(self, task: Callable[[], object], on_ok: Callable[[object], None]) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self._status_var.set("Running...")

        def worker() -> None:
            try:
                result = task()
                self._events.put(("ok", (on_ok, result)))
            except (ValueError, OSError, UnicodeError) as exc:
                self._events.put(("err", (exc, "")))
            except Exception as exc:
                context = make_error("internal_error", "unexpected background task failure")
                self._events.put(("err", (context, traceback.format_exc())))
                raise RuntimeError(str(context)) from exc

        def worker_guarded() -> None:
            try:
                worker()
            except RuntimeError:
                return

        threading.Thread(target=worker_guarded, daemon=True).start()

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "ok":
                    on_ok, result = payload  # type: ignore[misc]
                    on_ok(result)
                    self._status_var.set("Done.")
                else:
                    msg, tb = payload if isinstance(payload, tuple) else (str(payload), "")
                    self._status_var.set(format_error_status(msg))
                    if tb:
                        if os.environ.get("USNPW_GUI_VERBOSE_ERRORS", "").strip().lower() in ("1", "true", "yes", "on"):
                            print(tb, file=sys.stderr)
                        else:
                            print("internal_error: RuntimeError", file=sys.stderr)
                self._set_busy(False)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_events)

    def _clear_text(self, widget: ScrolledText) -> None:
        if widget in self._output_timer_ids:
            self.after_cancel(self._output_timer_ids[widget])
            self._output_timer_ids.pop(widget, None)
        self._output_cache[widget] = ()
        self._render_output(widget, reveal=True)

    def _write_lines(self, widget: ScrolledText, lines: Iterable[str]) -> None:
        normalized = tuple(lines)
        self._output_cache[widget] = normalized
        self._render_output(widget, reveal=False)
        if self.output_auto_clear.get():
            try:
                self._schedule_output_clear(widget)
            except ValueError as exc:
                self._status_var.set(format_error_status(str(exc)))

    def _schedule_clipboard_clear(self) -> None:
        if self._clipboard_timer_id is not None:
            self.after_cancel(self._clipboard_timer_id)
            self._clipboard_timer_id = None
        seconds = parse_int(self.clipboard_ttl_seconds.get(), "clipboard auto-clear seconds")
        if seconds <= 0:
            raise ValueError("clipboard auto-clear seconds must be > 0")
        self._clipboard_timer_id = self.after(seconds * 1000, self._clear_clipboard_now)

    def _clear_clipboard_now(self) -> None:
        self.clipboard_clear()
        self._clipboard_timer_id = None
        self._status_var.set("Clipboard cleared.")

    def _copy_text(self, widget: ScrolledText) -> None:
        if not self._confirm_sensitive_action("Copying output"):
            self._status_var.set("Copy canceled by copy guard.")
            return

        lines = self._output_cache.get(widget, ())
        if not lines:
            self._status_var.set("Nothing to copy.")
            return
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        if self.auto_clear_clipboard.get():
            try:
                self._schedule_clipboard_clear()
            except ValueError as exc:
                self._status_var.set(format_error_status(str(exc)))
                return
            self._status_var.set("Copied output to clipboard (auto-clear scheduled).")
        else:
            self._status_var.set("Copied output to clipboard.")

    def _atomic_write_text(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp_usnpw_export_", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            try:
                dir_fd = os.open(str(path.parent), os.O_RDONLY)
            except OSError:
                dir_fd = None
            if dir_fd is not None:
                try:
                    os.fsync(dir_fd)
                except OSError:
                    pass
                finally:
                    try:
                        os.close(dir_fd)
                    except OSError:
                        pass
        finally:
            if os.path.exists(tmp_name):
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

    def _export_text(self, widget: ScrolledText, label: str) -> None:
        if not self._confirm_sensitive_action("Exporting output"):
            self._status_var.set("Export canceled by copy guard.")
            return

        lines = self._output_cache.get(widget, ())
        if not lines:
            self._status_var.set("Nothing to export.")
            return
        text = "\n".join(lines)

        encrypted = self.encrypt_exports.get()
        export_payload = text + "\n"
        if encrypted:
            passphrase = self.export_passphrase.get()
            if not passphrase:
                self._status_var.set(format_error_status("export passphrase is required when encryption is enabled"))
                return
            try:
                export_payload = encrypt_text(export_payload, passphrase)
            except ValueError as exc:
                self._status_var.set(format_error_status(str(exc)))
                return

        proceed = messagebox.askyesno(
            title="Sensitive Data Warning",
            message=build_export_warning(label, encrypted),
            icon=messagebox.WARNING,
            default=messagebox.NO,
        )
        if not proceed:
            self._status_var.set("Export canceled.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Output",
            defaultextension=".enc" if encrypted else ".txt",
        )
        if not path:
            self._status_var.set("Export canceled.")
            return

        export_path = Path(path)
        if self.unsafe_path_block.get() and self._is_risky_path(export_path):
            self._status_var.set(format_error_status(f"unsafe export path blocked: {export_path}"))
            return

        try:
            self._atomic_write_text(export_path, export_payload)
        except OSError as exc:
            self._status_var.set(format_error_status(f"export failed: {exc}"))
            return

        if encrypted:
            self._status_var.set(f"Exported encrypted output to {path}")
        else:
            self._status_var.set(f"Exported output to {path}")

    def _generate_passwords(self) -> None:
        def task() -> tuple[str, ...]:
            request = build_password_request(
                {
                    "count": self.p_count.get(),
                    "length": self.p_length.get(),
                    "charset": self.p_charset.get(),
                    "symbols": self.p_symbols.get(),
                    "no_symbols": self.p_no_symbols.get(),
                    "max_entropy": self.p_max_entropy.get(),
                    "format": self.p_format.get(),
                    "entropy_bytes": self.p_bytes.get(),
                    "bits": self.p_bits.get(),
                    "out_enc": self.p_out_enc.get(),
                    "group": self.p_group.get(),
                    "group_sep": self.p_group_sep.get(),
                    "group_pad": self.p_group_pad.get(),
                    "words": self.p_words.get(),
                    "delim": self.p_delim.get(),
                    "bip39_wordlist": self.p_bip39_wordlist.get(),
                }
            )
            result = generate_passwords(request)
            return result.outputs

        self._start_job(task, lambda lines: self._write_lines(self.password_output, lines))

    def _generate_usernames(self) -> None:
        def task() -> tuple[str, ...]:
            fields: dict[str, object] = {
                "count": self.u_count.get(),
                "min_len": self.u_min_len.get(),
                "max_len": self.u_max_len.get(),
                "profile": self.u_profile.get(),
                "safe_mode": self.u_safe_mode.get(),
                "uniqueness_mode": self.u_uniqueness_mode.get(),
                "blacklist": self.u_blacklist.get(),
                "no_save": self.u_no_save.get(),
                "token_blacklist": self.u_token_blacklist.get(),
                "no_token_save": self.u_no_token_save.get(),
                "no_token_block": self.u_no_token_block.get(),
                "stream_save_tokens": self.u_stream_save_tokens.get(),
                "stream_state": self.u_stream_state.get(),
                "allow_plaintext_stream_state": self.u_allow_plaintext.get(),
                "disallow_prefix": self.u_disallow_prefix.get(),
                "disallow_substring": self.u_disallow_substring.get(),
                "no_leading_digit": self.u_no_leading_digit.get(),
                "max_scheme_pct": self.u_max_scheme_pct.get(),
                "history": self.u_history.get(),
                "pool_scale": self.u_pool_scale.get(),
                "initials_weight": self.u_initials_weight.get(),
                "show_meta": self.u_show_meta.get(),
            }
            fields = self._apply_runtime_username_safety_fields(fields)
            request = build_username_request(fields)
            result = generate_usernames(request)
            return result.as_lines(show_meta=request.show_meta)

        self._start_job(task, lambda lines: self._write_lines(self.username_output, lines))


def main(argv: list[str] | None = None) -> int:
    del argv
    app = USnPwApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
