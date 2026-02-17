from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _windows_identity_candidates() -> tuple[str, ...]:
    domain = os.environ.get("USERDOMAIN", "").strip()
    user = os.environ.get("USERNAME", "").strip()
    candidates: list[str] = []
    if domain and user:
        candidates.append(f"{domain}\\{user}")
    if user:
        candidates.append(user)
    return tuple(dict.fromkeys(candidates))


def _run_icacls_hardening(path: Path, identity: str) -> None:
    command = [
        "icacls",
        str(path),
        "/inheritance:r",
        "/grant:r",
        f"{identity}:(R,W)",
        "/grant:r",
        "*S-1-5-18:(F)",
        "/grant:r",
        "*S-1-5-32-544:(F)",
    ]
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "icacls failed"
        raise ValueError(detail)


def enforce_private_file_permissions(path: Path, *, strict_windows_acl: bool = False) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        if os.name != "nt":
            raise ValueError(f"Unable to enforce private permissions on '{path}': {exc}") from exc
        if strict_windows_acl:
            raise ValueError(f"Unable to set private mode on '{path}': {exc}") from exc

    if os.name != "nt" or not strict_windows_acl:
        return

    candidates = _windows_identity_candidates()
    if not candidates:
        raise ValueError("Unable to resolve current Windows identity for ACL hardening.")

    errors: list[str] = []
    for identity in candidates:
        try:
            _run_icacls_hardening(path, identity)
            return
        except ValueError as exc:
            errors.append(f"{identity}: {exc}")

    joined = "; ".join(errors) if errors else "no identity candidates succeeded"
    raise ValueError(f"Unable to harden Windows ACLs for '{path}': {joined}")

