# AGENTS.md
## We do not encourage any kind of nefarious activity or crime using this or any software created or owned by us. You are fully responsible for your actions.
## Human Written "Project Vision" Context
This is a personal project that began with a simple need to generate cryptographically sound passwords quickly from CLI for iterative testing purposes (Pw).  
A second small project, the "OPSEC Username Generator (USn)", was added later to complement password generation. Combined, they form a practical OPSEC tool for single-use and mass-generation workflows.
This project started as a set of internal Python scripts and is now intentionally focused back to a CLI-only toolchain.
USnPw is intended to become a fully fledged sensitive-use account name and password creator, with deep anti-fingerprinting and non-deterministic username generation across large output volumes.
Password generation includes randomness from `os.urandom` and supports formats/encodings such as hex, base64/base64url, crock32/crock32check, base58/base58check, uuid, sha256, blake2b, and BIP39 (English only today).

## Mission
Build a small, auditable FOSS CLI for high-privacy username and secret generation.
Prioritize OPSEC and anti-fingerprinting over everything else.

## Core Directive (Seed Phrase)
Auditable credential generation for sensitive workflows.

## Non-Negotiables
- Keep dependencies to Python stdlib unless explicitly approved, even then vet each lib choice from a cybersecurity POV.
- No silent security/privacy failures.
- No broad `except Exception` unless re-raised with explicit user-facing context.
- No telemetry, analytics, network calls, or background services; run offline locally.
- Avoid storing raw historical usernames.

## Architecture Priorities
- Platform-aware canonicalization must happen before uniqueness decisions.
- Prefer in-memory uniqueness-by-construction over historical ledgers.
- Keep public-facing defaults hardened: token blocking on, no-leading-digit, history=10, pool_scale=4, initials_weight=0.
- Keep identity handling out of orchestration; treat generation runs as ephemeral by default.
- Keep reusable generation logic in importable `usnpw/core/*` modules.
- Keep argument parsing / terminal UX in `usnpw/cli/*`.
- Keep typed request/response contracts in `usnpw/core/models.py`.
- Route all generation paths through service boundaries (`usnpw/core/password_service.py`, `usnpw/core/username_service.py`).

## Supported Platform Profiles
- `generic`
- `reddit`
- `x`
- `github`
- `discord`
- `facebook`
- `linkedin`
- `instagram`
- `pinterest`
- `snapchat`
- `telegram`
- `tiktok`
- `douyin`
- `vk`
- `youtube`

## Anti-Fingerprinting Guidelines
- Avoid deterministic output signatures that create a "house style".
- Diversify separators, case, token placement, and noise patterns.
- Periodically review distribution drift (scheme ratios, digit placement, token reuse patterns).
- Keep non-Windows behavior close to Windows while avoiding plaintext secret persistence by default.
- Treat metadata outputs as sensitive; keep off by default.

## Code Change Policy
- Add only code needed for the current threat model and use case.
- Every new flag or persistence path must include:
  - clear threat-model rationale in code comments/docstring,
  - failure behavior (fail closed vs fail open),
  - migration/backward-compatibility note if applicable.
- Prefer small composable functions over large rewrites.

## Review Checklist (Before Merge/Release)
- Security: no fail-open input validation or uniqueness behavior.
- Privacy: no raw identifier leakage in logs/files by default.
- Correctness: case-insensitive uniqueness where platform semantics require it.
- UX: errors are explicit and actionable.
- Bloat: remove dead code and avoid duplicate pathways.

## Validation Minimum
- `py -m py_compile usnpw/core/password_engine.py usnpw/core/username_generation.py usnpw/core/username_lexicon.py usnpw/core/username_schemes.py usnpw/core/username_stream_state.py usnpw/core/username_uniqueness.py usnpw/core/username_policies.py`
- `py -m py_compile usnpw/core/models.py usnpw/core/password_service.py usnpw/core/username_service.py`
- `py -m py_compile usnpw/cli/pwgen_cli.py usnpw/cli/opsec_username_cli.py usnpw/cli/usnpw_cli.py usnpw/__main__.py`
- `py -m unittest tests/test_core_smoke.py`
- `py -m unittest tests/test_service_layer.py`
- Run sample generation in password and username modes across at least two platform profiles.

## Phase 4 Release Ops
- `py .\tools\release.py preflight` for compile + unit-test gate.
- `py .\tools\release.py binaries` to build default host-native CLI binaries (`usnpw-<platform>-cli`) and checksums.
- `py .\tools\release.py install-cli` to install the CLI command (`usnpw`) into a user-local bin and persist PATH.
- `py .\tools\release.py all` for preflight + host-native CLI binary release prep.
- Binary builds are pinned to `pyinstaller==6.16.0`; release commands hard-fail on version mismatch.
- CI matrix workflow: `.github/workflows/ci-matrix.yml` (Windows/Linux/macOS preflight + native binaries).
- Release workflow: `.github/workflows/release-artifacts.yml` (tag/manual native CLI binary artifacts).
- Signing:
  - GPG signatures for `*.sha256` sidecars are produced by CI (requires repo secrets `USNPW_GPG_PRIVATE_KEY` and optional `USNPW_GPG_PASSPHRASE`).

## Local-Only Notes
- Keep sensitive/operator notes out of git history (for example: `GitHub Audit For Agent.md`).
- Prefer `.git/info/exclude` for local-only ignore rules to avoid changing repo policy.

## Future Additions
- "Red Team" anti-anti-fingerprinting tool
- CSysP site integration for demonstrative display/site traffic
- Low bloat quantum ready passwords?
- Codeberg-hosted, GitHub-mirrored public repo with fully auditable and buildable versions.
- Entropy Counter Tool
- Rewrite in Rust
