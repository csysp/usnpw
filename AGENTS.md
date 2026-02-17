# AGENTS.md
## We do not encourage any kind of nefarious activity or crime using this or any software created or owned by us. You are fully responsible for your actions.
## Human Written "Project Vision" Context
This is a personal project that began with a simple need to generate cryptographically sound passwords quickly from CLI for iterative testing purposes (Pw).  
A second small project, the "OPSEC Username Generator (USn)" was added later to complement the password generation. Once combined they form a powerful opsec tool for mass deployments or single use generations.
This project is currently a few .py scripts for internal use and iteration but will be expanded into a GUI app in the future.
Once completed, USnPw will function as a fully fledged "sensitive use" OPESEC account name and password creator, with deep anti-fingerprinting, anti-deterministic username generations across thousands of name generations. 
Password generation included randomness (derived from os.urandom) hashing and encoding processes including hex, base64/base64url, crock32/crock32check, base58/base58check, uuid, sha256, blake2b, and even bip39 with only english supported currently. 

## Mission
Build a small, auditable FOSS CLI for high-privacy username and secret generation.
Prioritize OPSEC and anti-fingerprinting over everything else.

## Non-Negotiables
- Keep dependencies to Python stdlib unless explicitly approved, even then vet each lib choice from a cybersecurity POV.
- No silent security/privacy failures.
- No broad `except Exception` unless re-raised with explicit user-facing context.
- No telemetry, analytics, network calls, or background services, it must be run offline locally or served via website.
- Avoid storing raw historical usernames.

## Architecture Priorities
- Platform-aware canonicalization must happen before uniqueness decisions.
- Prefer uniqueness-by-construction (`stream` mode with secret state + counter) over historical ledgers.
- Keep public-facing defaults hardened: stream uniqueness, no username save, no token save, no-leading-digit, history=10, pool_scale=4, initials_weight=0.
- If persistence is required, store the minimum viable state only.
- Keep identity handling out of code orchestration; tool remains stateless between profiles except explicit local state files.
- Keep reusable generation logic in importable `usnpw/core/*` modules.
- Keep argument parsing / terminal UX in `usnpw/cli/*`, with root scripts as thin wrappers for backward compatibility.
- Keep typed request/response contracts in `usnpw/core/models.py`.
- Route all generation paths through service boundaries (`usnpw/core/password_service.py`, `usnpw/core/username_service.py`).
- Keep sensitive export transformations in `usnpw/core/export_crypto.py`.
- Keep GUI as a thin adapter layer (`usnpw/gui/*`) that does not duplicate generation logic.
- Keep GUI parsing and presets in `usnpw/gui/adapters.py` so request-mapping is testable without opening windows.

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
- Security: no fail-open blacklist/state behavior.
- Privacy: no raw identifier leakage in logs/files by default.
- Correctness: case-insensitive uniqueness where platform semantics require it.
- UX: errors are explicit and actionable.
- Bloat: remove dead code and avoid duplicate pathways.

## Validation Minimum
- `py -m py_compile scripts/pwgen.py`
- `py -m py_compile scripts/opsec_username_gen.py`
- `py -m py_compile scripts/usnpw_cli.py`
- `py -m py_compile scripts/usnpw_api.py`
- `py -m py_compile scripts/usnpw_gui.py`
- `py -m py_compile usnpw/core/password_engine.py usnpw/core/username_generation.py usnpw/core/username_lexicon.py usnpw/core/username_schemes.py usnpw/core/username_storage.py usnpw/core/username_stream_state.py usnpw/core/username_uniqueness.py usnpw/core/username_policies.py`
- `py -m py_compile usnpw/core/models.py usnpw/core/password_service.py usnpw/core/username_service.py usnpw/core/export_crypto.py`
- `py -m py_compile usnpw/core/services.py`
- `py -m py_compile usnpw/cli/pwgen_cli.py usnpw/cli/opsec_username_cli.py usnpw/cli/usnpw_cli.py usnpw/__main__.py`
- `py -m py_compile usnpw/gui/adapters.py usnpw/gui/app.py scripts/usnpw_gui.py`
- `py -m unittest tests/test_core_smoke.py`
- `py -m unittest tests/test_service_layer.py`
- `py -m unittest tests/test_gui_adapters.py`
- `py -m unittest tests/test_export_crypto.py`
- Optional (quick robustness pass): `py .\tools\fuzz_gui_adapters.py --iterations 20000 --seed 1`
- Run sample generation in each supported mode and at least two platform profiles.

## Phase 4 Release Ops
- `py .\tools\release.py preflight` for compile + unit-test gate.
- `py .\tools\release.py bundle` to build a timestamped source artifact (`usnpw-source-<stamp>.zip`) in `.\dist\`.
- `py .\tools\release.py checksums --artifact <zip>` to write a SHA-256 sidecar.
- `py .\tools\release.py binaries` to build default host-native binaries (`usnpw-<platform>-gui` + `usnpw-cli`).
- `py .\tools\release.py install-cli` to install the CLI command (`usnpw`) into a user-local bin and persist PATH.
- `py .\tools\release.py all` for end-to-end source release prep.
- `py .\tools\release.py all --with-binaries` for source + host-native binary release prep.
- Binary builds are pinned to `pyinstaller==6.16.0`; release commands hard-fail on version mismatch.
- CI matrix workflow: `.github/workflows/ci-matrix.yml` (Windows/Linux/macOS preflight + native binaries).
- Release workflow: `.github/workflows/release-artifacts.yml` (tag/manual source + binary artifacts).
- Signing:
  - GPG signatures for `*.sha256` sidecars are produced by CI (requires repo secrets `USNPW_GPG_PRIVATE_KEY` and optional `USNPW_GPG_PASSPHRASE`).
  - GHCR container images are cosign-signed by CI on tag publishes.

## Local-Only Notes
- Keep sensitive/operator notes out of git history (ex: `Github Audit For Agent.md`).
- Prefer `.git/info/exclude` for local-only ignore rules to avoid changing repo policy.

## Future Additions
- "Red Team" anti-anti-fingerprinting tool
- CSysP site integration for demonstrative display/site traffic
- Low bloat quantum ready passwords?
- Codeberg hosted, Github mirrored public repo with fully auditable and buildable versions.
- Entropy Counter Tool
- Re-Write in Rust
