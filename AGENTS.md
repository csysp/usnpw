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
- Errors: use structured error types or codes for routing, not string comparison on exception messages.
- Tests: new encoding or format code must include correctness tests before merge.

## Validation Minimum
- `py -m py_compile usnpw/core/password_engine.py usnpw/core/username_generation.py usnpw/core/username_lexicon.py usnpw/core/username_schemes.py usnpw/core/username_stream_state.py usnpw/core/username_uniqueness.py usnpw/core/username_policies.py`
- `py -m py_compile usnpw/core/models.py usnpw/core/password_service.py usnpw/core/username_service.py`
- `py -m py_compile usnpw/cli/pwgen_cli.py usnpw/cli/opsec_username_cli.py usnpw/cli/usnpw_cli.py usnpw/__main__.py`
- `py -m unittest tests/test_core_smoke.py`
- `py -m unittest tests/test_service_layer.py`
- `py -m unittest tests/test_cli_args.py`
- `py -m unittest tests/test_password_engine.py`
- `py -m unittest tests/test_password_entropy.py`
- `py -m unittest tests/test_rng_health_probe.py`
- Run sample generation in password and username modes across at least two platform profiles.

## Release Ops
- `py .\tools\release.py preflight` for compile + unit-test gate.
- `py .\tools\release.py binaries` to build default host-native CLI + installer binaries (`usnpw-<platform>-cli`, `usnpw-<platform>-installer`) and checksums.
- `py .\tools\release.py bundle` to package distributable release assets in `dist/release` (`.exe` on Windows, `.tar.gz` on Linux/macOS) with checksums.
- `py .\tools\release.py install-cli` to install the CLI command (`usnpw`) into a user-local bin and persist PATH.
- `py .\tools\release.py all` for preflight + host-native CLI/installer binary release prep.
- Binary builds are pinned to `pyinstaller==6.16.0`; release commands hard-fail on version mismatch.
- CI matrix workflow: `.github/workflows/ci-matrix.yml` (Windows/Linux/macOS preflight + binaries + packaged release artifacts).
- Release workflow: `.github/workflows/release-artifacts.yml` (tag/manual packaged native CLI/installer release artifacts).
- Signing:
  - GPG signatures for `*.sha256` sidecars are produced by CI (requires repo secrets `USNPW_GPG_PRIVATE_KEY` and optional `USNPW_GPG_PASSPHRASE`).

## Local-Only Notes
- Keep sensitive/operator notes out of git history (for example: `GitHub Audit For Agent.md`).
- Prefer `.git/info/exclude` for local-only ignore rules to avoid changing repo policy.

## Project Health (Audited 2026-03-13)

### Security Posture: Strong
- 0 Critical, 0 High, 3 Medium, 4 Low findings.
- CSPRNG usage correct throughout (`os.urandom` + `secrets` module, zero use of `random`).
- Zero non-stdlib dependencies in application code.
- Fail-closed error handling confirmed across all CLI and service layers.
- Zero bare `except:` or `except Exception:` in the codebase.
- GPG signing pipeline well-structured with proper passphrase handling.

### Medium Security Findings (Open)
1. No upper bound on `--count` for password generation -- can OOM/hang on extreme values (`password_service.py`).
2. BIP39 `--bip39-wordlist` reads arbitrary file paths without symlink or directory restriction (`password_engine.py:174-218`).
3. `lru_cache` on pseudoword pools means single pool per process lifetime -- acceptable for CLI, document as limitation for library reuse (`username_lexicon.py:166-173`).

### Low Security Findings (Open)
1. Stream root secret not zeroizable in CPython (language limitation, documented in threat model).
2. Installer modifies user PATH by default without interactive prompt; `--no-path-update` exists but opt-out.
3. GitHub Actions pinned by mutable tag (`@v4`/`@v5`) not commit SHA -- supply chain hardening opportunity.

### Quality Assessment: B (Needs One Revision Cycle)
- Architecture separation is clean: CLI -> Service -> Core, no circular dependencies.
- Spec-to-code alignment is strong; non-negotiables are honored in code.
- README usage examples verified accurate against actual CLI flags.

### Known Dead Code (Violates Review Checklist)
- `usnpw/core/error_dialect.py`: `error_payload()`, `error_payload_from_exception()`, `make_error()` -- never imported outside module.
- `usnpw/core/username_uniqueness.py`: `contains_subsequence()` -- defined and exported but never called.

### Test Coverage Gaps
- No tests for custom encoding implementations: crock32, crock32check, base58, base58check, `group_string`.
- No BIP39 mnemonic output correctness test (checksum verification against spec).
- No tests for per-platform policy output validity (15 profiles, 0 policy-specific tests).
- No property-based or fuzz testing for the entropy estimator (~840 lines).
- No test for `error_dialect.py` formatting functions.

### Workflow / Process Issues (Prioritized)
1. **Release workflow has no preflight gate** -- `release-artifacts.yml` skips tests before building binaries. A tag push from any branch bypasses CI. High priority.
2. **Duplicated install/uninstall utilities** -- `_host_platform_tag()`, `_default_cli_install_dir()`, `_normalize_path_for_compare()`, `_posix_shell_name()`, `_posix_profile_targets()`, `PATH_MARKER` are copied across `tools/release.py`, `tools/uninstall_cli.py`, and `tools/ci_smoke_installer.py`. Path divergence = broken uninstaller.
3. **String-based error routing** -- `username_generation.py` and `username_service.py` compare exception message strings to route errors. Fragile; should use error codes or exception subclasses.
4. **CI workflow duplication** -- `release-artifacts.yml` binary build steps are near-verbatim copies of `ci-matrix.yml`. Should extract to reusable `workflow_call`.
5. **No `pyproject.toml`** -- no standard project metadata, no `pip install -e .` for development, no coverage tooling integration.
6. **Password CLI defaults hardcoded** -- `pwgen_cli.py` hardcodes `default=20` for length instead of importing from `PasswordRequest` field defaults in `models.py`. Risk of silent drift.
7. **`_BASE36` constant defined twice** -- `username_schemes.py:25` and `username_stream_state.py:9`.

### Anti-Fingerprinting Status: Multi-Layered, Not Yet Adversarially Validated
- 10 distinct variation dimensions implemented (scheme, separator, case, noise, tag placement, tag scrambling, token blocking, repeated-pattern rejection, platform canonicalization, pool permutation).
- Stream counter scrambling via HMAC-derived affine cipher is mathematically sound.
- Limitation: English-only vocabulary (~750 words) is a fingerprinting vector at scale.
- Limitation: noise injection patterns are statistically detectable in large corpora.
- The planned "Red Team" tool (see Future Additions) would close this validation gap.

## Future Additions
- "Red Team" anti-anti-fingerprinting tool
- CSysP site integration for demonstrative display/site traffic
- Low bloat quantum ready passwords?
- Codeberg-hosted, GitHub-mirrored public repo with fully auditable and buildable versions.
- Entropy Counter Tool
- Rewrite in Rust
