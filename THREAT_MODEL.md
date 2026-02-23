# Threat Model

Last updated: 2026-02-23

This threat model covers the reduced USnPw scope: local, offline, single-user CLI credential generation.

## Scope
- CLI entrypoints:
  - `usnpw/__main__.py`
  - `usnpw/cli/usnpw_cli.py`
  - `usnpw/cli/pwgen_cli.py`
  - `usnpw/cli/opsec_username_cli.py`
- Core modules under `usnpw/core/*`

Out of scope:
- API server
- GUI
- container deployment

## Security Objectives
1. Generate unpredictable secrets from OS CSPRNG.
2. Generate usernames with anti-pattern checks and per-run uniqueness controls.
3. Minimize recoverable local artifacts by default.
4. Fail closed on invalid inputs and unsupported secure-state pathways.
5. Avoid dependency and network attack surface (stdlib-only, no telemetry, no background calls).
6. In memory cleared on application exit. 

## Assets
- Generated password outputs.
- Generated username outputs.

## Trust Boundaries
1. Host boundary:
   If host is compromised (malware, keylogger, memory scraper), outputs can be exposed.
2. Operator boundary:
   Unsafe CLI options can reduce privacy posture (for example `--allow-token-reuse`).
3. Artifact boundary:
   Terminal history, clipboard use, and manual file exports can leak sensitive data.

## Primary Threats
1. Input abuse:
   malformed or extreme inputs trying to trigger undefined behavior.
2. Predictability drift:
   repetitive username structures at high volume.
3. Local artifact leakage:
   accidental retention in shell/history/memory
4. Dependency expansion:
   additional third-party packages increasing supply-chain risk.

## Mitigations
1. Strict request validation with explicit errors.
2. Hardened username defaults:
   token blocking on, no-leading-digit on, anti-repeat tuning enabled.
3. In-memory-only username stream behavior:
   no stream-state file persistence, no username/token ledger persistence.
4. Statically bounded generation attempts and deterministic fail messages.
5. Release verification:
   checksums and optional signed checksum sidecars.

## Residual Risks
1. Compromised endpoint can still exfiltrate generated data.
2. Human operational mistakes (copy/paste, screen capture, shell logs) remain possible.
3. Very large runs may require `--allow-token-reuse`, which reduces uniqueness quality.
