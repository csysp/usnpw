# Stream State (Uniqueness) Operations

This document explains how stream uniqueness works, where stream state lives, and how to recover safely if state or locks become problematic.

## What Stream Mode Does
In `stream` uniqueness mode, USnPw derives a per-profile key from:
- a secret (root secret), and
- a counter (monotonic integer).

Each generated username consumes counter space. The goal is uniqueness-by-construction without maintaining a full historical ledger.

## Where Stream State Is Stored
Default stream-state path (when persistence is enabled and no explicit path is set):
- `~/.opsec_username_stream_<profile>.json`

Lock file path:
- `<state>.lock` (same directory)

## OS Behavior
- Windows:
  - Stream secret is persisted encrypted via DPAPI when persistence is enabled.
- Linux/macOS:
  - By default, persistent stream state is disabled (no plaintext secret on disk).
  - Plaintext persistence requires explicit opt-in (`--allow-plaintext-stream-state`).

If persistence is disabled, USnPw uses an in-memory secret for the run.

## Recommended Operational Patterns
- Keep state per profile and per tenant/persona.
- Do not share stream-state files across unrelated teams.
- Do not commit state files to source control.

## Common Failures And Recovery

### 1. Lock Timeout Errors
Symptom:
- `Timed out waiting for stream state lock ...`

Likely causes:
- Another process is actively generating usernames using the same stream-state file.
- A prior process crashed and left a lock behind.

Recovery steps:
1. Verify there is no other active USnPw process using the same state path.
2. If you are confident no process is active, remove the lock file (`<state>.lock`).
3. Re-run with an explicit, writable `--stream-state` path if directory permissions are the issue.

Note:
- Locks have a heartbeat and stale locks may be reclaimed automatically after a staleness threshold.

### 2. Corrupted Or Unreadable State File
Symptoms:
- `Unable to read stream state file ...`
- `Invalid stream state format ...`
- `Unsupported stream state version ...`

Recovery steps:
1. Preserve the file for forensics:
   - rename the file instead of deleting it.
2. To continue generation without persistence:
   - run with `--no-stream-state-persist` (ephemeral run).
3. To reset the stream state for that persona:
   - delete the state file and lock file, then re-run.

Tradeoff:
- Resetting state can allow re-use of previously generated usernames across runs.

### 3. Plaintext State Blocked On Non-Windows
Symptom:
- `Plaintext stream state is blocked on this OS by default. Pass --allow-plaintext-stream-state to proceed.`

Options:
1. Prefer the default behavior (in-memory stream state) when you do not need cross-run uniqueness.
2. If you require persistence on non-Windows:
   - pass `--allow-plaintext-stream-state` and set a dedicated `--stream-state` path.

Threat reminder:
- Plaintext stream-state persistence leaks a secret that influences future generation behavior.

## Container Notes
In container/API mode, treat persistence as an explicit opt-in:
- mount only the minimum required state/token paths
- keep each deployment isolated (per team/tenant/profile)
- prefer single-replica deployments unless you have explicitly designed shared-state locking semantics

