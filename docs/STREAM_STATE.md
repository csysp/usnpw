# Stream State (Uniqueness) Operations

This guide explains stream uniqueness behavior, persistence semantics, and safe recovery workflows.

## What Stream Mode Does
In `stream` mode, USnPw derives per-profile generation behavior from a secret plus a monotonic counter. Each emitted username consumes counter space. The design goal is uniqueness-by-construction without maintaining a full historical username ledger.

## Storage Paths
Default state path (when persistence is enabled and no explicit path is set):

`~/.opsec_username_stream_<profile>.json`

Lock path:

`<state>.lock` (same directory as the state file)

## OS Behavior
On Windows, persisted stream secrets are protected with DPAPI. On Linux and macOS, plaintext stream-state persistence is blocked by default and requires explicit opt-in (`--allow-plaintext-stream-state`). If persistence is disabled, stream state remains in memory for the run.

## Recommended Operating Pattern
Keep stream state isolated per profile and per tenant/persona. Never share stream-state files across unrelated teams, and never commit state files to source control.

## Common Failures and Recovery
### Lock timeout errors
Symptom:

`Timed out waiting for stream state lock ...`

Likely causes:
- Another process is actively writing the same state path.
- A prior process left a stale lock file.

Recovery:
1. Confirm no active process is using the same stream-state path.
2. If you are certain no process is active, remove the lock file (`<state>.lock`).
3. If permission issues persist, rerun with an explicit writable `--stream-state` path.

Note: lock heartbeat and stale lock reclamation are built in, so stale locks may self-clear after the staleness threshold.

### Corrupted or unreadable state file
Common errors:

`Unable to read stream state file ...`

`Invalid stream state format ...`

`Unsupported stream state version ...`

Recovery:
1. Preserve the file for forensics by renaming it.
2. Continue without persistence using `--no-stream-state-persist`.
3. If reset is required, remove state and lock files and rerun.

Tradeoff: resetting state can allow previously generated usernames to reappear across runs.

### Plaintext state blocked on non-Windows
Symptom:

`Plaintext stream state is blocked on this OS by default. Pass --allow-plaintext-stream-state to proceed.`

Guidance: keep default in-memory behavior unless cross-run uniqueness is required. If you must persist on non-Windows, pass `--allow-plaintext-stream-state` and use a dedicated `--stream-state` path.

Threat reminder: plaintext stream-state persistence stores a secret that influences future generation behavior.

## Container Notes
In API and container deployments, treat persistence as an explicit opt-in. Mount only required state/token paths, isolate each deployment by tenant/profile, and prefer single-replica operation unless shared-state locking semantics are explicitly designed and tested.
