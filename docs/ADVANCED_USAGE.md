# USnPw Advanced Usage

This guide covers advanced operation of:
- `scripts/usnpw_cli.py`
- `scripts/pwgen.py`
- `scripts/opsec_username_gen.py`
- `scripts/usnpw_gui.py`

For installation and basic setup, use `docs/SETUP.md`.

## Command Conventions
Windows examples use `py .\scripts\...`. Linux and macOS equivalents use `python3 ./scripts/...`.

The unified wrapper defaults to password mode (`usnpw -n 5 -l 24`). Username mode is explicit (`usnpw username -n 20 --profile reddit`).

## Username Generation: Operating Strategy
### Choose Uniqueness Mode Deliberately
Use `stream` mode (default) when privacy and low artifact creation matter most. It provides uniqueness-by-construction from secret state and a counter, without a full username ledger. Use `blacklist` mode only when a persistent username ledger is an explicit operational requirement.

### Understand Stream-State Behavior by OS
On Windows, stream state can persist with DPAPI protection when persistence is enabled. On Linux and macOS, persistence is blocked by default unless you allow plaintext stream state explicitly with `--allow-plaintext-stream-state`. If you want an intentionally ephemeral run on any OS, use `--no-stream-state-persist`.

### Keep Persona Files Isolated
Use dedicated token and stream-state paths per persona.

```powershell
py .\scripts\opsec_username_gen.py -n 150 --profile reddit `
  --token-blacklist "$env:USERPROFILE\.u_tokens_reddit_personaA.txt" `
  --stream-state "$env:USERPROFILE\.u_stream_reddit_personaA.json"
```

For strict ephemerality:

```powershell
py .\scripts\opsec_username_gen.py -n 150 --profile reddit `
  --no-stream-state-persist --no-token-block --no-token-save --no-save
```

### High-Volume Baseline (Anti-Fingerprinting)

```powershell
py .\scripts\opsec_username_gen.py -n 200 --profile reddit `
  --min-len 10 --max-len 18 `
  --max-scheme-pct 0.28 --history 10 --pool-scale 4 `
  --initials-weight 0 --no-leading-digit `
  --token-blacklist "$env:USERPROFILE\.u_tokens_reddit.txt"
```

If you want to avoid strict generation-order consumption in downstream processing:

```powershell
py .\scripts\opsec_username_gen.py -n 200 --profile reddit | Sort-Object {Get-Random}
```

### Tune Diversity Controls
| Control | Effect | Practical range |
|---|---|---|
| `--max-scheme-pct` | Reduces dominant scheme repetition; values that are too low increase saturation pressure | `0.22` to `0.35` |
| `--history` | Reduces short-window style repeats | `8` to `14` |
| `--pool-scale` | Expands run-local token diversity | `3` to `6` |
| `--initials-weight` | Controls initials-style prevalence | `0` for strict posture |
| `--no-leading-digit` | Removes leading-digit pattern class | enabled for hardened posture |

### Handle Token Saturation
When token blocking is enabled, capacity is finite. If you hit token-capacity errors, reduce `-n`, rotate or clear token blacklists, increase `--max-scheme-pct` slightly, or run without token blocking (`--no-token-block`) for non-strict operations.

Cleanup example:

```powershell
Remove-Item "$env:USERPROFILE\.u_tokens_reddit.txt" -Force -ErrorAction SilentlyContinue
```

### Persistence Tradeoffs
`--no-save` and `--no-token-save` remain the hardened defaults. Enable persistence only when your operational model requires cross-run continuity, and scope files per persona and profile.
When username persistence is enabled in blacklist mode, saved username entries are HMAC-hashed (`h1:<digest>`) rather than stored as raw identifiers. The per-blacklist key is stored locally at `<blacklist>.key` with private file permissions. If a key exists and legacy raw entries are present, they are migrated to hashed entries on the next persisted run.

### Content Constraints
Use explicit prefix and substring blocks when operational policy requires it.

```powershell
py .\scripts\opsec_username_gen.py -n 100 --profile generic `
  --disallow-prefix admin --disallow-prefix mod `
  --disallow-substring test --disallow-substring bot
```

### Profile-Aware Generation
Profiles apply platform-specific canonicalization and length policy.

```powershell
py .\scripts\opsec_username_gen.py -n 25 --profile x
py .\scripts\opsec_username_gen.py -n 25 --profile github
py .\scripts\opsec_username_gen.py -n 25 --profile telegram
py .\scripts\opsec_username_gen.py -n 25 --profile vk
```

### Metadata Hygiene
`--show-meta` emits internal generation metadata (scheme, separator, case). Treat this as sensitive output and keep it off unless you are debugging distribution behavior.

### Safe Mode Conflict Behavior
With `--safe-mode`, conflicting options fail closed. Conflicts include persistence flags (`--save`, `--token-save`, `--stream-save-tokens`), de-hardening flags (`--no-token-block`, `--allow-leading-digit`), and non-default anti-fingerprint knobs (`--max-scheme-pct`, `--history`, `--pool-scale`, `--initials-weight`).

## Password Generator: Advanced Use
### Select Output Type by Use Case
Use `--format bip39` for human memorization workflows. Use token formats (`hex`, `base64url`, `base58`) for credentials and key material. Use hash-style formats (`sha256`, `sha512`, `sha3_256`, `sha3_512`, `blake2b`, `blake2s`) when deterministic hash text is needed.

### Entropy Planning

```powershell
# 256-bit URL-safe token
py .\scripts\pwgen.py --format base64url --bits 256

# 512-bit max-entropy preset
py .\scripts\pwgen.py --max-entropy

# 32-byte hex token
py .\scripts\pwgen.py --format hex --bytes 32

# BIP39, 24 words
py .\scripts\pwgen.py --format bip39 --words 24 --bip39-wordlist .\path\to\bip39_english.txt
```

### Grouping Behavior

```powershell
py .\scripts\pwgen.py --format base58check --bits 256 --group 4 --group-sep "-"
py .\scripts\pwgen.py --format hex --bits 136 --group 4 --group-pad "0"
```

Rules: `--bytes > 0` overrides `--bits`; `--bits` must be a multiple of `8`; grouping is not applied to `uuid` or `bip39`; and `--max-entropy` forces 64 bytes with base64url output.

## GUI Notes (Safety-Centric)
`scripts/usnpw_gui.py` uses the same service layer as CLI. The GUI safety model combines hardened safe-mode defaults, strict/session-only controls, copy guard, auto-clear timers, panic clear, encrypted export, and unsafe-path blocking for file-destructive actions.
Team deployments can opt in to hardened GUI defaults by setting `USNPW_TEAM_HARDENED_DEFAULTS=1` (enables strict OPSEC lock, copy guard, and output auto-clear defaults).

## Container Operations Hardening
In API mode, request envelopes are strict and persistence-sensitive fields are policy-locked. Username/path persistence overrides in request payloads are rejected by design, and runtime defaults keep persistence disabled.

Default to a single replica unless you have a formal shared-state strategy. Multi-replica deployments require explicit lock semantics, profile/state affinity, and saturation testing before production.

Use file-backed token secrets (`USNPW_API_TOKEN_FILE`) instead of plaintext environment injection whenever possible, rotate tokens on schedule, and treat access logs as sensitive metadata.

For load-abuse resistance, keep per-client concurrency and request-rate controls enabled. Tune with:
- `USNPW_API_MAX_CONCURRENT_REQUESTS_PER_CLIENT`
- `USNPW_API_REQUEST_RATE_LIMIT`
- `USNPW_API_REQUEST_RATE_WINDOW_SECONDS`
- `USNPW_API_REQUEST_RATE_BLOCK_SECONDS`
- `USNPW_API_MAX_RESPONSE_BYTES`

## API Hardening and Runtime Controls
### Endpoint Contract
- `GET /healthz` for basic health checks.
- `POST /v1/passwords` and `POST /v1/usernames` for generation requests.
- API responses are strict JSON envelopes, including `4xx` and `5xx` failures.

### Authentication and Token Handling
- Bearer token auth is required for generation endpoints.
- Prefer `USNPW_API_TOKEN_FILE` for secret injection.
- `USNPW_API_TOKEN` and CLI token flags are opt-in and disabled by default.
- API tokens must meet a minimum length requirement (`24` characters).
- API tokens must be visible ASCII and may not contain whitespace.
- On POSIX, token files should use owner-only permissions (`chmod 600`).
- Auth-failure throttling keys are composite and route-aware to resist token spray patterns.

### Request Envelope Policy
- Unknown fields are rejected.
- Policy-locked username controls are rejected in API mode.
- BIP39 password fields are rejected in API mode.
- Payloads must be UTF-8 JSON objects with `Content-Type: application/json`.

### Load and Abuse Mitigations
- Global concurrent worker cap: `USNPW_API_MAX_CONCURRENT_REQUESTS`.
- Per-client concurrent cap: `USNPW_API_MAX_CONCURRENT_REQUESTS_PER_CLIENT`.
- Route-scoped request-rate limiting with block windows: `USNPW_API_REQUEST_RATE_LIMIT`, `USNPW_API_REQUEST_RATE_WINDOW_SECONDS`, `USNPW_API_REQUEST_RATE_BLOCK_SECONDS`.
- Rate and concurrency violations return JSON `429` with `Retry-After`.
- Over-capacity worker saturation returns JSON `503`.

### Deployment Notes
- Non-loopback API binds require TLS by default.
- For direct TLS in-process, set both `USNPW_API_TLS_CERT_FILE` and `USNPW_API_TLS_KEY_FILE`.
- `USNPW_API_ALLOW_INSECURE_NO_TLS=true` is an explicit compatibility override and should stay disabled for production.
- Treat access logs as sensitive metadata and keep them disabled unless needed.

## Troubleshooting
### `bits must be a multiple of 8`
Use bit sizes such as `128`, `192`, or `256`, or set `--bytes` directly.

### `No wordlist path set`
BIP39 mode requires `--bip39-wordlist` pointing to a valid local 2048-word list.

### `--min-len cannot be greater than --max-len`
Set a valid inclusive length window (`min <= max`).

### `invalid choice: '<profile>'`
Run `py .\scripts\opsec_username_gen.py --help` and use a supported profile.

### Token-capacity errors
Lower count, rotate token state, or relax constraints.

### Stream-state lock or permission errors
Use a writable explicit `--stream-state` path; remove stale lock files only when no active process owns them; and prefer ephemeral behavior on non-Windows when plaintext persistence is not needed.

## Release and CI

```powershell
py .\tools\release.py preflight
py .\tools\release.py all
py .\tools\release.py all --with-binaries
```

```bash
python3 ./tools/release.py preflight
python3 ./tools/release.py all
python3 ./tools/release.py all --with-binaries
```

CI builds native artifacts for Windows, Linux, and macOS with pinned PyInstaller (`6.16.0`). Local binary commands enforce the same version pin. `tools/security_audit.py` is local-only unless overridden with `--allow-ci`.
