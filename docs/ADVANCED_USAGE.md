# USnPw Advanced Usage

This guide focuses on advanced operational use of:
- `scripts/pwgen.py`
- `scripts/opsec_username_gen.py`
- `scripts/usnpw_gui.py`

For install/setup, use `docs/SETUP.md`.

## Command Conventions
- Windows examples use `py .\scripts\...`
- Linux/macOS equivalents use `python3 ./scripts/...`

## Username Generation: Operating Strategy

### 1. Choose Uniqueness Mode Intentionally
1. `stream` mode (default): no username ledger required, uniqueness from stream state.
2. `blacklist` mode: uniqueness from a persisted username ledger file.

Use `stream` for privacy-first workflows unless a persistent ledger is explicitly required.

### 2. Understand Stream-State Behavior by OS
1. Windows:
Stream-state secret can be persisted with DPAPI protection.
2. Non-Windows:
If plaintext state is not explicitly allowed, stream state stays in-memory for the run.
3. Explicit ephemeral run on any OS:
Use `--no-stream-state-persist`.
4. Non-Windows explicit state persistence:
Use `--allow-plaintext-stream-state` and set `--stream-state <path>`.

### 3. Keep Persona Files Isolated
Use separate files per persona for token/state/blacklist artifacts.

```powershell
py .\scripts\opsec_username_gen.py -n 150 --profile reddit `
  --token-blacklist "$env:USERPROFILE\.u_tokens_reddit_personaA.txt" `
  --stream-state "$env:USERPROFILE\.u_stream_reddit_personaA.json"
```

If strict ephemerality is required:

```powershell
py .\scripts\opsec_username_gen.py -n 150 --profile reddit `
  --no-stream-state-persist --no-token-block --no-token-save --no-save
```

### 4. High-Volume Baseline (Anti-Fingerprinting)

```powershell
py .\scripts\opsec_username_gen.py -n 200 --profile reddit `
  --min-len 10 --max-len 18 `
  --max-scheme-pct 0.28 --history 10 --pool-scale 4 `
  --initials-weight 0 --no-leading-digit `
  --token-blacklist "$env:USERPROFILE\.u_tokens_reddit.txt"
```

To avoid strict generation-order consumption:

```powershell
py .\scripts\opsec_username_gen.py -n 200 --profile reddit | Sort-Object {Get-Random}
```

### 5. Tune Diversity Knobs
1. `--max-scheme-pct`:
Lower values reduce dominant scheme repetition, but too low increases saturation risk.
2. `--history`:
Higher values reduce near-term style repeats.
3. `--pool-scale`:
Higher values increase run-local vocabulary spread.
4. `--initials-weight`:
Set to `0` for stricter anti-signature posture.
5. `--no-leading-digit`:
Removes leading-digit pattern class.

Suggested ranges:
1. `--max-scheme-pct`: `0.22` to `0.35`
2. `--history`: `8` to `14`
3. `--pool-scale`: `3` to `6`
4. `--initials-weight`: `0` for strict posture

### 6. Handle Token Saturation
When token blocking is enabled, capacity is finite. You can hit:
- theoretical capacity errors
- saturation before target count

Recovery options:
1. Lower `-n`.
2. Rotate/clear token blacklist.
3. Increase `--max-scheme-pct` modestly.
4. Use `--no-token-block` for non-strict runs.

Cleanup example:

```powershell
Remove-Item "$env:USERPROFILE\.u_tokens_reddit.txt" -Force -ErrorAction SilentlyContinue
```

### 7. Persistence Tradeoffs
Username ledger controls:
- `--no-save` (default)
- `--save` (explicit persistence)

Token controls:
- `--no-token-save` (default)
- `--token-save`
- `--stream-save-tokens` (stream mode only)

Persist only when required by your operational model.

### 8. Content Constraints
Use constraints to enforce your own naming boundaries:

```powershell
py .\scripts\opsec_username_gen.py -n 100 --profile generic `
  --disallow-prefix admin --disallow-prefix mod `
  --disallow-substring test --disallow-substring bot
```

### 9. Profile-Aware Generation
`--profile` applies canonicalization and length policy for each target platform.

Examples:

```powershell
py .\scripts\opsec_username_gen.py -n 25 --profile x
py .\scripts\opsec_username_gen.py -n 25 --profile github
py .\scripts\opsec_username_gen.py -n 25 --profile telegram
py .\scripts\opsec_username_gen.py -n 25 --profile vk
```

### 10. Metadata Hygiene
`--show-meta` emits scheme/separator/case diagnostics.
Treat this as sensitive output.

## Password Generator: Advanced Use

### 1. Select Output Type by Use Case
1. Human memorization:
`--format bip39`
2. Key material and tokens:
`--format hex`, `--format base64url`, `--format base58`
3. Hash-token style output:
`--format sha256`, `sha512`, `sha3_256`, `sha3_512`, `blake2b`, `blake2s`

### 2. Entropy Planning

```powershell
# 256-bit URL-safe token
py .\scripts\pwgen.py --format base64url --bits 256

# 512-bit max-entropy preset (post-quantum margin)
py .\scripts\pwgen.py --max-entropy

# 32-byte hex token
py .\scripts\pwgen.py --format hex --bytes 32

# BIP39, 24 words
py .\scripts\pwgen.py --format bip39 --words 24 --bip39-wordlist .\path\to\bip39_english.txt
```

### 3. Grouping Rules

```powershell
py .\scripts\pwgen.py --format base58check --bits 256 --group 4 --group-sep "-"
py .\scripts\pwgen.py --format hex --bits 136 --group 4 --group-pad "0"
```

Behavior:
1. `--bytes > 0` overrides `--bits`.
2. `--bits` must be a multiple of `8`.
3. Grouping is not applied to `uuid` and `bip39`.
4. `--max-entropy` forces 64 bytes (`512` bits) and base64url output.

## GUI Notes (Safety-Centric)
`scripts/usnpw_gui.py` uses the same service layer as CLI.

Safety controls include:
1. Safe mode lock for hardened username settings.
2. Strict lock/session-only controls.
3. Copy guard and clipboard auto-clear timer.
4. Output auto-clear timer and panic clear.
5. Optional encrypted export on Windows.
6. Unsafe path blocking and maintenance helpers.

## Troubleshooting

### `bits must be a multiple of 8`
Cause: invalid `--bits` for token/hash outputs.
Fix: use values like `128`, `192`, `256` or set `--bytes`.

### `No wordlist path set`
Cause: BIP39 mode without `--bip39-wordlist`.
Fix: provide path to a valid local 2048-word BIP39 list.

### `--min-len cannot be greater than --max-len`
Cause: invalid username length window.
Fix: ensure `min <= max`.

### `invalid choice: '<profile>'`
Cause: unsupported profile value.
Fix: run `py .\scripts\opsec_username_gen.py --help` and choose a listed profile.

### Token-capacity errors
Cause: token blocking cannot satisfy requested count.
Fix: lower count, rotate token blacklist, or relax constraints.

### Stream-state lock or permission errors
Fix:
1. Use a writable explicit `--stream-state` path.
2. Remove stale lock only if no active process is using it.
3. On non-Windows, prefer in-memory run behavior when plaintext state is not needed.

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

Phase 4 CI builds native artifacts for Windows, Linux, and macOS with pinned PyInstaller (`6.16.0`).
