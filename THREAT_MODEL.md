# Threat Model

Last updated: 2026-02-15

This document describes the threat model for USnPw across:
- CLI (`scripts/pwgen.py`, `scripts/opsec_username_gen.py`)
- GUI (`scripts/usnpw_gui.py`)
- API server (`scripts/usnpw_api.py`, `usnpw/api/*`)
- Container distribution (GHCR image)

USnPw is designed for **local-first** usage and **private-network** service use. It is not intended to be exposed to the public internet without additional controls.

## Assets
- Generated passwords/tokens and usernames (terminal output, GUI output, clipboard).
- Stream-state secret + counter (stream uniqueness mode).
- Token blacklist and username blacklist files (if persistence is enabled).
- API bearer token (CLI flag, token file, or environment variable if explicitly allowed).
- Exported plaintext/encrypted files (if the user chooses to export).

## Security Goals
- Unpredictable password/token generation using OS CSPRNG.
- Username uniqueness-by-construction in stream mode without maintaining full historical ledgers.
- Hardened defaults that minimize local artifacts (no-save, no-token-save, no plaintext stream-state on non-Windows).
- Fail closed on security-sensitive I/O and state operations (no silent fallback that weakens posture).
- No telemetry, analytics, or background network calls.
- API mode should be resilient to basic abuse (slowloris-style connections, unbounded thread growth, auth brute force).

## Non-Goals
- Protecting secrets on a compromised host. If an attacker can read your process memory, screen, clipboard, or home directory, they can likely recover outputs and local state.
- Multi-tenant isolation. The API server is not a shared hostile-tenant service.
- Internet-facing service hardening at the level of mature web servers (e.g., full rate limiting, WAF features, account management).
- Hardware-backed key management (HSM/TPM) and formal side-channel resistance.

## Attacker Models
- A1: Local file-system attacker (can read user files after device loss, backup leak, or low-privilege compromise).
- A2: Local process attacker (can observe clipboard, window contents, or process memory).
- A3: Network attacker on the same LAN/VPN segment (can connect to the API port and attempt abuse).
- A4: Malicious or careless operator (misconfiguration leading to persistence or exposure).
- A5: Supply-chain attacker (tampering with source, binaries, or container images).

## Assumptions
- The OS-provided RNG (`os.urandom`) is secure.
- The host OS and Python interpreter are trusted at runtime.
- For API usage, you control the network segment (private LAN/VPN), firewalling, and who can reach the service.

## Controls And Design Choices

### Password/Token Generation
- Entropy is derived from `os.urandom()`.
- Password mode uses unbiased rejection sampling to avoid modulo bias.
- Hash/token formats use stdlib `hashlib` and stdlib encodings only.

### Username Generation: Uniqueness Modes
- `stream` mode (default):
  - Uniqueness comes from secret state + counter (uniqueness-by-construction).
  - On Windows, stream state can be persisted with DPAPI protection.
  - On non-Windows, persistent stream state requires an explicit opt-in to plaintext state.
- `blacklist` mode:
  - Uniqueness is enforced by a persisted ledger.
  - This increases local artifact risk and should be used only when required.

### Stream State Storage And Recovery
- Stream state is a sensitive artifact because it can influence future generation behavior.
- Stream state is protected with DPAPI on Windows; non-Windows plaintext persistence is blocked by default.
- Locking is used to serialize writers across processes and avoid duplicate admissions.
- See `docs/STREAM_STATE.md` for operational guidance and recovery steps.

### GUI Safety Toggles (Rationale)
USnPw GUI provides three safety layers:

1. Safe mode (`safe_mode`)
  - Locks hardened defaults in the service layer: stream uniqueness, no-save, no-token-save, no plaintext stream-state, no metadata output.
  - Threat rationale: reduces local artifact creation and reduces metadata/fingerprint leakage.

2. Strict OPSEC lock (`strict_opsec_lock`)
  - Forces: stream uniqueness, no-save, no-token-save, no-leading-digit, show-meta off, plaintext stream-state off.
  - Threat rationale: prevents common persistence and signature patterns even if the user toggles UI fields.

3. Session-only mode (`session_only_mode`)
  - Forces: stream uniqueness, no-save, no-token-save, no-token-block, no token streaming persistence, no stream-state persistence, explicit empty stream-state path, plaintext stream-state off.
  - Threat rationale: maximizes ephemerality by avoiding disk artifacts entirely.
  - Tradeoff: uniqueness across runs is not guaranteed without persisted state.

### API Server (Private-Network Service Use)
- Auth: bearer token required for generation endpoints.
- Token handling:
  - Prefer `USNPW_API_TOKEN_FILE` (secret mount) over environment variables.
  - Environment token injection is blocked by default unless explicitly enabled.
- Abuse resistance:
  - Concurrency is bounded (caps worker threads).
  - Accepted socket timeouts mitigate slow connections.
  - Auth failures are throttled to slow brute forcing.
- Transport security:
  - Recommended: terminate TLS at a trusted reverse proxy on private networks.
  - Optional: in-process TLS for untrusted internal segments.

### Container Runtime Posture
- The image is designed to run read-only and without Linux capabilities.
- Recommended runtime flags:
  - `--read-only`
  - `--tmpfs /tmp`
  - `--cap-drop ALL`
  - `--security-opt no-new-privileges:true`
- Only mount volumes for the minimum required artifacts (token/state/blacklist) and keep them per-tenant.

### Supply Chain
- Release artifacts include SHA-256 checksums.
- Consider signing checksums and container images if distributing to teams that need provenance guarantees (see CI workflows and `SECURITY.md`).

## Residual Risks (What Can Still Go Wrong)
- Any clipboard usage can leak secrets to other local processes (or OS clipboard history).
- Exporting generated output creates durable artifacts; encrypted export is Windows-only in stdlib mode.
- Persisted token/username ledgers can leak operational patterns if exfiltrated.
- Stream state reset/rotation changes uniqueness guarantees across runs.
- Exposing the API port to untrusted networks without a reverse proxy and network ACLs increases risk.

