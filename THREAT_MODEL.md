# Threat Model

Last updated: 2026-02-17

This document defines the threat model for USnPw across CLI (`scripts/usnpw_cli.py`, `scripts/pwgen.py`, `scripts/opsec_username_gen.py`), GUI (`scripts/usnpw_gui.py`), API server (`scripts/usnpw_api.py`, `usnpw/api/*`), and container distribution.

USnPw is designed for local-first and private-network service use. It is not intended to be internet-facing without additional controls.

## Assets
- Generated passwords, tokens, and usernames (terminal, GUI, clipboard).
- Stream-state secret and counter.
- Token and username blacklist files when persistence is enabled.
- API bearer token.
- Exported plaintext or encrypted files.

## Security Goals
- Unpredictable secret generation using OS CSPRNG.
- Username uniqueness-by-construction in stream mode without full historical ledgers.
- Hardened defaults that minimize local artifacts.
- Fail-closed behavior on sensitive I/O and state operations.
- No telemetry, analytics, or background network calls.
- API resilience against basic abuse patterns (slow connections, brute-force auth attempts, unconstrained worker growth).

## Non-Goals
- Defending secrets on a fully compromised host.
- Hostile multi-tenant isolation.
- Internet-facing hardening equivalent to mature web infrastructure.
- Hardware-backed key management (HSM/TPM) or formal side-channel resistance.

## Attacker Models
- A1: Local filesystem attacker.
- A2: Local process attacker with clipboard/screen/memory visibility.
- A3: Network attacker on reachable LAN/VPN segment.
- A4: Malicious or careless operator causing unsafe configuration.
- A5: Supply-chain attacker tampering with source, artifacts, or images.

## Assumptions
- `os.urandom` is secure.
- Host OS and Python runtime are trusted.
- API deployments control network reachability and firewall boundaries.

## Controls and Design Choices
### Password and Token Generation
Entropy is derived from `os.urandom`. Password mode uses unbiased rejection sampling. Token and hash outputs rely on stdlib `hashlib` and stdlib encodings.

### Username Uniqueness Modes
`stream` mode is the default and derives uniqueness from secret state plus counter. On Windows, persistence can use DPAPI protection. On non-Windows systems, plaintext persistence requires explicit opt-in.

`blacklist` mode enforces uniqueness through a persisted username ledger and therefore increases artifact exposure risk.

### Stream State and Locking
Stream state is sensitive because it influences future generation behavior. Writer locking serializes state updates across processes. Operational recovery guidance lives in `docs/STREAM_STATE.md`.

### GUI Safety Layers
USnPw GUI has three independent control layers:

1. Safe mode (`safe_mode`) locks hardened defaults.
2. Strict OPSEC lock (`strict_opsec_lock`) enforces safe-mode-equivalent anti-fingerprint and persistence constraints.
3. Session-only mode (`session_only_mode`) maximizes ephemerality by disabling persistence paths.

Tradeoff: session-only operation weakens cross-run uniqueness guarantees because state is not persisted.

### API Server Posture
Generation endpoints require bearer token auth. File-backed token delivery (`USNPW_API_TOKEN_FILE`) is preferred; environment token injection is disabled by default unless explicitly enabled. The server enforces bounded concurrency, socket timeouts, and auth throttling.

For transport security, prefer TLS termination at a trusted reverse proxy on private networks. In-process TLS is available when needed.

### Container Runtime Posture
Recommended runtime profile uses read-only filesystem, tmpfs scratch space, dropped Linux capabilities, and `no-new-privileges`. Mount only required token/state paths and isolate by tenant/profile.

### Supply Chain Controls
Release artifacts include SHA-256 sidecars. CI supports GPG signatures for checksums and cosign keyless signatures for container images.

## Residual Risks
- Clipboard usage can leak to local processes and OS history.
- Exporting outputs creates durable artifacts.
- Persisted token and username ledgers can leak operational patterns.
- Stream-state reset or rotation affects cross-run uniqueness guarantees.
- Exposing API endpoints to untrusted networks without layered controls increases attack surface.
