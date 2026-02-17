# Threat Model

Last updated: 2026-02-17

This document defines the threat model for USnPw across CLI (`scripts/usnpw_cli.py`, `scripts/pwgen.py`, `scripts/opsec_username_gen.py`), GUI (`scripts/usnpw_gui.py`), API server (`scripts/usnpw_api.py`, `usnpw/api/*`), and container distribution.

USnPw is designed for local-first and private-network service use. It is not intended to be internet-facing without additional controls.

## Method Basis (LINDDUN-Informed)
This model follows the LINDDUN privacy framing and lifecycle:

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good job?

LINDDUN categories considered in scope: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness/Unintervenability, and Non-compliance.
Reference baseline: https://linddun.org/

## Assets
- Generated passwords, tokens, and usernames (terminal, GUI, clipboard).
- Stream-state secret and counter.
- Token and username blacklist files when persistence is enabled.
- API bearer token.
- Exported plaintext or encrypted files.

## OPSEC Boundaries of Use
These boundaries are explicit and non-ambiguous:

1. Host trust boundary: USnPw does not protect secrets on a compromised host. If local malware, keyloggers, memory scrapers, or hostile admin access exist, generated data can be exposed.
2. Network boundary: API mode is not intended to be internet-facing by default. Private-network deployment, TLS, auth, and external perimeter controls are required when exposing endpoints beyond localhost.
3. Artifact boundary: clipboard use, exports, and persistence paths create local artifacts. Recovery risk remains even with hardened defaults unless operators keep runs ephemeral.
4. Isolation boundary: USnPw is not a multi-tenant isolation platform and is not a substitute for sandboxing or VM/container hard isolation between trust zones.
5. Compliance boundary: USnPw can support minimization and retention discipline, but legal and regulatory compliance remains an organizational duty outside this tool.
6. Identity boundary: USnPw reduces predictable generation signatures; it does not provide anonymity, deniability, or attribution resistance against endpoint/traffic correlation.

## Security and Privacy Goals
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

## LINDDUN Category Mapping
| Category | USnPw exposure pattern | Primary controls |
|---|---|---|
| Linkability | Reused generation patterns, shared token ledgers, cross-profile state reuse | Stream mode defaults, anti-fingerprint controls, per-profile state paths, no-save/no-token-save defaults |
| Identifiability | Metadata or naming conventions revealing operator/user context | `show_meta` off by default, bounded status output, explicit profile controls |
| Non-repudiation | Durable local artifacts tie actions to an operator account/host | Ephemeral modes, panic clear, minimal persistence, strict export warnings |
| Detectability | Existence of state/token files or reachable API reveals use activity | Optional persistence, bounded file paths, private file permissions, private-network deployment guidance |
| Disclosure of information | Clipboard leakage, plaintext exports, mis-scoped file permissions, token exposure | Copy guard, auto-clear timers, encrypted exports (Windows), strict optional Windows ACL hardening, token-file preference |
| Unawareness / Unintervenability | Operator misunderstands persistence or hardening side effects | Safe mode, strict OPSEC lock, session-only mode, explicit warnings and fail-closed validation |
| Non-compliance | Excessive retention, weak deployment hygiene, insecure token handling | Data-minimizing defaults, explicit retention tradeoffs, signed artifacts, documented runtime hardening baselines |

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

For destructive flows, the GUI applies fast-but-bounded controls: non-canonical and unusual targets are blocked, and unsafe-path checks apply to maintenance deletes and panic-clear cleanup targets.

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
