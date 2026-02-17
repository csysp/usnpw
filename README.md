# USnPw
[![Release Artifacts](https://github.com/csysp/UsnPw/actions/workflows/release-artifacts.yml/badge.svg)](https://github.com/csysp/UsnPw/actions/workflows/release-artifacts.yml)
[![Container GHCR](https://github.com/csysp/UsnPw/actions/workflows/container-ghcr.yml/badge.svg)](https://github.com/csysp/UsnPw/actions/workflows/container-ghcr.yml)
[![CodeQL](https://github.com/csysp/UsnPw/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/csysp/UsnPw/actions/workflows/github-code-scanning/codeql)

USnPw is local-first, stdlib-only tooling for secure password generation and OPSEC-focused username generation.

## Safety Notice
Do not use this project for illegal activity. You are responsible for your own use.

## Platform Support
USnPw supports Windows, Linux, and macOS in source mode and in labeled binary mode.

Common release artifact names:
- `usnpw-windows-cli.exe`, `usnpw-windows-gui.exe`
- `usnpw-linux-cli`, `usnpw-linux-gui`
- `usnpw-macos-cli`, `usnpw-macos-gui`

## Install and Setup
Use `docs/SETUP.md` for full platform-specific setup, binary install, checksum verification, and troubleshooting.

Quick source run:

```powershell
# Windows (PowerShell)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py .\scripts\usnpw_gui.py
```

```bash
# Linux/macOS (bash/zsh)
python3 -m venv .venv
source .venv/bin/activate
python3 ./scripts/usnpw_gui.py
```

## Core Entrypoints
| Path | Purpose |
|---|---|
| `scripts/pwgen.py` | Password and token generator |
| `scripts/opsec_username_gen.py` | Anti-fingerprinting username generator |
| `scripts/usnpw_cli.py` | Unified CLI wrapper (`password` default, `username` subcommand) |
| `scripts/usnpw_gui.py` | Cross-platform GUI using the same service layer as CLI |
| `usnpw/core/*` | Reusable generation and policy services |

No telemetry, no runtime network calls, and no external Python runtime dependencies.

## Quick Usage
```powershell
# Windows
py .\scripts\usnpw_cli.py -n 5 -l 24
py .\scripts\usnpw_cli.py username -n 20 --profile reddit --safe-mode
py .\scripts\pwgen.py -n 5 -l 24
py .\scripts\opsec_username_gen.py -n 20 --profile reddit
py .\scripts\usnpw_gui.py
```

```bash
# Linux/macOS
python3 ./scripts/usnpw_cli.py -n 5 -l 24
python3 ./scripts/usnpw_cli.py username -n 20 --profile reddit --safe-mode
python3 ./scripts/pwgen.py -n 5 -l 24
python3 ./scripts/opsec_username_gen.py -n 20 --profile reddit
python3 ./scripts/usnpw_gui.py
```

## Supported Username Profiles
`generic`, `reddit`, `x`, `github`, `discord`, `facebook`, `linkedin`, `instagram`, `pinterest`, `snapchat`, `telegram`, `tiktok`, `douyin`, `vk`, `youtube`

## Documentation
Use `docs/INDEX.md` for the full document map.

Key guides:
| File | Focus |
|---|---|
| `docs/SETUP.md` | Setup and install (Windows, Linux, macOS) |
| `docs/ADVANCED_USAGE.md` | Operational tuning and OPSEC tradeoffs |
| `docs/ARCHITECTURE.md` | Module boundaries and contracts |
| `docs/DOCKER_CHECKLIST.md` | Docker/GHCR implementation checklist |
| `docs/PERFORMANCE.md` | Baseline performance notes |
| `docs/RELEASE_SIGNING.md` | Artifact and container signing |
| `docs/STREAM_STATE.md` | Stream-state persistence and recovery |
| `CONTRIBUTING.md` | Contribution workflow |
| `SECURITY.md` | Vulnerability reporting policy |
| `THREAT_MODEL.md` | Security goals, non-goals, and assumptions |

## Programmatic API
```python
from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames

pw = generate_passwords(PasswordRequest(count=3, length=24))
un = generate_usernames(UsernameRequest(count=20, profile="reddit"))
```

## Container Distribution (GHCR)
Image reference format:

```text
ghcr.io/<owner>/<image>:<tag>
```

Examples:

```text
ghcr.io/csysp/usnpw:sha-<commit>
ghcr.io/csysp/usnpw:v1.0.0
```

Private pull (if the package is private):

```bash
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u <github-username> --password-stdin
docker pull ghcr.io/csysp/usnpw:v1.0.0
```

Runtime summary:
- The API listens on `8080` in the container.
- `POST /v1/passwords` and `POST /v1/usernames` require `Authorization: Bearer <USNPW_API_TOKEN>`.
- Prefer `USNPW_API_TOKEN_FILE` secret mounts over plaintext `USNPW_API_TOKEN`.
- Keep deployments private; for untrusted links, terminate TLS upstream or provide `USNPW_API_TLS_CERT_FILE` and `USNPW_API_TLS_KEY_FILE`.

## Development and Release
```powershell
# Compile + tests
py .\tools\release.py preflight

# Build default binaries (gui + cli), then install CLI for current user
py .\tools\release.py binaries
py .\tools\release.py install-cli

# Source artifact + checksums
py .\tools\release.py all

# Source + host-native binaries + checksums
py .\tools\release.py all --with-binaries
```

```bash
# Linux/macOS equivalents
python3 ./tools/release.py preflight
python3 ./tools/release.py binaries
python3 ./tools/release.py install-cli
python3 ./tools/release.py all
python3 ./tools/release.py all --with-binaries
```

Build notes:
- Build binaries natively on each target OS (no cross-compilation in this workflow).
- PyInstaller is pinned to `6.16.0`; `tools/release.py` hard-fails on version mismatch.

## Repository Layout
| Path | Role |
|---|---|
| `scripts/*` | Compatibility entrypoints |
| `usnpw/core/*` | Engines, policies, storage, stream state, and services |
| `usnpw/cli/*` | CLI parsing and dispatch |
| `usnpw/gui/*` | GUI app and adapter mapping |
| `tests/*` | Stdlib unit tests |
| `tools/release.py` | Preflight and release automation |

## License
This project is licensed under GNU GPLv3 (`GPL-3.0-only`). See `LICENSE`.
