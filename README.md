# USnPw
[![Release Artifacts](https://github.com/csysp/UsnPw/actions/workflows/release-artifacts.yml/badge.svg)](https://github.com/csysp/UsnPw/actions/workflows/release-artifacts.yml)[![Container GHCR](https://github.com/csysp/UsnPw/actions/workflows/container-ghcr.yml/badge.svg)](https://github.com/csysp/UsnPw/actions/workflows/container-ghcr.yml)[![CodeQL](https://github.com/csysp/UsnPw/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/csysp/UsnPw/actions/workflows/github-code-scanning/codeql)

Local-first, stdlib-only tooling for secure password generation and OPSEC-focused username generation.

## Safety Notice
Do not use this project for illegal activity. You are responsible for your own use.

## Platform Support
- Windows (source mode + `UsnPw.exe` release artifact)
- Linux (source mode + `UsnPw` release artifact)
- macOS (source mode + `UsnPw` or `UsnPw.app` release artifact)

## Install and Setup
Use `docs/SETUP.md` for complete platform-specific setup, binary install, checksum verification, and troubleshooting.

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

## What You Get
- `scripts/pwgen.py`: password/token generator
- `scripts/opsec_username_gen.py`: anti-fingerprinting username generator
- `scripts/usnpw_gui.py`: cross-platform GUI using the same service layer as CLI
- `usnpw/core/*`: reusable API layer
- No telemetry, no network calls, no external runtime dependencies

## Quick Usage

```powershell
# Windows
py .\scripts\pwgen.py -n 5 -l 24
py .\scripts\opsec_username_gen.py -n 20 --profile reddit
py .\scripts\usnpw_gui.py
```

```bash
# Linux/macOS
python3 ./scripts/pwgen.py -n 5 -l 24
python3 ./scripts/opsec_username_gen.py -n 20 --profile reddit
python3 ./scripts/usnpw_gui.py
```

## Supported Username Profiles
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

## Documentation
- `docs/SETUP.md`: install and setup for Windows, Linux, and macOS
- `docs/ADVANCED_USAGE.md`: advanced tuning, OPSEC tradeoffs, and troubleshooting
- `docs/ARCHITECTURE.md`: module boundaries and API model
- `docs/DOCKER_CHECKLIST.md`: phased Docker/GHCR implementation plan
- `docs/STREAM_STATE.md`: stream-state persistence behavior and recovery
- `docs/INDEX.md`: docs map
- `CONTRIBUTING.md`: contribution workflow
- `SECURITY.md`: vulnerability reporting policy
- `THREAT_MODEL.md`: security goals, non-goals, and threat model

## Programmatic API
```python
from usnpw.core.models import PasswordRequest, UsernameRequest
from usnpw.core.password_service import generate_passwords
from usnpw.core.username_service import generate_usernames

pw = generate_passwords(PasswordRequest(count=3, length=24))
un = generate_usernames(UsernameRequest(count=20, profile="reddit"))
```

## Container Distribution (GHCR)
Image format:

```text
ghcr.io/<owner>/<image>:<tag>
```

UsnPw image examples:

```text
ghcr.io/csysp/usnpw:sha-<commit>
ghcr.io/csysp/usnpw:v1.0.0
```

Private package pull (if package visibility is private):

```bash
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u <github-username> --password-stdin
docker pull ghcr.io/csysp/usnpw:v1.0.0
```

Private-network runtime summary:
- API listens on `8080` in container.
- Requests to `POST /v1/passwords` and `POST /v1/usernames` require `Authorization: Bearer <USNPW_API_TOKEN>`.
- Prefer `USNPW_API_TOKEN_FILE` secret mount over plaintext `USNPW_API_TOKEN` env.
- `USNPW_API_TOKEN` is blocked by default unless `USNPW_API_ALLOW_ENV_TOKEN=true` is set.
- Keep deployments on internal/private networks and run with `--read-only`, `--tmpfs /tmp`, `--cap-drop ALL`, and `--security-opt no-new-privileges:true`.
- For untrusted networks, terminate TLS in front of the service or provide `USNPW_API_TLS_CERT_FILE` + `USNPW_API_TLS_KEY_FILE`.

## Development and Release
```powershell
# compile + tests
py .\tools\release.py preflight

# source artifact + checksums
py .\tools\release.py all

# source + host-native binaries + checksums
py .\tools\release.py all --with-binaries
```

```bash
# Linux/macOS equivalents
python3 ./tools/release.py preflight
python3 ./tools/release.py all
python3 ./tools/release.py all --with-binaries
```

Notes:
- Build binaries natively on each target OS (no cross-compilation in this workflow).
- PyInstaller is pinned to `6.16.0` for release/CI consistency.

## Repository Layout
- `scripts/pwgen.py`, `scripts/opsec_username_gen.py`, `scripts/usnpw_gui.py`: entrypoints
- `usnpw/core/*`: engines, policies, storage, stream state, service orchestration
- `usnpw/cli/*`: CLI parsing and command dispatch
- `usnpw/gui/*`: GUI app and adapter mapping
- `tests/*`: stdlib unit tests
- `tools/release.py`: preflight/release automation

## License
This project is licensed under GNU GPLv3 (`GPL-3.0-only`). See `LICENSE`.
