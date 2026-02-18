# USnPw

USnPw combines two high-friction security tasks into one auditable toolchain: generating strong secrets and generating profile-aware usernames that avoid predictable output signatures. It is designed for operators, developers, and security teams who need fast generation at scale without handing sensitive workflows to cloud services.
The project pairs hardened defaults with practical usability: a unified CLI, a thin GUI over the same service layer, and release artifacts you can verify with checksums and signatures. No telemetry, no background network calls, and no dependency bloat.

## Safety Notice
Do not use this project for illegal activity. You are responsible for your own use.

## OPSEC Boundaries
USnPw is built for privacy-hardened credential generation, not anonymity or endpoint compromise defense.

1. If the host is compromised, generated data can be exposed.
2. API mode should remain private-network by default; internet exposure requires layered controls.
3. Clipboard, exports, and persistence paths create recoverable local artifacts.
4. The tool supports minimization and hardening, but legal/compliance responsibility stays with operators.

See `THREAT_MODEL.md` for the full OWASP + ISACA + LINDDUN + OPSEC-aligned threat model and control mapping.

## Install and Setup
Use `docs/SETUP.md` for complete setup instructions across Windows, Linux, and macOS.

Quick source run:

```powershell
# Windows (PowerShell)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py .\tools\release.py preflight
py .\scripts\usnpw_gui.py
```

```bash
# Linux/macOS (bash/zsh)
python3 -m venv .venv
source .venv/bin/activate
python3 ./tools/release.py preflight
python3 ./scripts/usnpw_gui.py
```

## Quick Usage
```powershell
# Windows
usnpw -n 5 -l 24
usnpw username -n 20 --profile reddit --safe-mode
```

```bash
# Linux/macOS
usnpw -n 5 -l 24
usnpw username -n 20 --profile reddit --safe-mode
```

## Supported Username Profiles
`generic`, `reddit`, `x`, `github`, `discord`, `facebook`, `linkedin`, `instagram`, `pinterest`, `snapchat`, `telegram`, `tiktok`, `douyin`, `vk`, `youtube`

## Core Entrypoints
| Path | Purpose |
|---|---|
| `scripts/pwgen.py` | Password and token generator |
| `scripts/opsec_username_gen.py` | Username generator |
| `scripts/usnpw_cli.py` | Unified CLI wrapper |
| `scripts/usnpw_gui.py` | GUI wrapper |
| `usnpw/core/*` | Shared generation services |

## Documentation
Start here:
- `docs/SETUP.md` for installation and first-run setup.
- `docs/ADVANCED_USAGE.md` for API/runtime hardening, load controls, and advanced operational tuning.
- `docs/INDEX.md` for the full documentation map.

## Development
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

Build note: `tools/release.py` enforces `pyinstaller==6.16.0` for local binary builds.

## License
This project is licensed under GNU GPLv3 (`GPL-3.0-only`). See `LICENSE`.
