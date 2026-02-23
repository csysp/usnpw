# USnPw

USnPw is a local, offline CLI for private credential generation.
It supports:
- strong password/secret generation
- profile-aware username generation

Current scope is intentionally small: single-user CLI only, stdlib-only, no API server, no GUI, no telemetry, no background network services.

## Safety Notice
Do not use this project for illegal activity. You are responsible for your own use.

## Quick Start
```powershell
# Windows (PowerShell)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install pyinstaller==6.16.0
py .\tools\release.py preflight
py .\tools\release.py binaries
py .\tools\release.py install-cli
usnpw --help
```

```bash
# Linux/macOS (bash/zsh)
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pyinstaller==6.16.0
python3 ./tools/release.py preflight
python3 ./tools/release.py binaries
python3 ./tools/release.py install-cli
usnpw --help
```

## Usage
```powershell
# Passwords
usnpw -n 5 -l 24

# Usernames (hardened defaults)
usnpw username -n 20 --profile reddit

# Higher throughput (allows token reuse)
usnpw username -n 200 --profile reddit --allow-token-reuse
```

## Supported Username Profiles
`generic`, `reddit`, `x`, `github`, `discord`, `facebook`, `linkedin`, `instagram`, `pinterest`, `snapchat`, `telegram`, `tiktok`, `douyin`, `vk`, `youtube`

## Core Entrypoints
| Path | Purpose |
|---|---|
| `usnpw` | Installed CLI command |
| `usnpw/cli/usnpw_cli.py` | Unified CLI router |
| `usnpw/core/*` | Shared generation services |

## Development
```powershell
py -m pip install pyinstaller==6.16.0
py .\tools\release.py preflight
py .\tools\release.py binaries
py .\tools\release.py install-cli
```

```bash
python3 -m pip install pyinstaller==6.16.0
python3 ./tools/release.py preflight
python3 ./tools/release.py binaries
python3 ./tools/release.py install-cli
```

Build note: `tools/release.py` enforces `pyinstaller==6.16.0` for local binary builds.
Windows binary builds also emit a companion installer script in `dist/bin/`:
`usnpw-windows-cli-installer.ps1`

Iterative uninstall helper:
- Windows: `py .\tools\uninstall_cli.py`
- Linux/macOS: `python3 ./tools/uninstall_cli.py`

## License
This project is licensed under GNU GPLv3 (`GPL-3.0-only`). See `LICENSE`.
