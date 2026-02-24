# usnpw

[![CI Matrix](https://github.com/csysp/usnpw/actions/workflows/ci-matrix.yml/badge.svg)](https://github.com/csysp/usnpw/actions/workflows/ci-matrix.yml)

usnpw is a local only CLI for private credential generation.
Designed around proven OS CSPRNG for strong password/secret generation and it also includes a profile-aware, anti-fingerprint username generator. 
Hardened by default it is single-user CLI only, stdlib-only, no API server, no GUI, no telemetry, no background network services.
FOSS and easily extensible this tool can greatly increase time saved in iterative testing situations, as well as general use on the internet.

Why use usnpw? It's just easier and safer.

## Usage Examples (Once Installed)
```powershell
# Passwords
usnpw -n 5 -l 24

# Passwords with estimated entropy metadata
usnpw -n 5 -l 24 --show-meta

# Usernames (hardened defaults)
usnpw username -n 20 --profile reddit

# Higher throughput (allows token reuse)
usnpw username -n 200 --profile reddit --allow-token-reuse
*
# Check advanced use for detailed runbook
```

## Supported Username Profiles (Create git issue to request new profiles)
`generic`, `reddit`, `x`, `github`, `discord`, `facebook`, `linkedin`, `instagram`, `pinterest`, `snapchat`, `telegram`, `tiktok`, `douyin`, `vk`, `youtube`

## Quick Start (Python SC only)
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
Default binary builds emit both:
- `usnpw-<platform>-cli` (`.exe` on Windows)
- `usnpw-<platform>-installer` (`.exe` on Windows)

Run `python tools/release.py bundle` to package distributable assets into `dist/release`:
- Windows: `usnpw-<platform>-*.exe`
- Linux/macOS: `usnpw-<platform>-*.tar.gz` (preserves executable mode when extracted)

Installer binary usage (host-native):
- Windows: `.\dist\bin\usnpw-windows-installer.exe`
- Linux: `./dist/bin/usnpw-linux-installer`
- macOS: `./dist/bin/usnpw-macos-installer`
- Optional: pass `--no-path-update` to skip persistent PATH updates.
- Installer binaries embed the matching host CLI payload and can install without a separate `--artifact`.

Published Linux/macOS release assets:
- Extract first: `tar -xzf usnpw-<platform>-installer.tar.gz`
- Run installer: `./usnpw-<platform>-installer`

Iterative uninstall helper:
- Windows: `py .\tools\uninstall_cli.py`
- Linux/macOS: `python3 ./tools/uninstall_cli.py`

RNG health probe:
- `py .\tools\rng_health_probe.py`

## License
This project is licensed under GNU GPLv3 (`GPL-3.0-only`). See `LICENSE`.
