# Setup

USnPw is a local, offline CLI project with Python stdlib-only runtime dependencies.

## Requirements
- Python 3.13 (recommended)
- `pip` (only needed for optional tooling like PyInstaller)

## Windows (PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install pyinstaller==6.16.0
py .\tools\release.py preflight
py .\tools\release.py binaries
py .\tools\release.py install-cli
usnpw --help
```

## Linux/macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pyinstaller==6.16.0
python3 ./tools/release.py preflight
python3 ./tools/release.py binaries
python3 ./tools/release.py install-cli
usnpw --help
```

## Quick Run
```powershell
# Passwords
usnpw -n 5 -l 24

# Usernames
usnpw username -n 20 --profile reddit
```

## Validation
Use the release preflight gate:
```powershell
py .\tools\release.py preflight
```

This runs compile checks and all unit tests in `tests/`.

## Windows Installer Artifact
After `py .\tools\release.py binaries`, a companion installer script is written to:
`dist\bin\usnpw-windows-cli-installer.ps1`

Run it on target hosts:
```powershell
.\dist\bin\usnpw-windows-cli-installer.ps1
# optional: skip persistent PATH update
.\dist\bin\usnpw-windows-cli-installer.ps1 -NoPathUpdate
```

## Uninstall (Iterative Testing)
```powershell
py .\tools\uninstall_cli.py
# optional: also remove persistent PATH entry
py .\tools\uninstall_cli.py --remove-path
```

```bash
python3 ./tools/uninstall_cli.py
# optional: also remove persistent PATH entry
python3 ./tools/uninstall_cli.py --remove-path
```
