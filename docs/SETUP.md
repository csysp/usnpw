# Setup

USnPw is a local, offline CLI project with Python stdlib-only runtime dependencies.
Setup varies dependant on the users needs, run via python script for easy iteration or run via command line with a host-native installer binary to add PATH.
CSysP recommends CLI for day to day use as it is what is maintained via updates. 

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

## Native Installer Artifacts
After `py .\tools\release.py binaries`, host-native CLI and installer artifacts are written to `dist\bin`:
- Windows: `usnpw-windows-cli.exe` and `usnpw-windows-installer.exe`
- Linux: `usnpw-linux-cli` and `usnpw-linux-installer`
- macOS: `usnpw-macos-cli` and `usnpw-macos-installer`

Run the installer artifact on target hosts:
```powershell
.\dist\bin\usnpw-windows-installer.exe
# optional: skip persistent PATH update
.\dist\bin\usnpw-windows-installer.exe --no-path-update
```

```bash
./dist/bin/usnpw-linux-installer
# optional: skip persistent PATH update
./dist/bin/usnpw-linux-installer --no-path-update
```

Installer binaries embed the matching host CLI payload and can install without passing `--artifact`.

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
