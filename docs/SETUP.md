# Setup and Installation

This guide covers source and binary setup for Windows, Linux, and macOS.

## Install Modes
USnPw supports two installation patterns:
1. Source mode: run Python entrypoints directly from the repository.
2. Binary mode: run release artifacts such as `usnpw-<platform>-cli(.exe)` and `usnpw-<platform>-gui(.exe)`.

## Prerequisites
- Python `3.9+` for source mode.
- No runtime Python dependencies beyond stdlib.
- PyInstaller `6.16.0` only if you build binaries locally (`tools/release.py` enforces this pin).
- Optional for BIP39: local 2048-word BIP39 wordlist file.
- Optional for container mode: Docker Engine with BuildKit.

## Container Setup (Phase 2 API Baseline)
This phase provides a hardened non-root container running the stdlib API server for private-network use.

Build:

```bash
docker build -t usnpw:local .
```

Run (token file required):

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/secrets:/run/secrets:ro" \
  -e USNPW_API_TOKEN_FILE=/run/secrets/usnpw_api_token.txt \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  usnpw:local
```

Probe:

```bash
curl http://127.0.0.1:8080/healthz
curl -X POST http://127.0.0.1:8080/v1/passwords \
  -H 'Authorization: Bearer YOUR_TOKEN_VALUE' \
  -H 'Content-Type: application/json' \
  -d '{"count":2,"length":24,"format":"password"}'
```

Operational guidance: prefer `USNPW_API_TOKEN_FILE` over plaintext environment variables; keep `USNPW_API_TOKEN` disabled unless explicitly required; use owner-only token file permissions on POSIX (`chmod 600`); keep tokens visible ASCII without whitespace; run with read-only root and minimal capabilities; and keep deployments on private networks. Non-loopback binds require TLS by default unless you explicitly opt in to insecure mode.

API runtime hardening controls are enabled by default. For load-abuse tuning details, use `docs/ADVANCED_USAGE.md`.

## Source Setup: Windows
From repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py .\tools\release.py preflight
```

Run tools:

```powershell
py .\scripts\usnpw_cli.py -n 5 -l 24
py .\scripts\usnpw_cli.py username -n 20 --profile reddit --safe-mode
py .\scripts\pwgen.py -n 5 -l 24
py .\scripts\opsec_username_gen.py -n 20 --profile reddit
py .\scripts\usnpw_gui.py
```

If PowerShell execution policy blocks activation:

```powershell
.\.venv\Scripts\python.exe .\scripts\usnpw_gui.py
```

## Source Setup: Linux
From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 ./tools/release.py preflight
```

Run tools:

```bash
python3 ./scripts/usnpw_cli.py -n 5 -l 24
python3 ./scripts/usnpw_cli.py username -n 20 --profile reddit --safe-mode
python3 ./scripts/pwgen.py -n 5 -l 24
python3 ./scripts/opsec_username_gen.py -n 20 --profile reddit
python3 ./scripts/usnpw_gui.py
```

## Source Setup: macOS
From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 ./tools/release.py preflight
```

Run tools:

```bash
python3 ./scripts/usnpw_cli.py -n 5 -l 24
python3 ./scripts/usnpw_cli.py username -n 20 --profile reddit --safe-mode
python3 ./scripts/pwgen.py -n 5 -l 24
python3 ./scripts/opsec_username_gen.py -n 20 --profile reddit
python3 ./scripts/usnpw_gui.py
```

Confirm Tkinter before using GUI:

```bash
python3 -m tkinter
```

## Binary Setup: Windows
1. Download Windows release artifacts (`usnpw-windows-cli.exe`, `usnpw-windows-gui.exe`, and sidecars).
2. Verify checksum:

```powershell
Get-FileHash .\usnpw-windows-cli.exe -Algorithm SHA256
Get-Content .\usnpw-windows-cli.exe.sha256
```

3. Install CLI and persist user PATH:

```powershell
py .\tools\release.py install-cli --artifact .\usnpw-windows-cli.exe
```

4. Restart PowerShell and validate:

```powershell
usnpw -n 5 -l 24
usnpw username -n 20 --profile reddit --safe-mode
```

5. Launch GUI with the labeled artifact (`usnpw-windows-gui.exe`).

## Binary Setup: Linux
1. Download Linux artifacts (`usnpw-linux-cli`, `usnpw-linux-gui`) and sidecars.
2. Verify checksum:

```bash
sha256sum -c usnpw-linux-cli.sha256
```

3. Install CLI and persist PATH:

```bash
python3 ./tools/release.py install-cli --artifact ./usnpw-linux-cli
```

4. Restart shell and validate:

```bash
usnpw -n 5 -l 24
usnpw username -n 20 --profile reddit --safe-mode
```

## Binary Setup: macOS
1. Download macOS artifacts (`usnpw-macos-cli`, `usnpw-macos-gui.app.zip`) and sidecars.
2. Verify checksum:

```bash
shasum -a 256 ./usnpw-macos-cli
cat ./usnpw-macos-cli.sha256
```

3. Install CLI and persist PATH:

```bash
python3 ./tools/release.py install-cli --artifact ./usnpw-macos-cli
```

4. Restart shell and validate:

```bash
usnpw -n 5 -l 24
usnpw username -n 20 --profile reddit --safe-mode
```

## Build Binaries Locally
Run on each target OS natively:

```powershell
py .\tools\release.py preflight
py .\tools\release.py binaries
py .\tools\release.py install-cli
```

```bash
python3 ./tools/release.py preflight
python3 ./tools/release.py binaries
python3 ./tools/release.py install-cli
```

Expected output names:
- GUI: `usnpw-<platform>-gui(.exe)`
- Unified CLI: `usnpw-<platform>-cli(.exe)` (install step exposes `usnpw(.exe)`)
- Extra CLI binaries: `usnpw-pwgen(.exe)`, `usnpw-username(.exe)`

`tools/release.py binaries` builds GUI and unified CLI by default.

## First-Run Validation

```powershell
usnpw -n 2 -l 24
usnpw username -n 5 --profile reddit
py .\scripts\pwgen.py -n 2 -l 24
py .\scripts\opsec_username_gen.py -n 5 --profile reddit
```

```bash
usnpw -n 2 -l 24
usnpw username -n 5 --profile reddit
python3 ./scripts/pwgen.py -n 2 -l 24
python3 ./scripts/opsec_username_gen.py -n 5 --profile reddit
```

Expected result: outputs are generated without traceback.

## Common Setup Issues
### `py` not found on Windows
Install Python with launcher support or run Python by full path, then retry.

### `python3` not found on Linux/macOS
Install Python `3.9+` and rerun setup.

### GUI does not launch
Validate Tkinter support with `python3 -m tkinter` and use a Python build that includes Tk.

### `No wordlist path set`
For BIP39 mode, pass `--bip39-wordlist <path-to-2048-word-file>`.

### `PyInstaller version mismatch` during binary build
Local binary commands require `pyinstaller==6.16.0`:

```powershell
py -m pip install pyinstaller==6.16.0
```

```bash
python3 -m pip install pyinstaller==6.16.0
```

### `ModuleNotFoundError: No module named 'usnpw'` when running `usnpw`
Your shell is resolving an older binary from another path entry. On Windows, inspect active resolution:

```powershell
Get-Command usnpw | Select-Object -ExpandProperty Source
```

Then reinstall from current artifacts and restart shell:

```powershell
py .\tools\release.py binaries
py .\tools\release.py install-cli
```
