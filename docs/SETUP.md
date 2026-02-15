# Setup and Installation

This guide covers install and setup for Windows, Linux, and macOS in both source mode and binary mode.

## Install Modes
1. Source mode: run the Python entrypoints directly.
2. Binary mode: run release artifacts (`UsnPw.exe` on Windows, `UsnPw` on Linux/macOS).

## Prerequisites
- Python `3.9+` for source mode.
- No external Python dependencies for runtime (stdlib-only project).
- Optional for local binary builds: PyInstaller `6.16.0`.
- Optional for BIP39 mode: local 2048-word BIP39 wordlist file.
- Optional for container mode: Docker Engine with BuildKit enabled.

## Container Setup (Phase 2 API Baseline)

This phase provides a hardened non-root container running the stdlib API adapter for private-network use.

Build image:

```bash
docker build -t usnpw:local .
```

Run API server (requires token):

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

Probe health and make authenticated requests:

```bash
curl http://127.0.0.1:8080/healthz
curl -X POST http://127.0.0.1:8080/v1/passwords \
  -H 'Authorization: Bearer YOUR_TOKEN_VALUE' \
  -H 'Content-Type: application/json' \
  -d '{"count":2,"length":24,"format":"password"}'
```

Hardening recommendations:
- Use `USNPW_API_TOKEN_FILE` secret mount instead of plaintext env where possible.
- `USNPW_API_TOKEN` is disabled by default; only enable it intentionally via `USNPW_API_ALLOW_ENV_TOKEN=true`.
- Run with `--read-only`, `--tmpfs /tmp`, `--cap-drop ALL`, and `--security-opt no-new-privileges:true`.
- Set `USNPW_API_MAX_CONCURRENT_REQUESTS`, `USNPW_API_SOCKET_TIMEOUT_SECONDS`, and auth-throttle envs for your expected load profile.
- If clients traverse untrusted links, terminate TLS in a reverse proxy, or mount cert/key and set `USNPW_API_TLS_CERT_FILE` + `USNPW_API_TLS_KEY_FILE`.
- Avoid host mounts unless you explicitly need local persistence for stream/token state.
- Keep container on private networks only during team rollout.

## Source Setup: Windows

```powershell
# from repo root
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py .\tools\release.py preflight
```

Run tools:

```powershell
py .\scripts\pwgen.py -n 5 -l 24
py .\scripts\opsec_username_gen.py -n 20 --profile reddit
py .\scripts\usnpw_gui.py
```

If PowerShell execution policy blocks activation, run without activation:

```powershell
.\.venv\Scripts\python.exe .\scripts\usnpw_gui.py
```

## Source Setup: Linux

```bash
# from repo root
python3 -m venv .venv
source .venv/bin/activate
python3 ./tools/release.py preflight
```

Run tools:

```bash
python3 ./scripts/pwgen.py -n 5 -l 24
python3 ./scripts/opsec_username_gen.py -n 20 --profile reddit
python3 ./scripts/usnpw_gui.py
```

## Source Setup: macOS

```bash
# from repo root
python3 -m venv .venv
source .venv/bin/activate
python3 ./tools/release.py preflight
```

Run tools:

```bash
python3 ./scripts/pwgen.py -n 5 -l 24
python3 ./scripts/opsec_username_gen.py -n 20 --profile reddit
python3 ./scripts/usnpw_gui.py
```

Tkinter check (GUI prerequisite):

```bash
python3 -m tkinter
```

If that command fails, use a Python build with Tk support before running `scripts/usnpw_gui.py`.

## Binary Setup: Windows

1. Download release artifacts for Windows.
2. Keep `UsnPw.exe` and its sidecar checksum file `UsnPw.exe.sha256` together.
3. Verify checksum:

```powershell
Get-FileHash .\UsnPw.exe -Algorithm SHA256
Get-Content .\UsnPw.exe.sha256
```

4. Run:

```powershell
.\UsnPw.exe
```

## Binary Setup: Linux

1. Download Linux release artifacts.
2. Keep `UsnPw` and `UsnPw.sha256` together.
3. Verify checksum:

```bash
sha256sum -c UsnPw.sha256
```

4. Make executable and run:

```bash
chmod +x ./UsnPw
./UsnPw
```

## Binary Setup: macOS

1. Download macOS release artifacts (`UsnPw` or `UsnPw.app`) and checksum sidecar.
2. Verify checksum:

```bash
shasum -a 256 ./UsnPw
cat ./UsnPw.sha256
```

3. Run:

```bash
chmod +x ./UsnPw
./UsnPw
```

If using `UsnPw.app`, launch it from Finder or:

```bash
open ./UsnPw.app
```

## Build Binaries Locally

Run on each target OS natively:

```powershell
py .\tools\release.py preflight
py .\tools\release.py binaries
```

```bash
python3 ./tools/release.py preflight
python3 ./tools/release.py binaries
```

Expected output names:
- Windows: `UsnPw.exe`
- Linux: `UsnPw`
- macOS: `UsnPw` or `UsnPw.app` (host behavior)

## First-Run Validation

```powershell
py .\scripts\pwgen.py -n 2 -l 24
py .\scripts\opsec_username_gen.py -n 5 --profile reddit
```

```bash
python3 ./scripts/pwgen.py -n 2 -l 24
python3 ./scripts/opsec_username_gen.py -n 5 --profile reddit
```

You should see output lines and no traceback.

## Common Setup Issues

### `py` not found on Windows
Use full Python launcher path or install Python with launcher support, then rerun.

### `python3` not found on Linux/macOS
Install Python `3.9+` and retry.

### GUI does not launch
Verify Tkinter support:

```bash
python3 -m tkinter
```

### `No wordlist path set`
For BIP39 mode, pass `--bip39-wordlist <path-to-2048-word-file>`.
