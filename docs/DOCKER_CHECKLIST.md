# Docker/GHCR Implementation Checklist

Branch scope: `docker` branch only until stable.

Design goal: least-invasive containerization for private-network team use, with no changes to `usnpw/core/*` generation behavior.

## Phase 0: Planning and Guardrails

### `docs/DOCKER_CHECKLIST.md`
- [x] Define phased plan and file-by-file changes.
- [x] Keep security defaults explicit (fail closed, no telemetry, no hidden persistence).

### `docs/ARCHITECTURE.md`
- [x] Add `usnpw/api/*` boundary notes (thin adapter over service layer).
- [x] State that container/API adapters must not duplicate generation logic.

## Phase 1: Runtime Container Baseline (No Publish Yet)

### `.dockerignore`
- [x] Exclude `.git`, `dist/`, `__pycache__/`, local state/temp files, venvs.
- [x] Keep runtime surface small and deterministic.

### `Dockerfile`
- [x] Multi-stage build:
  - Stage A: run `python tools/release.py preflight`.
  - Stage B: minimal runtime image only.
- [x] Run as non-root user.
- [x] Set safe runtime env defaults (`PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`).
- [x] Add OCI label placeholders:
  - `org.opencontainers.image.source`
  - `org.opencontainers.image.description`
- [x] Keep final image stdlib-only (no new Python deps).

### `docs/SETUP.md`
- [x] Add local Docker build/run quickstart.
- [x] Add hardened runtime flags (`read_only`, `tmpfs`, dropped caps).

## Phase 2: API Adapter for Team Serving (Stdlib Only)

### `usnpw/api/__init__.py`
- [x] Public API module exports only.

### `usnpw/api/adapters.py`
- [x] Parse/validate JSON payloads to `PasswordRequest` / `UsernameRequest`.
- [x] Reject unknown fields and invalid types with explicit errors.
- [x] Enforce request ceilings (`count`, length window, payload size).
- [x] Apply hardened defaults for username generation in API mode.

### `usnpw/api/server.py`
- [x] Implement `ThreadingHTTPServer` + `BaseHTTPRequestHandler`.
- [x] Endpoints:
  - [x] `GET /healthz`
  - [x] `POST /v1/passwords`
  - [x] `POST /v1/usernames`
- [x] Require bearer token auth via env (`USNPW_API_TOKEN`) by default.
- [x] Return JSON-only responses; never return stack traces to clients.
- [x] Do not log generated secrets/usernames.

### `scripts/usnpw_api.py`
- [x] Thin bootstrap wrapper (same style as existing `scripts/*.py` wrappers).

### `tests/test_api_adapters.py`
- [x] Validate payload mapping, unknown-field rejection, bounds checks.

### `tests/test_api_server.py`
- [x] Validate auth required path.
- [x] Validate happy path for both generation endpoints.
- [x] Validate invalid JSON / oversize body fail-closed behavior.

## Phase 3: GHCR Workflow (Build, Then Publish)

### `.github/workflows/container-ghcr.yml`
- [x] Build-only job on PR/push (no publish).
- [x] Publish job on tag/manual trigger:
  - [x] `permissions: contents: read`
  - [x] `permissions: packages: write`
  - [x] Login with `docker/login-action` to `ghcr.io` using `${{ github.actor }}` + `${{ secrets.GITHUB_TOKEN }}`
  - [x] Build/push with `docker/build-push-action`
  - [x] Tag strategy: `sha-*`, branch tag, semver tag.
- [x] Attach OCI source label so package links to repo cleanly.

### `README.md`
- [x] Add GHCR image reference format:
  - `ghcr.io/<owner>/<image>:<tag>`
- [x] Add private network deployment summary and auth expectations.

## Phase 4: Private-Network Ops Hardening

### `docker-compose.private.yml` (optional but recommended)
- [ ] Internal-network deployment example.
- [ ] Read-only root fs.
- [ ] `tmpfs` mounts for writable paths.
- [ ] `security_opt: no-new-privileges:true`
- [ ] Drop all capabilities unless explicitly required.
- [ ] Bind service to private interface only.

### `docs/ADVANCED_USAGE.md`
- [ ] Add operational guidance:
  - [ ] token/blacklist/state volume behavior under concurrency
  - [ ] single-replica default unless shared-state strategy is explicit
  - [ ] auth token rotation and log hygiene

## Phase 5: Merge Readiness (`docker` -> `main`)

### Validation gates
- [x] `py tools/release.py preflight` passes.
- [ ] Container build job green.
- [x] API unit tests green.
- [ ] GHCR publish tested on tag/manual trigger.
- [ ] Basic private-network smoke test completed.

### Git workflow
- [x] Keep Docker work isolated on `docker`.
- [ ] Rebase `docker` onto `main` before merge.
- [ ] Squash or structured commits with clear scope.

## Notes
- GHCR reference docs:
  - https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry
  - https://docs.github.com/en/actions/use-cases-and-examples/publishing-packages/publishing-docker-images
