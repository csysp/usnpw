# Docker and GHCR Checklist

Branch scope: `docker` branch until stabilization.  
Design goal: least-invasive containerization for private-network team use, with no behavior changes to `usnpw/core/*`.

## Phase 0: Planning and Guardrails
- [x] Define phased plan and file-level scope in `docs/DOCKER_CHECKLIST.md`.
- [x] Keep security defaults explicit: fail closed, no telemetry, no hidden persistence.
- [x] Document `usnpw/api/*` boundaries in `docs/ARCHITECTURE.md`.

## Phase 1: Runtime Container Baseline
- [x] `.dockerignore` excludes `.git`, `dist/`, `__pycache__/`, local temp/state files, and virtual environments.
- [x] `Dockerfile` uses multi-stage build (`preflight` then minimal runtime image).
- [x] Runtime executes as non-root.
- [x] Safe runtime defaults are set (`PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`).
- [x] OCI labels include source and description metadata.
- [x] Runtime image remains stdlib-only.
- [x] `docs/SETUP.md` includes local build/run quickstart and hardened runtime flags.

## Phase 2: API Adapter (stdlib only)
- [x] `usnpw/api/__init__.py` exposes public API symbols only.
- [x] `usnpw/api/adapters.py` validates JSON payloads, rejects unknown fields, and enforces ceilings.
- [x] API defaults apply hardened username posture.
- [x] `usnpw/api/server.py` serves `GET /healthz`, `POST /v1/passwords`, and `POST /v1/usernames`.
- [x] Bearer token auth required for generation endpoints.
- [x] Responses are JSON-only; stack traces are not returned to clients.
- [x] Server avoids logging generated secrets and usernames.
- [x] `scripts/usnpw_api.py` remains a thin bootstrap wrapper.
- [x] `tests/test_api_adapters.py` and `tests/test_api_server.py` cover mapping, auth, happy paths, and fail-closed paths.

## Phase 3: GHCR Workflow
- [x] `.github/workflows/container-ghcr.yml` has build-only paths for PR/push.
- [x] Publish paths run on tag/manual triggers with scoped permissions.
- [x] GHCR login uses `${{ github.actor }}` with `${{ secrets.GITHUB_TOKEN }}`.
- [x] Build/push runs via `docker/build-push-action`.
- [x] Tag strategy covers commit SHA, branch, and semver tags.
- [x] OCI source label links image metadata back to repository.
- [x] `README.md` includes GHCR reference format and private-network runtime summary.

## Phase 4: Private-Network Hardening
- [x] `docker-compose.private.yml` provides internal-network example.
- [x] Runtime profile uses read-only root, tmpfs, `no-new-privileges`, and dropped capabilities.
- [x] Service binding targets private interfaces.
- [x] `docs/ADVANCED_USAGE.md` documents persistence behavior under concurrency, replica strategy, and token/log hygiene.

## Phase 5: Merge Readiness (`docker` -> `main`)
- [x] `py tools/release.py preflight` passes.
- [x] Container build job is green.
- [x] API unit tests are green.
- [x] GHCR publish is validated on tag/manual triggers.
- [x] Private-network smoke test is complete.
- [ ] Rebase `docker` onto `main` before merge.
- [ ] Squash or structure commits with clear scopes.

## References
- https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry
- https://docs.github.com/en/actions/use-cases-and-examples/publishing-packages/publishing-docker-images
