# Architecture

## Top-Level Layout
- `scripts/pwgen.py`, `scripts/opsec_username_gen.py`, `scripts/usnpw_gui.py`: compatibility entrypoints
- `scripts/usnpw_api.py`: compatibility entrypoint for stdlib HTTP API server
- `usnpw/cli/*`: argument parsing + command execution
- `usnpw/gui/*`: Tkinter UI + adapter mapping
- `usnpw/api/*`: thin network adapter for private-network service use
- `usnpw/core/*`: reusable generation, policy, storage, and crypto APIs
- `tests/*`: stdlib unit tests
- `tools/release.py`: preflight/release automation

## Core Module Fleet
- `password_engine.py`: low-level password/token generation primitives
- `password_service.py`: request validation + orchestration for password generation
- `username_engine.py`: compatibility facade and orchestration boundary
- `username_lexicon.py`: word pools and run-pool construction
- `username_schemes.py`: scheme/state logic and token-cap computations
- `username_generation.py`: unique + stream-unique generation pipelines
- `username_uniqueness.py`: anti-pattern checks, tag layout, saturation messaging
- `username_stream_state.py`: stream state locking/persistence/scrambling
- `username_storage.py`: blacklist/token file persistence helpers
- `username_policies.py`: per-platform normalization/policy definitions
- `export_crypto.py`: encrypted export transforms
- `dpapi.py`: Windows DPAPI wrappers
- `models.py`: typed request/response contracts
- `services.py`: public service-level convenience exports
- `api/adapters.py`: strict JSON request parsing and hardened API defaults
- `api/server.py`: `ThreadingHTTPServer` API adapter over service layer

## Boundary Rules
- `core/*` is treated as reusable library surface.
- CLI and GUI should not duplicate generation logic.
- API adapters should not duplicate generation logic; they only map and validate request payloads.
- Stream state, storage, and uniqueness are separated to keep failure domains explicit.
- `username_engine.py` remains a stable facade for compatibility while delegating internals to specialized modules.

## Validation Gate
- Primary gate: `py .\tools\release.py preflight`
- Includes compile checks and unit suite before release/binary workflows.
