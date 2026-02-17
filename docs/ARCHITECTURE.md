# Architecture

## Top-Level Layout
| Path | Purpose |
|---|---|
| `scripts/pwgen.py`, `scripts/opsec_username_gen.py`, `scripts/usnpw_cli.py`, `scripts/usnpw_gui.py` | Compatibility entrypoints |
| `scripts/usnpw_api.py` | Compatibility entrypoint for stdlib HTTP API server |
| `usnpw/__main__.py` | Package entrypoint (`py -m usnpw`) |
| `usnpw/cli/*` | Argument parsing and command execution |
| `usnpw/gui/*` | Tkinter UI and request adapters |
| `usnpw/api/*` | Thin network adapter for private-network use |
| `usnpw/core/*` | Reusable generation, policy, storage, and crypto services |
| `tests/*` | Stdlib unit tests |
| `tools/release.py` | Preflight and release automation |

## Core Module Fleet
| Module | Responsibility |
|---|---|
| `password_engine.py` | Low-level password/token primitives |
| `password_service.py` | Password request validation and orchestration |
| `username_lexicon.py` | Token pools and run-pool construction |
| `username_schemes.py` | Scheme logic and token-cap computations |
| `username_generation.py` | Unique and stream-unique generation pipelines |
| `username_uniqueness.py` | Anti-pattern checks, tag layout, saturation messaging |
| `username_stream_state.py` | Stream-state locking, persistence, and scrambling |
| `username_storage.py` | Blacklist and token persistence helpers |
| `username_policies.py` | Per-platform normalization and policy definitions |
| `export_crypto.py` | Encrypted export transforms |
| `dpapi.py` | Windows DPAPI wrappers |
| `models.py` | Typed request and response contracts |
| `services.py` | Public convenience exports |
| `api/adapters.py` | Strict JSON mapping and hardened API defaults |
| `api/server.py` | `ThreadingHTTPServer` API adapter over service layer |

## Boundary Rules
`core/*` is reusable library surface. CLI, GUI, and API layers should map inputs and outputs only, without duplicating generation logic. Stream state, persistence, and uniqueness logic remain separated to keep failure domains explicit and testable.

## Validation Gate
Primary gate: `py .\tools\release.py preflight` (compile checks and unit tests).
