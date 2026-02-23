# Architecture

USnPw is now a CLI-only codebase.

## Entrypoints
| Path | Role |
|---|---|
| `usnpw` | Installed CLI command |
| `usnpw/cli/usnpw_cli.py` | Unified CLI router |

## CLI Layer
| Path | Role |
|---|---|
| `usnpw/cli/usnpw_cli.py` | Subcommand router (`password`, `username`) |
| `usnpw/cli/pwgen_cli.py` | Password argument parsing |
| `usnpw/cli/opsec_username_cli.py` | Username argument parsing |

## Service Layer
| Path | Role |
|---|---|
| `usnpw/core/password_service.py` | Password request validation + orchestration |
| `usnpw/core/username_service.py` | In-memory stream-only username orchestration |
| `usnpw/core/models.py` | Typed request/response contracts |

## Generation Primitives
| Path | Role |
|---|---|
| `usnpw/core/password_engine.py` | Secret generation primitives |
| `usnpw/core/username_generation.py` | Candidate generation and stream tagging |
| `usnpw/core/username_lexicon.py` | Token pools and run subsets |
| `usnpw/core/username_schemes.py` | Scheme definitions and balancing |
| `usnpw/core/username_policies.py` | Platform normalization policies |
| `usnpw/core/username_uniqueness.py` | Token extraction and repeat checks |
| `usnpw/core/username_stream_state.py` | Stateless stream tag derivation helpers |

## Explicitly Removed
- API server surface
- GUI surface
- container distribution files
- username/token persistence ledgers
- stream-state persistence files and locking pathways
