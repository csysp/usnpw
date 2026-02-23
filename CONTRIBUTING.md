# Contributing

## Scope
Keep contributions minimal, auditable, and stdlib-first. Preserve hardened defaults and OPSEC posture. Avoid dependencies.

## Development Workflow
1. Create a focused branch.
2. Implement a small, reviewable change.
3. Run `py .\tools\release.py preflight`.
4. Add or update tests for behavioral changes.
5. Open a PR that includes the problem statement, approach and tradeoffs, and validation evidence.

## Coding Standards
No telemetry or hidden network behavior. No silent security or privacy failures. Keep `usnpw/core/*` reusable and keep the CLI layer thin. Error messages should be explicit and actionable.

## Security-Sensitive Changes
Changes to uniqueness logic, stream tagging/counter handling, release artifact verification, or output handling must document threat-model rationale, failure behavior, and migration or compatibility notes when relevant.
