# Contributing

## Scope
- Keep changes minimal, auditable, and stdlib-first.
- Preserve hardened defaults and OPSEC posture.
- Avoid adding dependencies unless explicitly justified.

## Development Workflow
1. Create a focused branch.
2. Implement a small, reviewable change.
3. Run:
   - `py .\tools\release.py preflight`
4. Include tests for behavioral changes.
5. Open a PR with:
   - problem statement
   - approach/tradeoffs
   - validation evidence

## Coding Standards
- No telemetry, analytics, or network calls.
- No silent security/privacy failures.
- Keep `usnpw/core/*` reusable and CLI/GUI thin.
- Prefer explicit, actionable error messages.

## Security-Sensitive Changes
- Any change to uniqueness logic, stream state, token persistence, or export crypto must include:
  - threat-model rationale
  - failure mode description
  - migration/compatibility note if relevant
