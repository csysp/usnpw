# Advanced Usage

This guide focuses on the reduced private CLI profile.

## Username Generation Defaults
`usnpw username` defaults are privacy-focused:
- token blocking enabled (`block_tokens=True`)
- no-leading-digit enforced
- anti-repeat history window (`history=10`)
- diversified run pools (`pool_scale=4`)

## Throughput vs Uniqueness Tradeoff
For very large batches, token blocking can saturate candidate space.

Use:
```powershell
usnpw username -n 500 --profile reddit --allow-token-reuse
```

This disables token blocking for higher throughput at the cost of more reusable components in output.

## Constraint Tuning
Useful knobs:
- `--min-len`, `--max-len`
- `--profile`
- `--disallow-prefix` (repeatable)
- `--disallow-substring` (repeatable)
- `--max-scheme-pct`
- `--history`
- `--pool-scale`
- `--initials-weight`

## Metadata Output
Use `--show-meta` for debugging scheme/case/separator decisions.

```powershell
usnpw username -n 10 --profile github --show-meta
```

## Security Posture
- no API surface
- no GUI surface
- no username/token persistence files
- no stream-state persistence
- no network calls or telemetry
