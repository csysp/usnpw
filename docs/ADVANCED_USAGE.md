# Advanced Usage

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

Password mode also supports metadata output for estimated entropy:

```powershell
usnpw -n 3 -l 24 --show-meta
usnpw --format sha512 --bytes 16 --show-meta
```

Metadata includes per-output entropy estimate plus a KeePassXC-style quality tier:
- `bad`
- `poor`
- `weak`
- `good`
- `excellent`

Entropy vetting uses a clean-room, stdlib-only matcher model inspired by zxcvbn concepts:
- dictionary and leet token matches
- repeated-pattern and sequence detection
- keyboard-walk and compact-date pattern checks
- brute-force fallback with minimum-guess segmentation

## RNG Health Probe
Run a local CSPRNG sanity probe (health check only, not certification):

```powershell
py .\tools\rng_health_probe.py
```
