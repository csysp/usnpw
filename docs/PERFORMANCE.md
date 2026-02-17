# Performance Notes

USnPw is stdlib-only and optimized for auditability and operational safety. Runtime performance varies mainly with uniqueness mode (`stream` vs `blacklist`), token blocking pressure at high counts, platform-specific canonicalization rules, and persistence choices (locks plus disk I/O).

## Benchmark Script
`tools/bench.py` provides a lightweight baseline benchmark using the same service layer as CLI and GUI paths.

Windows examples:

```powershell
py .\tools\bench.py --usernames 5000 --profile reddit
py .\tools\bench.py --passwords 5000 --length 24
```

Linux/macOS examples:

```bash
python3 ./tools/bench.py --usernames 5000 --profile reddit
python3 ./tools/bench.py --passwords 5000 --length 24
```

The default benchmark configuration avoids persistence and disables token blocking to reduce saturation artifacts in large runs. Treat benchmark output as informational capacity data, not as a security test.
