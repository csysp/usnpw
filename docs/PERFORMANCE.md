# Performance Notes

USnPw is stdlib-only and optimized for auditability and operational safety. Performance depends heavily on:
- username mode (`stream` vs `blacklist`)
- whether token blocking is enabled (can saturate at high counts)
- platform profile canonicalization rules
- persistence choices (locks + disk I/O)

## Bench Script
`tools/bench.py` provides a lightweight, repeatable baseline benchmark using the same service layer as CLI/GUI.

Example (Windows):
```powershell
py .\tools\bench.py --usernames 5000 --profile reddit
py .\tools\bench.py --passwords 5000 --length 24
```

Example (Linux/macOS):
```bash
python3 ./tools/bench.py --usernames 5000 --profile reddit
python3 ./tools/bench.py --passwords 5000 --length 24
```

Notes:
- The default bench configuration avoids persistence and disables token blocking to prevent saturation in large runs.
- Treat benchmark output as informational only. It is not a security test.

