# Performance

Runtime cost is dominated by:
- requested output count
- username constraints (`min/max`, disallow filters)
- token blocking pressure
- pool diversity (`pool_scale`)

## Notes
Overall performance is solid at present as large generations are capped first by token count. 

## Benchmark Helper
Use:
```powershell
py .\tools\bench.py --passwords 10000 --length 24
py .\tools\bench.py --usernames 5000 --profile reddit
py .\tools\bench.py --usernames 5000 --profile reddit --allow-token-reuse
```

`--allow-token-reuse` improves throughput for large username batches by disabling token blocking.
