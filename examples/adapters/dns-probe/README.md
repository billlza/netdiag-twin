# DNS Probe Adapter

Runs repeated resolver lookups and emits DNS failures as canonical events.

```bash
python3 adapter.py \
  --host service.internal \
  --count 10 \
  --scenario-id lab-dns-failure-001 \
  --ground-truth dns_failure
```

Use this behind an HTTP wrapper or write the JSON to a scenario `trace-file`
fixture after converting the `records` array to CSV/JSON trace input.
