# HTTP JSON Adapter

Tiny lab adapter that exposes canonical `TraceRecord` rows over HTTP.

```bash
python3 adapter.py \
  --csv ../../../data/samples/congestion.csv \
  --port 8765 \
  --scenario-id lab-congestion-001 \
  --ground-truth congestion
cargo run -p netdiag-cli -- collect --kind http-json --endpoint http://127.0.0.1:8765/trace --diagnose
```

Keep this adapter thin: convert device or experiment output into canonical
fields plus `experiment` metadata and let NetDiag Twin own diagnosis, ML, and
evidence persistence.
