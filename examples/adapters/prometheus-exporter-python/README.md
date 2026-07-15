# Prometheus Exporter Adapter

Minimal `/metrics` endpoint for lab scripts that already compute canonical
NetDiag fields.

```bash
python3 exporter.py \
  --csv ../../../data/samples/congestion.csv \
  --port 9107 \
  --scenario-id lab-congestion-001 \
  --ground-truth congestion
cargo run -p netdiag-cli -- collect --kind prometheus-metrics --endpoint http://127.0.0.1:9107/metrics --diagnose
```

The same process exposes `GET /trace` with the canonical adapter JSON payload
for lab evidence capture.

For production lab usage, keep authentication and network binding outside this
sample process.

CSV ingestion is bounded to a regular, non-symlink UTF-8 file of at most
16 MiB and 100,000 rows. The full canonical header set is required; duplicate
headers, missing or empty values, non-finite or negative numbers, percentages
outside `0..100`, and unit ratios outside `0..1` are rejected. Records and
metric aggregates are built in one pass. Both HTTP bodies are pre-encoded at
startup, limited to 16 MiB, and served with a 10-second socket deadline. Live
mode refuses to start on a platform that cannot provide all required descriptor
flags. The boundary stays in this file because Pilot executes an isolated
single-file snapshot.

Every CSV header is already a canonical quantity and is emitted as `measured` in
the complete top-level `measurement_quality` declaration. This describes the
adapter input contract; upstream identity and evidence integrity remain the
caller's responsibility.
