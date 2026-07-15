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

CSV ingestion is bounded to a regular, non-symlink UTF-8 file of at most
16 MiB and 100,000 rows. The full canonical header set is required; duplicate
headers, missing or empty values, non-finite or negative numbers, percentages
outside `0..100`, and unit ratios outside `0..1` are rejected. The server
pre-encodes the JSON response with strict finite-number encoding, enforces a
16 MiB response limit, and applies a 10-second socket deadline before serving.
Live mode refuses to start on a platform that cannot provide all required
descriptor flags. The boundary stays in this file because Pilot executes an
isolated single-file snapshot.

Every CSV header is already a canonical quantity and is emitted as `measured` in
the complete top-level `measurement_quality` declaration. This describes the
adapter input contract; upstream identity and evidence integrity remain the
caller's responsibility.
