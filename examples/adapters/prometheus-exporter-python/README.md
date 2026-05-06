# Prometheus Exporter Adapter

Minimal `/metrics` endpoint for lab scripts that already compute canonical
NetDiag fields.

```bash
python3 exporter.py --csv ../../../data/samples/congestion.csv --port 9107
cargo run -p netdiag-cli -- collect --kind prometheus-metrics --endpoint http://127.0.0.1:9107/metrics --diagnose
```

For production lab usage, keep authentication and network binding outside this
sample process.
