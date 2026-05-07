# OTLP Metrics Gateway

Use this template when an OpenTelemetry Collector or lab gateway pushes metrics
to NetDiag Twin.

1. Map device metrics to the canonical names in `examples/mappings/otlp-netdiag.json`.
2. Run NetDiag's receiver:

```bash
cargo run -p netdiag-cli -- collect --kind otlp-grpc --endpoint 127.0.0.1:4317 --mapping examples/mappings/otlp-netdiag.json --diagnose
```

3. Configure the gateway or Collector to export OTLP metrics to
`http://127.0.0.1:4317`.

When the same gateway also writes a JSON evidence sidecar, use
`../schema/netdiag-adapter-payload.schema.json` and include the `experiment`
block so lab runs can tie OTLP metrics back to the scenario window and ground
truth.
