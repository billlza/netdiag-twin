# Lab Adapter Templates

These adapters convert lab tools into the canonical NetDiag JSON payload:

```json
{
  "schema": "netdiag-adapter-payload/v1",
  "sample": "lab-congestion-001",
  "protocol": "TCP",
  "flow_count": 1,
  "records": [],
  "experiment": {
    "scenario_id": "lab-congestion-001",
    "fault_start": "2026-05-07T09:00:00Z",
    "fault_end": "2026-05-07T09:05:00Z",
    "ground_truth": "congestion"
  }
}
```

`records` must contain numeric canonical `TraceRecord` fields. The schema file
at `schema/netdiag-adapter-payload.schema.json` is intentionally strict for
records and permissive for lab-specific metadata under `experiment`.

Every Python adapter supports deterministic offline sample generation:

```sh
python3 examples/adapters/dns-probe/adapter.py --emit-sample
python3 scripts/validate_adapter_samples.py
```

The CI validator uses `--emit-sample`, so adapter schema checks do not require
network access, `tc`, an `iperf3` server, or long-running HTTP exporters.

Templates:

- `http-json-python`: expose a CSV/JSON trace as `GET /trace`.
- `iperf3-http-json`: convert `iperf3 -J` throughput/loss output.
- `tc-netem-lab`: emit or apply a planned `tc netem` impairment.
- `dns-probe`: count resolver failures.
- `tls-probe`: measure TLS handshake failures.
- `quic-probe`: measure UDP/QUIC reachability.
- `prometheus-exporter-python`: expose `/metrics` plus `/trace`.
- `otlp-metrics-gateway`: map gateway metrics into NetDiag's OTLP receiver.
