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
network access, `tc`, an `iperf3` server, SNMP/gNMI credentials, or long-running
HTTP exporters.

For v0.5 Pilot Run Center, adapters should converge on this executable
contract:

- `--preflight`: validate local binaries, credentials, input files, and endpoint
  syntax without changing the device or lab.
- `--collect`: collect one bounded read-only sample and emit the same
  `netdiag-adapter-payload/v1` JSON schema as stdout.
- `--emit-sample`: emit a deterministic offline sample for CI and schema drift
  checks.

The Generic Lab Kit adapters implement this contract now:

```sh
python3 scripts/validate_adapter_contract.py
```

Pilot keeps `adapter_sample` as a compatibility mode for older adapters, but
Generic Lab Kit templates can be validated through preflight and collect before
they are used in a real pilot.

Templates:

- `http-json-python`: expose a CSV/JSON trace as `GET /trace`.
- `iperf3-http-json`: convert `iperf3 -J` throughput/loss output.
- `tc-netem-lab`: emit or apply a planned `tc netem` impairment.
- `openconfig-gnmi`: convert normalized OpenConfig interface notifications.
- `snmp-if-mib`: convert IF-MIB counter deltas from SNMP polling.
- `frr-routing-state`: convert FRR route-state snapshots and flap counters.
- `dns-probe`: count resolver failures.
- `tls-probe`: measure TLS handshake failures.
- `quic-probe`: measure UDP/QUIC reachability.
- `prometheus-exporter-python`: expose `/metrics` plus `/trace`.
- `otlp-metrics-gateway`: map gateway metrics into NetDiag's OTLP receiver.
- `opentelemetry-collector-config`: collector pipeline examples for Prometheus,
  host metrics, and OTLP forwarding.

For a complete local lab, use `iperf3-http-json` for traffic, `tc-netem-lab`
for impairment control, Prometheus/OTLP for time-series evidence, and pcap or
native capture for packet-level corroboration.

Adapters that cannot directly observe a canonical field must say so in
`experiment.measurement_quality`. For example, IF-MIB counters can derive
throughput and discard/error ratios but cannot prove RTT; routing-state snapshots
can indicate churn and forwarding stalls but should not pretend to measure
packet loss. Use those adapters as corroborating sources unless the missing
metrics are supplied by Prometheus, pcap, active probes, or another primary
source.
