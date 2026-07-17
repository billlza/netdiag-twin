# Lab Adapter Templates

These adapters convert lab tools into the canonical NetDiag JSON payload:

```json
{
  "schema": "netdiag-adapter-payload/v2",
  "collection_mode": "sample",
  "sample": "lab-congestion-001",
  "protocol": "TCP",
  "flow_count": 1,
  "measurement_quality": {
    "latency_ms": "measured",
    "jitter_ms": "missing",
    "packet_loss_rate": "missing",
    "retransmission_rate": "missing",
    "timeout_events": "missing",
    "retry_events": "missing",
    "throughput_mbps": "measured",
    "dns_failure_events": "missing",
    "tls_failure_events": "missing",
    "quic_blocked_ratio": "missing"
  },
  "records": [{
    "timestamp": "2026-05-07T09:00:00Z",
    "latency_ms": 42.0,
    "jitter_ms": 0.0,
    "packet_loss_rate": 0.0,
    "retransmission_rate": 0.0,
    "timeout_events": 0.0,
    "retry_events": 0.0,
    "throughput_mbps": 88.0,
    "dns_failure_events": 0.0,
    "tls_failure_events": 0.0,
    "quic_blocked_ratio": 0.0
  }],
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

```bash
python3 examples/adapters/dns-probe/adapter.py --emit-sample
python3 -m venv --clear --copies .venv-jsonschema
.venv-jsonschema/bin/python -m pip install --disable-pip-version-check \
  --only-binary=:all: --require-hashes -r requirements-jsonschema.lock
validator_target="$(pwd -P)/target/adapter-validator"
CARGO_TARGET_DIR="$validator_target" cargo build --locked \
  -p netdiag-cli --bin netdiag-cli
.venv-jsonschema/bin/python scripts/validate_adapter_samples.py \
  --rust-validator "$validator_target/debug/netdiag-cli"
```

The CI validator uses `--emit-sample`, so adapter schema checks do not require
network access, `tc`, an `iperf3` server, SNMP/gNMI credentials, or long-running
HTTP exporters.

For v0.5 Pilot Run Center, adapters should converge on this executable
contract:

- `--preflight`: validate local binaries, credentials, input files, and endpoint
  syntax without changing the device or lab.
- `--collect`: collect one bounded read-only sample and emit the same
  `netdiag-adapter-payload/v2` JSON schema as stdout.
- `--emit-sample`: emit a deterministic offline sample for CI and schema drift
  checks.

The Generic Lab Kit adapters implement this contract now:

```bash
validator_target="$(pwd -P)/target/adapter-validator"
CARGO_TARGET_DIR="$validator_target" cargo build --locked \
  -p netdiag-cli --bin netdiag-cli
.venv-jsonschema/bin/python scripts/validate_adapter_contract.py \
  --rust-validator "$validator_target/debug/netdiag-cli"
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

Bundled adapters emit `netdiag-adapter-payload/v2` and declare all ten canonical
numeric fields in the required top-level `measurement_quality` object. It is a
closed object: every canonical field is required, unknown fields are rejected,
and values are limited to `measured`, `estimated`, `fallback`, or `missing`.
There is no free-text source or reason field in this contract. The reader keeps
v1 input compatibility, but because v1 has no quality declaration, every v1
metric is treated as `missing`; bundled adapters no longer emit v1.

- `measured` means the source directly supplied the canonical quantity.
- `estimated` means the same canonical quantity was calculated from direct raw
  observations, such as an interval counter rate.
- `fallback` marks a proxy, heuristic, or unapplied plan that must not be treated
  as a direct observation.
- `missing` marks a required numeric placeholder that carries no evidence.

The bundled mappings are intentionally conservative:

| Adapter | Measured | Estimated | Fallback | Missing |
| --- | --- | --- | --- | --- |
| HTTP JSON / Prometheus CSV | all ten fields | — | — | — |
| iperf3 TCP | `throughput_mbps` | `retry_events` | — | all other fields |
| iperf3 UDP | `jitter_ms`, `packet_loss_rate`, `throughput_mbps` | — | — | all other fields |
| OpenConfig/gNMI | `latency_ms`, `jitter_ms`, `throughput_mbps` | — | discard/error proxies | unobserved fields |
| SNMP IF-MIB | — | `throughput_mbps` | discard/error proxies | unobserved fields |
| FRR routing state | — | — | stall, flap, churn, and throughput proxies | unobserved fields, including both canonical rates |
| DNS probe | latency, jitter, timeout, and DNS failure counts | — | application-failure packet-loss proxy | unobserved fields |
| TLS probe | latency, jitter, timeout, DNS failure, and TLS failure counts | — | application-failure packet-loss proxy | unobserved fields |
| QUIC probe | latency, jitter, timeout, and DNS failure counts | — | UDP reachability loss/blocking proxies | unobserved fields |
| tc/netem plan | — | — | planned latency, jitter, loss, and throughput | all unobserved fields |

For example, IF-MIB counters can calculate throughput and expose discard/error
proxies but cannot prove RTT or transport retransmission. Routing-state
snapshots can indicate churn and forwarding stalls but do not emit a fabricated
canonical retransmission rate. Use fallback fields only as corroborating
evidence unless a primary source supplies the missing canonical measurement.
