# Getting Started

This guide describes the stable v0.3.3 platform contract: how telemetry becomes
canonical `TraceRecord` rows, how live adapters map into the same pipeline, and
where the diagnosis, what-if, recommendation, and human-review artifacts are
written.

## Quick Path

Run the desktop app:

```bash
cargo run -p netdiag-app
```

Run one deterministic sample through the CLI:

```bash
cargo run -p netdiag-cli -- diagnose data/samples/congestion.csv
```

Use a separate artifact directory when comparing runs:

```bash
cargo run -p netdiag-cli -- diagnose data/samples/dns_failure.csv --artifacts /tmp/netdiag-artifacts
cargo run -p netdiag-cli -- history --artifacts /tmp/netdiag-artifacts --limit 20
cargo run -p netdiag-cli -- evidence <run_id> --artifacts /tmp/netdiag-artifacts
cargo run -p netdiag-cli -- compare <run_id_a> <run_id_b> --artifacts /tmp/netdiag-artifacts
```

Run the core golden contract tests:

```bash
cargo test -p netdiag-core --test golden
```

## Canonical Trace Schema

All sources are normalized into the same canonical fields before telemetry
aggregation. CSV headers are case-insensitive after trimming and alias mapping.
JSON inputs may be either an array of records or an object with a `records`
array.

| Field | Required | Unit | Notes |
| --- | --- | --- | --- |
| `timestamp` | yes | UTC time | RFC 3339, `YYYY-MM-DD HH:MM:SS[.f]`, or `YYYY-MM-DDTHH:MM:SS[.f]`. Naive timestamps are treated as UTC. |
| `latency_ms` | yes | milliseconds | End-to-end RTT or request latency. Must be finite and non-negative. |
| `jitter_ms` | yes | milliseconds | Jitter for the sample or window. Must be finite and non-negative. |
| `packet_loss_rate` | yes | percent | Use `1.5` for 1.5 percent, not `0.015`. |
| `retransmission_rate` | yes | percent | TCP retransmission or equivalent retry pressure. |
| `timeout_events` | optional | count | Missing optional event counters are warning-backed `0.0`. |
| `retry_events` | optional | count | Missing optional event counters are warning-backed `0.0`. |
| `throughput_mbps` | yes | Mbps | Measured or estimated throughput for the sample. |
| `dns_failure_events` | optional | count | DNS errors in the sample interval. |
| `tls_failure_events` | optional | count | TLS handshake/certificate failures in the sample interval. |
| `quic_blocked_ratio` | optional | ratio | `0.0` to `1.0`; sustained values above `0.25` trigger UDP/QUIC evidence. |

Accepted CSV/JSON aliases:

| Alias | Canonical field |
| --- | --- |
| `time`, `ts` | `timestamp` |
| `latency`, `rtt_ms` | `latency_ms` |
| `jitter` | `jitter_ms` |
| `loss`, `loss_rate` | `packet_loss_rate` |
| `retrans` | `retransmission_rate` |
| `throughput` | `throughput_mbps` |
| `dns_errors` | `dns_failure_events` |
| `tls_errors` | `tls_failure_events` |
| `quic_blocked` | `quic_blocked_ratio` |

Minimal CSV:

```csv
timestamp,latency_ms,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps
2026-04-30T12:00:00Z,18.4,1.1,0.0,0.0,94.2
```

Minimal JSON:

```json
{
  "sample": "lab-window-1",
  "records": [
    {
      "timestamp": "2026-04-30T12:00:00Z",
      "latency_ms": 18.4,
      "jitter_ms": 1.1,
      "packet_loss_rate": 0.0,
      "retransmission_rate": 0.0,
      "timeout_events": 0.0,
      "retry_events": 0.0,
      "throughput_mbps": 94.2,
      "dns_failure_events": 0.0,
      "tls_failure_events": 0.0,
      "quic_blocked_ratio": 0.0
    }
  ]
}
```

## HTTP JSON Adapter

The HTTP adapter is the simplest platform boundary for labs, scripts, and
instrument gateways. The CLI sends `GET` and accepts either `TraceRecord[]` or
an object containing `records`.

```bash
NETDIAG_API_TOKEN="optional bearer token" \
cargo run -p netdiag-cli -- collect \
  --kind http-json \
  --endpoint https://example.internal/netdiag/trace \
  --diagnose
```

The response should include `sample`, `protocol`, `flow_count`, canonical
`records`, and an `experiment` object with `scenario_id`, `fault_start`,
`fault_end`, and `ground_truth`. Diagnosis uses only the canonical records;
lab evidence keeps the metadata for reproducibility. Tokens are read from
`NETDIAG_API_TOKEN` in CLI mode and from Settings/Keychain in the app.

## Prometheus Mapping

Prometheus inputs map metric names or PromQL expressions into canonical fields.
Defaults are:

| Canonical field | Default Prometheus metric/query |
| --- | --- |
| `latency_ms` | `netdiag_latency_ms` |
| `jitter_ms` | `netdiag_jitter_ms` |
| `packet_loss_rate` | `netdiag_packet_loss_rate` |
| `retransmission_rate` | `netdiag_retransmission_rate` |
| `timeout_events` | `netdiag_timeout_events_total` |
| `retry_events` | `netdiag_retry_events_total` |
| `throughput_mbps` | `netdiag_throughput_mbps` |
| `dns_failure_events` | `netdiag_dns_failure_events_total` |
| `tls_failure_events` | `netdiag_tls_failure_events_total` |
| `quic_blocked_ratio` | `netdiag_quic_blocked_ratio` |

Use `prometheus-query` for `/api/v1/query_range`:

```bash
cargo run -p netdiag-cli -- collect \
  --kind prometheus-query \
  --endpoint http://127.0.0.1:9090 \
  --lookback-secs 300 \
  --step-secs 15 \
  --mapping ./prometheus-netdiag-mapping.json \
  --diagnose
```

Use `prometheus-metrics` for text exposition:

```bash
cargo run -p netdiag-cli -- collect \
  --kind prometheus-metrics \
  --endpoint http://127.0.0.1:9100/metrics \
  --diagnose
```

Required metrics must be present. For `query_range`, rows missing required
metrics are dropped with a warning. Optional event metrics may be absent; NetDiag
records a warning and uses `0.0`.

## OTLP gRPC

NetDiag v0.3.3 can run a local OTLP Metrics gRPC receiver and wait for one
metrics export. It is a receiver, not a Prometheus-style pull API: an
OpenTelemetry Collector, lab gateway, or application must push metrics into the
bind address.

```bash
cargo run -p netdiag-cli -- collect \
  --kind otlp-grpc \
  --endpoint 127.0.0.1:4317 \
  --timeout-secs 20 \
  --mapping ./otlp-netdiag-mapping.json \
  --diagnose
```

The mapping file uses the same canonical-field-to-metric-name shape as the
Prometheus mapping. Keep units explicit before they reach NetDiag:
latency and jitter in milliseconds, throughput in Mbps, loss/retransmission in
percent, and QUIC blocked state as a `0.0..1.0` ratio.

## pcap And Native Capture

NetDiag v0.3.3 includes Rust-native packet capture support through `pcap` and
`etherparse`. It can read a `.pcap` file or capture from a live interface.
Live capture on macOS may require packet-capture permission or elevated
privileges; when that is unavailable, file import is the stable path.

```bash
cargo run -p netdiag-cli -- collect \
  --kind native-pcap \
  --endpoint ./fixtures/retransmission.pcap \
  --packet-limit 1000 \
  --diagnose

cargo run -p netdiag-cli -- collect \
  --kind native-pcap \
  --endpoint iface:en0 \
  --timeout-secs 8
```

Native capture computes observed throughput, flow bytes, DNS/TLS/UDP hints, and
simple TCP retransmission evidence. Fields that cannot be proven from passive
packet capture alone, such as end-to-end packet loss or QUIC policy blocking,
are recorded as warnings with fallback values rather than presented as measured
facts.

Local and website probes in the desktop app are active probes, not packet
capture. They record warnings for metrics they cannot observe directly instead
of silently inventing data.

## System Counters

On macOS, the system counters connector samples `netstat -ibn` before and after
a short interval and converts interface byte/error deltas into throughput and
drop evidence.

```bash
cargo run -p netdiag-cli -- collect \
  --kind system-counters \
  --endpoint all \
  --interval-secs 1 \
  --diagnose
```

RTT, jitter, retransmission, and QUIC policy state are not exposed by interface
counters, so NetDiag records explicit warnings for those fallback fields.

## Artifacts

Every diagnosis writes a run directory under `artifacts/runs/<run_id>/` unless a
different `--artifacts` root is provided.

| Artifact | Purpose |
| --- | --- |
| `manifest.json` | Run metadata and paths to written artifacts. |
| `trace_schema.json` | Canonical columns, row count, sample name, and ingest timestamps. |
| `telemetry_summary.json` | Overall telemetry distributions and window count. |
| `telemetry_windows.json` | Five-second windows used by rules and ML. |
| `diagnosis_events.json` | Evidence-first rule events with supporting metrics. |
| `ml_result.json` | Rust ML top predictions, features, and feature importance. |
| `connector_health.json` | Source profile, row count, warnings, missing metrics, and measurement quality summary. |
| `whatif_<action>.json` | Digital-twin baseline, proposed state, and deltas. |
| `recommendations.json` | Approval-required recommendation records. |
| `report.json` | End-user report combining telemetry, rules, ML, what-if, recommendations, and HIL summary. |
| `hil_feedback.json` | Created after human review is saved. |

The model cache is stored under `artifacts/model/`. It is deterministic and can
be regenerated if removed.

`run_index.json` is the Evidence Console index. New runs also write
`connector_health.json`, which records source kind, profile name, rows,
warnings, missing metrics, and measured/estimated/fallback/missing quality. The
desktop Reports page and CLI history/evidence commands read these artifacts to
show recent runs, review state, root causes, model kind, connector health,
measurement quality, artifact count, and run-to-run comparison.

```bash
cargo run -p netdiag-cli -- history --artifacts artifacts --limit 20
cargo run -p netdiag-cli -- history --artifacts artifacts --quality degraded
cargo run -p netdiag-cli -- evidence <run_id> --artifacts artifacts
cargo run -p netdiag-cli -- artifacts <run_id> --artifacts artifacts
cargo run -p netdiag-cli -- compare <run_id_a> <run_id_b> --artifacts artifacts
cargo run -p netdiag-cli -- evidence-bundle <run_id> \
  --artifacts artifacts \
  --output target/netdiag-evidence-<run_id>.zip
```

## Lab Scenarios

Lab scenarios are YAML files with a stable `netdiag-lab-scenario/v1` schema.
They bind a primary data source, optional corroborating sources, topology,
policy, collection windows, and acceptance gates.

```bash
cargo run -p netdiag-cli -- lab preflight examples/scenarios/lab-congestion-001.yaml
cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
cargo run -p netdiag-cli -- lab validate <run_id> \
  --artifacts artifacts
```

`lab validate` first reads `artifacts/lab_run_index.json`, then falls back to a
bounded scan under `artifacts/lab-runs/*/*/runs/<run_id>`. Passing `--scenario`
is still supported, but indexed lab runs can validate from the global artifact
root.

Each lab run writes:

| Artifact | Purpose |
| --- | --- |
| `scenario.yaml` | Exact scenario input used for the run. |
| `connector_health.json` | Health and quality for primary and corroborating sources. |
| `report.json` | Diagnosis report enriched with multi-source evidence. |
| `multi_source_evidence.json` | Primary, corroborating, and counter-evidence summaries. |
| `comparison.json` | Expected vs actual labels, ML agreement, and optional previous-run comparison. |
| `acceptance.json` | Typed pass/fail gate results and concrete failures. |
| `evidence_bundle.json` | Manifest for the exported zip bundle. |
| `netdiag-evidence-<run_id>.zip` | Portable evidence package for reviewers. |

The zip bundle includes the nested pipeline artifacts plus top-level lab
`acceptance.json`, `comparison.json`, `multi_source_evidence.json`, aggregate
`connector_health.json`, and `scenario.yaml`.

Validate topology and policy files before adding them to a scenario:

```bash
cargo run -p netdiag-cli -- topology validate examples/topologies/ring.yaml
cargo run -p netdiag-cli -- policy validate examples/policies/reroute-path-b.yaml \
  --topology examples/topologies/ring.yaml
cargo run -p netdiag-cli -- whatif-policy <run_id> \
  --topology examples/topologies/ring.yaml \
  --policy examples/policies/reroute-path-b.yaml
```

## Dataset Registry

Feedback and lab datasets should be managed as hash-addressed JSONL artifacts,
not anonymous files. The dataset commands inspect labels and hashes, validate
row contracts, and create deterministic train/validation/test splits.

```bash
cargo run -p netdiag-cli -- dataset inspect artifacts/datasets/feedback.jsonl
cargo run -p netdiag-cli -- dataset validate artifacts/datasets/feedback.jsonl
cargo run -p netdiag-cli -- dataset split artifacts/datasets/feedback.jsonl \
  --stratified \
  --seed 2026
```

## Human-In-The-Loop Review

Recommendations are approval-required by default. Review state is persisted into
`recommendations.json`, `report.json`, `hil_feedback.json`, `manifest.json`, and
`run_index.json`.

```bash
cargo run -p netdiag-cli -- review <run_id> <recommendation_id> \
  --state accepted \
  --notes "approved for lab run" \
  --reviewer "operator"
```

Accepted review states are `unreviewed`, `accepted`, `rejected`, `uncertain`,
and `requires_rerun`. The run index status is `pending_review`, `reviewed`,
`requires_rerun`, or `complete` depending on the aggregate HIL state.

## Common Errors

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `missing required column latency_ms` | CSV/JSON did not include a required canonical field or alias. | Add the field or map the upstream name to the canonical schema. |
| `invalid timestamp` | Timestamp is not RFC 3339 or an accepted UTC-naive format. | Emit `2026-04-30T12:00:00Z` or `2026-04-30 12:00:00`. |
| `invalid number` | Empty, negative, `NaN`, or non-finite metric value. | Emit finite non-negative numbers and use documented zeros only for optional event counters. |
| `HTTP/JSON response is not valid JSON` | Adapter returned HTML, text, or malformed JSON. | Check the endpoint, auth token, and content type. |
| `HTTP/JSON must return TraceRecord[] or { records: TraceRecord[] }` | Adapter metadata exists but `records` is missing or malformed. | Return a canonical array or object with `records`. |
| `Prometheus query is missing required metric ...` | Mapping omits a required field. | Add a query for every required canonical metric. |
| `Prometheus query returned no data for required metric ...` | PromQL expression is valid but empty for the lookback/step. | Extend lookback, check labels, or fix scrape availability. |
| `Prometheus rows missing required metrics were dropped` | Query timestamps do not align across required metrics. | Use aligned recording rules or a coarser step. |
| `unknown topology` or `unknown action` | What-if used an unsupported built-in key. | Use `line`, `mesh`, or `star`; use `reroute_path_b`, `increase_queue`, or `reduce_bandwidth`. |
| `unknown recommendation` | HIL review targeted an ID not present in the run. | Read the run's `recommendations.json` and retry with an existing `recommendation_id`. |

For deeper connector examples, see [api-source.md](api-source.md).
