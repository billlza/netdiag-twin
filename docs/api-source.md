# Live API Source

`netdiag-app` can ingest a live HTTP JSON source when a Live API URL is configured
in Settings or when `NETDIAG_API_URL` is set.
The API response is normalized into the same Rust `TraceRecord` pipeline used by
file import and simulation.

The desktop app now treats live collection as a connector family:

- `Local Probe`: measures the local host network stack and records explicit
  warnings for metrics an active probe cannot observe directly.
- `Website Probe`: measures configured public or lab web targets such as
  Cloudflare, `example.com`, or `host:port` TCP endpoints.
- `HTTP/JSON Lab Adapter`: ingests an experiment platform or instrument gateway
  using the contract below.
- `Prometheus query_range`: reads configured PromQL expressions from
  `/api/v1/query_range` and maps them into canonical `TraceRecord` fields.
- `Prometheus /metrics`: scrapes Prometheus text exposition and maps metric
  names into a single canonical `TraceRecord` sample.

## Settings And Environment

```bash
export NETDIAG_API_URL="https://example.internal/netdiag/trace"
export NETDIAG_API_TOKEN="optional bearer token"
export NETDIAG_API_TIMEOUT_SECONDS="8"
```

The app sends a `GET` request. Settings take precedence for the URL and timeout.
The token is stored in macOS Keychain from the Settings UI; `NETDIAG_API_TOKEN`
remains a development fallback. Tokens are never written to `settings.json`.
The same token fallback is used for Prometheus endpoints that require bearer
authentication.

## Response Shape

The endpoint may return either a bare array of canonical `TraceRecord` objects:

```json
[
  {
    "timestamp": "2026-04-29T09:35:00Z",
    "latency_ms": 42.1,
    "jitter_ms": 2.8,
    "packet_loss_rate": 0.05,
    "retransmission_rate": 0.08,
    "timeout_events": 0.0,
    "retry_events": 0.0,
    "throughput_mbps": 41.2,
    "dns_failure_events": 0.0,
    "tls_failure_events": 0.0,
    "quic_blocked_ratio": 0.0
  }
]
```

Or an object with metadata:

```json
{
  "sample": "edge-prod-window",
  "protocol": "TCP",
  "flow_count": 4,
  "flows": [
    { "src": "10.0.0.2", "dst": "10.0.0.3", "bytes": 142000000, "protocol": "TCP" },
    { "label": "Others", "bytes": 18000000 }
  ],
  "records": []
}
```

If `flows` or `top_talkers` are missing, the UI shows unknown per-flow metadata
instead of inventing demo talkers.

## Experiment Platform Adapter

For lab hardware or scripts, expose an HTTP endpoint that returns either the
bare array or metadata object above. A minimal gateway can translate instrument
counters into canonical fields:

```json
{
  "sample": "lab-otn-ring-1",
  "protocol": "TCP",
  "flow_count": 2,
  "flows": [
    { "label": "tester-a ↔ dut-1", "bytes": 84200000, "protocol": "TCP" }
  ],
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

If the instrument cannot provide a metric, the gateway should either omit only
optional event counters or provide a documented zero with an external note. The
app-side Local/Website probes add warnings whenever they use such fallbacks.

## Prometheus Mapping

Default mappings expect lab-friendly metric names:

```json
{
  "latency_ms": "netdiag_latency_ms",
  "jitter_ms": "netdiag_jitter_ms",
  "packet_loss_rate": "netdiag_packet_loss_rate",
  "retransmission_rate": "netdiag_retransmission_rate",
  "throughput_mbps": "netdiag_throughput_mbps",
  "timeout_events": "netdiag_timeout_events_total",
  "retry_events": "netdiag_retry_events_total",
  "dns_failure_events": "netdiag_dns_failure_events_total",
  "tls_failure_events": "netdiag_tls_failure_events_total",
  "quic_blocked_ratio": "netdiag_quic_blocked_ratio"
}
```

For `query_range`, required metrics must return aligned samples or incomplete
rows are dropped with a warning. Optional event counters may be absent; NetDiag
records a warning and uses `0.0` instead of silently pretending the metric was
measured.

The CLI accepts a JSON mapping file:

```bash
cargo run -p netdiag-cli -- collect \
  --kind prometheus-query \
  --endpoint http://127.0.0.1:9090 \
  --mapping ./prometheus-netdiag-mapping.json \
  --diagnose
```
