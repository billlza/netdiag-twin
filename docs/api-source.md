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
- `OTLP gRPC`: starts a local Metrics receiver and converts pushed metric
  exports into canonical records. The unauthenticated receiver only binds to a
  loopback interface, applies a 1 MiB decoded-message limit and bounded shape
  validation, and retains only compact mapped frames in a fail-closed
  256-frame/64 KiB queue.
- `Native pcap`: reads bounded, stable classic `.pcap` snapshots or captures a
  live interface with Rust-native packet parsing. pcapng and symbolic
  link/reparse sources are rejected explicitly.
- `System counters`: samples macOS interface counters and records byte/error
  deltas with explicit measurement-quality provenance.

For OTLP, native pcap, and system counter examples, see
[getting-started.md](getting-started.md#otlp-grpc).

All connector collect paths return the same `ConnectorHealthSnapshot` shape in
the CLI and write `connector_health.json` when run with `--diagnose`, so
measured, estimated, fallback, and missing metrics stay visible in Evidence
Console instead of being treated as normal values.

## Settings And Environment

```bash
export NETDIAG_API_URL="https://example.internal/netdiag/trace"
export NETDIAG_API_TIMEOUT_SECONDS="8"
```

The app sends a `GET` request. Settings take precedence for the URL and timeout.
Tokens are stored in macOS Keychain from the Settings UI and are never written
to `settings.json`. Each token is bound to the exact profile identity, connector
kind, and canonical HTTP origin. The app does not read a process-wide token
variable, and changing the source identity or origin does not reuse an older
credential.

CLI `collect` reads a token variable only when the invocation explicitly names
it with `--bearer-token-env ENV_NAME`. Pilot and Lab manifests must both declare
`bearer_token_env` and receive an exact external `--bearer-binding SOURCE_NAME
SOURCE_KIND CANONICAL_ORIGIN ENV_NAME`; a manifest declaration alone does not
authorize environment access.

HTTP/JSON and Prometheus clients never follow redirects: every `3xx` response
is reported as an explicit connector failure, so an authorization header cannot
be forwarded to a different origin or downgraded endpoint. Connector requests
are direct and do not inherit process/system proxy configuration. Bearer authentication
requires HTTPS. Plain HTTP is allowed only when the host is an IP literal whose
address is loopback, such as `127.0.0.1` or `[::1]`; hostnames including
`localhost` are intentionally not trusted as the loopback exception. Endpoint
query strings may contain ordinary routing parameters, but credential-like keys
such as `token`, `api_key`, `password`, `secret`, `auth`, or `authorization` are
rejected case-insensitively (including encoded variants). Put credentials only
in the dedicated token field, Keychain, or named environment variable.

`settings.json` is a bounded local configuration boundary. NetDiag accepts at
most 1 MiB from a regular, non-symlink/non-reparse file and verifies two reads
from the same opened file generation before parsing it. A missing file selects
product defaults without a warning. Malformed, unstable, non-regular, or
structurally invalid settings are rejected: source execution, automatic startup
diagnosis, and settings persistence remain disabled until the operator repairs
or removes the file and restarts. Load and save enforce the same persistence contract: 1–64 profiles,
at most 256 entries per mapping and 4096 in aggregate, at most 64 website
targets per list and 4096 in aggregate, 16 KiB per string and 1 MiB of strings
in aggregate, and a final pretty-printed representation no larger than 1 MiB.
Explicitly empty profiles or an unknown active profile are errors rather than
being silently rewritten. Endpoint security validation runs before settings are
published, so a credential-bearing query URL is never written to
`settings.json`.

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

HTTP/JSON records are decoded directly into the bounded canonical record vector.
The connector payload retained for App and Pilot consumers contains only validated,
allow-listed metadata; it never retains the record JSON tree or unknown response
fields. Pilot evidence keeps experiment metadata while normalized diagnosis
artifacts remain the authoritative record evidence.

## Experiment Platform Adapter

For lab hardware or scripts, expose an HTTP endpoint that returns either the
bare array or metadata object above. A minimal gateway can translate instrument
counters into canonical fields:

```json
{
  "schema": "netdiag-adapter-payload/v2",
  "collection_mode": "live",
  "sample": "lab-otn-ring-1",
  "protocol": "TCP",
  "flow_count": 2,
  "flows": [
    { "label": "tester-a ↔ dut-1", "bytes": 84200000, "protocol": "TCP" }
  ],
  "measurement_quality": {
    "latency_ms": "measured",
    "jitter_ms": "measured",
    "packet_loss_rate": "measured",
    "retransmission_rate": "measured",
    "timeout_events": "measured",
    "retry_events": "measured",
    "throughput_mbps": "measured",
    "dns_failure_events": "measured",
    "tls_failure_events": "measured",
    "quic_blocked_ratio": "measured"
  },
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
  ],
  "experiment": {
    "scenario_id": "lab-congestion-001",
    "fault_start": "2026-04-30T12:00:00Z",
    "fault_end": "2026-04-30T12:05:00Z",
    "ground_truth": "congestion"
  }
}
```

Adapter payload v2 requires every numeric slot and a complete top-level
`measurement_quality` declaration. If the instrument cannot provide a metric,
the gateway uses the canonical numeric placeholder and marks that field
`missing`; a proxy or heuristic must be `fallback`, never `measured`. V1 remains
read-compatible for migration, but its undeclared metrics fail closed as
`missing`. The Core Local/Website probe connector adds warnings whenever it uses
fallbacks; the desktop app only adapts the typed connector result for display.
Validate lab adapter output against
`examples/adapters/schema/netdiag-adapter-payload.schema.json`; NetDiag uses the
canonical `records` for diagnosis and preserves experiment metadata in lab
evidence files.
Every example Python adapter also supports `--emit-sample`. CI installs the
reviewed schema lock, builds one Rust ingest validator at the fixed workspace
target, and passes that exact binary to both validation passes:

```bash
python3 -m venv --clear --copies .venv-jsonschema
.venv-jsonschema/bin/python -m pip install --disable-pip-version-check \
  --only-binary=:all: --require-hashes -r requirements-jsonschema.lock
validator_target="$(pwd -P)/target/adapter-validator"
CARGO_TARGET_DIR="$validator_target" cargo build --locked \
  -p netdiag-cli --bin netdiag-cli
.venv-jsonschema/bin/python scripts/validate_adapter_samples.py \
  --rust-validator "$validator_target/debug/netdiag-cli"
.venv-jsonschema/bin/python scripts/validate_adapter_contract.py \
  --rust-validator "$validator_target/debug/netdiag-cli"
```

This catches JSON Schema drift, Rust ingest regressions, and full
pipeline/report smoke failures without touching live lab infrastructure. Pilot
manifests must explicitly set `adapter.mode:
sample` before a contract adapter receives `--emit-sample`; `adapter.mode: live`
uses `--collect` without the sample flag. Missing or legacy mode metadata fails
closed.
Pilot adapter execution is a trusted-code boundary: manifests declare a
relative `safety.adapter_execution_root`, runtime calls require the independent
`--allow-adapter-execution` opt-in, and adapter endpoints must canonicalize
inside that root. An explicitly configured relative root such as `../adapters`
may select a shared sibling tree, but normalized endpoints must remain below
that one root. On Unix, NetDiag requires root/effective-user ownership and
rejects group/world-writable permissions for the canonical root, every
ancestor and intermediate directory, and the opened adapter file; it opens
source components without following symlinks. Directory traversal and ACL
inspection are descriptor-native: macOS rejects dangerous allow entries for
non-root/non-effective-user principals but accepts restrictive deny entries;
Linux permits only audited local POSIX-mode filesystems and rejects rich/NFSv4
ACL attributes or unknown filesystem types. Other Unix platforms fail closed.
NetDiag executes a private
read-only snapshot with an absolute pre-resolved Python interpreter, rather
than reopening the checked path. Unix PATH discovery applies the same
descriptor-native ACL, ownership, and writable-ancestor policy to the
interpreter. Python adapter execution is currently disabled
on Windows until interpreter and ancestor DACL/identity validation is
implemented. The
child environment is cleared; an adapter that needs a specific variable must
name it in its bounded `adapter.env_allowlist`. Loader/runtime variable names
are blocked case-insensitively, and allowlisted values are exact-redaction
secrets.
On Unix, stdout and stderr use a single-threaded nonblocking poll loop. Reads
are fair-batched and bounded to 4 MiB for stdout and 256 KiB for stderr. A pipe
that remains open beyond the post-exit deadline is closed and reported as an
output error, so inherited descriptors cannot strand a reader thread or file
descriptor.
Path confinement controls adapter selection, not the filesystem or network
access of the trusted Python process; this is not an OS sandbox.

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
