# Pilot Run Center v0.5

Pilot Run Center is the v0.5 product spine for real-device trials. It turns the
existing diagnosis, connector, lab, evidence, review, and verification features
into one operator-facing flow instead of another pile of single-purpose
commands.

## Goal

An SRE or platform engineer should be able to select one pilot manifest and run:

```text
preflight -> collect -> diagnose -> evidence bundle -> review -> verify
```

The implementation should preserve the current safety posture:

- Real pilots require an existing trained model bundle under `<artifacts>/model`.
- Synthetic fallback models stay rejected for pilot and production lab flows.
- Sources are read-only by default.
- Any source marked `active: true` requires both manifest `safety.allow_active`
  and the CLI or UI operator opt-in.
- Connector quality and missing/fallback metrics stay visible through
  `connector_health.json`.

## v0.5 Work Slices

1. Pilot connector unification: Pilot sources now use the same read-only
   connector families as CLI collect and Lab: `trace_file`, `adapter_sample`,
   `http_json`, `prometheus_query`, `prometheus_metrics`, `otlp_grpc`,
   `native_pcap`, and `system_counters`. Hyphenated aliases are accepted in
   manifests for parity with Lab and CLI connector names.
2. Generic Lab Kit executable path: the OpenConfig/gNMI, SNMP IF-MIB, FRR,
   iperf3, and tc/netem templates now implement `--preflight`, `--collect`, and
   `--emit-sample`. `scripts/validate_adapter_contract.py` checks preflight
   health/redaction metadata plus collect schema and Rust ingest.
3. Pilot UI / Run Center: the desktop Lab page includes a Pilot Run Center card
   that loads a manifest, inventories sources, shows active-probe opt-in,
   runs preflight, runs workflow, and opens run/evidence artifacts.
4. Model promotion workflow: `pilot model-gate` connects trained model bundles
   to dataset hash, training gate, evaluation, per-label samples, benchmark
   report, and explicit promotion gates before a model is considered releasable.
5. Architecture refactor: keep new v0.5 code in narrow modules. Do not add more
   connector orchestration to `lab.rs`, `connectors.rs`, CLI `main.rs`, or app
   `main.rs`.

## Pilot Manifest Source Contract

Each source has a stable envelope:

```yaml
- name: prometheus-primary
  kind: prometheus-query
  endpoint: http://127.0.0.1:9090
  mapping: ../mappings/prometheus-netdiag.json
  role: primary
  active: false
  collection:
    timeout_secs: 8
    lookback_secs: 300
    step_secs: 15
    packet_limit: 256
    interval_secs: 1
  bearer_token_env: NETDIAG_API_TOKEN
  metadata:
    stack: Prometheus
```

`mapping` is used by Prometheus and OTLP sources. If it is omitted, NetDiag uses
the default canonical metric mapping. `collection` is optional and defaults to
short read-only windows suitable for preflight and pilot smoke runs.

Start from:

- `examples/pilots/loopback-mock.yaml` for CI-safe adapter smoke.
- `examples/pilots/generic-lab-kit.yaml` for the current generic adapter kit.
- `examples/pilots/connector-family-readonly.yaml` for the v0.5 connector
  family shape.

## Run Artifacts

Pilot runs write under:

```text
<artifacts>/pilot-runs/<pilot_id>/<timestamp>/
```

The v0.5 artifact contract should include:

- `pilot.yaml`: redacted manifest snapshot.
- `pilot_report.json`: machine-readable run summary and gate outcome.
- `pilot_workflow.json`: preflight, collect, diagnose, evidence, review, and
  verification phase summary.
- `pilot_summary.md`: human-readable handoff summary.
- `connector_health.json`: aggregate health for primary and corroborating
  sources.
- `source_<name>_redacted.json`: redacted payload snapshots when available.
- `runs/<run_id>/`: normal diagnosis artifacts.
- `netdiag-evidence-<run_id>.zip`: portable evidence bundle.
- Future closed-loop artifacts: `operator_decision.json`,
  `action_verification.json`, `baseline_run_id`, and `after_run_id`.

## Model Promotion Gate

A model should become active for real pilots only after:

- Dataset registry rows are hash-addressed and traceable to reviewed runs or
  accepted lab runs.
- Per-label minimum sample counts pass the training gate.
- Validation includes known labels and explicit OOD examples.
- OOD false positives, OOD false negatives, and rule/ML disagreement hotspots
  stay below release thresholds.
- Benchmark report and performance budget pass.
- The promoted manifest records dataset hash, model hash, training gate, and
  evaluation summary.

Run the gate with:

```bash
cargo run -p netdiag-cli -- pilot model-gate \
  --model-dir artifacts/model \
  --benchmark-report target/benchmark-report/benchmark_report.json \
  --min-rows-per-label 10 \
  --min-accuracy 0.90 \
  --min-macro-f1 0.90
```

## Refactor Boundaries

The Pilot Run Center should add modules before it adds features:

- `netdiag-core::pilot`: manifest, report, and run orchestration only.
- `netdiag-core::pilot::pilot_sources`: source loading and preflight checks.
- `netdiag-core::pilot::workflow`: closed-loop workflow report.
- `netdiag-core::pilot::promotion`: model promotion gates.
- `netdiag-cli::commands::pilot`: CLI dispatch only.
- `netdiag-app::pilot_run_center`: UI state and rendering only; no connector
  logic.
