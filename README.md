# NetDiag Twin

## Rust-native reliability diagnosis and digital-twin validation

NetDiag Twin is a Rust desktop application and CLI for SRE/platform teams that need fast telemetry-driven incident triage, network regression gates, evidence packages for handoff, and post-action verification. It compares evidence-first rules with Rust ML inference, abstains when telemetry is uncertain or out of distribution, runs graph-backed what-if analysis over a digital twin topology, and writes reproducible run artifacts for human review and run-to-run comparison.

## Product Flow

1. Trace Input
2. Telemetry Dashboard
3. Diagnosis Result
4. Rule vs ML Comparison
5. Digital Twin / Topology View
6. Evidence Console / Recommendation Report

Typical service reliability workflows include before/after deploy network
regression checks, platform incident evidence bundles, lab gates for adapter or
telemetry-source changes, and calibrated unknown/OOD checks before a model is
trusted in a real environment.

v0.4.3 adds pilot-ready reliability hardening: explicit artifact integrity
checks, a benchmark report that pairs CI-friendly JSON with a human Markdown
summary, and a safe real-device pilot flow for generic lab kits.

## Rust Workspace

```text
Cargo.toml
crates/
  netdiag-core/   # ingest, telemetry, rules, Rust ML, what-if, recommendations, reports
  netdiag-cli/    # batch diagnosis, connector smoke, review, and artifact export
  netdiag-app/    # eframe/egui native desktop app
data/
  samples/        # six regression traces
docs/
```

## Quick Start

Start with [docs/getting-started.md](docs/getting-started.md) for the canonical
trace schema, live adapter contracts, artifact layout, HIL review flow, and
common ingestion errors.

```bash
cargo run -p netdiag-app
```

Build a clickable macOS app bundle with the generated icon:

```bash
scripts/package_macos_app.sh
open "target/debug/NetDiag Twin.app"
```

Install a release build for the current Mac:

```bash
scripts/package_macos_app.sh release
ditto "target/release/NetDiag Twin.app" "/Applications/NetDiag Twin.app"
open "/Applications/NetDiag Twin.app"
```

Release packaging also creates `target/release/NetDiag-Twin-<version>.dmg`.
The bundle embeds Sparkle 2 for GitHub Releases/appcast updates. For local smoke
builds, set `NETDIAG_SPARKLE_PUBLIC_KEY`; production releases must use the real
Sparkle EdDSA public/private key pair.
For notarization, provide a Developer ID identity and a `notarytool` keychain
profile:

```bash
CODESIGN_IDENTITY="Developer ID Application: Example Team (TEAMID)" \
NETDIAG_NOTARY_PROFILE="netdiag-notary" \
NETDIAG_NOTARIZE=1 \
scripts/package_macos_app.sh release
```

If those credentials are missing, the script reports the exact blocker instead
of claiming a notarized build.

Generate Sparkle appcast metadata after packaging. The script signs the appcast
with the Sparkle EdDSA private key and defaults the enclosure URL prefix to the
matching GitHub Release tag:

```bash
SPARKLE_PRIVATE_KEY="..." scripts/generate_appcast.sh target/release
```

GitHub Actions provide CI and release workflows. The release workflow requires
`CODESIGN_IDENTITY`, `NETDIAG_SPARKLE_PUBLIC_KEY`, `SPARKLE_PRIVATE_KEY`, and
`NETDIAG_NOTARY_PROFILE` secrets before it will publish assets.
Use [docs/release-process.md](docs/release-process.md) as the step-by-step
release checklist for version bumps, tags, GitHub Releases, Sparkle appcast,
Homebrew cask updates, and old-version update smoke.

Finder and `open` launches do not inherit shell-only `export` variables. Prefer
Settings for the Live API URL/token, or set launchd environment variables before
opening the app:

```bash
launchctl setenv NETDIAG_API_URL "https://example.internal/netdiag/trace"
launchctl setenv NETDIAG_API_TOKEN "optional bearer token"
```

The desktop app supports three data source families:

- `Simulate`: deterministic fault scenarios generated in Rust and diagnosed through the real core pipeline.
- `Import Trace`: local CSV/JSON files using canonical trace ingest.
- `Live collection`: source profiles for Local Probe, Website Probe, HTTP/JSON lab adapters, Prometheus `query_range`, Prometheus `/metrics` exposition, OTLP gRPC receiver, Rust-native pcap capture/import, and macOS system counters. Tokens use macOS Keychain with environment-variable fallback. Every collected run now writes a `connector_health.json` evidence artifact with rows, warnings, measured/fallback/missing quality, and missing metrics. Lab adapter templates live under `examples/adapters/` and include `experiment` metadata for scenario ID, fault window, and ground truth.
- `Evidence Console`: the Reports tab shows current connector health, recent run timeline, selected-run evidence, artifacts, HIL state, and run-to-run quality deltas.

See [docs/api-source.md](docs/api-source.md) for the connector overview and HTTP/JSON lab adapter contract, and [docs/getting-started.md](docs/getting-started.md) for OTLP, native pcap, system counters, artifacts, and HIL review examples.

Run a batch diagnosis:

```bash
cargo run -p netdiag-cli -- diagnose data/samples/congestion.csv
```

Run a connector smoke without opening the GUI:

```bash
cargo run -p netdiag-cli -- collect --kind prometheus-metrics --endpoint http://127.0.0.1:9100/metrics
cargo run -p netdiag-cli -- collect --kind prometheus-query --endpoint http://127.0.0.1:9090 --diagnose
cargo run -p netdiag-cli -- collect --kind http-json --endpoint https://example.internal/netdiag/trace
cargo run -p netdiag-cli -- collect --kind otlp-grpc --endpoint 127.0.0.1:4317 --timeout-secs 20
cargo run -p netdiag-cli -- collect --kind native-pcap --endpoint ./fixtures/retransmission.pcap --diagnose
cargo run -p netdiag-cli -- collect --kind system-counters --endpoint all --interval-secs 1
```

Run a what-if action against an existing run:

```bash
cargo run -p netdiag-cli -- whatif <run_id> line reroute_path_b
cargo run -p netdiag-cli -- whatif-policy <run_id> \
  --topology examples/topologies/ring.yaml \
  --policy examples/policies/reroute-path-b.yaml
cargo run -p netdiag-cli -- lab verify-action <before_run_id> \
  --after <after_run_id> \
  --artifacts artifacts \
  --recommendation-id <recommendation_id>
cargo run -p netdiag-cli -- lab verify-action \
  --before <before_run_id> \
  --after <after_run_id> \
  --artifacts artifacts \
  --policy examples/policies/reroute-path-b.yaml \
  --objective examples/policies/verification-objective.yaml
```

What-if output is advisory. `lab verify-action` is the closed-loop check that
compares observed before/after telemetry. By default it still accepts a clear
5% improvement with no quality degradation; Lab scenarios can now define a
`verification.objective` and `verification.fail_if` policy when a change has a
specific latency/loss/throughput target. When a policy is provided, the command
also reports predicted-vs-observed percentage deltas and prediction error.

Export a saved report:

```bash
cargo run -p netdiag-cli -- export <run_id>
```

List recent runs, inspect artifacts, and compare two incidents:

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

Review a recommendation and persist HIL state:

```bash
cargo run -p netdiag-cli -- review <run_id> <recommendation_id> --state accepted --notes "approved for lab run"
```

Run a reproducible lab scenario with typed acceptance gates:

```bash
cargo run -p netdiag-cli -- train \
  --dataset examples/datasets/pilot-smoke-training.jsonl \
  --model-dir artifacts/model \
  --validation-split 0 \
  --min-rows-per-label 1
shasum -a 256 artifacts/model/model_manifest.json artifacts/model/rust_logistic_model.json
cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
cargo run -p netdiag-cli -- lab preflight examples/scenarios/lab-congestion-001.yaml
cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
cargo run -p netdiag-cli -- lab validate <run_id> --artifacts artifacts
```

Copy the manifest/model hashes into the scenario acceptance block when the lab
gate must be pinned to a specific model bundle. Known-fault scenarios should set
`expected_label` or `acceptance.expected_root_cause`; OOD-only scenarios can
omit both when `allowed_diagnosis_statuses` explicitly contains only
`out_of_distribution` or `uncertain`. `lab calibrate` summarizes per-label
accuracy, OOD false positives/false negatives, rule/ML disagreement hotspots,
feature-distance distributions, and proposed uncertainty/rule thresholds. It
only writes `model_manifest.json` when accepted lab runs cover all known labels
and at least one explicit OOD run; low-coverage calibration is reported but not
applied.

Run the bundled unknown/OOD benchmark pack when tuning abstention behavior:

```bash
for scenario in examples/scenarios/ood-*.yaml; do
  cargo run -p netdiag-cli -- lab preflight "$scenario"
done
```

Validate topology and policy YAML before giving it to a lab run:

```bash
cargo run -p netdiag-cli -- topology validate examples/topologies/ring.yaml
cargo run -p netdiag-cli -- policy validate examples/policies/reroute-path-b.yaml --topology examples/topologies/ring.yaml
cargo run -p netdiag-cli -- topology calibrate \
  --topology examples/topologies/ring.yaml \
  --runs artifacts/lab-runs \
  --output target/calibrated-ring.yaml
```

Register and split supervised datasets with deterministic hashes:

```bash
cargo run -p netdiag-cli -- dataset inspect artifacts/datasets/feedback.jsonl
cargo run -p netdiag-cli -- dataset validate artifacts/datasets/feedback.jsonl
cargo run -p netdiag-cli -- dataset split artifacts/datasets/feedback.jsonl --stratified --seed 2026
```

## Validation

```bash
cargo fmt --check --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTFLAGS="-D warnings" cargo test --workspace
scripts/check_perf_budget.sh
scripts/check_architecture_guard.sh
cargo run -p netdiag-cli -- benchmark run \
  --artifacts target/benchmark-artifacts \
  --output target/benchmark-report
```

Golden tests cover all six sample traces:

- `normal`
- `congestion`
- `random_loss`
- `dns_failure`
- `tls_failure`
- `udp_quic_blocked`

`perf-baseline.json` is the tracked performance budget. Refresh it only after an
intentional performance change:

```bash
scripts/check_perf_budget.sh --update-baseline
```

Run the reliability guard against an artifact root after it contains at least
one run, or against a single run:

```bash
cargo run -p netdiag-cli -- reliability check --artifacts artifacts
cargo run -p netdiag-cli -- reliability check --artifacts artifacts --run-id <run_id>
```

Run the bundled benchmark report:

```bash
cargo run -p netdiag-cli -- benchmark run \
  --artifacts target/benchmark-artifacts \
  --output target/benchmark-report
```

The command writes `benchmark_report.json` with schema
`netdiag-benchmark-report/v1` and `benchmark_report.md` for release review.

Run a CI-safe pilot smoke or adapt the generic lab kit manifest for real
devices:

```bash
cargo run -p netdiag-cli -- train \
  --dataset examples/datasets/pilot-smoke-training.jsonl \
  --model-dir target/pilot-artifacts/model \
  --validation-split 0 \
  --min-rows-per-label 1
cargo run -p netdiag-cli -- pilot preflight examples/pilots/loopback-mock.yaml \
  --artifacts target/pilot-artifacts
cargo run -p netdiag-cli -- pilot run examples/pilots/loopback-mock.yaml \
  --artifacts target/pilot-artifacts
```

Pilot runs default to read-only. Sources marked `active: true` require both
manifest `safety.allow_active: true` and the CLI `--allow-active` flag. Pilot
runs require an existing model bundle and never create a synthetic fallback.
The bundled dataset is only a smoke fixture; real lab gates should train from
representative accepted runs and use stricter per-label minimums.

## Artifacts

Runs are written to `artifacts/runs/<run_id>/`:

- `manifest.json`
- `trace_schema.json`
- `telemetry_summary.json`
- `telemetry_windows.json`
- `diagnosis_events.json`
- `ml_result.json`
- `evidence_timeline` in `report.json`, ordering telemetry, rule, ML, and corroborating evidence into a human-readable incident sequence.
- `whatif_*.json`
- `action_verification_<run_id>.json`
- `recommendations.json`
- `hil_feedback.json` after human review
- `report.json`

Regular diagnosis may create a deterministic synthetic model under
`artifacts/model/` for local smoke runs. Lab scenarios are stricter: they require
an existing complete model bundle and never create an implicit per-lab-run model
under `artifacts/lab-runs/.../model/`.

Lab runs are written to `artifacts/lab-runs/<scenario_id>/<timestamp>/` and
indexed in `artifacts/lab_run_index.json`. They include `scenario.yaml`,
`connector_health.json`, `report.json`,
`multi_source_evidence.json`, `comparison.json`, `acceptance.json`,
`evidence_bundle.json`, and a reviewable `netdiag-evidence-<run_id>.zip`.
Evidence, review, export, feedback, what-if, and evidence-bundle commands can
resolve indexed lab runs from the top-level `--artifacts artifacts` directory.

Version bumps are procedural: run `scripts/bump_version.sh <semver>`, then run
the validation gates above before tagging `v<semver>`.
