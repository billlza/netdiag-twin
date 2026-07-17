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

v0.5.3 hardens typed, crash-consistent publication for the audited dataset,
model, HIL, and run transaction boundaries, filesystem trust boundaries,
bounded evidence/model validation, native Windows security contracts, and the
signed release supply chain. Release publication now waits for the Linux full
consumer suite and native Windows platform/fail-closed contracts, an exact-main
CI result, and a verified checksum-bound artifact;
each version is serialized and its signing window packages a prebuilt sealed binary.

v0.5.2 introduced the model-promotion OOD behavior gate: `pilot model-gate` now
requires a fresh lab calibration artifact that matches the promoted
model/dataset hashes, confirms calibrated thresholds were applied, and enforces
OOD false-positive, OOD false-negative, and rule/ML disagreement hotspot limits.

The v0.5 direction is [Pilot Run Center](docs/pilot-run-center.md): a real-device
trial loop that turns pilot manifests into preflight, collection, diagnosis,
evidence bundle, review, and verification instead of more one-off commands.

Real-device pilot proof is currently `pending_lab_access` / `not_validated`.
Local gates prove the software path with CI-safe adapters and trace artifacts;
they must not be described as physical lab-device validation until
[`docs/real-device-pilot-readiness.json`](docs/real-device-pilot-readiness.json)
points to reviewed real-device evidence.

## Rust Workspace

```text
Cargo.toml
crates/
  netdiag-core/   # ingest, telemetry, rules, Rust ML, what-if, recommendations, reports
  netdiag-cli/    # batch diagnosis, connector smoke, review, and artifact export
  netdiag-app/    # eframe/egui native desktop app
  netdiag-platform/ # isolated native FFI behind safe platform APIs
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
Settings for source profiles and credentials. The legacy API URL can also be
provided through launchd before opening the app:

```bash
launchctl setenv NETDIAG_API_URL "https://example.internal/netdiag/trace"
```

The desktop app never reads a process-wide bearer-token variable. Enabling
authentication stores a token in Keychain under the exact profile identity,
connector kind, and canonical HTTP origin, so changing profiles or origins
cannot reuse another source's credential.

The desktop app supports three data source families:

- `Simulate`: deterministic fault scenarios generated in Rust and diagnosed through the real core pipeline.
- `Import Trace`: local CSV/JSON files using canonical trace ingest.
- `Live collection`: source profiles for Local Probe, Website Probe, HTTP/JSON lab adapters, Prometheus `query_range`, Prometheus `/metrics` exposition, OTLP gRPC receiver, Rust-native pcap capture/import, and macOS system counters. Bearer tokens use source- and origin-scoped Keychain entries with no process-wide fallback. Every collected run writes a `connector_health.json` evidence artifact with rows, warnings, measured/fallback/missing quality, and missing metrics. Lab adapter templates live under `examples/adapters/` and include `experiment` metadata for scenario ID, fault window, and ground truth.
- `Evidence Console`: the Reports tab shows current connector health, recent run timeline, selected-run evidence, artifacts, HIL state, and run-to-run quality deltas.

See [docs/api-source.md](docs/api-source.md) for the connector overview and HTTP/JSON lab adapter contract, and [docs/getting-started.md](docs/getting-started.md) for OTLP, native pcap, system counters, artifacts, and HIL review examples.

Bearer-authenticated HTTP/JSON and Prometheus connectors require HTTPS or a
literal loopback IP over HTTP, reject credential-like endpoint query keys, and
surface redirects as errors instead of following them.

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

CLI bearer access is opt-in per invocation. The variable is not read unless its
name is supplied explicitly:

```bash
NETDIAG_API_TOKEN="..." cargo run -p netdiag-cli -- collect \
  --kind http-json \
  --endpoint https://example.internal/netdiag/trace \
  --bearer-token-env NETDIAG_API_TOKEN
```

Run the v0.5 Pilot Run Center loop from CLI:

```bash
cargo run -p netdiag-cli -- train \
  --dataset examples/datasets/pilot-smoke-training.jsonl \
  --model-dir artifacts/model \
  --validation-split 0 \
  --min-rows-per-label 1
cargo run -p netdiag-cli -- pilot preflight examples/pilots/loopback-mock.yaml --artifacts artifacts
cargo run -p netdiag-cli -- pilot run examples/pilots/loopback-mock.yaml \
  --artifacts artifacts \
  --allow-adapter-execution
```

The desktop app exposes the same flow from the Lab page as `Pilot Run Center`.
Use `examples/pilots/generic-lab-kit.yaml` to exercise the executable adapter
contract, or `examples/pilots/connector-family-readonly.yaml` to review the
read-only connector family manifest shape.
Use `pilot workflow --after-run-id <after_run_id>` when an after-run is
available for closed-loop verification; without it, workflow reports remain
partial with `verify` pending and exit non-zero.

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
generation="$(jq -r '.generation' artifacts/model/current.json)"
shasum -a 256 \
  "artifacts/model/generations/$generation/model_manifest.json" \
  "artifacts/model/generations/$generation/rust_logistic_model.json"
cargo run -p netdiag-cli -- lab preflight examples/scenarios/lab-congestion-001.yaml
cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
cargo run -p netdiag-cli -- lab validate <run_id> --artifacts artifacts
cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
```

Copy the manifest/model hashes into the scenario acceptance block when the lab
gate must be pinned to a specific model bundle. `current.json` is the sole
publication pointer; see [Model bundle publication](docs/model-bundle-publication.md)
for the crash-atomic generation and legacy migration contract. Known-fault scenarios should set
`expected_label` or `acceptance.expected_root_cause`; OOD-only scenarios can
omit both when `allowed_diagnosis_statuses` explicitly contains only
`out_of_distribution` or `uncertain`. `lab calibrate` summarizes per-label
accuracy, OOD false positives/false negatives, rule/ML disagreement hotspots,
feature-distance distributions, and proposed uncertainty/rule thresholds. It
only publishes a new generation with an updated `model_manifest.json` when accepted lab runs cover all known labels
and at least one explicit OOD run; low-coverage calibration is reported but not
applied.

Run the bundled unknown/OOD benchmark pack when tuning abstention behavior:

```bash
for scenario in examples/scenarios/ood-*.yaml; do
  cargo run -p netdiag-cli -- lab preflight "$scenario"
done
```

Gate a trained model before promoting it for real pilots:

```bash
validator_target="$(pwd -P)/target/adapter-validator"
CARGO_TARGET_DIR="$validator_target" cargo build --locked -p netdiag-cli --bin netdiag-cli
cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
cargo run -p netdiag-cli -- benchmark run \
  --artifacts target/benchmark-artifacts \
  --output target/benchmark-report \
  --model-dir artifacts/model
cargo run -p netdiag-cli -- pilot model-gate \
  --model-dir artifacts/model \
  --benchmark-report target/benchmark-report/benchmark_report.json \
  --calibration-report artifacts/lab_calibration_report.json \
  --min-rows-per-label 10 \
  --max-ood-false-positive-rate 0.05 \
  --max-ood-false-negative-rate 0.05 \
  --max-rule-ml-disagreement-hotspot-rate 0.10
```

Since v0.5.2, `pilot model-gate` combines known-label coverage, explicit OOD
benchmark preflight coverage, and behavior-level calibration gates. The
calibration artifact must be `applied: true`, fresh, hash-matched to the model
bundle, and internally consistent with recomputed OOD FP/FN and hotspot rates.

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

Each split output directory is a single immutable transaction namespace. The
hidden `.dataset-split-transaction.json` receipt is durable ownership metadata,
not a temporary file: it lets an identical command resume safely after a crash
before `dataset_manifest.json` is published. If the manifest was committed but
the success response or final durability acknowledgement was lost, a matching
retry verifies the exact receipt-bound manifest and every immutable partition,
reconfirms directory durability, then returns the original manifest (including
its original `created_at`). It never recreates a missing partition after commit.
Keep the receipt with its partitions, use a new empty directory for different
split parameters, and remove the whole directory—not individual transaction
files—when intentionally
discarding an incomplete split.

Dataset inspection, validation, comparison, and existing-bundle reads remain
available on Windows. Dataset split/register, model training or rebuild, HIL
review, and workflows that publish new run directories require the audited Unix
directory durability boundary in v0.5.3. On Windows they return a typed
`NotPublished` error before creating an output hierarchy; a no-op flush is never
reported as success. The bundled benchmark's trusted Python schema validators
also fail closed on non-Unix platforms before a child process is spawned; this
does not reduce the supported read-only inspect, validate, and compare commands.
The Windows CI lane therefore runs every platform test,
compiles/lints every consumer target, and executes dedicated no-side-effect
mutation contracts instead of pretending Unix-only mutation tests are portable.

## Validation

```bash
python3 -m venv --clear --copies .venv-jsonschema
.venv-jsonschema/bin/python -m pip install --disable-pip-version-check --only-binary=:all: --require-hashes -r requirements-jsonschema.lock
scripts/check_rust_quality.sh fast
cargo fmt --check --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTFLAGS="-D warnings" cargo test --workspace
scripts/check_perf_budget.sh
scripts/check_architecture_guard.sh
validator_target="$(pwd -P)/target/adapter-validator"
CARGO_TARGET_DIR="$validator_target" cargo build --locked -p netdiag-cli --bin netdiag-cli
cargo run -p netdiag-cli -- benchmark run \
  --artifacts target/benchmark-artifacts \
  --output target/benchmark-report
```

The v0.5 strict release gate is documented in
[docs/quality-gates.md](docs/quality-gates.md). It targets at least 90% line
coverage on the Pilot/CLI/platform release-critical slice, reports the measured
core/CLI/platform workspace coverage as a ratchet floor, and independently gates
the desktop credential, secret, API-test status, and destructive-confirmation
security slice at 80% aggregate and 50% per production file. It also runs
nextest, dependency checks, complexity ratchets, performance budget, and
benchmark artifacts. The strict gate fails on rustc, clippy, and cargo-deny
warnings, not just non-zero exit codes.

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
validator_target="$(pwd -P)/target/adapter-validator"
CARGO_TARGET_DIR="$validator_target" cargo build --locked -p netdiag-cli --bin netdiag-cli
cargo run -p netdiag-cli -- benchmark run \
  --artifacts target/benchmark-artifacts \
  --output target/benchmark-report
```

The bundled benchmark reuses the prebuilt Rust ingest validator from the fixed
workspace target shown above and provisions its deterministic smoke model. For
promotion/release use, pass `--model-dir artifacts/model` so
`benchmark_report.json` records the candidate model and dataset hashes that
`pilot model-gate` verifies.

Model bundles use `netdiag-model-manifest/v2`; the manifest binds the exact
serialized model with `model_file_hash_sha256`. Legacy v1, one-file, or
hash-mismatched bundles are rejected and are never repaired implicitly. Retrain
the candidate bundle, or use the desktop model reset only when a clearly marked
synthetic development model is intended.

Run a CI-safe pilot smoke or adapt the generic lab kit manifest for real
devices:

```bash
cargo run -p netdiag-cli -- artifact-root initialize \
  --artifacts target/pilot-artifacts
cargo run -p netdiag-cli -- train \
  --dataset examples/datasets/pilot-smoke-training.jsonl \
  --model-dir target/pilot-artifacts/model \
  --validation-split 0 \
  --min-rows-per-label 1
cargo run -p netdiag-cli -- pilot preflight examples/pilots/loopback-mock.yaml \
  --artifacts target/pilot-artifacts
cargo run -p netdiag-cli -- pilot run examples/pilots/loopback-mock.yaml \
  --artifacts target/pilot-artifacts \
  --allow-adapter-execution
```

Pilot manifests can now use the same read-only connector family as CLI collect:
`prometheus_query`, `prometheus_metrics`, `otlp_grpc`, `native_pcap`, and
`system_counters`, with hyphenated aliases accepted for Lab/CLI parity. See
`examples/pilots/connector-family-readonly.yaml` for the v0.5 source envelope.

Pilot runs default to read-only. Sources marked `active: true` require both
manifest `safety.allow_active: true` and the CLI `--allow-active` flag. Pilot
runs that include adapters additionally require `--allow-adapter-execution`;
this is independent from active-probe authorization. Adapter endpoints are
trusted executable code and must remain inside the manifest's canonical
`safety.adapter_execution_root`. On Unix, the canonical adapter root, every
ancestor and intermediate source directory, and the opened adapter file must be
owned by root or the effective user and must not be group/world-writable;
symlink source components are rejected. Trust checks walk already-open directory
descriptors and inspect ACLs on those descriptors, rather than re-reading ACLs
by path. macOS rejects write/replacement/ownership/ACL-control allow entries for
any principal other than root or the effective user while accepting restrictive
deny entries. Linux accepts only audited local POSIX-mode filesystems and rejects
rich/NFSv4 ACL attributes and unknown filesystem types; other Unix platforms
fail closed. A relative root such as `../adapters` is supported for an explicitly
shared sibling tree, but every normalized endpoint must still remain below that
one declared root. Interpreter discovery applies the same opened-object ACL,
ownership, and writable-path trust rules. Python adapter execution is currently
fail-closed on Windows because
the interpreter file and every ancestor need DACL and identity validation that
is not yet implemented; inherited `PATH` and configured absolute paths are not
treated as trust proof. Python adapters run with `-I -B`, excluding user
site-packages, Python environment settings, bytecode writes, and unsafe
script-directory path injection before the staged self-contained adapter starts.
On Unix, adapter stdout and stderr are drained by one nonblocking poll loop with
fixed per-stream limits and deadlines. If an inherited writer keeps a pipe open
after the adapter exits, the run fails explicitly and closes both read pipes;
no background reader thread is detached.
All pilot runs require an existing model bundle and never create a synthetic fallback.
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
Evidence export first captures every source into a bounded, immutable temporary
snapshot and revalidates its opened-handle identity, length, modification time,
and SHA-256 before building the zip. Lab export is an explicit context: all five
top-level lab inputs (`scenario`, `acceptance`, `comparison`, multi-source
evidence, and aggregate connector health) are required rather than silently
omitted. Plain export includes only manifest-declared run artifacts plus extras
the caller explicitly marks as required.
Evidence, review, export, feedback, what-if, and evidence-bundle commands can
resolve indexed lab runs from the top-level `--artifacts artifacts` directory.

Version bumps are procedural: run `scripts/bump_version.sh <semver>`, then run
the validation gates above before tagging `v<semver>`.
