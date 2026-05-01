# NetDiag Twin

## Rust-native telemetry diagnosis and digital-twin validation

NetDiag Twin is now a pure Rust desktop application and CLI for telemetry-driven network diagnosis. It compares evidence-first rules with Rust ML inference, runs graph-backed what-if validation over a digital twin topology, and writes reproducible run artifacts for human review.

## Product Flow

1. Trace Input
2. Telemetry Dashboard
3. Diagnosis Result
4. Rule vs ML Comparison
5. Digital Twin / Topology View
6. Recommendation Report

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

Release packaging also creates `target/release/NetDiag Twin-<version>.dmg`.
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

Generate Sparkle appcast metadata after packaging:

```bash
SPARKLE_PRIVATE_KEY="..." scripts/generate_appcast.sh target/release
```

GitHub Actions provide CI and release workflows. The release workflow requires
`CODESIGN_IDENTITY`, `NETDIAG_SPARKLE_PUBLIC_KEY`, `SPARKLE_PRIVATE_KEY`, and
`NETDIAG_NOTARY_PROFILE` secrets before it will publish assets.

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
- `Live collection`: source profiles for local host probes, website/Cloudflare-style probes, HTTP/JSON lab adapters, Prometheus `query_range`, and Prometheus `/metrics` exposition. Tokens use macOS Keychain with environment-variable fallback.

See [docs/api-source.md](docs/api-source.md) for the connector and HTTP/JSON lab adapter contract.

Run a batch diagnosis:

```bash
cargo run -p netdiag-cli -- diagnose data/samples/congestion.csv
```

Run a connector smoke without opening the GUI:

```bash
cargo run -p netdiag-cli -- collect --kind prometheus-metrics --endpoint http://127.0.0.1:9100/metrics
cargo run -p netdiag-cli -- collect --kind prometheus-query --endpoint http://127.0.0.1:9090 --diagnose
cargo run -p netdiag-cli -- collect --kind http-json --endpoint https://example.internal/netdiag/trace
```

Run a what-if action against an existing run:

```bash
cargo run -p netdiag-cli -- whatif <run_id> line reroute_path_b
```

Export a saved report:

```bash
cargo run -p netdiag-cli -- export <run_id>
```

Review a recommendation and persist HIL state:

```bash
cargo run -p netdiag-cli -- review <run_id> <recommendation_id> --state accepted --notes "approved for lab run"
```

## Validation

```bash
cargo fmt --check --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTFLAGS="-D warnings" cargo test --workspace
scripts/check_perf_budget.sh
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

## Artifacts

Runs are written to `artifacts/runs/<run_id>/`:

- `manifest.json`
- `trace_schema.json`
- `telemetry_summary.json`
- `telemetry_windows.json`
- `diagnosis_events.json`
- `ml_result.json`
- `whatif_*.json`
- `recommendations.json`
- `hil_feedback.json` after human review
- `report.json`

The Rust ML model cache is generated under `artifacts/model/` when needed.
