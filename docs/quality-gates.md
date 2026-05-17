# Rust CLI Quality Gates

NetDiag Twin v0.5 treats quality gates as product functionality. The goal is
not to hide real defects behind fallback patches, but to catch complexity,
performance, stability, robustness, dependency, and memory-safety regressions
before pilot users depend on a build.

## Gate Levels

Use the fast gate for every PR:

```bash
scripts/check_rust_quality.sh fast
```

Use the strict gate before v0.5 release candidates and model promotion:

```bash
NETDIAG_COVERAGE_MIN=90 scripts/check_rust_quality.sh strict
```

The strict gate requires:

- `cargo-nextest` 0.9.136
- `cargo-llvm-cov` 0.8.7
- `cargo-deny` 0.19.6
- `cargo-machete` 0.9.2

## Fast Gate

The fast gate runs:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `RUSTFLAGS="-D warnings" cargo test --workspace`
- `scripts/validate_adapter_samples.py`
- `scripts/validate_adapter_contract.py`
- `python3 scripts/check_complexity.py`
- `scripts/check_architecture_guard.sh`
- `scripts/check_perf_budget.sh`

This is intentionally close to the existing CI contract, with the new
complexity guard added so v0.5 modules do not grow into the same shape as the
legacy large files.

## Strict Gate

The strict gate adds:

- `cargo nextest run --workspace --lib --bins --tests`
- `RUSTFLAGS="-D warnings" cargo nextest run --workspace --lib --bins --tests`
- `cargo llvm-cov nextest --workspace --lib --bins --tests --summary-only --json`
- `scripts/check_coverage_summary.py` with `NETDIAG_COVERAGE_MIN=90`
- `cargo deny --locked check --hide-inclusion-graph`
- `cargo machete`
- Generic Lab Kit adapter contract validation
- Release benchmark report generation
- Pilot smoke workflow through `pilot preflight` and `pilot workflow`
- Optional Miri with `NETDIAG_RUN_MIRI=1`

The cargo-deny invocation is also wrapped by the strict gate and fails if the
command emits any `warning[...]` diagnostics. Duplicate dependencies are set to
`deny`; every current transitive duplicate must be an exact version-pinned
`skip` entry with an audit reason in `deny.toml`, and
`scripts/check_deny_waivers.py` rejects broad `skip-tree` entries.

The strict release gate enforces at least 90% line coverage on the v0.5
Pilot/CLI release-critical slice:

- `crates/netdiag-core/src/pilot.rs`
- `crates/netdiag-core/src/pilot/*`
- `crates/netdiag-cli/src/commands/pilot.rs`

The full workspace coverage report is still generated on every strict run and
guarded by `NETDIAG_WORKSPACE_COVERAGE_MIN` as a ratchet floor. This is
deliberate: the current desktop GUI and legacy large modules are not hidden, but
they are not allowed to make the v0.5 Pilot/CLI release gate meaningless. Do not
claim full-workspace 90% until the app and legacy split work have tests to back
that number.

## Complexity Policy

`scripts/check_complexity.py` enforces two ideas:

- New Rust modules should stay under 800 lines, functions under 120 lines, and
  branch-heavy functions below the default branch heuristic.
- Existing large files are grandfathered with exact ratchet limits so they
  cannot grow while we split them.

Current high-priority split targets:

- `crates/netdiag-app/src/main.rs`: views, capture sessions, evidence console,
  settings UI, i18n.
- `crates/netdiag-core/src/lab.rs`: scenario, preflight, runner, acceptance,
  verification, calibration, index, corroboration.
- `crates/netdiag-core/src/connectors.rs`: HTTP JSON, Prometheus, OTLP, pcap,
  system counters, provenance.
- `crates/netdiag-cli/src/main.rs`: collect, lab, dataset, topology, policy,
  and perf dispatch into `commands/*`.
- `crates/netdiag-core/src/ml.rs`: features, training, inference, uncertainty,
  manifest, and dataset export.

## Memory And Stability

Rust prevents most memory leaks and use-after-free defects, but v0.5 should add
nightly and platform-specific checks before release:

- `unsafe_code = "forbid"` is enabled for core and CLI crates. The desktop app
  has macOS/Sparkle FFI and should isolate unsafe code behind small reviewed
  modules instead of pretending it can be globally forbidden today.
- Run Miri on focused unit tests that avoid network, pcap, GUI, and process
  spawning.
- Run sanitizer builds on Linux CI for connector parsers and ingest paths where
  dependencies support them.
- Keep pcap and OTLP capture loops cancellable and timeout-bound.
- Prefer explicit error propagation over silent fallback when telemetry is
  missing, malformed, or permission-blocked.

## Coverage Ownership

Coverage is not just a global number. The 90% strict gate is scoped to the
v0.5 Pilot/CLI release surface while the workspace total is reported and
ratcheted:

- v0.5 Pilot/CLI release surface: at least 90% aggregate line coverage.
- Workspace total: never decrease below the configured ratchet floor.
- `lab`, `connectors`, app UI, and CLI main dispatch: split large files and
  ratchet module coverage upward as ownership improves.
- Parser, schema, redaction, artifact integrity, and model promotion code:
  branch-focused tests for all failure modes.

Do not add low-value tests that only execute lines. Prefer tests that prove
operator safety, artifact reproducibility, source quality, and failure
transparency.
