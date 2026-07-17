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
NETDIAG_COVERAGE_MIN=90 NETDIAG_WORKSPACE_COVERAGE_MIN=79.5 \
NETDIAG_APP_SECURITY_COVERAGE_MIN=80 \
NETDIAG_APP_SECURITY_FILE_COVERAGE_MIN=50 \
scripts/check_rust_quality.sh strict
```

The strict gate requires:

- `cargo-nextest` 0.9.136
- `cargo-llvm-cov` 0.8.7
- `cargo-deny` 0.19.6
- `cargo-machete` 0.9.2

## Fast Gate

The fast gate runs:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test --locked --workspace --all-features`
- `python3 scripts/test_quality_guards.py`
- `python3 scripts/check_workspace_publish_policy.py`
- `python3 scripts/check_patch_contract_hygiene.py`
- explicit metadata, test, and warning-denied Clippy for every local patch
  contract
- one locked `netdiag-cli` build with
  `CARGO_TARGET_DIR="$(pwd -P)/target/adapter-validator"`
- `.venv-jsonschema/bin/python scripts/validate_adapter_samples.py
  --rust-validator "$(pwd -P)/target/adapter-validator/debug/netdiag-cli"`
- `.venv-jsonschema/bin/python scripts/validate_adapter_contract.py
  --rust-validator "$(pwd -P)/target/adapter-validator/debug/netdiag-cli"`
- `python3 scripts/check_release_gate_hygiene.py`
- `python3 scripts/check_docs_workflow_hygiene.py`
- `python3 scripts/check_real_device_readiness.py`
- `python3 scripts/check_complexity.py`
- `scripts/check_architecture_guard.sh`
- `python3 scripts/check_architecture_guard_sanity.py`
- `scripts/check_perf_budget.sh`

This is intentionally close to the existing CI contract, with the new
complexity guard added so v0.5 modules do not grow into the same shape as the
legacy large files.

## Strict Gate

The strict gate adds:

- `RUSTFLAGS="-D warnings" cargo nextest run --locked --workspace --all-features --lib --bins --tests`
- `cargo test --locked -p netdiag-core --bench perf_budget --all-features`
- `python3 scripts/test_quality_guards.py`
- `python3 scripts/check_workspace_publish_policy.py`
- explicit independent `cargo metadata`, all-feature tests, and warning-denied
  Clippy for every local patch contract
- `cargo llvm-cov nextest -p netdiag-core -p netdiag-cli -p netdiag-platform --all-features --lib --bins --tests --test-threads 1 --summary-only --json`
- `scripts/check_coverage_summary.py` with `NETDIAG_COVERAGE_MIN=90` and the
  measured core/CLI/platform workspace ratchet floor, cross-checked against rustc
  dep-info from the coverage build
- an independent `cargo llvm-cov nextest -p netdiag-app --all-features --lib
  --bins --tests --test-threads 1 --summary-only --json` run
- `scripts/check_app_security_coverage.py` with an 80% aggregate floor and a 50%
  per-file floor for the credential lifecycle, secret storage, API-test status,
  and destructive-action confirmation modules, cross-checked against both the
  library and binary dep-info
- `cargo deny fetch db`, then `cargo deny --locked check --hide-inclusion-graph --disable-fetch`
- `cargo machete`
- Generic Lab Kit adapter contract validation
- Lab calibration, followed by release benchmark generation with the calibrated
  candidate `--model-dir`, followed by `pilot model-gate`
- Pilot smoke workflow through `pilot preflight`, `diagnose`, and `pilot workflow --after-run-id` so the verify phase completes
- Optional Miri with `NETDIAG_RUN_MIRI=1`

The cargo-deny invocation is also wrapped by the strict gate. It refreshes the
RustSec advisory database before running the offline check so a stale or missing
runner cache cannot mask the real dependency result, and it fails if either step
emits warning diagnostics. Duplicate dependencies are set to
`deny`; every current transitive duplicate must be an exact version-pinned
`skip` entry with an audit reason in `deny.toml`, and
`scripts/check_deny_waivers.py` rejects broad `skip-tree` entries.
No RustSec advisory waiver is currently active. Security compatibility patches
under `third_party/` must retain the upstream license and source provenance,
describe the exact behavioral delta in `PATCH.md`, and define a verifiable
removal condition. The local argmin 0.11.0 patch removes `paste` from the
production dependency graph without changing its numeric algorithms or public
bulk method names. `scripts/check_patch_contract_hygiene.py` requires every
local patch directory to remain excluded from the root workspace, independently
parses its manifest, maps it to exactly one executable workspace contract, and
verifies that the strict script explicitly runs that contract's all-feature
tests and warning-denied Clippy. Each patch also carries a bounded
`PATCH_PROVENANCE.json` containing the published crate archive SHA-256, a hash
for every upstream file, and exact modified/added/removed allow-lists. The
normal gate verifies the complete local snapshot offline and rejects undeclared
files, missing files, symlinks, content drift, duplicate manifest keys, and any
change under a published `tests/` directory. When original `.crate` files are
available, `python3 scripts/check_patch_contract_hygiene.py --archive-dir DIR`
also verifies their raw SHA-256 and archive inventory without network access.
The restored Wayland scanner test assets execute directly, and both their test
run and warning-denied Clippy are required by the strict gate.

The strict release gate enforces at least 90% line coverage for every
llvm-cov-reportable production file in the Pilot, CLI, and executable-code or
temporary-storage trust release-critical slice, and for the slice in aggregate:

- `crates/netdiag-core/src/pilot.rs`
- `crates/netdiag-core/src/pilot/*`
- `crates/netdiag-cli/src/commands/pilot.rs`
- `crates/netdiag-cli/src/commands/pilot/*`
- `crates/netdiag-core/src/python_runtime.rs`
- `crates/netdiag-core/src/python_runtime/*`
- `crates/netdiag-platform/src/system_temporary_root.rs`
- `crates/netdiag-platform/src/trusted_directory.rs`
- `crates/netdiag-platform/src/trusted_directory/strict.rs`
- `crates/netdiag-platform/src/trusted_directory/unix.rs`
- `crates/netdiag-platform/src/trusted_directory/unix/*`
- `crates/netdiag-platform/src/trusted_temp_directory.rs`
- `crates/netdiag-platform/src/trusted_temp_directory/{cleanup,create,finish}.rs`
- `crates/netdiag-platform/src/trusted_temp_directory/create/name.rs`
- `crates/netdiag-platform/src/trusted_temp_directory/create/platform/unix.rs`
- `crates/netdiag-platform/src/trusted_temp_directory/identity/unix.rs`
- `crates/netdiag-platform/src/unix_acl.rs`

The strict coverage run covers the Rust core, CLI, and platform release surface and is
guarded by `NETDIAG_WORKSPACE_COVERAGE_MIN` as a ratchet floor. Coverage totals
are recomputed from individual core/CLI/platform production files; files from
GUI, test, or patch-contract crates cannot raise the result. The critical file
inventory is generated from the checked-out release-critical source tree and every
entry must appear in rustc's dep-info for the coverage build. Declaration-only
modules with no instrumentable lines may therefore be absent from llvm-cov
without being misreported as missing coverage. For reportable files, the gate
requires llvm-cov's totals to equal the exact sum of all file summaries, so a
dropped file cannot silently disappear from the denominator; every reported
critical file must also meet the per-file floor. Source-level `coverage(off)`
attributes and environment flags that filter reports or disable instrumentation
are rejected before coverage runs. The default floor is 79.5% for
the measured core/CLI/platform llvm-cov merge.

The desktop app remains excluded from that merge so GUI dependencies cannot
inflate or destabilize the core/CLI/platform result. A second, independent
instrumented run covers the app library and binary security boundary. It
requires at least 80% aggregate line coverage and at least 50% for each selected
production file. The selected inventory contains the credential lifecycle,
secret storage, API-test status, and destructive-action confirmation module
roots and automatically discovers their production submodules. Every selected
file must be present in the matching library or binary rustc dep-info and in the
llvm-cov summary. This is an app security-boundary claim, not GUI-wide or full
workspace coverage.

## Cross-Platform Consumer Gate

The reusable `platform-security` matrix runs on Ubuntu and Windows. Both runners
compile and lint `netdiag-platform`, `netdiag-core`, `netdiag-cli`, and
`netdiag-app` with rustc warnings denied. Ubuntu executes the full platform and
consumer test suite and runs warning-denied Clippy across all `netdiag-platform`
targets for `wasm32-wasip1`; this is a compile-only proof that unsupported
operating-system boundaries and their contracts build and fail closed, not a claim
of WASI runtime support. Windows
executes every native platform test plus a dedicated
public-API contract proving that Unix-only model, dataset, HIL, and run-directory
mutations return typed `NotPublished` errors without creating output; running the
Unix success suite on Windows would contradict the product capability boundary.
The same compile lane covers the bounded benchmark-validator boundary's explicit
non-Unix failure path; it does not claim that the Python validators execute on
Windows.
Ubuntu installs ACL and libpcap fixtures. Windows builds libpcap from a pinned
vcpkg commit with the null live-capture backend and the `wpcap` ABI name; this
executes offline pcap parsing without requiring a privileged capture driver. The
setup fails before Cargo if either the import library or runtime DLL is absent.
Because GitHub's Ubuntu workspace inherits a default ACL from `/home`, the Linux
runtime suite is executed from a private `0700` checkout atomically created by
`sudo mktemp` beneath root-owned, non-writable `/opt`, then assigned to the runner.
The harness verifies that this checkout is the exact caller SHA and treats cleanup
failure as a job failure; the production trusted-directory policy is never relaxed
for CI. A private child beneath sticky, world-writable `/tmp` is intentionally not
used because the strict adapter trust chain validates every ancestor.

Both CI and Release call this same reusable workflow, so a tag cannot bypass
native Windows validation. Release additionally requires a successful main CI
run for the exact tagged SHA before any signing or publication side effect. The
release workflow serializes each version, refuses to rebuild an existing formal
Release, and performs the final locked build in a fresh exact-SHA macOS job that
has no release secrets and does not install Python or quality tooling. A second
fresh exact-SHA runner accepts only the sealed binary and checksum manifest,
validates both before importing signing keys, and cannot run Cargo or mutate its
checkout. Packaging recreates Sparkle from its hash-pinned archive and uses an
explicit no-build path while the signing keychain is unlocked. Publication uses
atomic release creation, followed by a read-only verifier that downloads the
exact remote asset set, checks its digest, validates GitHub's release attestation
for every asset, and compares every file byte-for-byte before Pages or Homebrew
can run.

## Real-Device Evidence Policy

Real-device pilot proof is currently `pending_lab_access` /
`real_device_validation=not_validated`. Strict gates run CI-safe pilot and lab
smoke flows, but they do not prove physical lab-device connectivity. The
release gate runs `scripts/check_real_device_readiness.py` so documentation and
machine-readable status stay fail-closed until
`docs/real-device-pilot-readiness.json` points to reviewed real-device
evidence. A validated manifest must declare `collection_mode=live`, bind one
run, pilot, and model identity, and reference five hash-matching JSON artifacts
whose schemas, pass states, connector health, workflow verification, bundle
identity, and model identity all pass semantic cross-checks.

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
- Windows crash-durable file replacement is isolated in `netdiag-platform`:
  core calls its safe boundary after syncing
  the temporary file, while the adapter invokes `MoveFileExW` with
  `REPLACE_EXISTING | WRITE_THROUGH`. It never deletes the destination first or
  falls back to a non-write-through rename. Platforms without either Unix
  rename-plus-directory-sync or the reviewed Windows path fail before rename;
  unsupported cases are never reported as durable success.
- Run Miri on focused unit tests that avoid network, pcap, GUI, and process
  spawning.
- Run sanitizer builds on Linux CI for connector parsers and ingest paths where
  dependencies support them.
- Keep pcap and OTLP capture loops cancellable and timeout-bound. OTLP must
  remain loopback-only unless a complete authenticated transport mode is
  designed, must configure the generated tonic decoding limit explicitly, and
  must never queue raw `ExportMetricsServiceRequest` values.
- Prefer explicit error propagation over silent fallback when telemetry is
  missing, malformed, or permission-blocked.

## Coverage Ownership

Coverage is not just a global number. The 90% strict gate is scoped to the
Pilot/CLI and executable-code or temporary-storage trust release surface while the measured
workspace total is reported and
ratcheted:

- Release-critical Pilot/CLI and trust surface: at least 90% line coverage for every
  llvm-cov-reportable production file and for the aggregate slice.
- Measured core/CLI/platform workspace total: never decrease below the configured
  ratchet floor.
- App credential, secret, API-test status, and destructive confirmation modules:
  at least 80% aggregate line coverage and 50% per production file in their
  independent library-and-binary coverage run.
- `lab`, `connectors`, remaining app UI, and CLI main dispatch: split large files and
  ratchet module coverage upward as ownership improves.
- Parser, schema, redaction, artifact integrity, and model promotion code:
  branch-focused tests for all failure modes.

Do not add low-value tests that only execute lines. Prefer tests that prove
operator safety, artifact reproducibility, source quality, and failure
transparency.
