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

## Current Real-Device Status

Real-device pilot proof is `pending_lab_access` and
`real_device_validation=not_validated`. The current gates validate the software
workflow with CI-safe adapters, local trace samples, benchmark reports,
calibration artifacts, and model promotion gates. They are not evidence that
this checkout connected to a physical lab device.

The machine-readable status is
[`real-device-pilot-readiness.json`](real-device-pilot-readiness.json). Keep
`real_device_release_claim_eligible=false` until a real lab manifest produces a
reviewed preflight report, workflow report with after-run verification,
`connector_health.json`, evidence bundle manifest, and matching model promotion
gate report.

When the status eventually changes to `validated`, the referenced evidence
manifest must use `netdiag-real-device-evidence-manifest/v1`, set
`source_mode=real_device`, set `sample_only=false`, set
`collection_mode=live`, and bind a single `run_id`, `pilot_id`, and model
identity to SHA-256 entries for `pilot_preflight`, `pilot_workflow`,
`connector_health`, `evidence_bundle`, and `model_promotion_gate`. The
readiness gate parses and cross-checks those files; hashes by themselves are
not validation evidence.

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
Collection limits are enforced: timeout 1–300 seconds, lookback 1–86,400
seconds, step 1–3,600 seconds and no greater than lookback, packet limit
1–100,000, and interval 1–10 seconds. Out-of-range values fail preflight rather
than being silently clamped.
Pilot manifests only send bearer tokens when the source explicitly declares
`bearer_token_env`; they do not inherit a global token for every endpoint.
CLI pilot and lab commands additionally require one explicit external binding
for every declaration. Each repeatable binding supplies all four identity
fields, and the origin must already be canonical (scheme, host, and effective
port only):

```bash
netdiag pilot preflight pilot.yaml \
  --bearer-binding prometheus-primary prometheus-query \
  https://metrics.example.internal NETDIAG_API_TOKEN
```

The same `--bearer-binding SOURCE_NAME SOURCE_KIND CANONICAL_ORIGIN ENV_NAME`
form is accepted by `pilot preflight`, `pilot run`, `pilot workflow`, `lab
preflight`, `lab run`, and `lab batch`. Omitting bindings authorizes no
environment access. Partial, duplicate, extra, mismatched, non-HTTP, insecure,
or noncanonical bindings fail before token lookup and collection. Static
preflight validates identities without reading token values; live preflight and
run commands resolve every authorized token before network or artifact writes.

Adapter sources must declare both `metadata.adapter_contract` and
`adapter.mode`. Real-device collection uses `adapter.mode: live`; CI/sample
manifests use `adapter.mode: sample`. Sample-mode adapter output is valid for
schema and workflow smoke tests, but it is not real-device validation evidence.
Adapters are trusted executable code. A manifest containing one must declare a
relative `safety.adapter_execution_root`; each relative endpoint is
canonicalized and rejected if it is absolute or resolves outside that root.
The relative root may explicitly name a shared sibling tree such as
`../adapters`; normalization must still leave every endpoint below that single
declared root. On Unix, the canonical root, its complete ancestor chain, each
opened intermediate source directory, and the opened adapter file must be owned
by root or the effective user and must not be group/world-writable. Source path
components are opened without following symlinks, so a symlink or replacement
race fails closed. ACL checks use the same opened descriptors: macOS accepts
restrictive deny entries but rejects dangerous allow entries for any principal
other than root or the effective user; Linux accepts only audited local
POSIX-mode filesystems and rejects rich/NFSv4 ACL attributes and unknown
filesystem types. Other Unix platforms fail closed before adapter execution.
The root limits which adapter file can be selected; it is not an operating
system sandbox, so operators must inspect and trust the adapter itself.
Adapter endpoints must be regular, non-symlink files no larger than 2 MiB.
Static `pilot preflight` validates the path and contract without executing
Python. `pilot run` and `pilot workflow` execute the adapter contract preflight
only after the caller separately supplies `--allow-adapter-execution` (the
`--allow-active` gate does not substitute for it). Preflight and collection use
the same parsed manifest and opened adapter snapshot, so path replacement after
validation is not followed. NetDiag copies the adapter into a private,
read-only staging directory and starts it with a pre-resolved absolute Python
interpreter. The execution boundary separately creates and retains a private
`0700` runtime directory for the full preflight-and-collection lifetime. That
directory is the adapter working directory and the deterministic value of
`TMPDIR`, `TMP`, and `TEMP`; parent-process temp variables and the original
adapter parent directory are never inherited. Adapter bundles must currently be
self-contained: relative auxiliary files and implicit resources beside the
original script are unsupported and fail closed. A future resource mechanism
must declare and snapshot each resource before execution instead of restoring
original-directory lookup. On Unix, automatic interpreter discovery applies the same
descriptor-native ACL, root/effective-user ownership, and non-writable-ancestor
policy to PATH
directories and the interpreter. Python adapter execution is
currently fail-closed on Windows: neither inherited `PATH` nor a configured
absolute path is accepted until interpreter and ancestor DACL/identity
validation is implemented. The subprocess environment is cleared; only a sanitized
absolute-directory `PATH`, the boundary-owned temp values, and names listed in
`adapter.env_allowlist` are forwarded. Controlled loader/runtime names
(`PATH`, `PYTHON*`, `LD_*`, and `DYLD_*`) are rejected case-insensitively.
Python starts in isolated, no-bytecode mode (`-I -B`), so it ignores Python
environment settings, user site-packages, and unsafe script-directory path
injection before executing the staged self-contained adapter.
Unix stdout/stderr capture uses nonblocking polling with fixed memory and time
bounds. Output above 4 MiB/256 KiB fails immediately; if a descendant retains a
pipe after the adapter exits, NetDiag closes the read descriptors at the drain
deadline and reports the incomplete drain instead of leaving a reader behind.
Explicitly allowed environment values and every passthrough argument value are
exact-redaction secrets across stderr, payload
keys/values, ingest errors, and persisted payloads. Manifest size, source count,
adapter files, I/O, arguments, environment, and aggregate execution time are
bounded. Passthrough argument values are also redacted from persisted pilot
manifests; command-line secrets remain discouraged because process listings are
outside NetDiag's redaction boundary.

`pilot workflow` is the closed-loop command. It can still record a partial
workflow without `--after-run-id`, but that report leaves the `verify` phase
`pending` and the CLI exits non-zero. A workflow only passes when collection,
diagnosis, evidence export, and after-run verification gates all pass.

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
- `pilot_evidence_report.json`: immutable pre-export result payload without a
  recursive evidence-manifest field.
- `pilot_report.json`: final machine-readable run summary and gate outcome,
  written only after it includes the published evidence manifest.
- `pilot_workflow.json`: preflight, collect, diagnose, evidence, review, and
  verification phase summary.
- `pilot_summary.md`: human-readable handoff summary.
- `connector_health.json`: aggregate health for primary and corroborating
  sources.
- `source_<name>_redacted.json`: redacted, allow-listed source metadata snapshots
  when available; canonical records remain in the diagnosis artifacts.
- `runs/<run_id>/`: normal diagnosis artifacts.
- `netdiag-evidence-<run_id>.zip`: portable evidence bundle.
- Future closed-loop artifacts: `operator_decision.json`,
  `action_verification.json`, `baseline_run_id`, and `after_run_id`.

Pilot export is a distinct required evidence context. Before export, the run
finalizes redacted source payloads, aggregate connector health,
`pilot_evidence_report.json`, and `pilot_summary.md`. The bundle stores that
immutable payload as `pilot_report.json`, then requires and hashes the redacted
`pilot.yaml`, connector health, final summary, and any available redacted source
payloads alongside the nested diagnosis artifacts. The bundled payload omits the
`evidence_bundle` field to avoid a recursive report -> bundle manifest -> report
hash contract. After export, the manifest is stored as
`runs/<run_id>/evidence_bundle.json`, attached to the returned result, and
atomically written into the final top-level `pilot_report.json`. Successful
export therefore binds the final gate result without self-reference while the
external final report still contains the evidence manifest; missing required
Pilot files fail instead of being skipped.

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

The v0.5.3 gate enforces known-label coverage, explicit OOD benchmark preflight
coverage, and behavior-level OOD calibration. Promotion requires a fresh
`lab_calibration_report.json` whose model manifest hash, model file hash,
dataset hash, and calibrated thresholds match the bundle being promoted. The
benchmark report must be generated with the same `--model-dir` so its candidate
model hashes also match.

Run the gate with:

```bash
cargo run -p netdiag-cli -- pilot model-gate \
  --model-dir artifacts/model \
  --benchmark-report target/benchmark-report/benchmark_report.json \
  --calibration-report artifacts/lab_calibration_report.json \
  --min-rows-per-label 10 \
  --min-accuracy 0.90 \
  --min-macro-f1 0.90 \
  --max-ood-false-positive-rate 0.05 \
  --max-ood-false-negative-rate 0.05 \
  --max-rule-ml-disagreement-hotspot-rate 0.10
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
