# Real-Device Pilot Readiness

Real-device pilot proof: `pending_lab_access`.

The v0.5.3 quality gates prove the software path with CI-safe adapters, local
trace samples, benchmark artifacts, calibration artifacts, and model promotion
gates. They do not prove that NetDiag Twin has connected to a physical lab
device in this environment.

Machine-readable status lives in
[`docs/real-device-pilot-readiness.json`](real-device-pilot-readiness.json):

- `real_device_validation`: `not_validated`
- `real_device_release_claim_eligible`: `false`
- `blocking_reason`: `lab_device_access_unavailable`

Do not describe a release as physically lab-validated until the status file
points to a reviewed evidence manifest produced from real lab devices. The
required evidence is:

- A `pilot preflight` report from a real lab manifest.
- A `pilot workflow` report with a real `--after-run-id` verification.
- `connector_health.json` from real device sources.
- An evidence bundle manifest with SHA-256 file hashes.
- A model promotion gate report matching the promoted model, benchmark, and
  calibration artifacts.

The reviewed evidence manifest must use
`netdiag-real-device-evidence-manifest/v1`, set `source_mode=real_device`, set
`sample_only=false`, set `collection_mode=live`, and bind one non-empty
`run_id`, `pilot_id`, and model identity to every required artifact descriptor.
Each descriptor must repeat the same `run_id` and carry the SHA-256 of the
referenced JSON file. Sample-mode adapter output is valid for smoke tests only;
it is not eligible real-device evidence.

The readiness gate parses the five referenced artifacts instead of trusting
their hashes alone:

- `pilot_preflight` must use `netdiag-pilot-preflight/v1`, pass, contain exactly
  one primary source, and have no failed preflight checks.
- `pilot_workflow` and its nested pilot report must pass; collection, diagnosis,
  evidence export, and after-run verification phases must pass; the verification
  verdict must be `verified`.
- `connector_health` must be a non-empty array of real connector health
  snapshots with positive row counts and no `error` source.
- `evidence_bundle` must use `netdiag-evidence-bundle/v1`, match the reviewed
  run, and contain non-empty, hash-addressed file entries.
- `model_promotion_gate` must pass, include the model/benchmark/calibration
  identity gates, and match the reviewed model manifest and model file hashes.

The standalone preflight, connector health, and evidence bundle files must be
byte-hash-addressed and semantically identical to the corresponding values
embedded in the workflow report. A validated status also fails if any status
document still says `pending_lab_access` or `not_validated`.
