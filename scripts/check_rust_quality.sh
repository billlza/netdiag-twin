#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-fast}"
COVERAGE_MIN="${NETDIAG_COVERAGE_MIN:-90}"
WORKSPACE_COVERAGE_MIN="${NETDIAG_WORKSPACE_COVERAGE_MIN:-55}"
STRICT_COVERAGE_FLOOR="90"
STRICT_WORKSPACE_COVERAGE_FLOOR="55"

cd "$ROOT"

require_tool() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required tool: $name" >&2
    exit 2
  fi
}

require_cargo_subcommand() {
  local name="$1"
  if ! cargo "$name" --version >/dev/null 2>&1; then
    echo "missing required cargo subcommand: cargo $name" >&2
    exit 2
  fi
}

schema_python() {
  if [[ -x .venv-jsonschema/bin/python ]]; then
    echo ".venv-jsonschema/bin/python"
  else
    echo "python3"
  fi
}

run_adapter_contracts() {
  local python
  python="$(schema_python)"
  "$python" scripts/validate_adapter_samples.py
  "$python" scripts/validate_adapter_contract.py
}

run_cargo_deny_clean() {
  local fetch_output
  local output

  if ! fetch_output="$(cargo deny fetch db 2>&1)"; then
    printf '%s\n' "$fetch_output" >&2
    return 1
  fi

  if grep -E '(^|[[:space:]])warning(\[|:)' <<<"$fetch_output" >/dev/null; then
    printf '%s\n' "$fetch_output" >&2
    echo "cargo-deny advisory fetch emitted warnings; strict release gate requires clean output" >&2
    return 1
  fi

  if ! output="$(cargo deny --locked check --hide-inclusion-graph --disable-fetch 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi

  if grep -E '(^|[[:space:]])warning(\[|:)' <<<"$output" >/dev/null; then
    printf '%s\n' "$output" >&2
    echo "cargo-deny emitted warnings; strict release gate requires clean output" >&2
    return 1
  fi

  printf '%s\n' "$fetch_output"
  printf '%s\n' "$output"
}

strict_floor() {
  local value="$1"
  local floor="$2"
  local name="$3"
  python3 - "$value" "$floor" "$name" <<'PY'
import sys

value_raw, floor_raw, name = sys.argv[1:]
try:
    value = float(value_raw)
    floor = float(floor_raw)
except ValueError as exc:
    raise SystemExit(f"{name} must be numeric: {exc}")

if value < floor:
    print(
        f"{name}={value:g} is below strict release floor {floor:g}; using {floor:g}",
        file=sys.stderr,
    )
    value = floor
print(f"{value:g}")
PY
}

run_pilot_smoke() {
  cargo run --quiet -p netdiag-cli -- train \
    --dataset examples/datasets/pilot-smoke-training.jsonl \
    --model-dir target/pilot-artifacts/model \
    --validation-split 0 \
    --min-rows-per-label 1
  cargo run --quiet -p netdiag-cli -- pilot preflight examples/pilots/loopback-mock.yaml \
    --artifacts target/pilot-artifacts
  local after_run_id
  after_run_id="$(
    cargo run --quiet -p netdiag-cli -- diagnose data/samples/normal.csv \
      --artifacts target/pilot-artifacts \
      | python3 -c 'import json, sys; print(json.load(sys.stdin)["run_id"])'
  )"
  cargo run --quiet -p netdiag-cli -- pilot workflow examples/pilots/loopback-mock.yaml \
    --artifacts target/pilot-artifacts \
    --after-run-id "$after_run_id"
  python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

artifacts = Path("target/pilot-artifacts")
model_dir = artifacts / "model"
manifest_path = model_dir / "model_manifest.json"
model_path = model_dir / "rust_logistic_model.json"
manifest = json.loads(manifest_path.read_text())
thresholds = manifest.get("uncertainty_thresholds")
if not thresholds:
    raise SystemExit("pilot smoke model manifest is missing uncertainty_thresholds")

labels = [
    "normal",
    "congestion",
    "random_loss",
    "dns_failure",
    "tls_failure",
    "udp_quic_blocked",
]
per_label = {
    label: {
        "runs": 1,
        "accepted_known_runs": 1,
        "rule_correct": 1,
        "ml_correct": 1,
        "rule_accuracy": 1.0,
        "ml_accuracy": 1.0,
        "known_rate": 1.0,
        "uncertain_rate": 0.0,
        "out_of_distribution_rate": 0.0,
    }
    for label in labels
}
report = {
    "schema": "netdiag-lab-calibration/v1",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "artifact_root": str(artifacts),
    "model_manifest_path": str(manifest_path),
    "model_manifest_hash_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    "model_file_hash_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
    "dataset_hash_sha256": manifest.get("dataset_hash_sha256"),
    "evaluated_runs": len(labels) + 1,
    "known_runs": len(labels),
    "uncertain_runs": 0,
    "out_of_distribution_runs": 1,
    "skipped_runs": 0,
    "per_label": per_label,
    "ood": {
        "expected_ood_runs": 1,
        "expected_known_runs": len(labels),
        "false_positive_runs": 0,
        "false_negative_runs": 0,
        "false_positive_rate": 0.0,
        "false_negative_rate": 0.0,
    },
    "rule_ml_disagreement_hotspots": [],
    "feature_distance_distribution": {
        "count": len(labels) + 1,
        "p50": 1.0,
        "p95": 2.0,
        "max": 3.0,
    },
    "suggested_rule_thresholds": {},
    "applied": True,
    "calibrated_thresholds": thresholds,
    "warnings": [],
}
(artifacts / "lab_calibration_report.json").write_text(json.dumps(report, indent=2) + "\n")
PY
  cargo run --quiet -p netdiag-cli -- pilot model-gate \
    --model-dir target/pilot-artifacts/model \
    --benchmark-report target/benchmark-report/benchmark_report.json \
    --calibration-report target/pilot-artifacts/lab_calibration_report.json \
    --min-rows-per-label 1 \
    --allow-missing-evaluation
}

run_fast() {
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  RUSTFLAGS="-D warnings" cargo test --workspace
  run_adapter_contracts
  python3 scripts/check_complexity.py
  scripts/check_architecture_guard.sh
  scripts/check_perf_budget.sh
}

run_strict() {
  require_tool python3
  require_cargo_subcommand nextest
  require_cargo_subcommand llvm-cov
  require_cargo_subcommand deny
  require_cargo_subcommand machete

  local coverage_min
  local workspace_coverage_min
  coverage_min="$(strict_floor "$COVERAGE_MIN" "$STRICT_COVERAGE_FLOOR" NETDIAG_COVERAGE_MIN)"
  workspace_coverage_min="$(strict_floor "$WORKSPACE_COVERAGE_MIN" "$STRICT_WORKSPACE_COVERAGE_FLOOR" NETDIAG_WORKSPACE_COVERAGE_MIN)"

  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo nextest run --workspace --lib --bins --tests
  RUSTFLAGS="-D warnings" cargo nextest run --workspace --lib --bins --tests
  cargo llvm-cov clean --workspace
  cargo llvm-cov nextest --workspace --exclude netdiag-app --lib --bins --tests \
    --test-threads 1 \
    --summary-only \
    --json \
    --output-path target/llvm-cov-workspace-summary.json
  python3 scripts/check_coverage_summary.py \
    --summary target/llvm-cov-workspace-summary.json \
    --critical-min "$coverage_min" \
    --workspace-min "$workspace_coverage_min"
  run_cargo_deny_clean
  python3 scripts/check_deny_waivers.py
  cargo machete
  python3 scripts/check_pilot_cli_wiring.py
  run_adapter_contracts
  python3 scripts/check_complexity.py
  scripts/check_architecture_guard.sh
  scripts/check_perf_budget.sh
  cargo run --quiet --release -p netdiag-cli -- benchmark run \
    --artifacts target/benchmark-artifacts \
    --output target/benchmark-report
  run_pilot_smoke
  if [[ "${NETDIAG_RUN_MIRI:-0}" == "1" ]]; then
    cargo miri test --workspace
  fi
}

case "$MODE" in
  fast)
    run_fast
    ;;
  strict)
    run_strict
    ;;
  *)
    echo "usage: scripts/check_rust_quality.sh [fast|strict]" >&2
    exit 2
    ;;
esac
