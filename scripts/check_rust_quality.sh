#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODE="${1:-fast}"
COVERAGE_MIN="${NETDIAG_COVERAGE_MIN:-90}"
WORKSPACE_COVERAGE_MIN="${NETDIAG_WORKSPACE_COVERAGE_MIN:-79.5}"
APP_SECURITY_COVERAGE_MIN="${NETDIAG_APP_SECURITY_COVERAGE_MIN:-80}"
APP_SECURITY_FILE_COVERAGE_MIN="${NETDIAG_APP_SECURITY_FILE_COVERAGE_MIN:-50}"
STRICT_COVERAGE_FLOOR="90"
STRICT_WORKSPACE_COVERAGE_FLOOR="79.5"
STRICT_APP_SECURITY_COVERAGE_FLOOR="80"
STRICT_APP_SECURITY_FILE_COVERAGE_FLOOR="50"

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
  local interpreter=".venv-jsonschema/bin/python"
  if [[ ! -f "$interpreter" || -L "$interpreter" || ! -x "$interpreter" ]]; then
    echo "missing trusted schema Python: recreate it with 'python3 -m venv --clear --copies .venv-jsonschema' and install requirements-jsonschema.lock with --require-hashes and --only-binary=:all:" >&2
    return 2
  fi
  printf '%s\n' "$interpreter"
}

run_adapter_contracts() {
  local python
  local validator
  local validator_target_dir
  python="$(schema_python)"
  validator_target_dir="$ROOT/target/adapter-validator"
  validator="$validator_target_dir/debug/netdiag-cli"
  CARGO_TARGET_DIR="$validator_target_dir" cargo build --locked --quiet \
    -p netdiag-cli --bin netdiag-cli
  "$python" scripts/validate_adapter_samples.py --rust-validator "$validator"
  "$python" scripts/validate_adapter_contract.py --rust-validator "$validator"
}

run_python_quality_guards() {
  local python
  python="$(schema_python)"
  "$python" -W error::ResourceWarning scripts/test_quality_guards.py
}

run_patch_contracts() {
  cargo metadata --locked --offline --no-deps --format-version 1 \
    --manifest-path third_party/argmin-0.11.0/Cargo.toml >/dev/null
  cargo metadata --locked --offline --no-deps --format-version 1 \
    --manifest-path third_party/wayland-scanner-0.31.10/Cargo.toml >/dev/null
  cargo test --locked --offline \
    --target-dir target/patch-contracts/wayland-scanner-upstream \
    --manifest-path third_party/wayland-scanner-0.31.10/Cargo.toml \
    --all-targets --all-features
  cargo clippy --locked --offline \
    --target-dir target/patch-contracts/wayland-scanner-upstream \
    --manifest-path third_party/wayland-scanner-0.31.10/Cargo.toml \
    --all-targets --all-features -- -D warnings
  cargo test --locked -p netdiag-argmin-patch-contract \
    --all-targets --all-features
  cargo clippy --locked -p netdiag-argmin-patch-contract \
    --all-targets --all-features -- -D warnings
  cargo test --locked -p netdiag-wayland-scanner-patch-contract \
    --all-targets --all-features
  cargo clippy --locked -p netdiag-wayland-scanner-patch-contract \
    --all-targets --all-features -- -D warnings
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
  (
  umask 077
  mkdir -p "$ROOT/target"

  local workspace
  local artifacts
  local scenarios
  local training_dataset
  local benchmark_artifacts
  local benchmark_report
  local benchmark_report_archive
  local published_benchmark_report
  workspace="$(mktemp -d "$ROOT/target/pilot-smoke.XXXXXX")"
  artifacts="$workspace/artifacts"
  scenarios="$workspace/scenarios"
  training_dataset="$workspace/input/pilot-smoke-training-expanded.jsonl"
  benchmark_artifacts="$workspace/benchmark-artifacts"
  benchmark_report="$workspace/benchmark-report"
  benchmark_report_archive="$ROOT/target/benchmark-reports"
  published_benchmark_report="$benchmark_report_archive/${workspace##*/}"

  cleanup_pilot_smoke() {
    local status=$?
    trap - EXIT HUP INT TERM
    if (( status != 0 )); then
      echo "failed pilot smoke workspace preserved for diagnosis: $workspace" >&2
      exit "$status"
    fi
    if [[ "$workspace" != "$ROOT"/target/pilot-smoke.?????? \
      || ! -d "$workspace" \
      || -L "$workspace" \
      || ! -f "$artifacts/.netdiag-artifact-root.json" \
      || -L "$artifacts/.netdiag-artifact-root.json" ]]; then
      echo "refusing to clean an unverified pilot smoke workspace: $workspace" >&2
      exit 1
    fi
    if ! rm -rf -- "$workspace"; then
      echo "failed to remove successful pilot smoke workspace: $workspace" >&2
      exit 1
    fi
    exit 0
  }
  trap cleanup_pilot_smoke EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  mkdir -p "$artifacts" "$scenarios" "$(dirname "$training_dataset")"
  cargo run --locked --quiet -p netdiag-cli -- artifact-root initialize \
    --artifacts "$artifacts"
  PILOT_SMOKE_WORKSPACE="$workspace" python3 - <<'PY'
from __future__ import annotations

import json
import os
from pathlib import Path

source = Path("examples/datasets/pilot-smoke-training.jsonl")
output = Path(os.environ["PILOT_SMOKE_WORKSPACE"]) / "input/pilot-smoke-training-expanded.jsonl"
with source.open() as handle, output.open("w") as out:
    for line in handle:
        row = json.loads(line)
        for idx in range(6):
            cloned = json.loads(json.dumps(row))
            features = cloned.get("features", {})
            for name in ("latency_mean", "latency_p95", "jitter_std"):
                if name in features:
                    features[name] = round(float(features[name]) + (idx * 0.01), 4)
            out.write(json.dumps(cloned, separators=(",", ":")) + "\n")
PY
  cargo run --locked --quiet -p netdiag-cli -- train \
    --dataset "$training_dataset" \
    --model-dir "$artifacts/model" \
    --validation-split 0.34 \
    --stratified \
    --min-rows-per-label 1
  cargo run --locked --quiet -p netdiag-cli -- pilot preflight examples/pilots/loopback-mock.yaml \
    --artifacts "$artifacts"
  local after_run_id
  after_run_id="$(
    cargo run --locked --quiet -p netdiag-cli -- diagnose data/samples/normal.csv \
      --artifacts "$artifacts" \
      | python3 -c 'import json, sys; print(json.load(sys.stdin)["run_id"])'
  )"
  cargo run --locked --quiet -p netdiag-cli -- pilot workflow examples/pilots/loopback-mock.yaml \
    --artifacts "$artifacts" \
    --allow-adapter-execution \
    --after-run-id "$after_run_id"
  PILOT_SMOKE_WORKSPACE="$workspace" python3 - <<'PY'
from __future__ import annotations

import os
from pathlib import Path

workspace = Path(os.environ["PILOT_SMOKE_WORKSPACE"])
scenarios = workspace / "scenarios"
sample_root = Path.cwd() / "data/samples"
known = [
    ("normal", "normal.csv"),
    ("congestion", "congestion.csv"),
    ("random_loss", "random_loss.csv"),
    ("dns_failure", "dns_failure.csv"),
    ("tls_failure", "tls_failure.csv"),
    ("udp_quic_blocked", "udp_quic_blocked.csv"),
]
for label, sample in known:
    endpoint = Path(os.path.relpath(sample_root / sample, scenarios)).as_posix()
    (scenarios / f"{label}.yaml").write_text(
        f"""schema: netdiag-lab-scenario/v1
id: smoke-{label}
name: Smoke {label}
expected_label: {label}
data_sources:
  - name: {label}
    role: primary
    kind: trace-file
    endpoint: {endpoint}
acceptance:
  expected_root_cause: {label}
  min_rule_confidence: 0.0
  min_ml_probability: 0.0
  require_rule_ml_agreement: false
  require_what_if_improvement: false
""",
    )
ood_endpoint = Path(
    os.path.relpath(sample_root / "ood_mtu_blackhole.csv", scenarios)
).as_posix()
(scenarios / "ood.yaml").write_text(
    f"""schema: netdiag-lab-scenario/v1
id: smoke-ood
name: Smoke OOD
data_sources:
  - name: ood
    role: primary
    kind: trace-file
    endpoint: {ood_endpoint}
acceptance:
  min_ml_probability: 0.0
  allowed_diagnosis_statuses:
    - uncertain
    - out_of_distribution
  require_rule_ml_agreement: false
  require_what_if_improvement: false
""",
)
PY
  for scenario in "$scenarios"/*.yaml; do
    cargo run --locked --quiet -p netdiag-cli -- lab run "$scenario" \
      --artifacts "$artifacts"
  done
  cargo run --locked --quiet -p netdiag-cli -- lab calibrate \
    --artifacts "$artifacts"
  cargo run --locked --quiet --release -p netdiag-cli -- benchmark run \
    --artifacts "$benchmark_artifacts" \
    --output "$benchmark_report" \
    --model-dir "$artifacts/model"
  cargo run --locked --quiet -p netdiag-cli -- pilot model-gate \
    --model-dir "$artifacts/model" \
    --benchmark-report "$benchmark_report/benchmark_report.json" \
    --calibration-report "$artifacts/lab_calibration_report.json" \
    --min-rows-per-label 1
  python3 scripts/publish_benchmark_report.py \
    "$benchmark_report" "$published_benchmark_report"
  cleanup_pilot_smoke
  )
}

run_fast() {
  require_tool rg
  cargo fmt --all -- --check
  cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
  RUSTFLAGS="-D warnings" cargo test --locked --workspace --all-features
  run_python_quality_guards
  python3 scripts/check_workspace_publish_policy.py
  python3 scripts/check_patch_contract_hygiene.py
  run_patch_contracts
  run_adapter_contracts
  python3 scripts/check_release_gate_hygiene.py
  python3 scripts/check_docs_workflow_hygiene.py
  python3 scripts/check_real_device_readiness.py
  python3 scripts/check_complexity.py
  scripts/check_architecture_guard.sh
  python3 scripts/check_architecture_guard_sanity.py
  scripts/check_perf_budget.sh
}

run_strict() {
  require_tool python3
  require_tool rg
  require_cargo_subcommand nextest
  require_cargo_subcommand llvm-cov
  require_cargo_subcommand deny
  require_cargo_subcommand machete

  local coverage_min
  local workspace_coverage_min
  local app_security_coverage_min
  local app_security_file_coverage_min
  coverage_min="$(strict_floor "$COVERAGE_MIN" "$STRICT_COVERAGE_FLOOR" NETDIAG_COVERAGE_MIN)"
  workspace_coverage_min="$(strict_floor "$WORKSPACE_COVERAGE_MIN" "$STRICT_WORKSPACE_COVERAGE_FLOOR" NETDIAG_WORKSPACE_COVERAGE_MIN)"
  app_security_coverage_min="$(strict_floor "$APP_SECURITY_COVERAGE_MIN" "$STRICT_APP_SECURITY_COVERAGE_FLOOR" NETDIAG_APP_SECURITY_COVERAGE_MIN)"
  app_security_file_coverage_min="$(strict_floor "$APP_SECURITY_FILE_COVERAGE_MIN" "$STRICT_APP_SECURITY_FILE_COVERAGE_FLOOR" NETDIAG_APP_SECURITY_FILE_COVERAGE_MIN)"

  cargo fmt --all -- --check
  cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
  RUSTFLAGS="-D warnings" cargo nextest run --locked --workspace --all-features --lib --bins --tests
  cargo test --locked -p netdiag-core --bench perf_budget --all-features
  run_python_quality_guards
  python3 scripts/check_workspace_publish_policy.py
  python3 scripts/check_patch_contract_hygiene.py
  run_patch_contracts
  python3 scripts/check_complexity.py
  scripts/check_architecture_guard.sh
  python3 scripts/check_architecture_guard_sanity.py
  python3 scripts/check_release_gate_hygiene.py
  local coverage_dir
  local coverage_target_dir
  local coverage_summary
  local app_security_coverage_summary
  mkdir -p "$ROOT/target"
  coverage_dir="$(mktemp -d "$ROOT/target/netdiag-llvm-cov.XXXXXX")"
  coverage_target_dir="$coverage_dir/cargo-target"
  coverage_summary="$coverage_dir/summary.json"
  app_security_coverage_summary="$coverage_dir/app-security-summary.json"
  CARGO_TARGET_DIR="$coverage_target_dir" cargo llvm-cov clean --workspace || {
    echo "strict coverage artifacts preserved for diagnosis: $coverage_dir" >&2
    return 1
  }
  LLVM_PROFILE_FILE_NAME="netdiag-%m-%p.profraw" CARGO_TARGET_DIR="$coverage_target_dir" cargo llvm-cov nextest --locked \
    -p netdiag-core -p netdiag-cli -p netdiag-platform --all-features --lib --bins --tests \
    --test-threads 1 \
    --summary-only \
    --json \
    --output-path "$coverage_summary" || {
      echo "strict coverage artifacts preserved for diagnosis: $coverage_dir" >&2
      return 1
    }
  python3 scripts/check_coverage_summary.py \
    --summary "$coverage_summary" \
    --dep-info-dir "$coverage_target_dir/llvm-cov-target/debug/deps" \
    --critical-min "$coverage_min" \
    --workspace-min "$workspace_coverage_min" || {
      echo "strict coverage artifacts preserved for diagnosis: $coverage_dir" >&2
      return 1
    }
  LLVM_PROFILE_FILE_NAME="netdiag-%m-%p.profraw" CARGO_TARGET_DIR="$coverage_target_dir" cargo llvm-cov nextest --locked \
    -p netdiag-app --all-features --lib --bins --tests \
    --test-threads 1 \
    --summary-only \
    --json \
    --output-path "$app_security_coverage_summary" || {
      echo "strict app security coverage artifacts preserved for diagnosis: $coverage_dir" >&2
      return 1
    }
  python3 scripts/check_app_security_coverage.py \
    --summary "$app_security_coverage_summary" \
    --dep-info-dir "$coverage_target_dir/llvm-cov-target/debug/deps" \
    --aggregate-min "$app_security_coverage_min" \
    --file-min "$app_security_file_coverage_min" || {
      echo "strict app security coverage artifacts preserved for diagnosis: $coverage_dir" >&2
      return 1
    }
  cp "$coverage_summary" "$coverage_dir/validated-summary.json" || {
    echo "strict coverage artifacts preserved for diagnosis: $coverage_dir" >&2
    return 1
  }
  cp "$app_security_coverage_summary" "$coverage_dir/validated-app-security-summary.json" || {
    echo "strict app security coverage artifacts preserved for diagnosis: $coverage_dir" >&2
    return 1
  }
  mv "$coverage_dir/validated-app-security-summary.json" target/llvm-cov-app-security-summary.json || {
    echo "strict app security coverage artifacts preserved for diagnosis: $coverage_dir" >&2
    return 1
  }
  mv "$coverage_dir/validated-summary.json" target/llvm-cov-workspace-summary.json || {
    echo "strict coverage artifacts preserved for diagnosis: $coverage_dir" >&2
    return 1
  }
  if ! rm -rf "$coverage_dir"; then
    echo "failed to remove successful strict coverage work directory: $coverage_dir" >&2
    return 1
  fi
  run_cargo_deny_clean
  python3 scripts/check_deny_waivers.py
  cargo machete
  python3 scripts/check_pilot_cli_wiring.py
  python3 scripts/check_docs_workflow_hygiene.py
  python3 scripts/check_real_device_readiness.py
  run_adapter_contracts
  scripts/check_perf_budget.sh
  run_pilot_smoke
  if [[ "${NETDIAG_RUN_MIRI:-0}" == "1" ]]; then
    cargo miri test --locked --workspace
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
