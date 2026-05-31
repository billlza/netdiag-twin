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
  local output

  if ! output="$(cargo deny --locked check --hide-inclusion-graph --disable-fetch 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi

  if grep -E '(^|[[:space:]])warning\[' <<<"$output" >/dev/null; then
    printf '%s\n' "$output" >&2
    echo "cargo-deny emitted warnings; strict release gate requires clean output" >&2
    return 1
  fi

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
