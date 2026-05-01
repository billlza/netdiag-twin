#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="${NETDIAG_PERF_BASELINE:-$ROOT/perf-baseline.json}"
OUTPUT="${NETDIAG_PERF_OUTPUT:-$ROOT/target/perf-budget-report.json}"
ARTIFACTS="${NETDIAG_PERF_ARTIFACTS:-$ROOT/target/perf-artifacts}"
THRESHOLD="${NETDIAG_PERF_THRESHOLD_PERCENT:-15}"
BASELINE_SCALE="${NETDIAG_PERF_BASELINE_SCALE:-3.0}"
MODE="${1:-check}"

rm -rf "$ARTIFACTS"
mkdir -p "$(dirname "$OUTPUT")"

args=(
  run
  --quiet
  --release
  -p
  netdiag-cli
  --
  perf-budget
  --baseline
  "$BASELINE"
  --output
  "$OUTPUT"
  --artifacts
  "$ARTIFACTS"
  --threshold-percent
  "$THRESHOLD"
)

case "$MODE" in
  check)
    ;;
  --update-baseline|update)
    args+=(--update-baseline --baseline-scale "$BASELINE_SCALE")
    ;;
  *)
    echo "usage: scripts/check_perf_budget.sh [check|--update-baseline]" >&2
    exit 2
    ;;
esac

cargo "${args[@]}"
