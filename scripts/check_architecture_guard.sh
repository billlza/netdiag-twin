#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail=0

check_lines() {
  local path="$1"
  local max_lines="$2"
  local lines
  lines="$(awk '/^#\[cfg\(test\)\]/{exit} {count++} END{print count+0}' "$ROOT/$path")"
  if (( lines > max_lines )); then
    echo "architecture guard failed: $path has $lines production lines, max $max_lines" >&2
    fail=1
  else
    echo "$path: $lines/$max_lines production lines"
  fi
}

# v0.4.2 baselines. Small allowances are limited to transitional exports/dispatch.
check_lines "crates/netdiag-core/src/lab.rs" 5107
check_lines "crates/netdiag-core/src/connectors.rs" 2168
check_lines "crates/netdiag-cli/src/main.rs" 1535
check_lines "crates/netdiag-app/src/main.rs" 6535

# New modules should stay narrow enough to remain reviewable.
check_lines "crates/netdiag-core/src/reliability.rs" 825
check_lines "crates/netdiag-core/src/benchmark.rs" 525
check_lines "crates/netdiag-core/src/pilot.rs" 800
check_lines "crates/netdiag-core/src/pilot/adapter_contract.rs" 140
check_lines "crates/netdiag-core/src/pilot/pilot_sources.rs" 500
check_lines "crates/netdiag-core/src/pilot/types.rs" 260
check_lines "crates/netdiag-core/src/pilot/workflow.rs" 240
check_lines "crates/netdiag-core/src/pilot/promotion.rs" 320
check_lines "crates/netdiag-core/src/pilot/promotion/gates.rs" 240
check_lines "crates/netdiag-app/src/pilot_run_center.rs" 320
check_lines "crates/netdiag-app/src/pilot_run_center/view.rs" 180

exit "$fail"
