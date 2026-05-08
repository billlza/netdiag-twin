#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail=0

check_lines() {
  local path="$1"
  local max_lines="$2"
  local lines
  lines="$(wc -l < "$ROOT/$path" | tr -d ' ')"
  if (( lines > max_lines )); then
    echo "architecture guard failed: $path has $lines lines, max $max_lines" >&2
    fail=1
  else
    echo "$path: $lines/$max_lines"
  fi
}

# v0.4.2 baselines. Small allowances are limited to transitional exports/dispatch.
check_lines "crates/netdiag-core/src/lab.rs" 5107
check_lines "crates/netdiag-core/src/connectors.rs" 2168
check_lines "crates/netdiag-cli/src/main.rs" 1535
check_lines "crates/netdiag-app/src/main.rs" 6564

# New modules should stay narrow enough to remain reviewable.
check_lines "crates/netdiag-core/src/reliability.rs" 825
check_lines "crates/netdiag-core/src/benchmark.rs" 525
check_lines "crates/netdiag-core/src/pilot.rs" 800

exit "$fail"
