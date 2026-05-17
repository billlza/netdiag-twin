#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FILE_LINES = 800
DEFAULT_FUNCTION_LINES = 120
DEFAULT_BRANCH_POINTS = 30

# Ratchet existing large modules without pretending they are the desired shape.
# New modules must stay under the defaults unless they are explicitly reviewed.
LEGACY_FILE_LIMITS = {
    "crates/netdiag-app/src/data_source.rs": 1126,
    "crates/netdiag-app/src/main.rs": 6535,
    "crates/netdiag-app/src/settings.rs": 1018,
    "crates/netdiag-cli/src/main.rs": 1488,
    "crates/netdiag-core/src/connectors.rs": 2168,
    "crates/netdiag-core/src/dataset.rs": 968,
    "crates/netdiag-core/src/lab.rs": 5107,
    "crates/netdiag-core/src/ml.rs": 2028,
    "crates/netdiag-core/src/models.rs": 1170,
    "crates/netdiag-core/src/storage.rs": 1060,
    "crates/netdiag-core/src/twin.rs": 1189,
    "crates/netdiag-core/tests/golden.rs": 960,
}

LEGACY_FUNCTION_LINE_LIMITS = {
    "crates/netdiag-app/src/main.rs": 394,
    "crates/netdiag-app/src/native_menu.rs": 233,
    "crates/netdiag-app/src/settings.rs": 117,
    "crates/netdiag-cli/src/main.rs": 577,
    "crates/netdiag-core/src/connectors.rs": 130,
    "crates/netdiag-core/src/lab.rs": 264,
    "crates/netdiag-core/src/ml.rs": 134,
    "crates/netdiag-core/src/perf_budget.rs": 108,
    "crates/netdiag-core/src/pilot.rs": 120,
    "crates/netdiag-core/src/report.rs": 194,
    "crates/netdiag-core/src/rules.rs": 158,
    "crates/netdiag-core/src/twin.rs": 111,
    "crates/netdiag-core/tests/golden.rs": 235,
}

LEGACY_BRANCH_LIMITS = {
    "crates/netdiag-app/src/main.rs": 160,
    "crates/netdiag-app/src/native_menu.rs": 80,
    "crates/netdiag-cli/src/main.rs": 220,
    "crates/netdiag-core/src/connectors.rs": 60,
    "crates/netdiag-core/src/lab.rs": 100,
    "crates/netdiag-core/src/ml.rs": 70,
    "crates/netdiag-core/src/report.rs": 90,
    "crates/netdiag-core/src/rules.rs": 70,
}

FUNCTION_START = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z0-9_]+"
)
BRANCH_RE = re.compile(r"\b(if|else if|match|for|while|loop)\b|&&|\|\|")


def main() -> int:
    failures: list[str] = []
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        rel = path.relative_to(ROOT).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        file_limit = LEGACY_FILE_LIMITS.get(rel, DEFAULT_FILE_LINES)
        if len(lines) > file_limit:
            failures.append(f"{rel}: {len(lines)} lines exceeds file limit {file_limit}")

        function_limit = LEGACY_FUNCTION_LINE_LIMITS.get(rel, DEFAULT_FUNCTION_LINES)
        branch_limit = LEGACY_BRANCH_LIMITS.get(rel, DEFAULT_BRANCH_POINTS)
        for start, end, signature in function_spans(lines):
            span = end - start + 1
            body = "\n".join(lines[start - 1 : end])
            branch_points = len(BRANCH_RE.findall(body))
            location = f"{rel}:{start}"
            if span > function_limit:
                failures.append(
                    f"{location}: function is {span} lines, limit {function_limit}: {signature}"
                )
            if branch_points > branch_limit:
                failures.append(
                    f"{location}: branch heuristic is {branch_points}, limit {branch_limit}: {signature}"
                )

    if failures:
        print("complexity guard failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("complexity guard passed")
    return 0


def function_spans(lines: list[str]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines, start=1):
        if not FUNCTION_START.match(line):
            continue
        brace_depth = 0
        started = False
        for cursor in range(index, len(lines) + 1):
            current = lines[cursor - 1]
            brace_depth += current.count("{") - current.count("}")
            started = started or "{" in current
            if started and brace_depth <= 0:
                spans.append((index, cursor, line.strip()))
                break
    return spans


if __name__ == "__main__":
    raise SystemExit(main())
