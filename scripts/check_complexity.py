#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

from count_production_lines import mask_rust_non_code


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FILE_LINES = 800
DEFAULT_FUNCTION_LINES = 120
DEFAULT_BRANCH_POINTS = 30

# Ratchet existing large modules without pretending they are the desired shape.
# New modules must stay under the defaults unless they are explicitly reviewed.
LEGACY_FILE_LIMITS = {
    "crates/netdiag-app/src/data_source.rs": 960,
    "crates/netdiag-app/src/main.rs": 6535,
    "crates/netdiag-app/src/settings.rs": 910,
    "crates/netdiag-cli/src/main.rs": 1360,
    "crates/netdiag-core/src/connectors.rs": 1540,
    "crates/netdiag-core/src/dataset.rs": 968,
    "crates/netdiag-core/src/lab.rs": 5107,
    "crates/netdiag-core/src/ml.rs": 2028,
    "crates/netdiag-core/src/models.rs": 1170,
    "crates/netdiag-core/src/storage.rs": 1060,
    "crates/netdiag-core/src/twin.rs": 1000,
    "crates/netdiag-core/tests/golden.rs": 960,
}

LEGACY_FUNCTION_LINE_LIMITS = {
    "crates/netdiag-app/src/main.rs": 394,
    "crates/netdiag-app/src/native_menu.rs": 233,
    "crates/netdiag-app/src/settings.rs": 117,
    "crates/netdiag-cli/src/main.rs": 510,
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
    "crates/netdiag-cli/src/main.rs": 50,
    "crates/netdiag-core/src/connectors.rs": 60,
    "crates/netdiag-core/src/lab.rs": 100,
    "crates/netdiag-core/src/ml.rs": 70,
    "crates/netdiag-core/src/report.rs": 90,
    "crates/netdiag-core/src/rules.rs": 70,
}

FUNCTION_START = re.compile(
    r"(?m)^[ \t]*(?:(?:pub(?:\s*\([^)]*\))?|const|async|unsafe|extern)\s+)*"
    r"fn\s+[A-Za-z_][A-Za-z0-9_]*\b"
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
        try:
            spans = function_spans("\n".join(lines))
        except ValueError as error:
            failures.append(f"{rel}: could not parse Rust source: {error}")
            continue
        for start, end, signature, body in spans:
            span = end - start + 1
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


def function_spans(source: str) -> list[tuple[int, int, str, str]]:
    masked = mask_rust_non_code(source)
    spans: list[tuple[int, int, str, str]] = []
    for match in FUNCTION_START.finditer(masked):
        opening = _function_body_open(masked, match.end())
        if opening is None:
            continue
        closing = _balanced_body_end(masked, opening, match.start())
        start_line = source.count("\n", 0, match.start()) + 1
        end_line = source.count("\n", 0, closing) + 1
        signature = " ".join(source[match.start() : opening].split())
        body = masked[opening : closing + 1]
        spans.append((start_line, end_line, signature, body))
    return spans


def _function_body_open(masked: str, offset: int) -> int | None:
    parentheses = 0
    brackets = 0
    for cursor in range(offset, len(masked)):
        char = masked[cursor]
        if char == "(":
            parentheses += 1
        elif char == ")":
            parentheses -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == ";" and parentheses == 0 and brackets == 0:
            return None
        elif char == "{" and parentheses == 0 and brackets == 0:
            return cursor
        if parentheses < 0 or brackets < 0:
            raise ValueError("unbalanced function signature delimiter")
    raise ValueError("function declaration has no body or terminator")


def _balanced_body_end(masked: str, opening: int, declaration: int) -> int:
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor
    line = masked.count("\n", 0, declaration) + 1
    raise ValueError(f"unterminated function body starting on line {line}")


if __name__ == "__main__":
    raise SystemExit(main())
