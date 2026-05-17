#!/usr/bin/env python3
"""Validate cargo-llvm-cov summary output for release quality gates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


CRITICAL_EXACT_FILES = (
    "crates/netdiag-core/src/pilot.rs",
    "crates/netdiag-cli/src/commands/pilot.rs",
)

CRITICAL_PREFIXES = ("crates/netdiag-core/src/pilot/",)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--critical-min", required=True, type=float)
    parser.add_argument("--workspace-min", required=True, type=float)
    return parser.parse_args()


def normalize_filename(filename: str) -> str:
    return filename.replace("\\", "/")


def critical_relative_path(filename: str) -> str | None:
    normalized = normalize_filename(filename)
    for relative in CRITICAL_EXACT_FILES:
        if normalized == relative or normalized.endswith(f"/{relative}"):
            return relative
    for prefix in CRITICAL_PREFIXES:
        if normalized.startswith(prefix):
            relative = normalized
        elif f"/{prefix}" in normalized:
            relative = prefix + normalized.split(prefix, 1)[1]
        else:
            continue
        if is_production_rust_source(relative):
            return relative
    return None


def is_production_rust_source(relative: str) -> bool:
    return (
        relative.endswith(".rs")
        and "/tests/" not in relative
        and not relative.endswith("/tests.rs")
    )


def find_critical_files(files: list[dict]) -> dict[str, dict | None]:
    found: dict[str, dict | None] = {path: None for path in CRITICAL_EXACT_FILES}
    for entry in files:
        relative = critical_relative_path(entry["filename"])
        if relative is not None:
            found[relative] = entry
    return dict(sorted(found.items()))


def line_totals(files: list[dict]) -> tuple[int, int]:
    covered = 0
    count = 0
    for entry in files:
        if entry is None:
            continue
        lines = entry["summary"]["lines"]
        covered += int(lines["covered"])
        count += int(lines["count"])
    return covered, count


def percent(covered: int, count: int) -> float:
    if count == 0:
        return 0.0
    return covered * 100.0 / count


def main() -> int:
    args = parse_args()
    with args.summary.open() as handle:
        payload = json.load(handle)

    data = payload["data"][0]
    workspace_lines = data["totals"]["lines"]
    workspace_percent = float(workspace_lines["percent"])
    files = data["files"]
    critical_files = find_critical_files(files)
    critical_covered, critical_count = line_totals(list(critical_files.values()))
    critical_percent = percent(critical_covered, critical_count)

    print(
        "coverage: "
        f"workspace={workspace_percent:.2f}% "
        f"({workspace_lines['covered']}/{workspace_lines['count']} lines), "
        f"v0.5_pilot_cli={critical_percent:.2f}% "
        f"({critical_covered}/{critical_count} lines)"
    )

    failures = []
    for relative, entry in critical_files.items():
        if entry is None:
            failures.append(f"critical coverage file is missing from llvm-cov summary: {relative}")
            continue
        lines = entry["summary"]["lines"]
        file_percent = float(lines["percent"])
        print(
            "coverage file: "
            f"{relative}={file_percent:.2f}% "
            f"({lines['covered']}/{lines['count']} lines)"
        )
        if file_percent < args.critical_min:
            failures.append(
                f"{relative} coverage {file_percent:.2f}% "
                f"is below required {args.critical_min:.2f}%"
            )
    if critical_percent < args.critical_min:
        failures.append(
            f"v0.5 Pilot/CLI coverage {critical_percent:.2f}% "
            f"is below required {args.critical_min:.2f}%"
        )
    if workspace_percent < args.workspace_min:
        failures.append(
            f"workspace coverage {workspace_percent:.2f}% "
            f"is below ratchet floor {args.workspace_min:.2f}%"
        )

    if failures:
        for failure in failures:
            print(f"coverage gate failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
