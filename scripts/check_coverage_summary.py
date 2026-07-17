#!/usr/bin/env python3
"""Validate cargo-llvm-cov summary output for release quality gates."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

from count_production_lines import mask_rust_non_code


ROOT = Path(__file__).resolve().parents[1]
CRITICAL_EXACT_FILES = (
    "crates/netdiag-core/src/managed_temp_directory.rs",
    "crates/netdiag-core/src/pilot.rs",
    "crates/netdiag-core/src/python_runtime.rs",
    "crates/netdiag-cli/src/commands/pilot.rs",
    "crates/netdiag-platform/src/system_temporary_root.rs",
    "crates/netdiag-platform/src/trusted_directory.rs",
    "crates/netdiag-platform/src/trusted_directory/strict.rs",
    "crates/netdiag-platform/src/trusted_directory/unix.rs",
    "crates/netdiag-platform/src/trusted_temp_directory.rs",
    "crates/netdiag-platform/src/trusted_temp_directory/cleanup.rs",
    "crates/netdiag-platform/src/trusted_temp_directory/create.rs",
    "crates/netdiag-platform/src/trusted_temp_directory/create/name.rs",
    "crates/netdiag-platform/src/trusted_temp_directory/create/platform/unix.rs",
    "crates/netdiag-platform/src/trusted_temp_directory/finish.rs",
    "crates/netdiag-platform/src/trusted_temp_directory/identity/unix.rs",
    "crates/netdiag-platform/src/unix_acl.rs",
)
CRITICAL_PREFIXES = (
    "crates/netdiag-core/src/managed_temp_directory/",
    "crates/netdiag-core/src/pilot/",
    "crates/netdiag-core/src/python_runtime/",
    "crates/netdiag-cli/src/commands/pilot/",
    "crates/netdiag-platform/src/trusted_directory/unix/",
)
CRITICAL_SOURCE_DIRS = (
    "crates/netdiag-core/src/managed_temp_directory",
    "crates/netdiag-core/src/pilot",
    "crates/netdiag-core/src/python_runtime",
    "crates/netdiag-cli/src/commands/pilot",
    "crates/netdiag-platform/src/trusted_directory/unix",
)
WORKSPACE_PREFIXES = (
    "crates/netdiag-core/",
    "crates/netdiag-cli/",
    "crates/netdiag-platform/",
)
WORKSPACE_SOURCE_DIRS = (
    "crates/netdiag-core/src",
    "crates/netdiag-cli/src",
    "crates/netdiag-platform/src",
)
PERCENT_TOLERANCE = 0.01
COVERAGE_OFF_ATTRIBUTE = re.compile(r"\bcoverage\s*\(\s*off\s*\)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--dep-info-dir", required=True, type=Path)
    parser.add_argument("--critical-min", required=True, type=float)
    parser.add_argument("--workspace-min", required=True, type=float)
    return parser.parse_args()


def normalize_filename(filename: str) -> str:
    return filename.replace("\\", "/")


def is_production_rust_source(relative: str) -> bool:
    return (
        relative.endswith(".rs")
        and "/tests/" not in relative
        and not relative.endswith("/tests.rs")
        and not relative.endswith("_tests.rs")
    )


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


def workspace_relative_path(filename: str) -> str | None:
    normalized = normalize_filename(filename)
    for prefix in WORKSPACE_PREFIXES:
        if normalized.startswith(prefix):
            relative = normalized
        elif f"/{prefix}" in normalized:
            relative = prefix + normalized.split(prefix, 1)[1]
        else:
            continue
        if is_production_rust_source(relative):
            return relative
    return None


def reported_workspace_files(files: list[dict]) -> set[str]:
    reported: set[str] = set()
    for entry in files:
        filename = entry.get("filename") if isinstance(entry, dict) else None
        if not isinstance(filename, str):
            continue
        relative = workspace_relative_path(filename)
        if relative is not None:
            reported.add(relative)
    return reported


def find_critical_files(
    files: list[dict],
    expected: set[str],
    failures: list[str],
) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for entry in files:
        filename = entry.get("filename") if isinstance(entry, dict) else None
        if not isinstance(filename, str):
            continue
        relative = critical_relative_path(filename)
        if relative is None:
            continue
        if relative not in expected:
            failures.append(
                "llvm-cov summary references a critical source that is absent from "
                f"the checkout: {relative}"
            )
            continue
        if relative in found:
            failures.append(
                f"critical coverage file appears more than once in llvm-cov summary: {relative}"
            )
            continue
        found[relative] = entry
    return dict(sorted(found.items()))


def makefile_words(contents: str) -> list[str]:
    """Split rustc Makefile-style dep-info while honoring escaped characters."""

    words: list[str] = []
    current: list[str] = []
    cursor = 0
    while cursor < len(contents):
        character = contents[cursor]
        if character == "\\":
            if cursor + 1 >= len(contents):
                raise ValueError("dep-info ends with an incomplete escape")
            following = contents[cursor + 1]
            if (
                following == "\r"
                and cursor + 2 < len(contents)
                and contents[cursor + 2] == "\n"
            ):
                cursor += 3
                continue
            if following == "\n":
                cursor += 2
                continue
            current.append(following)
            cursor += 2
            continue
        if character.isspace():
            if current:
                words.append("".join(current))
                current.clear()
        else:
            current.append(character)
        cursor += 1
    if current:
        words.append("".join(current))
    return words


def compiled_workspace_files(
    dep_info_dir: Path,
    expected: set[str],
    failures: list[str],
) -> set[str]:
    compiled: set[str] = set()
    try:
        canonical_root = ROOT.resolve(strict=True)
    except OSError as exc:
        failures.append(f"could not resolve coverage source root {ROOT}: {exc}")
        return compiled
    for crate_stem, requires_rlib in (
        ("netdiag_core", True),
        ("netdiag_cli", False),
        ("netdiag_platform", True),
    ):
        dep_info_files = sorted(dep_info_dir.glob(f"{crate_stem}-*.d"))
        if not dep_info_files:
            failures.append(
                f"coverage build dep-info is missing for {crate_stem}: {dep_info_dir}"
            )
            continue
        eligible_dep_info = 0
        for dep_info in dep_info_files:
            try:
                words = makefile_words(dep_info.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError) as exc:
                failures.append(f"could not read coverage dep-info {dep_info}: {exc}")
                continue
            if requires_rlib and not any(
                re.search(
                    rf"(?:^|/)lib{crate_stem}-[^/]+\.rlib:$",
                    normalize_filename(word),
                )
                for word in words
            ):
                continue
            eligible_dep_info += 1
            for word in words:
                if not word.endswith(".rs"):
                    continue
                claimed_relative = workspace_relative_path(word)
                if claimed_relative is None:
                    continue
                candidate = Path(word)
                if not candidate.is_absolute():
                    candidate = ROOT / candidate
                try:
                    canonical_source = candidate.resolve(strict=True)
                    relative = canonical_source.relative_to(canonical_root).as_posix()
                except (OSError, ValueError) as exc:
                    failures.append(
                        "coverage dep-info source must resolve inside the checkout: "
                        f"{word}: {exc}"
                    )
                    continue
                if relative != claimed_relative:
                    failures.append(
                        "coverage dep-info source path does not canonically match its "
                        f"workspace path: {word} -> {relative}"
                    )
                    continue
                if relative not in expected:
                    failures.append(
                        "coverage dep-info references a release-workspace production source "
                        f"that is absent from the checkout: {relative}"
                    )
                    continue
                compiled.add(relative)
        if eligible_dep_info == 0:
            target_kind = "production rlib " if requires_rlib else ""
            failures.append(
                f"coverage build dep-info has no eligible {target_kind}target for {crate_stem}"
            )
    if not compiled:
        failures.append("coverage build dep-info contains no release-workspace production sources")
    return compiled


def expected_critical_files(failures: list[str]) -> set[str]:
    expected = set(CRITICAL_EXACT_FILES)
    for relative in CRITICAL_EXACT_FILES:
        if not (ROOT / relative).is_file():
            failures.append(f"critical coverage source file is missing: {relative}")
    for relative_dir in CRITICAL_SOURCE_DIRS:
        source_dir = ROOT / relative_dir
        if not source_dir.is_dir():
            failures.append(f"critical coverage source directory is missing: {relative_dir}")
            continue
        for path in source_dir.rglob("*.rs"):
            relative = path.relative_to(ROOT).as_posix()
            if is_production_rust_source(relative):
                expected.add(relative)
    return expected


def expected_workspace_files(failures: list[str]) -> set[str]:
    expected: set[str] = set()
    for relative_dir in WORKSPACE_SOURCE_DIRS:
        source_dir = ROOT / relative_dir
        if not source_dir.is_dir():
            failures.append(f"workspace coverage source directory is missing: {relative_dir}")
            continue
        for path in source_dir.rglob("*.rs"):
            relative = path.relative_to(ROOT).as_posix()
            if is_production_rust_source(relative):
                expected.add(relative)
                try:
                    source = path.read_text(encoding="utf-8")
                    masked = mask_rust_non_code(source)
                except (OSError, UnicodeError, ValueError) as exc:
                    failures.append(f"could not inspect coverage source {relative}: {exc}")
                    continue
                if COVERAGE_OFF_ATTRIBUTE.search(masked):
                    failures.append(
                        f"coverage suppression is forbidden in production source: {relative}"
                    )
    return expected


def measured_workspace_summary(
    files: list[dict],
    expected: set[str],
    compiled: set[str],
    failures: list[str],
) -> tuple[int, int, float] | None:
    covered_total = 0
    count_total = 0
    seen: set[str] = set()
    for entry in files:
        filename = entry.get("filename") if isinstance(entry, dict) else None
        if not isinstance(filename, str):
            continue
        relative = workspace_relative_path(filename)
        if relative is None:
            continue
        if relative not in expected:
            failures.append(
                "llvm-cov summary references a release-workspace production source that is "
                f"absent from the checkout: {relative}"
            )
            continue
        if relative not in compiled:
            failures.append(
                "llvm-cov summary references a release-workspace production source that is "
                f"absent from the coverage build dep-info: {relative}"
            )
            continue
        if relative in seen:
            failures.append(
                "release-workspace coverage file appears more than once in llvm-cov summary: "
                f"{relative}"
            )
            continue
        seen.add(relative)
        summary = entry.get("summary")
        lines = summary.get("lines") if isinstance(summary, dict) else None
        result = validated_line_summary(lines, relative, failures)
        if result is None:
            continue
        covered, count, _ = result
        covered_total += covered
        count_total += count
    if count_total == 0:
        failures.append("llvm-cov summary contains no measured release-workspace production files")
        return None
    return covered_total, count_total, percent(covered_total, count_total)


def measured_file_totals(
    files: list[dict], failures: list[str]
) -> tuple[int, int] | None:
    covered_total = 0
    count_total = 0
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            failures.append(f"llvm-cov file entry {index} must be an object")
            continue
        filename = entry.get("filename")
        if not isinstance(filename, str) or not filename:
            failures.append(f"llvm-cov file entry {index} must have a non-empty filename")
            continue
        summary = entry.get("summary")
        lines = summary.get("lines") if isinstance(summary, dict) else None
        result = validated_line_summary(lines, filename, failures)
        if result is None:
            continue
        covered, count, _ = result
        covered_total += covered
        count_total += count
    if count_total == 0:
        failures.append("llvm-cov summary contains no measured file lines")
        return None
    return covered_total, count_total


def percent(covered: int, count: int) -> float:
    return covered * 100.0 / count


def validate_threshold(name: str, value: float, failures: list[str]) -> None:
    if not math.isfinite(value) or not 0.0 <= value <= 100.0:
        failures.append(f"{name} must be a finite percentage between 0 and 100")


def validated_line_summary(
    lines: object,
    scope: str,
    failures: list[str],
) -> tuple[int, int, float] | None:
    if not isinstance(lines, dict):
        failures.append(f"{scope} line summary must be an object")
        return None
    covered = lines.get("covered")
    count = lines.get("count")
    if (
        isinstance(covered, bool)
        or not isinstance(covered, int)
        or isinstance(count, bool)
        or not isinstance(count, int)
    ):
        failures.append(f"{scope} covered/count must be integers")
        return None
    if count <= 0 or covered < 0 or covered > count:
        failures.append(
            f"{scope} covered/count must satisfy 0 <= covered <= count with count > 0"
        )
        return None

    recomputed = percent(covered, count)
    reported_raw = lines.get("percent")
    try:
        reported = float(reported_raw)
    except (TypeError, ValueError):
        failures.append(f"{scope} reported percent must be numeric")
        return covered, count, recomputed
    if not math.isfinite(reported) or not 0.0 <= reported <= 100.0:
        failures.append(f"{scope} reported percent must be finite and between 0 and 100")
    elif not math.isclose(
        reported,
        recomputed,
        rel_tol=0.0,
        abs_tol=PERCENT_TOLERANCE,
    ):
        failures.append(
            f"{scope} reported percent {reported:.4f} does not match "
            f"covered/count recomputation {recomputed:.4f}"
        )
    return covered, count, recomputed


def load_summary(path: Path) -> tuple[dict, list[dict]]:
    with path.open() as handle:
        payload = json.load(handle)
    data_entries = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data_entries, list) or len(data_entries) != 1:
        raise ValueError("coverage summary must contain exactly one data entry")
    data = data_entries[0]
    if not isinstance(data, dict):
        raise ValueError("coverage summary data entry must be an object")
    totals = data.get("totals")
    files = data.get("files")
    if not isinstance(totals, dict) or not isinstance(files, list):
        raise ValueError("coverage summary must contain totals and files")
    return totals, files


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    validate_threshold("critical-min", args.critical_min, failures)
    validate_threshold("workspace-min", args.workspace_min, failures)
    if failures:
        for failure in failures:
            print(f"coverage gate failed: {failure}", file=sys.stderr)
        return 1

    try:
        totals, files = load_summary(args.summary)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"coverage gate failed: could not read coverage summary: {exc}", file=sys.stderr)
        return 1

    reported_totals = validated_line_summary(
        totals.get("lines"),
        "llvm-cov totals",
        failures,
    )
    measured_totals = measured_file_totals(files, failures)
    if reported_totals is not None and measured_totals is not None:
        reported_covered, reported_count, _ = reported_totals
        measured_covered, measured_count = measured_totals
        if (reported_covered, reported_count) != (measured_covered, measured_count):
            failures.append(
                "llvm-cov totals do not equal the sum of file line summaries: "
                f"totals={reported_covered}/{reported_count}, "
                f"files={measured_covered}/{measured_count}"
            )
    expected_workspace = expected_workspace_files(failures)
    compiled_workspace = compiled_workspace_files(
        args.dep_info_dir,
        expected_workspace,
        failures,
    )
    zero_mapping_files = compiled_workspace - reported_workspace_files(files)
    expected_critical = expected_critical_files(failures)
    for relative in sorted(expected_critical - compiled_workspace):
        failures.append(
            "critical coverage source is absent from the coverage build dep-info: "
            f"{relative}"
        )
    workspace = measured_workspace_summary(
        files,
        expected_workspace,
        compiled_workspace,
        failures,
    )
    critical_files = find_critical_files(
        files,
        expected_critical,
        failures,
    )

    for relative in CRITICAL_EXACT_FILES:
        if relative not in critical_files:
            failures.append(
                f"critical coverage file is missing from llvm-cov summary: {relative}"
            )

    critical_covered = 0
    critical_count = 0
    critical_results: list[tuple[str, int, int, float]] = []
    for relative, entry in critical_files.items():
        summary = entry.get("summary")
        lines = summary.get("lines") if isinstance(summary, dict) else None
        result = validated_line_summary(lines, relative, failures)
        if result is None:
            continue
        covered, count, file_percent = result
        critical_covered += covered
        critical_count += count
        critical_results.append((relative, covered, count, file_percent))

    critical_percent = percent(critical_covered, critical_count) if critical_count else 0.0
    if workspace is not None:
        workspace_covered, workspace_count, workspace_percent = workspace
        print(
            "coverage: "
            f"measured_core_cli_platform_workspace={workspace_percent:.2f}% "
            f"({workspace_covered}/{workspace_count} lines), "
            f"release_critical={critical_percent:.2f}% "
            f"({critical_covered}/{critical_count} lines)"
        )
        print(
            "coverage: "
            f"compiled_zero_mapping_files={len(zero_mapping_files)}"
        )
        for relative in sorted(zero_mapping_files):
            print(f"coverage zero-mapping file: {relative}")
    else:
        workspace_percent = 0.0

    for relative, covered, count, file_percent in critical_results:
        print(
            "coverage file: "
            f"{relative}={file_percent:.2f}% "
            f"({covered}/{count} lines)"
        )
        if file_percent < args.critical_min:
            failures.append(
                f"{relative} coverage {file_percent:.2f}% "
                f"is below required {args.critical_min:.2f}%"
            )

    if critical_percent < args.critical_min:
        failures.append(
            f"release-critical coverage {critical_percent:.2f}% "
            f"is below required {args.critical_min:.2f}%"
        )
    if workspace is not None and workspace_percent < args.workspace_min:
        failures.append(
            f"measured core/CLI/platform workspace coverage {workspace_percent:.2f}% "
            f"is below ratchet floor {args.workspace_min:.2f}%"
        )

    if failures:
        for failure in failures:
            print(f"coverage gate failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
