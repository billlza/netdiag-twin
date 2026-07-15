#!/usr/bin/env python3
"""Validate executable coverage for security-sensitive desktop app modules."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from check_coverage_summary import (
    COVERAGE_OFF_ATTRIBUTE,
    is_production_rust_source,
    load_summary,
    makefile_words,
    measured_file_totals,
    normalize_filename,
    percent,
    validate_threshold,
    validated_line_summary,
)
from count_production_lines import mask_rust_non_code


ROOT = Path(__file__).resolve().parents[1]
LIBRARY_SECURITY_ROOT_FILES = (
    "crates/netdiag-app/src/credential_lifecycle.rs",
    "crates/netdiag-app/src/secrets.rs",
)
LIBRARY_SECURITY_SOURCE_DIRS = (
    "crates/netdiag-app/src/credential_lifecycle",
    "crates/netdiag-app/src/secrets",
)
BINARY_SECURITY_ROOT_FILES = (
    "crates/netdiag-app/src/api_test.rs",
    "crates/netdiag-app/src/confirmation.rs",
)
BINARY_SECURITY_SOURCE_DIRS = (
    "crates/netdiag-app/src/api_test",
    "crates/netdiag-app/src/confirmation",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--dep-info-dir", required=True, type=Path)
    parser.add_argument("--aggregate-min", required=True, type=float)
    parser.add_argument("--file-min", required=True, type=float)
    return parser.parse_args()


def security_relative_path(filename: str) -> str | None:
    normalized = normalize_filename(filename)
    for relative in LIBRARY_SECURITY_ROOT_FILES + BINARY_SECURITY_ROOT_FILES:
        if normalized == relative or normalized.endswith(f"/{relative}"):
            return relative
    for relative_dir in LIBRARY_SECURITY_SOURCE_DIRS + BINARY_SECURITY_SOURCE_DIRS:
        prefix = f"{relative_dir}/"
        if normalized.startswith(prefix):
            relative = normalized
        elif f"/{prefix}" in normalized:
            relative = prefix + normalized.split(prefix, 1)[1]
        else:
            continue
        if is_production_rust_source(relative):
            return relative
    return None


def discover_security_files(
    root_files: tuple[str, ...], source_dirs: tuple[str, ...], failures: list[str]
) -> set[str]:
    expected = set(root_files)
    for relative in root_files:
        source = ROOT / relative
        if not source.is_file():
            failures.append(f"security coverage source file is missing: {relative}")
    for relative_dir in source_dirs:
        source_dir = ROOT / relative_dir
        if not source_dir.is_dir():
            continue
        for path in source_dir.rglob("*.rs"):
            relative = path.relative_to(ROOT).as_posix()
            if is_production_rust_source(relative):
                expected.add(relative)
    return expected


def expected_security_file_sets(
    failures: list[str],
) -> tuple[set[str], set[str]]:
    library = discover_security_files(
        LIBRARY_SECURITY_ROOT_FILES, LIBRARY_SECURITY_SOURCE_DIRS, failures
    )
    binary = discover_security_files(
        BINARY_SECURITY_ROOT_FILES, BINARY_SECURITY_SOURCE_DIRS, failures
    )
    for relative in sorted(library | binary):
        source = ROOT / relative
        if not source.is_file():
            continue
        try:
            masked = mask_rust_non_code(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            failures.append(f"could not inspect security coverage source {relative}: {exc}")
            continue
        if COVERAGE_OFF_ATTRIBUTE.search(masked):
            failures.append(
                f"coverage suppression is forbidden in security source: {relative}"
            )
    return library, binary


def compiled_security_files(
    dep_info_dir: Path,
    library_security_files: set[str],
    binary_security_files: set[str],
    failures: list[str],
) -> set[str]:
    try:
        canonical_root = ROOT.resolve(strict=True)
    except OSError as exc:
        failures.append(f"could not resolve coverage source root {ROOT}: {exc}")
        return set()

    dep_info_files = sorted(dep_info_dir.glob("netdiag_app-*.d"))
    if not dep_info_files:
        failures.append(f"app coverage dep-info is missing: {dep_info_dir}")
        return set()

    compiled: set[str] = set()
    library_target_seen = False
    binary_target_seen = False
    for dep_info in dep_info_files:
        try:
            contents = dep_info.read_text(encoding="utf-8")
            words = makefile_words(contents)
        except (OSError, UnicodeError, ValueError) as exc:
            failures.append(f"could not read app coverage dep-info {dep_info}: {exc}")
            continue

        normalized = normalize_filename(contents)
        is_library = bool(
            re.search(r"(?m)^.*?/libnetdiag_app-[^/\s]+\.rlib:", normalized)
        )
        is_binary = "crates/netdiag-app/src/main.rs" in words and bool(
            re.search(r"(?m)^.*?/netdiag_app-[^/\s]+:", normalized)
        )
        library_target_seen |= is_library
        binary_target_seen |= is_binary
        eligible = set()
        if is_library:
            eligible.update(library_security_files)
        if is_binary:
            eligible.update(binary_security_files)
        if not eligible:
            continue

        for word in words:
            relative = security_relative_path(word)
            if relative is None or relative not in eligible:
                continue
            candidate = Path(word)
            if not candidate.is_absolute():
                candidate = ROOT / candidate
            try:
                canonical_source = candidate.resolve(strict=True)
                canonical_relative = canonical_source.relative_to(canonical_root).as_posix()
            except (OSError, ValueError) as exc:
                failures.append(
                    "app coverage dep-info source must resolve inside the checkout: "
                    f"{word}: {exc}"
                )
                continue
            if canonical_relative != relative:
                failures.append(
                    "app coverage dep-info source path does not canonically match its "
                    f"security path: {word} -> {canonical_relative}"
                )
                continue
            compiled.add(relative)

    if not library_target_seen:
        failures.append("app coverage build has no production netdiag-app library target")
    if not binary_target_seen:
        failures.append("app coverage build has no netdiag-app binary test target")
    return compiled


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    validate_threshold("aggregate-min", args.aggregate_min, failures)
    validate_threshold("file-min", args.file_min, failures)
    if failures:
        for failure in failures:
            print(f"app security coverage gate failed: {failure}", file=sys.stderr)
        return 1

    try:
        totals, files = load_summary(args.summary)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(
            f"app security coverage gate failed: could not read coverage summary: {exc}",
            file=sys.stderr,
        )
        return 1

    reported_totals = validated_line_summary(
        totals.get("lines"), "llvm-cov totals", failures
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

    library_security_files, binary_security_files = expected_security_file_sets(
        failures
    )
    expected = library_security_files | binary_security_files
    compiled = compiled_security_files(
        args.dep_info_dir,
        library_security_files,
        binary_security_files,
        failures,
    )
    for relative in sorted(expected - compiled):
        failures.append(
            f"security coverage source is absent from app build dep-info: {relative}"
        )

    found: dict[str, dict] = {}
    for entry in files:
        filename = entry.get("filename") if isinstance(entry, dict) else None
        if not isinstance(filename, str):
            continue
        relative = security_relative_path(filename)
        if relative is None:
            continue
        if relative not in expected:
            failures.append(
                "security coverage summary references a production source that is "
                f"absent from the checkout: {relative}"
            )
            continue
        if relative not in compiled:
            failures.append(
                "security coverage summary references a production source that is "
                f"absent from app build dep-info: {relative}"
            )
            continue
        if relative in found:
            failures.append(f"security coverage file appears more than once: {relative}")
            continue
        found[relative] = entry

    covered_total = 0
    count_total = 0
    for relative in sorted(expected):
        entry = found.get(relative)
        if entry is None:
            failures.append(f"security coverage file is missing from summary: {relative}")
            continue
        summary = entry.get("summary")
        lines = summary.get("lines") if isinstance(summary, dict) else None
        result = validated_line_summary(lines, relative, failures)
        if result is None:
            continue
        covered, count, file_percent = result
        covered_total += covered
        count_total += count
        print(
            "app security coverage file: "
            f"{relative}={file_percent:.2f}% ({covered}/{count} lines)"
        )
        if file_percent < args.file_min:
            failures.append(
                f"{relative} coverage {file_percent:.2f}% "
                f"is below required {args.file_min:.2f}%"
            )

    aggregate_percent = percent(covered_total, count_total) if count_total else 0.0
    print(
        "app security coverage: "
        f"aggregate={aggregate_percent:.2f}% ({covered_total}/{count_total} lines)"
    )
    if aggregate_percent < args.aggregate_min:
        failures.append(
            f"app security coverage {aggregate_percent:.2f}% "
            f"is below required {args.aggregate_min:.2f}%"
        )

    if failures:
        for failure in failures:
            print(f"app security coverage gate failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
