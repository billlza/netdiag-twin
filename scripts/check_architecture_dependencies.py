#!/usr/bin/env python3
"""Enforce one-way dependencies across core orchestration boundaries."""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

from count_production_lines import mask_rust_non_code, mask_rust_test_code


COMPATIBILITY_FACADE = re.compile(
    r"^pub use crate::hil_review::\{HilReviewOutcome, review_recommendation\};$"
)
RUST_PATH_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|::|[{},;]")
FORBIDDEN_STORAGE_ROOTS = frozenset({"lab", "evidence_bundle"})
FORBIDDEN_BENCHMARK_ROOTS = frozenset({"pilot"})
FORBIDDEN_NEUTRAL_RUNTIME_ROOTS = frozenset({"benchmark", "pilot"})
FORBIDDEN_MANAGED_TEMP_ROOTS = frozenset(
    {
        "benchmark",
        "connectors",
        "dataset",
        "evidence_bundle",
        "hil_review",
        "ingest",
        "lab",
        "ml",
        "models",
        "perf_budget",
        "pilot",
        "pipeline",
        "python_runtime",
        "recommendation",
        "reliability",
        "report",
        "rules",
        "storage",
        "telemetry",
        "twin",
    }
)
FORBIDDEN_BOUNDED_PROCESS_ROOTS = FORBIDDEN_MANAGED_TEMP_ROOTS | frozenset(
    {"managed_temp_directory"}
)
LEGACY_CORE_FILESYSTEM_TRUST = (
    "crates/netdiag-core/src/filesystem_trust.rs",
    "crates/netdiag-core/src/filesystem_trust",
)
UNMANAGED_TEMPORARY_DIRECTORY_TOKEN = re.compile(
    r"\b(?:TempDir|tempdir|tempdir_in|temp_dir)\b"
)
UNBOUNDED_PROCESS_TOKEN = re.compile(
    r"\b(?:std::process::Command|process::Command|Command)::new\s*\("
)
SPLIT_PATH_IO_TOKEN = re.compile(
    r"\b(?:with_exclusive_file_lock|DatasetInputSnapshot|BoundAtomicFileTarget::bind)\b"
    r"|\bwrite_file_atomically_noclobber\s*\("
    r"|\bread_(?:optional|required)_stable_json_bounded\s*\("
    r"|\b(?:std::fs|fs)::(?:read|write|metadata|symlink_metadata|rename|remove_file)\b"
    r"|\.(?:exists|is_file)\s*\("
)
SPLIT_ENTRY_CONTRACTS = (
    re.compile(r"SplitTargets::new\s*\(\s*&root"),
    re.compile(r"with_exclusive_bound_file_lock\s*\(\s*&targets\.manifest"),
    re.compile(
        r"recovery::claim\s*\(\s*&root\s*,\s*&targets\.receipt\s*,\s*&targets\.public_targets"
    ),
)
SPLIT_PLAN_CONTRACTS = (
    re.compile(r"train\s*=\s*PartitionPlan::new\s*\(\s*root\.target"),
    re.compile(r"validation\s*=\s*PartitionPlan::new\s*\(\s*root\.target"),
    re.compile(r"test_target\s*=\s*root\.target"),
    re.compile(r"manifest:\s*root\.target"),
    re.compile(r"receipt:\s*root\.target"),
    re.compile(r"target:\s*BoundAtomicFileTarget"),
)


def production_storage_sources(root: Path) -> list[Path]:
    storage_root = root / "crates/netdiag-core/src/storage"
    paths = [root / "crates/netdiag-core/src/storage.rs", *storage_root.rglob("*.rs")]
    return sorted(
        path
        for path in paths
        if path.name != "tests.rs" and "tests" not in path.relative_to(root).parts
    )


def production_module_sources(root: Path, entry: str, module_root: str) -> list[Path]:
    paths: list[Path] = []
    entry_path = root / entry
    if entry_path.is_file():
        paths.append(entry_path)
    directory = root / module_root
    if directory.is_dir():
        paths.extend(directory.rglob("*.rs"))
    return sorted(
        path
        for path in paths
        if path.name != "tests.rs" and "tests" not in path.relative_to(root).parts
    )


def product_production_sources(root: Path) -> list[Path]:
    crates_root = root / "crates"
    if not crates_root.is_dir():
        return []
    paths = (
        path
        for crate in crates_root.iterdir()
        if crate.is_dir() and crate.name != "netdiag-platform"
        for path in (crate / "src").rglob("*.rs")
    )
    return sorted(
        path
        for path in paths
        if path.stem != "tests"
        and not path.stem.endswith("_tests")
        and "tests" not in path.relative_to(root).parts
    )


def split_publication_violations(root: Path) -> list[str]:
    entry = root / "crates/netdiag-core/src/dataset/split_publication.rs"
    module = root / "crates/netdiag-core/src/dataset/split_publication"
    if not entry.is_file() or not module.is_dir():
        return []
    violations: list[str] = []
    for path in production_module_sources(
        root,
        str(entry.relative_to(root)),
        str(module.relative_to(root)),
    ):
        source = path.read_text()
        production = mask_rust_test_code(source)
        for match in SPLIT_PATH_IO_TOKEN.finditer(production):
            line_number, _ = source_line(source, match.start())
            violations.append(
                f"{path.relative_to(root)}:{line_number}: dataset split publication must use retained bound targets"
            )
    entry_source = mask_rust_test_code(entry.read_text())
    for contract in SPLIT_ENTRY_CONTRACTS:
        if not contract.search(entry_source):
            violations.append(
                "crates/netdiag-core/src/dataset/split_publication.rs: split targets, receipt, and lock must share one retained root"
            )
    plan_path = module / "plan.rs"
    plan_source = mask_rust_test_code(plan_path.read_text()) if plan_path.is_file() else ""
    for contract in SPLIT_PLAN_CONTRACTS:
        if not contract.search(plan_source):
            violations.append(
                "crates/netdiag-core/src/dataset/split_publication/plan.rs: every split artifact must be a root-created bound target"
            )
    return violations


def crate_root_references(source: str, names: frozenset[str]) -> list[int]:
    """Return offsets of direct and grouped references to named crate roots."""

    masked = mask_rust_non_code(source)
    tokens = [(match.group(), match.start()) for match in RUST_PATH_TOKEN.finditer(masked)]
    references: list[int] = []
    cursor = 0
    while cursor + 2 < len(tokens):
        if tokens[cursor][0] != "crate" or tokens[cursor + 1][0] != "::":
            cursor += 1
            continue

        root, root_offset = tokens[cursor + 2]
        if root in names:
            references.append(root_offset)
            cursor += 3
            continue
        if root != "{":
            cursor += 3
            continue

        depth = 1
        entry_start = True
        grouped = cursor + 3
        while grouped < len(tokens) and depth:
            token, offset = tokens[grouped]
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1
            elif depth == 1 and token == ",":
                entry_start = True
            elif depth == 1 and entry_start and token not in {"::", ";"}:
                if token in names:
                    references.append(offset)
                entry_start = False
            grouped += 1
        cursor = grouped
    return references


def source_line(source: str, offset: int) -> tuple[int, str]:
    line_number = source.count("\n", 0, offset) + 1
    return line_number, source.splitlines()[line_number - 1].strip()


def dependency_violations(root: Path) -> list[str]:
    violations: list[str] = []
    violations.extend(split_publication_violations(root))
    for relative in LEGACY_CORE_FILESYSTEM_TRUST:
        if (root / relative).exists():
            violations.append(
                f"{relative}: filesystem trust primitives belong exclusively to netdiag-platform"
            )
    storage_entry = root / "crates/netdiag-core/src/storage.rs"
    for path in production_storage_sources(root):
        source = path.read_text()
        relative = path.relative_to(root)
        forbidden_lines = {
            source_line(source, offset)[0]
            for offset in crate_root_references(source, FORBIDDEN_STORAGE_ROOTS)
        }
        for line_number in sorted(forbidden_lines):
            violations.append(
                f"{relative}:{line_number}: storage implementation depends on Lab or evidence"
            )

        for offset in crate_root_references(source, frozenset({"hil_review"})):
            line_number, stripped = source_line(source, offset)
            if path == storage_entry and COMPATIBILITY_FACADE.fullmatch(stripped):
                continue
            violations.append(
                f"{relative}:{line_number}: storage may reference hil_review only through "
                "the documented compatibility pub use"
            )

    benchmark_sources = production_module_sources(
        root,
        "crates/netdiag-core/src/benchmark.rs",
        "crates/netdiag-core/src/benchmark",
    )
    for path in benchmark_sources:
        source = path.read_text()
        for offset in crate_root_references(source, FORBIDDEN_BENCHMARK_ROOTS):
            line_number, _ = source_line(source, offset)
            violations.append(
                f"{path.relative_to(root)}:{line_number}: benchmark must not depend on Pilot"
            )

    neutral_sources = production_module_sources(
        root,
        "crates/netdiag-core/src/python_runtime.rs",
        "crates/netdiag-core/src/python_runtime",
    )
    for path in neutral_sources:
        source = path.read_text()
        for offset in crate_root_references(source, FORBIDDEN_NEUTRAL_RUNTIME_ROOTS):
            line_number, _ = source_line(source, offset)
            violations.append(
                f"{path.relative_to(root)}:{line_number}: neutral Python runtime code must not "
                "depend on benchmark or Pilot"
            )

    bounded_process_sources = production_module_sources(
        root,
        "crates/netdiag-core/src/bounded_process.rs",
        "crates/netdiag-core/src/bounded_process",
    )
    for path in bounded_process_sources:
        source = path.read_text()
        for offset in crate_root_references(source, FORBIDDEN_BOUNDED_PROCESS_ROOTS):
            line_number, _ = source_line(source, offset)
            violations.append(
                f"{path.relative_to(root)}:{line_number}: bounded process boundary must not "
                "depend on product domains"
            )

    managed_temp_sources = production_module_sources(
        root,
        "crates/netdiag-core/src/managed_temp_directory.rs",
        "crates/netdiag-core/src/managed_temp_directory",
    )
    for path in managed_temp_sources:
        source = path.read_text()
        for offset in crate_root_references(source, FORBIDDEN_MANAGED_TEMP_ROOTS):
            line_number, _ = source_line(source, offset)
            violations.append(
                f"{path.relative_to(root)}:{line_number}: managed temporary directory boundary "
                "must not depend on product domains"
            )

    for path in product_production_sources(root):
        source = path.read_text()
        production = mask_rust_test_code(source)
        for match in UNMANAGED_TEMPORARY_DIRECTORY_TOKEN.finditer(production):
            line_number, _ = source_line(source, match.start())
            violations.append(
                f"{path.relative_to(root)}:{line_number}: product production code must use "
                "the managed or platform trusted temporary-directory boundary"
            )
        relative = path.relative_to(root)
        is_bounded_process = (
            relative.as_posix() == "crates/netdiag-core/src/bounded_process.rs"
            or "bounded_process" in relative.parts
        )
        if not is_bounded_process:
            for match in UNBOUNDED_PROCESS_TOKEN.finditer(production):
                line_number, _ = source_line(source, match.start())
                violations.append(
                    f"{path.relative_to(root)}:{line_number}: product production code must use "
                    "the bounded process boundary"
                )
    return violations


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        storage_root = root / "crates/netdiag-core/src/storage"
        storage_root.mkdir(parents=True)
        storage_entry = root / "crates/netdiag-core/src/storage.rs"
        storage_entry.write_text(
            "pub use crate::hil_review::{HilReviewOutcome, review_recommendation};\n"
        )
        (storage_root / "journal.rs").write_text("use crate::models::HilReview;\n")

        benchmark_root = root / "crates/netdiag-core/src/benchmark"
        benchmark_root.mkdir(parents=True)
        (root / "crates/netdiag-core/src/benchmark.rs").write_text(
            "use crate::python_runtime::TrustedPythonRuntime;\n"
        )
        benchmark_schema = benchmark_root / "schema_validation.rs"
        benchmark_schema.write_text("use crate::storage::PathStatus;\n")

        python_runtime_root = root / "crates/netdiag-core/src/python_runtime"
        python_runtime_root.mkdir(parents=True)
        (root / "crates/netdiag-core/src/python_runtime.rs").write_text(
            "use crate::error::Result;\n"
        )
        python_configured = python_runtime_root / "configured.rs"
        python_configured.write_text("use crate::storage::PathStatus;\n")

        bounded_process = root / "crates/netdiag-core/src/bounded_process.rs"
        bounded_process.write_text("use crate::error::Result;\n")

        managed_temp = root / "crates/netdiag-core/src/managed_temp_directory.rs"
        managed_temp.write_text("use crate::error::Result;\n")

        service = root / "crates/netdiag-core/src/service.rs"
        service.write_text(
            "// tempfile::tempdir() is test-only.\n"
            "const EXAMPLE: &str = \"TempDir\";\n"
            "#[cfg(test)] mod tests { fn fixture() { tempfile::tempdir(); std::env::temp_dir(); } }\n"
            "pub fn run() {}\n"
        )

        split_root = root / "crates/netdiag-core/src/dataset/split_publication"
        split_root.mkdir(parents=True)
        split_entry = root / "crates/netdiag-core/src/dataset/split_publication.rs"
        split_entry.write_text(
            "fn publish(root: Root) { let targets = SplitTargets::new(&root); "
            "with_exclusive_bound_file_lock(&targets.manifest); "
            "recovery::claim(&root, &targets.receipt, &targets.public_targets()); }\n"
        )
        split_plan = split_root / "plan.rs"
        split_plan.write_text(
            "struct PartitionPlan { target: BoundAtomicFileTarget }\n"
            "fn targets(root: Root) { let train = PartitionPlan::new(root.target()); "
            "let validation = PartitionPlan::new(root.target()); "
            "let test_target = root.target(); Self { manifest: root.target(), receipt: root.target() }; }\n"
        )

        assert dependency_violations(root) == []

        split_entry.write_text("fn publish(path: &Path) { with_exclusive_file_lock(path); }\n")
        violations = dependency_violations(root)
        assert any("retained bound targets" in item for item in violations)
        split_entry.write_text(
            "fn publish(root: Root) { let targets = SplitTargets::new(&root); "
            "with_exclusive_bound_file_lock(&targets.manifest); "
            "recovery::claim(&root, &targets.receipt, &targets.public_targets()); }\n"
        )

        service.write_text("pub fn run() { let _ = tempfile::tempdir(); }\n")
        violations = dependency_violations(root)
        assert any("trusted temporary-directory boundary" in item for item in violations)
        service.write_text("pub fn run() {}\n")

        service.write_text("pub fn run() { let _ = std::env::temp_dir(); }\n")
        violations = dependency_violations(root)
        assert any("trusted temporary-directory boundary" in item for item in violations)
        service.write_text("pub fn run() {}\n")

        service.write_text("pub fn run() { let _ = std::process::Command::new(\"tool\"); }\n")
        violations = dependency_violations(root)
        assert any("bounded process boundary" in item for item in violations)
        service.write_text("pub fn run() {}\n")

        benchmark_schema.write_text("use crate::pilot::PilotManifest;\n")
        violations = dependency_violations(root)
        assert any("benchmark must not depend on Pilot" in violation for violation in violations)
        benchmark_schema.write_text("use crate::storage::PathStatus;\n")

        python_configured.write_text("use crate::benchmark::BenchmarkReport;\n")
        violations = dependency_violations(root)
        assert any("neutral Python runtime" in violation for violation in violations)
        python_configured.write_text("use crate::storage::PathStatus;\n")

        bounded_process.write_text("use crate::pilot::PilotManifest;\n")
        violations = dependency_violations(root)
        assert any("bounded process boundary" in violation for violation in violations)
        bounded_process.write_text("use crate::error::Result;\n")

        managed_temp.write_text("use crate::evidence_bundle::EvidenceContext;\n")
        violations = dependency_violations(root)
        assert any("managed temporary directory boundary" in item for item in violations)
        managed_temp.write_text("use crate::error::Result;\n")

        legacy_trust = root / "crates/netdiag-core/src/filesystem_trust.rs"
        legacy_trust.write_text("use crate::pilot::PilotManifest;\n")
        violations = dependency_violations(root)
        assert any("belong exclusively to netdiag-platform" in violation for violation in violations)
        legacy_trust.unlink()

        (storage_root / "journal.rs").write_text(
            "// use crate::{lab::Scenario, evidence_bundle::export};\n"
            "const EXAMPLE: &str = r#\"crate::{lab::Scenario}\"#;\n"
            "use crate::{models::HilReview, report::Report};\n"
        )
        assert dependency_violations(root) == []

        (storage_root / "publisher.rs").write_text(
            "use crate::{\n"
            "    evidence_bundle::export,\n"
            "    models::Report,\n"
            "};\n"
        )
        violations = dependency_violations(root)
        assert any("depends on Lab or evidence" in violation for violation in violations)

        (storage_root / "publisher.rs").write_text(
            "use crate::{models::{lab::Label, Report}, report::render};\n"
        )
        assert dependency_violations(root) == []

        (storage_root / "publisher.rs").write_text(
            "use crate::{models::Report, hil_review::review_recommendation};\n"
        )
        violations = dependency_violations(root)
        assert any("compatibility pub use" in violation for violation in violations)

        storage_entry.write_text("pub use crate::hil_review::review_recommendation;\n")
        violations = dependency_violations(root)
        assert any("compatibility pub use" in violation for violation in violations)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        print("architecture dependency guard sanity passed")
        return 0

    violations = dependency_violations(args.root.resolve())
    if violations:
        for violation in violations:
            print(f"architecture dependency guard failed: {violation}")
        return 1
    print(
        "architecture dependency direction passed: hil_review -> storage + lab + evidence; "
        "benchmark -> python_runtime -> netdiag-platform; product domains -> bounded process and "
        "managed temp -> netdiag-platform; unmanaged product TempDir APIs forbidden"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
