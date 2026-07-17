#!/usr/bin/env python3
"""Verify architecture guard line accounting is not truncated by test-module declarations."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from adapter_process import run_bounded


ROOT = Path(__file__).resolve().parents[1]
APP_MAIN = "crates/netdiag-app/src/main.rs"
PILOT_ENTRY = "crates/netdiag-core/src/pilot.rs"
PILOT_MODULE_ROOT = "crates/netdiag-core/src/pilot"
CLI_PILOT_ENTRY = "crates/netdiag-cli/src/commands/pilot.rs"
OTLP_RECEIVER = "crates/netdiag-core/src/connectors/otlp.rs"
OTLP_BUFFER = "crates/netdiag-core/src/connectors/otlp/buffer.rs"
PERF_BENCH = "crates/netdiag-core/benches/perf_budget.rs"
OTLP_RUNTIME_PATHS = (
    OTLP_RECEIVER,
    OTLP_BUFFER,
    "crates/netdiag-core/src/connectors/otlp/projection.rs",
    "crates/netdiag-core/src/connectors/otlp/projection/budget.rs",
    "crates/netdiag-core/src/connectors/otlp/projection/numeric.rs",
    "crates/netdiag-core/src/connectors/otlp/server.rs",
    "crates/netdiag-core/src/connectors/otlp/server/incoming.rs",
    "crates/netdiag-core/src/connectors/otlp/server/runtime.rs",
    "crates/netdiag-core/src/connectors/otlp/server/shutdown.rs",
)
NEUTRAL_SECURITY_ENTRIES = (
    "crates/netdiag-core/src/managed_temp_directory.rs",
    "crates/netdiag-core/src/python_runtime.rs",
    "crates/netdiag-platform/src/trusted_directory.rs",
    "crates/netdiag-platform/src/trusted_directory/error.rs",
    "crates/netdiag-platform/src/trusted_directory/strict.rs",
    "crates/netdiag-platform/src/trusted_directory/unix.rs",
    "crates/netdiag-platform/src/trusted_temp_directory.rs",
    "crates/netdiag-platform/src/unix_acl.rs",
)
NEUTRAL_SECURITY_MODULE_ROOTS = (
    "crates/netdiag-core/src/managed_temp_directory",
    "crates/netdiag-core/src/python_runtime",
    "crates/netdiag-platform/src/trusted_directory/error",
    "crates/netdiag-platform/src/trusted_directory/unix",
    "crates/netdiag-platform/src/trusted_temp_directory",
)
ARCHITECTURE_CHECK_TIMEOUT_SECONDS = 120.0
ARCHITECTURE_CHECK_OUTPUT_LIMIT_BYTES = 2 * 1024 * 1024


def architecture_check_environment() -> dict[str, str]:
    path = os.environ.get("PATH")
    if not path:
        raise RuntimeError("PATH is required to execute architecture checks")
    return {
        "PATH": path,
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "NETDIAG_PYTHON_EXECUTABLE": str(Path(sys.executable).resolve()),
    }


def run_architecture_check(command: list[str]) -> tuple[int, str]:
    completed = run_bounded(
        command,
        cwd=ROOT,
        timeout_seconds=ARCHITECTURE_CHECK_TIMEOUT_SECONDS,
        stdout_limit_bytes=ARCHITECTURE_CHECK_OUTPUT_LIMIT_BYTES,
        stderr_limit_bytes=ARCHITECTURE_CHECK_OUTPUT_LIMIT_BYTES,
        environment=architecture_check_environment(),
    )
    return completed.returncode, completed.stdout + completed.stderr


def is_production_critical_source(path: Path, root: Path = ROOT) -> bool:
    relative = path.relative_to(root).as_posix()
    return "/tests/" not in relative and not relative.endswith("/tests.rs")


def test_code_violations(path: Path) -> list[int]:
    lines = path.read_text().splitlines()
    violations: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"mod\s+tests\s*\{", stripped):
            attribute = index - 1
            cfg_test_precedes = False
            while attribute >= 0 and lines[attribute].strip().startswith("#["):
                cfg_test_precedes |= (
                    lines[attribute].strip().startswith("#[cfg")
                    and "test" in lines[attribute]
                )
                attribute -= 1
            if not cfg_test_precedes:
                violations.append(index + 1)
            continue
        if not (stripped.startswith("#[cfg") and "test" in stripped):
            continue
        following = index + 1
        while following < len(lines) and lines[following].strip().startswith("#["):
            following += 1
        declaration = lines[following].strip() if following < len(lines) else ""
        if declaration != "mod tests;":
            violations.append(index + 1)
    return violations


def critical_test_code_violations(root: Path = ROOT) -> list[tuple[Path, int]]:
    paths = [
        root / PILOT_ENTRY,
        root / CLI_PILOT_ENTRY,
        *(root / entry for entry in NEUTRAL_SECURITY_ENTRIES),
        *(root / PILOT_MODULE_ROOT).rglob("*.rs"),
        *(
            path
            for module_root in NEUTRAL_SECURITY_MODULE_ROOTS
            for path in (root / module_root).rglob("*.rs")
        ),
    ]
    return [
        (path, line)
        for path in paths
        if is_production_critical_source(path, root)
        for line in test_code_violations(path)
    ]


def main() -> int:
    try:
        dependency_returncode, dependency_output = run_architecture_check(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts/check_architecture_dependencies.py"),
                "--self-test",
            ]
        )
    except RuntimeError as error:
        print(f"architecture dependency sanity failed: {error}")
        return 1
    if dependency_returncode != 0:
        print(dependency_output, end="")
        return dependency_returncode

    try:
        result_returncode, output = run_architecture_check(
            [str(ROOT / "scripts/check_architecture_guard.sh")]
        )
    except RuntimeError as error:
        print(f"architecture guard sanity failed: {error}")
        return 1
    if result_returncode != 0:
        print(output, end="")
        return result_returncode

    receiver = (ROOT / OTLP_RECEIVER).read_text()
    runtime_sources = "\n".join((ROOT / path).read_text() for path in OTLP_RUNTIME_PATHS)
    if ".max_decoding_message_size(MAX_DECODING_MESSAGE_BYTES)" not in receiver:
        print("architecture guard sanity failed: OTLP decoding limit is not wired")
        return 1
    if "parse_loopback_bind_addr(&config.bind_addr)" not in receiver:
        print("architecture guard sanity failed: OTLP loopback startup guard is not wired")
        return 1
    if "VecDeque<ExportMetricsServiceRequest" in runtime_sources:
        print("architecture guard sanity failed: OTLP buffer retains raw requests")
        return 1
    guard_body = (ROOT / "scripts/check_architecture_guard.sh").read_text()
    for path in OTLP_RUNTIME_PATHS:
        if f'"$ROOT/{path}"' not in guard_body:
            print(
                "architecture guard sanity failed: OTLP raw-request guard omits "
                f"{path}"
            )
            return 1
    if f'"$ROOT/{PERF_BENCH}"' not in guard_body:
        print(
            "architecture guard sanity failed: performance benchmark isolation guard "
            f"omits {PERF_BENCH}"
        )
        return 1

    test_violations = critical_test_code_violations()
    if test_violations:
        print(output, end="")
        for path, line in test_violations:
            print(
                "architecture guard sanity failed: critical production source contains "
                f"inline or non-tests-path cfg(test) code: {path.relative_to(ROOT)}:{line}"
            )
        return 1

    match = re.search(rf"^{re.escape(APP_MAIN)}: (\d+)/(\d+) production lines$", output, re.M)
    if match is None:
        print(output, end="")
        print(f"architecture guard sanity failed: missing {APP_MAIN} line")
        return 1

    reported = int(match.group(1))
    actual_lines = sum(1 for _ in (ROOT / APP_MAIN).open())
    if reported < actual_lines * 0.90:
        print(output, end="")
        print(
            "architecture guard sanity failed: "
            f"{APP_MAIN} reported {reported} production lines for {actual_lines} total lines"
        )
        return 1

    print("architecture guard sanity passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
