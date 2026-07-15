#!/usr/bin/env python3
"""Validate documented lab/pilot workflows and release-gate claims."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "getting-started.md",
    ROOT / "docs" / "quality-gates.md",
    ROOT / "docs" / "release-process.md",
]
SCOPED_COVERAGE_MARKERS = (
    "v0.5 pilot/cli",
    "release-critical",
    "release surface",
    "发布关键面",
    "scoped",
    "do not claim",
    "netdiag_coverage_min",
)


def first_index(body: str, needle: str) -> int:
    index = body.find(needle)
    return index if index >= 0 else 10**9


def paragraphs(body: str) -> list[str]:
    return [paragraph.strip() for paragraph in body.split("\n\n") if paragraph.strip()]


def strip_shell_comment(line: str) -> str:
    single_quoted = False
    double_quoted = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single_quoted:
            escaped = True
            continue
        if char == "'" and not double_quoted:
            single_quoted = not single_quoted
            continue
        if char == '"' and not single_quoted:
            double_quoted = not double_quoted
            continue
        if (
            char == "#"
            and not single_quoted
            and not double_quoted
            and (index == 0 or line[index - 1].isspace())
        ):
            return line[:index]
    return line


def begins_cargo_command(line: str) -> bool:
    parts = line.split()
    index = 0
    while index < len(parts) and "=" in parts[index] and not parts[index].startswith("-"):
        index += 1
    return index < len(parts) and parts[index] == "cargo"


def logical_cargo_commands(body: str) -> list[str]:
    commands: list[str] = []
    current: list[str] = []
    for raw_line in body.splitlines():
        line = strip_shell_comment(raw_line).strip()
        if not line:
            continue
        if current:
            continued = line.endswith("\\")
            current.append(line[:-1].strip() if continued else line)
            if not continued:
                commands.append(" ".join(current))
                current = []
            continue
        if not begins_cargo_command(line):
            continue
        continued = line.endswith("\\")
        current = [line[:-1].strip() if continued else line]
        if not continued:
            commands.append(" ".join(current))
            current = []
    if current:
        commands.append(" ".join(current))
    return commands


def check_coverage_claims(path: Path, body: str, failures: list[str]) -> None:
    for paragraph in paragraphs(body):
        lower = " ".join(paragraph.lower().split())
        if "90%" not in lower or "coverage" not in lower:
            continue
        if any(marker in lower for marker in SCOPED_COVERAGE_MARKERS):
            continue
        failures.append(
            f"{path.relative_to(ROOT)} has an unscoped 90% coverage claim: {paragraph!r}"
        )


def check_promotion_command_examples(path: Path, body: str, failures: list[str]) -> None:
    for paragraph in paragraphs(body):
        commands = logical_cargo_commands(paragraph)
        model_gate_indexes = [
            index for index, command in enumerate(commands) if "pilot model-gate" in command
        ]
        if not model_gate_indexes:
            continue

        benchmark_indexes = [
            index for index, command in enumerate(commands) if "benchmark run" in command
        ]
        calibrate_indexes = [
            index for index, command in enumerate(commands) if "lab calibrate" in command
        ]
        relative = path.relative_to(ROOT)
        for index in model_gate_indexes:
            command = commands[index]
            for option in ("--model-dir", "--benchmark-report", "--calibration-report"):
                if option not in command:
                    failures.append(
                        f"{relative} model-gate example missing {option}"
                    )
        for index in benchmark_indexes:
            if "--model-dir" not in commands[index]:
                failures.append(
                    f"{relative} promotion benchmark example missing --model-dir"
                )

        if not calibrate_indexes or not benchmark_indexes:
            failures.append(
                f"{relative} promotion command block must include lab calibrate, "
                "benchmark run, and pilot model-gate"
            )
            continue
        if not (
            calibrate_indexes[0] < benchmark_indexes[0] < model_gate_indexes[0]
        ):
            failures.append(
                f"{relative} promotion command block must order lab calibrate "
                "before benchmark run before pilot model-gate"
            )


def main() -> int:
    failures: list[str] = []
    for path in DOCS:
        body = path.read_text()
        lab_run = first_index(body, "lab run examples/scenarios/lab-congestion-001.yaml")
        calibrate = first_index(body, "lab calibrate --artifacts artifacts")
        if calibrate < lab_run:
            failures.append(
                f"{path.relative_to(ROOT)} documents lab calibrate before the first lab run"
            )
        check_coverage_claims(path, body, failures)
        check_promotion_command_examples(path, body, failures)

    if failures:
        for failure in failures:
            print(f"docs workflow hygiene failed: {failure}")
        return 1
    print("docs workflow hygiene passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
