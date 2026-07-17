#!/usr/bin/env python3
"""Validate documented lab/pilot workflows and release-gate claims."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "getting-started.md",
    ROOT / "docs" / "api-source.md",
    ROOT / "docs" / "quality-gates.md",
    ROOT / "docs" / "release-process.md",
    ROOT / "examples" / "adapters" / "README.md",
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


def shell_code_blocks(body: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] | None = None
    inside_fence = False
    for raw_line in body.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            if inside_fence:
                if current is not None:
                    blocks.append("\n".join(current))
                current = None
                inside_fence = False
            else:
                language = stripped[3:].strip().lower()
                current = [] if language in {"", "bash", "sh", "shell"} else None
                inside_fence = True
            continue
        if inside_fence and current is not None:
            current.append(raw_line)
    return blocks


def logical_shell_commands(body: str) -> list[str]:
    commands: list[str] = []
    current: list[str] = []
    for raw_line in body.splitlines():
        line = strip_shell_comment(raw_line).strip()
        if not line:
            continue
        continued = line.endswith("\\")
        normalized = line[:-1].strip() if continued else line
        if current:
            current.append(normalized)
        else:
            current = [normalized]
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


def check_benchmark_validator_prebuilds(
    path: Path, body: str, failures: list[str]
) -> None:
    for paragraph in paragraphs(body):
        commands = logical_cargo_commands(paragraph)
        benchmark_indexes = [
            index for index, command in enumerate(commands) if "benchmark run" in command
        ]
        if not benchmark_indexes:
            continue
        validator_build_indexes = [
            index
            for index, command in enumerate(commands)
            if "CARGO_TARGET_DIR=" in command
            and "cargo build --locked" in command
            and "-p netdiag-cli" in command
            and "--bin netdiag-cli" in command
        ]
        relative = path.relative_to(ROOT)
        for benchmark_index in benchmark_indexes:
            if not any(index < benchmark_index for index in validator_build_indexes):
                failures.append(
                    f"{relative} benchmark example must prebuild the trusted Rust validator"
                )


def check_adapter_validator_commands(
    path: Path, body: str, failures: list[str]
) -> None:
    relative = path.relative_to(ROOT)
    for stale in (
        "python3 scripts/validate_adapter_samples.py",
        "python3 scripts/validate_adapter_contract.py",
    ):
        if stale in body:
            failures.append(
                f"{relative} documents a validator command without the reviewed schema venv: {stale}"
            )
    for block in shell_code_blocks(body):
        commands = logical_shell_commands(block)
        validator_indexes = [
            index
            for index, command in enumerate(commands)
            if "scripts/validate_adapter_samples.py" in command
            or "scripts/validate_adapter_contract.py" in command
        ]
        if not validator_indexes:
            continue
        build_indexes = [
            index
            for index, command in enumerate(commands)
            if "CARGO_TARGET_DIR=" in command
            and "cargo build --locked" in command
            and "-p netdiag-cli" in command
            and "--bin netdiag-cli" in command
        ]
        if 'validator_target="$(pwd -P)/target/adapter-validator"' not in block:
            failures.append(
                f"{relative} adapter validation block must bind the fixed validator target"
            )
        for index in validator_indexes:
            command = commands[index]
            if not any(build_index < index for build_index in build_indexes):
                failures.append(
                    f"{relative} adapter validation command must follow a locked validator build"
                )
            if ".venv-jsonschema/bin/python" not in command:
                failures.append(
                    f"{relative} adapter validation command must use the reviewed schema venv"
                )
            if (
                "--rust-validator" not in command
                or "$validator_target/debug/netdiag-cli" not in command
            ):
                failures.append(
                    f"{relative} adapter validation command must pass the fixed Rust validator"
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
        check_benchmark_validator_prebuilds(path, body, failures)
        check_adapter_validator_commands(path, body, failures)

    if failures:
        for failure in failures:
            print(f"docs workflow hygiene failed: {failure}")
        return 1
    print("docs workflow hygiene passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
