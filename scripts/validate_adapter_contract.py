#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as error:
    raise SystemExit(
        "missing dependency: install jsonschema to validate adapter contracts"
    ) from error


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "examples/adapters/schema/netdiag-adapter-payload.schema.json"
GENERIC_LAB_ADAPTERS = [
    "openconfig-gnmi",
    "snmp-if-mib",
    "frr-routing-state",
    "iperf3-http-json",
    "tc-netem-lab",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--schema-only",
        action="store_true",
        help="skip Rust ingest validation and only validate JSON schema",
    )
    args = parser.parse_args()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    failed = False

    with tempfile.TemporaryDirectory(prefix="netdiag-adapter-contract-") as tmp:
        tmp_dir = Path(tmp)
        for name in GENERIC_LAB_ADAPTERS:
            adapter_path = ROOT / "examples/adapters" / name / "adapter.py"
            if not adapter_path.is_file():
                print(f"{name}: adapter.py is missing", file=sys.stderr)
                failed = True
                continue
            try:
                preflight = run_json(adapter_path, ["--preflight", "--emit-sample"])
                validate_preflight(name, preflight)
                payload = run_json(adapter_path, ["--collect", "--emit-sample"])
            except RuntimeError as error:
                print(f"{name}: {error}", file=sys.stderr)
                failed = True
                continue

            errors = validation_errors(validator, payload)
            if errors:
                print(f"{name}: --collect schema validation failed", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                failed = True
                continue

            if not args.schema_only:
                sample_path = tmp_dir / f"{name}.json"
                sample_path.write_text(json.dumps(payload), encoding="utf-8")
                try:
                    validate_rust_ingest(sample_path)
                except RuntimeError as error:
                    print(f"{name}: Rust ingest validation failed", file=sys.stderr)
                    print(f"  - {error}", file=sys.stderr)
                    failed = True
                    continue

            suffix = "schema ok" if args.schema_only else "schema+ingest ok"
            print(f"{name}: preflight+collect {suffix}")

    return 1 if failed else 0


def run_json(adapter_path: Path, args: list[str]) -> Any:
    completed = subprocess.run(
        [sys.executable, str(adapter_path), *args],
        cwd=adapter_path.parent,
        check=False,
        text=True,
        capture_output=True,
        timeout=15,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise RuntimeError(f"{' '.join(args)} exited {completed.returncode}: {stderr}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{' '.join(args)} did not emit JSON: {error}") from error


def validate_preflight(name: str, report: Any) -> None:
    if not isinstance(report, dict):
        raise RuntimeError("--preflight must emit a JSON object")
    if report.get("schema") != "netdiag-adapter-preflight/v1":
        raise RuntimeError("--preflight emitted an unsupported schema")
    if report.get("adapter") != name:
        raise RuntimeError("--preflight adapter name does not match directory")
    if report.get("passed") is not True:
        raise RuntimeError("--preflight sample mode did not pass")
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        raise RuntimeError("--preflight must emit non-empty checks")
    if "health" not in report:
        raise RuntimeError("--preflight must emit health metadata")
    if "redaction" not in report:
        raise RuntimeError("--preflight must emit redaction metadata")


def validate_rust_ingest(sample_path: Path) -> None:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "netdiag-cli",
            "--",
            "validate-trace",
            str(sample_path),
        ],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        detail = stderr or stdout or f"exit code {completed.returncode}"
        raise RuntimeError(detail)


def validation_errors(validator: Draft202012Validator, instance: Any) -> list[str]:
    return [
        f"{error.json_path}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda item: item.json_path)
    ]


if __name__ == "__main__":
    raise SystemExit(main())
