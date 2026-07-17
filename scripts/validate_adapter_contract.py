#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from adapter_process import (
    ADAPTER_STDERR_LIMIT_BYTES,
    ADAPTER_STDOUT_LIMIT_BYTES,
    ADAPTER_TIMEOUT_SECONDS,
    parse_json_strict,
    run_bounded,
    run_json,
    trusted_rust_ingest_validator,
    validate_rust_ingest,
    validation_python_environment,
)
from adapter_quality import (
    CANONICAL_NUMERIC_METRICS,
    validate_declared_measurement_quality,
)
from schema_validation import bounded_validation_errors

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
    parser.add_argument(
        "--rust-validator",
        type=Path,
        help="trusted absolute netdiag-cli path built for ingest validation",
    )
    args = parser.parse_args()
    if args.schema_only and args.rust_validator is not None:
        parser.error("--rust-validator cannot be used with --schema-only")
    if not args.schema_only and args.rust_validator is None:
        parser.error("--rust-validator is required unless --schema-only is used")
    rust_validator: Path | None = None
    if args.rust_validator is not None:
        try:
            rust_validator = trusted_rust_ingest_validator(args.rust_validator, ROOT)
        except RuntimeError as error:
            parser.error(str(error))
    schema = parse_json_strict(
        SCHEMA_PATH.read_text(encoding="utf-8"), source="adapter payload schema"
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validate_schema_requires_collection_mode(validator)
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
                validate_preflight(name, preflight, "sample")
                payload = run_json(adapter_path, ["--collect", "--emit-sample"])
                validate_collection_mode(payload, "sample")
                validate_declared_measurement_quality(payload)
                if name == "tc-netem-lab":
                    assert_command_fails(
                        adapter_path,
                        ["--collect"],
                        "--interface is required for live --collect",
                    )
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

            if rust_validator is not None:
                sample_path = tmp_dir / f"{name}.json"
                sample_path.write_text(
                    json.dumps(payload, allow_nan=False), encoding="utf-8"
                )
                try:
                    validate_rust_ingest(rust_validator, sample_path, ROOT)
                except RuntimeError as error:
                    print(f"{name}: Rust ingest validation failed", file=sys.stderr)
                    print(f"  - {error}", file=sys.stderr)
                    failed = True
                    continue

            suffix = "schema ok" if args.schema_only else "schema+ingest ok"
            print(f"{name}: preflight+collect {suffix}")

    return 1 if failed else 0


def validate_preflight(name: str, report: Any, expected_mode: str) -> None:
    if not isinstance(report, dict):
        raise RuntimeError("--preflight must emit a JSON object")
    if report.get("schema") != "netdiag-adapter-preflight/v1":
        raise RuntimeError("--preflight emitted an unsupported schema")
    if report.get("adapter") != name:
        raise RuntimeError("--preflight adapter name does not match directory")
    if report.get("collection_mode") != expected_mode:
        raise RuntimeError(
            f"--preflight collection_mode must be {expected_mode}, "
            f"got {report.get('collection_mode')!r}"
        )
    if report.get("passed") is not True:
        raise RuntimeError("--preflight sample mode did not pass")
    checks = report.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 64:
        raise RuntimeError("--preflight must emit 1..=64 structured checks")
    statuses: list[str] = []
    for check in checks:
        if not isinstance(check, dict):
            raise RuntimeError("--preflight checks must be objects")
        name_value = check.get("name")
        status_value = check.get("status")
        if not isinstance(name_value, str) or not 1 <= len(name_value.encode()) <= 128:
            raise RuntimeError("--preflight check names must contain 1..=128 bytes")
        if status_value not in {"ok", "degraded", "error"}:
            raise RuntimeError("--preflight check status is unsupported")
        statuses.append(status_value)
    checks_passed = all(status != "error" for status in statuses)
    if checks_passed is not report["passed"]:
        raise RuntimeError("--preflight passed does not match check statuses")
    health = report.get("health")
    if not isinstance(health, dict) or health.get("status") not in {
        "ok",
        "degraded",
        "error",
    }:
        raise RuntimeError("--preflight health must be an object with valid status")
    if (health["status"] != "error") is not report["passed"]:
        raise RuntimeError("--preflight passed does not match health.status")
    redaction = report.get("redaction")
    fields = redaction.get("fields") if isinstance(redaction, dict) else None
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        raise RuntimeError("--preflight redaction.fields must be a string array")


def validate_collection_mode(payload: Any, expected_mode: str) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("--collect must emit a JSON object")
    if payload.get("collection_mode") != expected_mode:
        raise RuntimeError(
            f"--collect collection_mode must be {expected_mode}, "
            f"got {payload.get('collection_mode')!r}"
        )


def assert_command_fails(
    adapter_path: Path, args: list[str], expected_stderr: str
) -> None:
    completed = run_bounded(
        [sys.executable, "-I", "-B", str(adapter_path), *args],
        cwd=adapter_path.parent,
        timeout_seconds=ADAPTER_TIMEOUT_SECONDS,
        stdout_limit_bytes=ADAPTER_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=ADAPTER_STDERR_LIMIT_BYTES,
        environment=validation_python_environment(),
    )
    if completed.returncode == 0:
        raise RuntimeError(f"{' '.join(args)} unexpectedly succeeded")
    if expected_stderr not in completed.stderr:
        raise RuntimeError(
            f"adapter command exited {completed.returncode} without the expected "
            f"error classification (stderr bytes: {len(completed.stderr.encode('utf-8'))})"
        )


def validation_errors(validator: Draft202012Validator, instance: Any) -> list[str]:
    return bounded_validation_errors(validator.iter_errors(instance))


def validate_schema_requires_collection_mode(validator: Draft202012Validator) -> None:
    payload = {
        "schema": "netdiag-adapter-payload/v2",
        "sample": "schema-negative-test",
        "protocol": "test",
        "flow_count": 1,
        "measurement_quality": {
            metric: "missing" for metric in CANONICAL_NUMERIC_METRICS
        },
        "records": [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "latency_ms": 1.0,
                "jitter_ms": 0.0,
                "packet_loss_rate": 0.0,
                "retransmission_rate": 0.0,
                "timeout_events": 0.0,
                "retry_events": 0.0,
                "throughput_mbps": 1.0,
                "dns_failure_events": 0.0,
                "tls_failure_events": 0.0,
                "quic_blocked_ratio": 0.0,
            }
        ],
        "experiment": {
            "scenario_id": "schema-negative-test",
            "fault_start": "2026-01-01T00:00:00Z",
            "fault_end": "2026-01-01T00:00:01Z",
            "ground_truth": "normal",
        },
    }
    if not any(
        error.validator == "required" and "collection_mode" in error.message
        for error in validator.iter_errors(payload)
    ):
        raise SystemExit("adapter JSON Schema must require collection_mode")


if __name__ == "__main__":
    raise SystemExit(main())
