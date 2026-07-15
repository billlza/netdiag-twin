#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import stat
from pathlib import Path


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ROUTING_STATES = 100_000
READ_CHUNK_BYTES = 64 * 1024
MAX_JSON_INTEGER_DIGITS = 308
MEASUREMENT_QUALITY = {
    "latency_ms": "fallback",
    "jitter_ms": "fallback",
    "packet_loss_rate": "missing",
    "retransmission_rate": "missing",
    "timeout_events": "fallback",
    "retry_events": "fallback",
    "throughput_mbps": "fallback",
    "dns_failure_events": "missing",
    "tls_failure_events": "missing",
    "quic_blocked_ratio": "missing",
}


def sample_frr() -> dict:
    return {
        "timestamp": SAMPLE_TIME,
        "routes_total": 124,
        "routes_changed": 8,
        "ospf_adjacency_flaps": 1,
        "bgp_session_flaps": 0,
        "bestpath_changes": 5,
        "forwarding_stall_ms": 140,
    }


def preflight_report(args: argparse.Namespace) -> dict:
    mode = "sample" if args.emit_sample else "live"
    if mode == "sample":
        input_ok, input_message = True, "built-in sample routing state"
    else:
        input_ok, input_message = validate_live_input(args.input_json)
    return {
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "frr-routing-state",
        "collection_mode": mode,
        "passed": input_ok,
        "checks": [
            {
                "name": "input-json",
                "status": "ok" if input_ok else "error",
                "message": input_message,
            },
            {
                "name": "collection-mode",
                "status": "ok",
                "message": "read-only routing-state conversion",
            },
        ],
        "health": {"status": "ok" if input_ok else "error", "source": args.sample},
        "redaction": {"secrets": [], "fields": ["router_id", "neighbor"]},
    }


def secure_open_flags() -> int:
    required = ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        raise RuntimeError(
            "secure input handling is unavailable: missing " + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def open_bounded_regular_input(path: Path) -> int:
    try:
        descriptor = os.open(path, secure_open_flags())
    except OSError as error:
        raise ValueError(f"cannot securely open input JSON {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"input JSON {path} must be a regular non-symlink file")
    if metadata.st_size > MAX_INPUT_BYTES:
        os.close(descriptor)
        raise ValueError(f"input JSON {path} exceeds the {MAX_INPUT_BYTES}-byte limit")
    return descriptor


def read_bounded_regular_file(path: Path) -> str:
    descriptor = open_bounded_regular_input(path)
    buffer = bytearray()
    total = 0
    try:
        while total <= MAX_INPUT_BYTES:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, MAX_INPUT_BYTES + 1 - total),
            )
            if not chunk:
                break
            buffer.extend(chunk)
            total += len(chunk)
    except BlockingIOError as error:
        raise ValueError(
            f"input JSON {path} did not behave as a regular file"
        ) from error
    finally:
        os.close(descriptor)
    if total > MAX_INPUT_BYTES:
        raise ValueError(f"input JSON {path} exceeds the {MAX_INPUT_BYTES}-byte limit")
    try:
        return buffer.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"input JSON {path} is not valid UTF-8") from error


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"input JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("input JSON contains a non-finite number")
    return parsed


def parse_bounded_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError("input JSON integer exceeds the finite numeric range")
    return int(value)


def reject_non_finite_constant(value: str) -> None:
    raise ValueError(f"input JSON contains non-standard number {value}")


def load_routing_states(path: Path) -> list[dict[str, object]]:
    try:
        raw = json.loads(
            read_bounded_regular_file(path),
            object_pairs_hook=reject_duplicate_keys,
            parse_float=parse_finite_json_float,
            parse_int=parse_bounded_json_int,
            parse_constant=reject_non_finite_constant,
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"input JSON {path} is invalid: {error}") from error
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        rows = raw.get("routing_state", [raw])
        if not isinstance(rows, list):
            raise ValueError("input JSON 'routing_state' must be an array")
    else:
        raise ValueError("input JSON must be an object or an array of objects")
    if not rows:
        raise ValueError("input JSON must contain at least one routing state")
    if len(rows) > MAX_ROUTING_STATES:
        raise ValueError(
            f"input JSON exceeds the {MAX_ROUTING_STATES}-routing-state limit"
        )
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or not row:
            raise ValueError(f"routing state {index} must be a non-empty object")
    return rows


def required_text(row: dict[str, object], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def required_number(row: dict[str, object], field: str) -> float:
    if field not in row:
        raise ValueError(f"missing required numeric field {field}")
    value = row[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a JSON number")
    try:
        parsed = float(value)
    except OverflowError as error:
        raise ValueError(f"{field} must be finite") from error
    if not math.isfinite(parsed) or parsed < 0.0:
        raise ValueError(f"{field} must be finite and non-negative")
    return 0.0 if parsed == 0.0 else parsed


def finite_value(name: str, value: float) -> float:
    if not math.isfinite(value) or value < 0.0:
        raise ValueError(f"{name} must be finite and non-negative")
    return value


def record_from_frr(row: dict[str, object]) -> dict:
    route_churn = required_number(row, "routes_changed")
    adjacency_flaps = finite_value(
        "adjacency flap count",
        required_number(row, "ospf_adjacency_flaps")
        + required_number(row, "bgp_session_flaps"),
    )
    forwarding_stall = required_number(row, "forwarding_stall_ms")
    churn_pressure = min(route_churn / 20.0, 100.0)
    return {
        "timestamp": required_text(row, "timestamp"),
        "latency_ms": forwarding_stall,
        "jitter_ms": forwarding_stall / 4.0,
        "packet_loss_rate": 0.0,
        "retransmission_rate": 0.0,
        "timeout_events": adjacency_flaps,
        "retry_events": route_churn,
        "throughput_mbps": max(100.0 - churn_pressure * 2.0, 1.0),
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }


def validate_live_input(path: Path | None) -> tuple[bool, str]:
    if path is None:
        return False, "--input-json is required in live mode"
    try:
        rows = load_routing_states(path)
    except (OSError, RuntimeError, ValueError) as error:
        return False, str(error)
    for index, row in enumerate(rows, start=1):
        try:
            record_from_frr(row)
        except ValueError as error:
            return False, f"routing state {index}: {error}"
    return True, f"{path} ({len(rows)} routing states)"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="frr-routing-state")
    parser.add_argument("--scenario-id", default="manual-frr-routing-state")
    parser.add_argument("--ground-truth", default="routing_state_change")
    args = parser.parse_args()

    if args.preflight:
        print(json.dumps(preflight_report(args), indent=2, allow_nan=False))
        return

    if args.emit_sample:
        rows = [sample_frr()]
    elif args.input_json:
        rows = load_routing_states(args.input_json)
    else:
        parser.error("--input-json is required unless --emit-sample is used")

    records = []
    for index, row in enumerate(rows, start=1):
        try:
            records.append(record_from_frr(row))
        except ValueError as error:
            raise ValueError(f"routing state {index}: {error}") from error
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v2",
                "collection_mode": "sample" if args.emit_sample else "live",
                "sample": args.sample,
                "protocol": "FRR routing-state",
                "flow_count": len(records),
                "records": records,
                "measurement_quality": MEASUREMENT_QUALITY,
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": records[0]["timestamp"],
                    "fault_end": records[-1]["timestamp"],
                    "ground_truth": args.ground_truth,
                },
            },
            indent=2,
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
