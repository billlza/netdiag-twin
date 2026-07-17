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
MAX_NOTIFICATIONS = 100_000
READ_CHUNK_BYTES = 64 * 1024
MAX_JSON_INTEGER_DIGITS = 308
MEASUREMENT_QUALITY = {
    "latency_ms": "measured",
    "jitter_ms": "measured",
    "packet_loss_rate": "fallback",
    "retransmission_rate": "fallback",
    "timeout_events": "missing",
    "retry_events": "fallback",
    "throughput_mbps": "measured",
    "dns_failure_events": "missing",
    "tls_failure_events": "missing",
    "quic_blocked_ratio": "missing",
}


def sample_notification() -> dict:
    return {
        "timestamp": SAMPLE_TIME,
        "interface": "xe-0/0/0",
        "rtt_ms": 42.0,
        "jitter_ms": 3.5,
        "in_discards_delta": 2,
        "out_discards_delta": 1,
        "in_packets_delta": 92000,
        "out_packets_delta": 88000,
        "in_errors_delta": 0,
        "out_errors_delta": 0,
        "throughput_bps": 92_000_000,
    }


def preflight_report(args: argparse.Namespace) -> dict:
    mode = "sample" if args.emit_sample else "live"
    if mode == "sample":
        input_ok, input_message = True, "built-in sample notification"
    else:
        input_ok, input_message = validate_live_input(args.input_json)
    return {
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "openconfig-gnmi",
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
                "message": "read-only normalized notification conversion",
            },
        ],
        "health": {"status": "ok" if input_ok else "error", "source": args.sample},
        "redaction": {"secrets": [], "fields": ["endpoint", "bearer_token"]},
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


def load_notifications(path: Path) -> list[dict[str, object]]:
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
        notifications = raw
    elif isinstance(raw, dict):
        notifications = raw.get("notifications", [raw])
        if not isinstance(notifications, list):
            raise ValueError("input JSON 'notifications' must be an array")
    else:
        raise ValueError("input JSON must be an object or an array of objects")
    if not notifications:
        raise ValueError("input JSON must contain at least one notification")
    if len(notifications) > MAX_NOTIFICATIONS:
        raise ValueError(
            f"input JSON exceeds the {MAX_NOTIFICATIONS}-notification limit"
        )
    for index, notification in enumerate(notifications, start=1):
        if not isinstance(notification, dict) or not notification:
            raise ValueError(f"notification {index} must be a non-empty object")
    return notifications


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


def finite_sum(name: str, *values: float) -> float:
    total = sum(values)
    if not math.isfinite(total):
        raise ValueError(f"{name} exceeds the finite numeric range")
    return total


def percentage(name: str, numerator: float, denominator: float) -> float:
    if denominator == 0.0:
        if numerator != 0.0:
            raise ValueError(f"{name} denominator cannot be zero")
        return 0.0
    value = numerator / denominator * 100.0
    if not math.isfinite(value) or not 0.0 <= value <= 100.0:
        raise ValueError(f"{name} must be between 0 and 100")
    return value


def record_from_notification(notification: dict[str, object]) -> dict:
    discards = finite_sum(
        "discard count",
        required_number(notification, "in_discards_delta"),
        required_number(notification, "out_discards_delta"),
    )
    packets = finite_sum(
        "packet count",
        required_number(notification, "in_packets_delta"),
        required_number(notification, "out_packets_delta"),
    )
    errors = finite_sum(
        "error count",
        required_number(notification, "in_errors_delta"),
        required_number(notification, "out_errors_delta"),
    )
    denominator = finite_sum("packet ratio denominator", packets, discards)
    loss_pct = percentage("packet_loss_rate", discards, denominator)
    error_pct = percentage("retransmission_rate", errors, denominator)
    return {
        "timestamp": required_text(notification, "timestamp"),
        "latency_ms": required_number(notification, "rtt_ms"),
        "jitter_ms": required_number(notification, "jitter_ms"),
        "packet_loss_rate": loss_pct,
        "retransmission_rate": error_pct,
        "timeout_events": 0.0,
        "retry_events": errors,
        "throughput_mbps": required_number(notification, "throughput_bps")
        / 1_000_000.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }


def validate_live_input(path: Path | None) -> tuple[bool, str]:
    if path is None:
        return False, "--input-json is required in live mode"
    try:
        notifications = load_notifications(path)
    except (OSError, RuntimeError, ValueError) as error:
        return False, str(error)
    for index, notification in enumerate(notifications, start=1):
        try:
            record_from_notification(notification)
        except ValueError as error:
            return False, f"notification {index}: {error}"
    return True, f"{path} ({len(notifications)} notifications)"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="openconfig-gnmi")
    parser.add_argument("--scenario-id", default="manual-openconfig-gnmi")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    if args.preflight:
        print(json.dumps(preflight_report(args), indent=2, allow_nan=False))
        return

    if args.emit_sample:
        notifications = [sample_notification()]
    elif args.input_json:
        notifications = load_notifications(args.input_json)
    else:
        parser.error("--input-json is required unless --emit-sample is used")

    records = []
    for index, notification in enumerate(notifications, start=1):
        try:
            records.append(record_from_notification(notification))
        except ValueError as error:
            raise ValueError(f"notification {index}: {error}") from error
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v2",
                "collection_mode": "sample" if args.emit_sample else "live",
                "sample": args.sample,
                "protocol": "gNMI/OpenConfig",
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
