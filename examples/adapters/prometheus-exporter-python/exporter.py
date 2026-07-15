#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import stat
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


FIELDS = [
    "latency_ms",
    "jitter_ms",
    "packet_loss_rate",
    "retransmission_rate",
    "timeout_events",
    "retry_events",
    "throughput_mbps",
    "dns_failure_events",
    "tls_failure_events",
    "quic_blocked_ratio",
]
REQUIRED_HEADERS = ("timestamp", *FIELDS)
PERCENTAGE_FIELDS = {"packet_loss_rate", "retransmission_rate"}
UNIT_RATIO_FIELDS = {"quic_blocked_ratio"}
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_HTTP_BODY_BYTES = 16 * 1024 * 1024
MAX_CSV_ROWS = 100_000
READ_CHUNK_BYTES = 64 * 1024
SOCKET_DEADLINE_SECONDS = 10.0
MEASUREMENT_QUALITY = {field: "measured" for field in FIELDS}


SAMPLE_RECORDS = [
    {
        "timestamp": "2026-05-07T09:00:00+00:00",
        "latency_ms": 42.0,
        "jitter_ms": 3.5,
        "packet_loss_rate": 0.5,
        "retransmission_rate": 1.0,
        "timeout_events": 0.0,
        "retry_events": 1.0,
        "throughput_mbps": 88.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }
]


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
        raise ValueError(f"cannot securely open input CSV {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"input CSV {path} must be a regular non-symlink file")
    if metadata.st_size > MAX_INPUT_BYTES:
        os.close(descriptor)
        raise ValueError(f"input CSV {path} exceeds the {MAX_INPUT_BYTES}-byte limit")
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
            f"input CSV {path} did not behave as a regular file"
        ) from error
    finally:
        os.close(descriptor)
    if total > MAX_INPUT_BYTES:
        raise ValueError(f"input CSV {path} exceeds the {MAX_INPUT_BYTES}-byte limit")
    try:
        return buffer.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"input CSV {path} is not valid UTF-8") from error


def validate_headers(fieldnames: list[str] | None) -> None:
    if fieldnames is None:
        raise ValueError("input CSV is missing a header row")
    invalid = [name for name in fieldnames if not name or not name.strip()]
    if invalid:
        raise ValueError("input CSV contains an empty header")
    duplicates = sorted(
        name for name, count in Counter(fieldnames).items() if count > 1
    )
    if duplicates:
        raise ValueError(
            "input CSV contains duplicate headers: " + ", ".join(duplicates)
        )
    missing = [name for name in REQUIRED_HEADERS if name not in fieldnames]
    if missing:
        raise ValueError("input CSV is missing required headers: " + ", ".join(missing))


def load_csv(path: Path) -> tuple[list[dict], dict[str, float]]:
    reader = csv.DictReader(
        io.StringIO(read_bounded_regular_file(path), newline=""), strict=True
    )
    records: list[dict] = []
    values = {field: 0.0 for field in FIELDS}
    try:
        validate_headers(reader.fieldnames)
        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_CSV_ROWS:
                raise ValueError(f"input CSV exceeds the {MAX_CSV_ROWS}-row limit")
            record = canonical_record(row, row_number)
            records.append(record)
            for field in FIELDS:
                updated = values[field] + (record[field] - values[field]) / row_number
                if not math.isfinite(updated):
                    raise ValueError(
                        f"aggregate {field} exceeds the finite numeric range"
                    )
                values[field] = updated
    except csv.Error as error:
        raise ValueError(f"input CSV {path} is invalid: {error}") from error
    if not records:
        raise ValueError("input CSV must contain at least one data row")
    return records, values


def canonical_record(row: dict[object, object], row_number: int = 1) -> dict:
    if not row or None in row:
        raise ValueError(f"CSV row {row_number} must be a non-empty row object")
    timestamp = row.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError(f"CSV row {row_number} timestamp must be non-empty")
    record = {"timestamp": timestamp.strip()}
    for field in FIELDS:
        raw = row.get(field)
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"CSV row {row_number} is missing {field}")
        try:
            value = float(raw)
        except ValueError as error:
            raise ValueError(f"CSV row {row_number} {field} must be numeric") from error
        if not math.isfinite(value) or value < 0.0:
            raise ValueError(
                f"CSV row {row_number} {field} must be finite and non-negative"
            )
        if field in PERCENTAGE_FIELDS and value > 100.0:
            raise ValueError(f"CSV row {row_number} {field} must be between 0 and 100")
        if field in UNIT_RATIO_FIELDS and value > 1.0:
            raise ValueError(f"CSV row {row_number} {field} must be between 0 and 1")
        record[field] = 0.0 if value == 0.0 else value
    return record


def bounded_http_body(body: bytes, endpoint: str) -> bytes:
    if len(body) > MAX_HTTP_BODY_BYTES:
        raise ValueError(
            f"{endpoint} response exceeds the {MAX_HTTP_BODY_BYTES}-byte limit"
        )
    return body


def encode_json_body(payload: dict) -> bytes:
    encoder = json.JSONEncoder(allow_nan=False, separators=(",", ":"))
    body = bytearray()
    for chunk in encoder.iterencode(payload):
        encoded = chunk.encode("utf-8")
        if len(encoded) > MAX_HTTP_BODY_BYTES - len(body):
            raise ValueError(
                f"/trace response exceeds the {MAX_HTTP_BODY_BYTES}-byte limit"
            )
        body.extend(encoded)
    return bytes(body)


def encode_metrics_body(values: dict[str, float]) -> bytes:
    body = "\n".join(
        f"{prometheus_name(name)} {value}" for name, value in values.items()
    )
    return bounded_http_body(f"{body}\n".encode("utf-8"), "/metrics")


def build_payload(
    collection_mode: str,
    sample: str,
    records: list[dict],
    experiment: dict[str, str],
) -> dict:
    return {
        "schema": "netdiag-adapter-payload/v2",
        "collection_mode": collection_mode,
        "sample": sample,
        "protocol": "TCP",
        "flow_count": 1,
        "records": records,
        "measurement_quality": MEASUREMENT_QUALITY,
        "experiment": experiment,
    }


class Handler(BaseHTTPRequestHandler):
    metrics_body = b""
    trace_body = b""

    def setup(self) -> None:
        self.request.settimeout(SOCKET_DEADLINE_SECONDS)
        super().setup()

    def do_GET(self) -> None:
        if self.path == "/metrics":
            body = self.metrics_body
            content_type = "text/plain; version=0.0.4"
        elif self.path == "/trace":
            body = self.trace_body
            content_type = "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def prometheus_name(field: str) -> str:
    if field in {
        "timeout_events",
        "retry_events",
        "dns_failure_events",
        "tls_failure_events",
    }:
        return f"netdiag_{field}_total"
    return f"netdiag_{field}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--port", default=9107, type=int)
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample")
    parser.add_argument("--scenario-id", default=None)
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()
    if args.emit_sample:
        sample = args.sample or "prometheus-exporter-python"
        experiment = {
            "scenario_id": args.scenario_id or sample,
            "fault_start": args.fault_start,
            "fault_end": args.fault_end,
            "ground_truth": args.ground_truth,
        }
        print(
            json.dumps(
                build_payload("sample", sample, SAMPLE_RECORDS, experiment),
                indent=2,
                allow_nan=False,
            )
        )
        return
    if not args.csv:
        parser.error("--csv is required unless --emit-sample is used")

    records, values = load_csv(args.csv)
    sample = args.sample or args.csv.stem
    experiment = {
        "scenario_id": args.scenario_id or args.csv.stem,
        "fault_start": args.fault_start,
        "fault_end": args.fault_end,
        "ground_truth": args.ground_truth,
    }
    Handler.metrics_body = encode_metrics_body(values)
    Handler.trace_body = encode_json_body(
        build_payload("live", sample, records, experiment)
    )
    del records
    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
