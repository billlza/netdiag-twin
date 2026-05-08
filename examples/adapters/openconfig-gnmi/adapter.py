#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"


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


def number(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    return float(value)


def record_from_notification(notification: dict) -> dict:
    discards = number(notification.get("in_discards_delta")) + number(
        notification.get("out_discards_delta")
    )
    packets = number(notification.get("in_packets_delta")) + number(
        notification.get("out_packets_delta")
    )
    errors = number(notification.get("in_errors_delta")) + number(
        notification.get("out_errors_delta")
    )
    denominator = max(packets + discards, 1.0)
    loss_pct = (discards / denominator) * 100.0
    error_pct = (errors / denominator) * 100.0
    return {
        "timestamp": notification.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        ),
        "latency_ms": number(notification.get("rtt_ms")),
        "jitter_ms": number(notification.get("jitter_ms")),
        "packet_loss_rate": loss_pct,
        "retransmission_rate": error_pct,
        "timeout_events": 0.0,
        "retry_events": errors,
        "throughput_mbps": number(notification.get("throughput_bps")) / 1_000_000.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="openconfig-gnmi")
    parser.add_argument("--scenario-id", default="manual-openconfig-gnmi")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    if args.emit_sample:
        notifications = [sample_notification()]
    elif args.input_json:
        raw = json.loads(args.input_json.read_text(encoding="utf-8"))
        notifications = raw if isinstance(raw, list) else raw.get("notifications", [raw])
    else:
        parser.error("--input-json is required unless --emit-sample is used")

    records = [record_from_notification(item) for item in notifications]
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "gNMI/OpenConfig",
                "flow_count": len(records),
                "records": records,
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": records[0]["timestamp"],
                    "fault_end": records[-1]["timestamp"],
                    "ground_truth": args.ground_truth,
                    "measurement_quality": {
                        "packet_loss_rate": "derived_from_discard_ratio",
                        "retransmission_rate": "derived_from_error_ratio",
                    },
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
