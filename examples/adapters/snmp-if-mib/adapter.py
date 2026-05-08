#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"


def sample_if_mib() -> dict:
    return {
        "timestamp": SAMPLE_TIME,
        "if_name": "eth0",
        "if_speed_bps": 1_000_000_000,
        "if_in_octets_delta": 34_000_000,
        "if_out_octets_delta": 28_000_000,
        "if_in_ucast_pkts_delta": 72000,
        "if_out_ucast_pkts_delta": 69000,
        "if_in_discards_delta": 3,
        "if_out_discards_delta": 1,
        "if_in_errors_delta": 0,
        "if_out_errors_delta": 0,
        "interval_seconds": 5,
    }


def number(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    return float(value)


def record_from_if_mib(row: dict) -> dict:
    interval = max(number(row.get("interval_seconds"), 1.0), 1.0)
    octets = number(row.get("if_in_octets_delta")) + number(
        row.get("if_out_octets_delta")
    )
    throughput_mbps = (octets * 8.0 / interval) / 1_000_000.0
    packets = number(row.get("if_in_ucast_pkts_delta")) + number(
        row.get("if_out_ucast_pkts_delta")
    )
    discards = number(row.get("if_in_discards_delta")) + number(
        row.get("if_out_discards_delta")
    )
    errors = number(row.get("if_in_errors_delta")) + number(
        row.get("if_out_errors_delta")
    )
    denominator = max(packets + discards, 1.0)
    return {
        "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "latency_ms": 0.0,
        "jitter_ms": 0.0,
        "packet_loss_rate": (discards / denominator) * 100.0,
        "retransmission_rate": (errors / denominator) * 100.0,
        "timeout_events": 0.0,
        "retry_events": errors,
        "throughput_mbps": throughput_mbps,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="snmp-if-mib")
    parser.add_argument("--scenario-id", default="manual-snmp-if-mib")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    if args.emit_sample:
        rows = [sample_if_mib()]
    elif args.input_json:
        raw = json.loads(args.input_json.read_text(encoding="utf-8"))
        rows = raw if isinstance(raw, list) else raw.get("interfaces", [raw])
    else:
        parser.error("--input-json is required unless --emit-sample is used")

    records = [record_from_if_mib(row) for row in rows]
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "SNMP/IF-MIB",
                "flow_count": len(records),
                "records": records,
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": records[0]["timestamp"],
                    "fault_end": records[-1]["timestamp"],
                    "ground_truth": args.ground_truth,
                    "measurement_quality": {
                        "latency_ms": "unobserved_fallback_zero",
                        "jitter_ms": "unobserved_fallback_zero",
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
