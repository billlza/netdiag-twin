#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"


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
    input_ok = args.input_json is None or args.input_json.is_file()
    return {
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "frr-routing-state",
        "passed": input_ok,
        "checks": [
            {
                "name": "input-json",
                "status": "ok" if input_ok else "error",
                "message": "offline sample mode"
                if args.input_json is None
                else str(args.input_json),
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


def record_from_frr(row: dict) -> dict:
    route_churn = float(row.get("routes_changed", 0) or 0)
    adjacency_flaps = float(row.get("ospf_adjacency_flaps", 0) or 0) + float(
        row.get("bgp_session_flaps", 0) or 0
    )
    forwarding_stall = float(row.get("forwarding_stall_ms", 0.0) or 0.0)
    churn_pressure = min(route_churn / 20.0, 100.0)
    return {
        "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "latency_ms": forwarding_stall,
        "jitter_ms": forwarding_stall / 4.0,
        "packet_loss_rate": 0.0,
        "retransmission_rate": adjacency_flaps,
        "timeout_events": adjacency_flaps,
        "retry_events": route_churn,
        "throughput_mbps": max(100.0 - churn_pressure * 2.0, 1.0),
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }


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
        print(json.dumps(preflight_report(args), indent=2))
        return

    if args.emit_sample:
        rows = [sample_frr()]
    elif args.input_json:
        raw = json.loads(args.input_json.read_text(encoding="utf-8"))
        rows = raw if isinstance(raw, list) else raw.get("routing_state", [raw])
    else:
        parser.error("--input-json is required unless --emit-sample is used")

    records = [record_from_frr(row) for row in rows]
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "FRR routing-state",
                "flow_count": len(records),
                "records": records,
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": records[0]["timestamp"],
                    "fault_end": records[-1]["timestamp"],
                    "ground_truth": args.ground_truth,
                    "measurement_quality": {
                        "latency_ms": "derived_from_forwarding_stall",
                        "packet_loss_rate": "unobserved_fallback_zero",
                        "throughput_mbps": "estimated_from_route_churn",
                    },
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
