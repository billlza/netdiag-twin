#!/usr/bin/env python3
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def record_from_iperf(payload: dict) -> dict:
    end = payload.get("end", {})
    timestamp = (
        payload.get("start", {})
        .get("timestamp", {})
        .get("time", datetime.now(timezone.utc).isoformat())
    )
    streams = end.get("streams") or []
    stream = streams[0] if streams else {}
    udp = stream.get("udp") or end.get("sum") or {}
    tcp = stream.get("sender") or end.get("sum_sent") or end.get("sum") or {}
    summary = udp or tcp
    bits_per_second = float(summary.get("bits_per_second", 0.0) or 0.0)
    return {
        "timestamp": timestamp,
        "latency_ms": 0.0,
        "jitter_ms": float(udp.get("jitter_ms", 0.0) or 0.0),
        "packet_loss_rate": float(udp.get("lost_percent", 0.0) or 0.0),
        "retransmission_rate": float(tcp.get("retransmits", 0.0) or 0.0),
        "timeout_events": 0.0,
        "retry_events": float(tcp.get("retransmits", 0.0) or 0.0),
        "throughput_mbps": bits_per_second / 1_000_000.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0,
    }


def load_iperf_json(args: argparse.Namespace) -> dict:
    if args.iperf_json:
        return json.loads(args.iperf_json.read_text(encoding="utf-8"))
    command = ["iperf3", "-J", "-c", args.server, "-t", str(args.duration_secs)]
    if args.udp:
        command.append("-u")
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    return json.loads(completed.stdout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iperf-json", type=Path)
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--duration-secs", default=10, type=int)
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--sample", default="iperf3-http-json")
    parser.add_argument("--scenario-id", default="manual-iperf3")
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    payload = load_iperf_json(args)
    record = record_from_iperf(payload)
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "UDP" if args.udp else "TCP",
                "flow_count": len(payload.get("end", {}).get("streams") or [record]),
                "records": [record],
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": args.fault_start,
                    "fault_end": args.fault_end,
                    "ground_truth": args.ground_truth,
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
