#!/usr/bin/env python3
import argparse
import json
import socket
import time
from datetime import datetime, timezone


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"


def sample_payload(args: argparse.Namespace) -> dict:
    return {
        "schema": "netdiag-adapter-payload/v1",
        "sample": args.sample,
        "protocol": "DNS",
        "flow_count": args.count,
        "records": [
            {
                "timestamp": SAMPLE_TIME,
                "latency_ms": 23.5,
                "jitter_ms": 0.0,
                "packet_loss_rate": 0.0,
                "retransmission_rate": 0.0,
                "timeout_events": 0.0,
                "retry_events": 0.0,
                "throughput_mbps": 0.0,
                "dns_failure_events": 0.0,
                "tls_failure_events": 0.0,
                "quic_blocked_ratio": 0.0,
            }
        ],
        "experiment": {
            "scenario_id": args.scenario_id,
            "fault_start": args.fault_start,
            "fault_end": args.fault_end,
            "ground_truth": args.ground_truth,
            "target": args.host or "example.test",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--count", default=5, type=int)
    parser.add_argument("--timeout-secs", default=2.0, type=float)
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="dns-probe")
    parser.add_argument("--scenario-id", default="manual-dns")
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    if args.emit_sample:
        print(json.dumps(sample_payload(args), indent=2))
        return
    if not args.host:
        parser.error("--host is required unless --emit-sample is used")

    failures = 0
    latencies = []
    for _ in range(args.count):
        start = time.perf_counter()
        socket.setdefaulttimeout(args.timeout_secs)
        try:
            socket.getaddrinfo(args.host, 443)
            latencies.append((time.perf_counter() - start) * 1000.0)
        except OSError:
            failures += 1

    latency = sum(latencies) / len(latencies) if latencies else args.timeout_secs * 1000.0
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "DNS",
                "flow_count": args.count,
                "records": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "latency_ms": latency,
                        "jitter_ms": 0.0,
                        "packet_loss_rate": failures / max(args.count, 1) * 100.0,
                        "retransmission_rate": 0.0,
                        "timeout_events": float(failures),
                        "retry_events": 0.0,
                        "throughput_mbps": 0.0,
                        "dns_failure_events": float(failures),
                        "tls_failure_events": 0.0,
                        "quic_blocked_ratio": 0.0,
                    }
                ],
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": args.fault_start,
                    "fault_end": args.fault_end,
                    "ground_truth": args.ground_truth,
                    "target": args.host,
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
