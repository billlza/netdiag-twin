#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import time
from datetime import datetime, timezone


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"


def tls_handshake(host: str, port: int, timeout: float) -> float:
    context = ssl.create_default_context()
    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host):
            return (time.perf_counter() - start) * 1000.0


def sample_payload(args: argparse.Namespace) -> dict:
    return {
        "schema": "netdiag-adapter-payload/v1",
        "sample": args.sample,
        "protocol": "TLS",
        "flow_count": args.count,
        "records": [
            {
                "timestamp": SAMPLE_TIME,
                "latency_ms": 41.0,
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
            "target": f"{args.host or 'example.test'}:{args.port}",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", default=443, type=int)
    parser.add_argument("--count", default=3, type=int)
    parser.add_argument("--timeout-secs", default=3.0, type=float)
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="tls-probe")
    parser.add_argument("--scenario-id", default="manual-tls")
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
        try:
            latencies.append(tls_handshake(args.host, args.port, args.timeout_secs))
        except OSError:
            failures += 1

    latency = sum(latencies) / len(latencies) if latencies else args.timeout_secs * 1000.0
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "TLS",
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
                        "dns_failure_events": 0.0,
                        "tls_failure_events": float(failures),
                        "quic_blocked_ratio": 0.0,
                    }
                ],
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": args.fault_start,
                    "fault_end": args.fault_end,
                    "ground_truth": args.ground_truth,
                    "target": f"{args.host}:{args.port}",
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
