#!/usr/bin/env python3
import argparse
import json
import socket
import time
from datetime import datetime, timezone


def udp_probe(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(b"netdiag-quic-probe", (host, port))
        try:
            sock.recvfrom(1200)
            return True
        except socket.timeout:
            return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", default=443, type=int)
    parser.add_argument("--count", default=5, type=int)
    parser.add_argument("--timeout-secs", default=1.0, type=float)
    parser.add_argument("--sample", default="quic-probe")
    parser.add_argument("--scenario-id", default="manual-quic")
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    blocked = 0
    latencies = []
    for _ in range(args.count):
        start = time.perf_counter()
        if udp_probe(args.host, args.port, args.timeout_secs):
            latencies.append((time.perf_counter() - start) * 1000.0)
        else:
            blocked += 1

    latency = sum(latencies) / len(latencies) if latencies else args.timeout_secs * 1000.0
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "QUIC",
                "flow_count": args.count,
                "records": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "latency_ms": latency,
                        "jitter_ms": 0.0,
                        "packet_loss_rate": blocked / max(args.count, 1) * 100.0,
                        "retransmission_rate": 0.0,
                        "timeout_events": float(blocked),
                        "retry_events": 0.0,
                        "throughput_mbps": 0.0,
                        "dns_failure_events": 0.0,
                        "tls_failure_events": 0.0,
                        "quic_blocked_ratio": blocked / max(args.count, 1),
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
