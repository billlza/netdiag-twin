#!/usr/bin/env python3
import argparse
import json
import subprocess
from datetime import datetime, timezone, timedelta


def maybe_apply_netem(args: argparse.Namespace) -> None:
    if not args.apply:
        return
    command = [
        "tc",
        "qdisc",
        "replace",
        "dev",
        args.interface,
        "root",
        "netem",
        "delay",
        f"{args.latency_ms}ms",
        "loss",
        f"{args.loss_pct}%",
    ]
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--latency-ms", default=100.0, type=float)
    parser.add_argument("--jitter-ms", default=10.0, type=float)
    parser.add_argument("--loss-pct", default=1.0, type=float)
    parser.add_argument("--throughput-mbps", default=50.0, type=float)
    parser.add_argument("--duration-secs", default=60, type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--sample", default="tc-netem-lab")
    parser.add_argument("--scenario-id", default="manual-netem")
    parser.add_argument("--ground-truth", default="congestion")
    args = parser.parse_args()

    start = datetime.now(timezone.utc)
    end = start + timedelta(seconds=args.duration_secs)
    maybe_apply_netem(args)
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": args.sample,
                "protocol": "TCP",
                "flow_count": 1,
                "records": [
                    {
                        "timestamp": start.isoformat(),
                        "latency_ms": args.latency_ms,
                        "jitter_ms": args.jitter_ms,
                        "packet_loss_rate": args.loss_pct,
                        "retransmission_rate": max(args.loss_pct * 1.5, 0.0),
                        "timeout_events": 0.0,
                        "retry_events": max(args.loss_pct, 0.0),
                        "throughput_mbps": args.throughput_mbps,
                        "dns_failure_events": 0.0,
                        "tls_failure_events": 0.0,
                        "quic_blocked_ratio": 0.0,
                    }
                ],
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": start.isoformat(),
                    "fault_end": end.isoformat(),
                    "ground_truth": args.ground_truth,
                    "interface": args.interface,
                    "applied": args.apply,
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
