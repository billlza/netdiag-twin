#!/usr/bin/env python3
import argparse
import json
import math
import re
from datetime import datetime, timezone, timedelta


SAMPLE_TIME = datetime(2026, 5, 7, 9, 0, tzinfo=timezone.utc)
INTERFACE_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")
MAX_DELAY_MS = 60_000.0
MAX_THROUGHPUT_MBPS = 1_000_000.0
MAX_DURATION_SECONDS = 86_400
MEASUREMENT_QUALITY = {
    "latency_ms": "fallback",
    "jitter_ms": "fallback",
    "packet_loss_rate": "fallback",
    "retransmission_rate": "missing",
    "timeout_events": "missing",
    "retry_events": "missing",
    "throughput_mbps": "fallback",
    "dns_failure_events": "missing",
    "tls_failure_events": "missing",
    "quic_blocked_ratio": "missing",
}


def bounded_number(
    parser: argparse.ArgumentParser,
    name: str,
    value: float,
    minimum: float,
    maximum: float,
) -> None:
    if not math.isfinite(value) or not minimum <= value <= maximum:
        parser.error(f"{name} must be finite and between {minimum:g} and {maximum:g}")


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    bounded_number(parser, "--latency-ms", args.latency_ms, 0.0, MAX_DELAY_MS)
    bounded_number(parser, "--jitter-ms", args.jitter_ms, 0.0, MAX_DELAY_MS)
    bounded_number(parser, "--loss-pct", args.loss_pct, 0.0, 100.0)
    bounded_number(
        parser,
        "--throughput-mbps",
        args.throughput_mbps,
        0.0,
        MAX_THROUGHPUT_MBPS,
    )
    if not 1 <= args.duration_secs <= MAX_DURATION_SECONDS:
        parser.error(
            f"--duration-secs must be between 1 and {MAX_DURATION_SECONDS}"
        )
    if args.interface is not None and INTERFACE_NAME.fullmatch(args.interface) is None:
        parser.error(
            "--interface must contain 1..=15 ASCII letters, digits, '.', '_', ':', or '-'"
        )
    if args.apply and not args.preflight:
        parser.error(
            "--apply is unavailable until qdisc identity, verification, and crash-safe rollback are implemented"
        )


def preflight_report(args: argparse.Namespace) -> dict:
    mode = "sample" if args.emit_sample else "live"
    interface_ok = mode == "sample" or bool(args.interface)
    active_change_ok = not args.apply
    passed = interface_ok and active_change_ok
    return {
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "tc-netem-lab",
        "collection_mode": mode,
        "passed": passed,
        "checks": [
            {
                "name": "interface",
                "status": "ok" if interface_ok else "error",
                "message": args.interface
                or (
                    "not required for built-in sample mode"
                    if mode == "sample"
                    else "--interface is required for live collection"
                ),
            },
            {
                "name": "active-change",
                "status": "ok" if active_change_ok else "error",
                "message": "read-only plan"
                if active_change_ok
                else "disabled until qdisc identity, verification, and crash-safe rollback are implemented",
            },
        ],
        "health": {"status": "ok" if passed else "error", "source": args.sample},
        "redaction": {"secrets": [], "fields": ["interface"]},
    }


def payload_from_args(
    args: argparse.Namespace, start: datetime, end: datetime, interface: str
) -> dict:
    return {
        "schema": "netdiag-adapter-payload/v2",
        "collection_mode": "sample" if args.emit_sample else "live",
        "sample": args.sample,
        "protocol": "TCP",
        "flow_count": 1,
        "records": [
            {
                "timestamp": start.isoformat(),
                "latency_ms": args.latency_ms,
                "jitter_ms": args.jitter_ms,
                "packet_loss_rate": args.loss_pct,
                "retransmission_rate": 0.0,
                "timeout_events": 0.0,
                "retry_events": 0.0,
                "throughput_mbps": args.throughput_mbps,
                "dns_failure_events": 0.0,
                "tls_failure_events": 0.0,
                "quic_blocked_ratio": 0.0,
            }
        ],
        "measurement_quality": MEASUREMENT_QUALITY,
        "experiment": {
            "scenario_id": args.scenario_id,
            "fault_start": start.isoformat(),
            "fault_end": end.isoformat(),
            "ground_truth": args.ground_truth,
            "interface": interface,
            "applied": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface")
    parser.add_argument("--latency-ms", default=100.0, type=float)
    parser.add_argument("--jitter-ms", default=10.0, type=float)
    parser.add_argument("--loss-pct", default=1.0, type=float)
    parser.add_argument("--throughput-mbps", default=50.0, type=float)
    parser.add_argument("--duration-secs", default=60, type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="tc-netem-lab")
    parser.add_argument("--scenario-id", default="manual-netem")
    parser.add_argument("--ground-truth", default="congestion")
    args = parser.parse_args()
    validate_args(parser, args)

    if args.preflight:
        print(json.dumps(preflight_report(args), indent=2))
        return

    if args.collect and not args.emit_sample and not args.interface:
        parser.error("--interface is required for live --collect")

    read_only_sample = args.emit_sample
    start = SAMPLE_TIME if read_only_sample else datetime.now(timezone.utc)
    end = start + timedelta(seconds=args.duration_secs)
    if read_only_sample:
        print(json.dumps(payload_from_args(args, start, end, args.interface or "lo"), indent=2))
        return
    if not args.interface:
        parser.error("--interface is required unless --emit-sample is used")

    print(json.dumps(payload_from_args(args, start, end, args.interface), indent=2))


if __name__ == "__main__":
    main()
