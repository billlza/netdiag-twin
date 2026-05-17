#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"


def preflight_report(args: argparse.Namespace) -> dict:
    input_ok = args.iperf_json is None or args.iperf_json.is_file()
    live_required = args.iperf_json is None and not args.emit_sample
    iperf_ok = not live_required or shutil.which("iperf3") is not None
    passed = input_ok and iperf_ok
    return {
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "iperf3-http-json",
        "passed": passed,
        "checks": [
            {
                "name": "iperf-json",
                "status": "ok" if input_ok else "error",
                "message": "offline sample mode"
                if args.iperf_json is None
                else str(args.iperf_json),
            },
            {
                "name": "iperf3-binary",
                "status": "ok" if iperf_ok else "error",
                "message": "not required for fixture/sample mode"
                if not live_required
                else "required for live iperf3 collection",
            },
        ],
        "health": {"status": "ok" if passed else "error", "source": args.sample},
        "redaction": {"secrets": [], "fields": ["server"]},
    }


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


def sample_iperf_json(udp: bool) -> dict:
    if udp:
        stream_summary = {
            "udp": {
                "bits_per_second": 48_500_000.0,
                "jitter_ms": 8.5,
                "lost_percent": 1.25,
            }
        }
        end_summary = stream_summary["udp"]
    else:
        stream_summary = {
            "sender": {
                "bits_per_second": 94_200_000.0,
                "retransmits": 2.0,
            }
        }
        end_summary = stream_summary["sender"]
    return {
        "start": {"timestamp": {"time": SAMPLE_TIME}},
        "end": {
            "streams": [stream_summary],
            "sum": end_summary,
            "sum_sent": end_summary,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iperf-json", type=Path)
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--duration-secs", default=10, type=int)
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="iperf3-http-json")
    parser.add_argument("--scenario-id", default="manual-iperf3")
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()

    if args.preflight:
        print(json.dumps(preflight_report(args), indent=2))
        return

    payload = sample_iperf_json(args.udp) if args.emit_sample else load_iperf_json(args)
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
