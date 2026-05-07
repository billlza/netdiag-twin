#!/usr/bin/env python3
import argparse
import csv
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


NUMERIC_FIELDS = [
    "latency_ms",
    "jitter_ms",
    "packet_loss_rate",
    "retransmission_rate",
    "timeout_events",
    "retry_events",
    "throughput_mbps",
    "dns_failure_events",
    "tls_failure_events",
    "quic_blocked_ratio",
]


def load_records(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [canonical_record(row) for row in csv.DictReader(handle)]


def canonical_record(row: dict[str, str]) -> dict:
    record = {"timestamp": row["timestamp"]}
    for field in NUMERIC_FIELDS:
        record[field] = float(row.get(field, 0.0) or 0.0)
    return record


class Handler(BaseHTTPRequestHandler):
    records: list[dict] = []
    sample: str = "http-json-python"
    protocol: str = "TCP"
    flow_count: int = 1
    experiment: dict[str, str] = {
        "scenario_id": "manual-http-json",
        "fault_start": "",
        "fault_end": "",
        "ground_truth": "normal",
    }

    def do_GET(self) -> None:
        if self.path != "/trace":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(
            {
                "schema": "netdiag-adapter-payload/v1",
                "sample": self.sample,
                "protocol": self.protocol,
                "flow_count": self.flow_count,
                "records": self.records,
                "experiment": self.experiment,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--protocol", default="TCP")
    parser.add_argument("--flow-count", default=1, type=int)
    parser.add_argument("--scenario-id", default=None)
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    args = parser.parse_args()
    Handler.records = load_records(args.csv)
    Handler.sample = args.csv.stem
    Handler.protocol = args.protocol
    Handler.flow_count = args.flow_count
    Handler.experiment = {
        "scenario_id": args.scenario_id or args.csv.stem,
        "fault_start": args.fault_start,
        "fault_end": args.fault_end,
        "ground_truth": args.ground_truth,
    }
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
