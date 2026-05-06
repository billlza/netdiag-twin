#!/usr/bin/env python3
import argparse
import csv
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from statistics import mean


FIELDS = [
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


def load_values(path: Path) -> dict[str, float]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    values = {}
    for field in FIELDS:
        samples = [float(row.get(field, 0.0) or 0.0) for row in rows]
        values[field] = mean(samples) if samples else 0.0
    return values


class Handler(BaseHTTPRequestHandler):
    values: dict[str, float] = {}

    def do_GET(self) -> None:
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = "\n".join(
            f"{prometheus_name(name)} {value}" for name, value in self.values.items()
        )
        body = f"{body}\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def prometheus_name(field: str) -> str:
    if field in {
        "timeout_events",
        "retry_events",
        "dns_failure_events",
        "tls_failure_events",
    }:
        return f"netdiag_{field}_total"
    return f"netdiag_{field}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--port", default=9107, type=int)
    args = parser.parse_args()
    Handler.values = load_values(args.csv)
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
