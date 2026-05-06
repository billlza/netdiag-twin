#!/usr/bin/env python3
import argparse
import csv
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def load_records(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class Handler(BaseHTTPRequestHandler):
    records: list[dict] = []
    sample: str = "http-json-python"

    def do_GET(self) -> None:
        if self.path != "/trace":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"sample": self.sample, "records": self.records}).encode("utf-8")
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
    args = parser.parse_args()
    Handler.records = load_records(args.csv)
    Handler.sample = args.csv.stem
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
