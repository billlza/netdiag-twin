#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"
MIN_COUNT = 1
MAX_COUNT = 20
MIN_TIMEOUT_SECONDS = 0.05
MAX_TIMEOUT_SECONDS = 10.0
MAX_TOTAL_TIMEOUT_SECONDS = 60.0
MAX_HOST_BYTES = 253
MAX_RESOLVED_ADDRESSES = 16
RESOLVER_OUTPUT_LIMIT_BYTES = 16 * 1024
RESOLVER_WORKER_COMMAND = "--internal-resolve-worker"
PROBE_BYTES = b"netdiag-quic-probe"

TIMEOUT_FAILURE = "timeout"
RESOLUTION_FAILURE = "resolution"
NETWORK_FAILURE = "network"
FAILURE_KINDS = (TIMEOUT_FAILURE, RESOLUTION_FAILURE, NETWORK_FAILURE)
MEASUREMENT_QUALITY = {
    "latency_ms": "measured",
    "jitter_ms": "measured",
    "packet_loss_rate": "fallback",
    "retransmission_rate": "missing",
    "timeout_events": "measured",
    "retry_events": "missing",
    "throughput_mbps": "missing",
    "dns_failure_events": "measured",
    "tls_failure_events": "missing",
    "quic_blocked_ratio": "fallback",
}


class ProbeRuntimeError(RuntimeError):
    """A non-observational failure that prevents a trustworthy probe result."""


class ResolutionOutcome(NamedTuple):
    addresses: tuple[tuple[int, tuple[object, ...]], ...]
    failure: str | None
    elapsed_ms: float


class ProbeAttempt(NamedTuple):
    elapsed_ms: float
    failure: str | None


def validate_host(parser: argparse.ArgumentParser, host: str | None) -> str:
    if host is None:
        parser.error("--host is required unless --emit-sample is used")
    try:
        encoded = host.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        parser.error("--host must contain only visible ASCII characters")
    if not 1 <= len(encoded) <= MAX_HOST_BYTES:
        parser.error("--host must contain 1..=253 ASCII bytes")
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        parser.error("--host must not contain whitespace or control characters")
    return host


def validate_arguments(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> str:
    if not MIN_COUNT <= args.count <= MAX_COUNT:
        parser.error("--count must be between 1 and 20")
    if not math.isfinite(args.timeout_secs):
        parser.error("--timeout-secs must be finite")
    if not MIN_TIMEOUT_SECONDS <= args.timeout_secs <= MAX_TIMEOUT_SECONDS:
        parser.error("--timeout-secs must be between 0.05 and 10 seconds")
    if args.count * args.timeout_secs > MAX_TOTAL_TIMEOUT_SECONDS:
        parser.error("--count * --timeout-secs must not exceed 60 seconds")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    sample_host = (
        "example.test" if args.emit_sample and args.host is None else args.host
    )
    return validate_host(parser, sample_host)


def resolver_worker_payload(host: str, port: int, socket_type: int) -> dict:
    started = time.perf_counter()
    try:
        resolved = socket.getaddrinfo(host, port, type=socket_type)
    except OSError:
        return {
            "status": RESOLUTION_FAILURE,
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        }

    addresses: list[list[object]] = []
    seen: set[tuple[object, ...]] = set()
    for family, _kind, _protocol, _canonname, socket_address in resolved:
        if family == socket.AF_INET:
            address = [family, socket_address[0], socket_address[1]]
        elif family == socket.AF_INET6:
            address = [
                family,
                socket_address[0],
                socket_address[1],
                socket_address[2],
                socket_address[3],
            ]
        else:
            continue
        key = tuple(address)
        if key in seen:
            continue
        seen.add(key)
        addresses.append(address)
        if len(addresses) == MAX_RESOLVED_ADDRESSES:
            break

    if not addresses:
        return {
            "status": RESOLUTION_FAILURE,
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        }
    return {
        "status": "ok",
        "addresses": addresses,
        "elapsed_ms": (time.perf_counter() - started) * 1000.0,
    }


def resolver_worker_main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    host, port_text, socket_type_text = argv
    try:
        port = int(port_text)
        socket_type = int(socket_type_text)
    except ValueError:
        return 2
    if not 1 <= port <= 65535 or socket_type not in {
        socket.SOCK_STREAM,
        socket.SOCK_DGRAM,
    }:
        return 2
    payload = resolver_worker_payload(host, port, socket_type)
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    if len(encoded) > RESOLVER_OUTPUT_LIMIT_BYTES:
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


def resolver_worker_environment() -> dict[str, str]:
    environment = {
        "PATH": str(Path(sys.executable).resolve().parent),
        "LANG": "C",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR"):
            value = os.environ.get(name)
            if value is not None:
                environment[name] = value
    return environment


def resolver_command(host: str, port: int, socket_type: int) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        RESOLVER_WORKER_COMMAND,
        host,
        str(port),
        str(socket_type),
    ]


def terminate_resolver_worker(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired as error:
            raise ProbeRuntimeError(
                "resolver worker could not be terminated"
            ) from error
    except OSError as error:
        raise ProbeRuntimeError("resolver worker could not be terminated") from error
    finally:
        if process.stdout is not None:
            process.stdout.close()


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_non_finite_number(_value: str) -> None:
    raise ValueError("non-finite number")


def parse_resolution_output(
    output: bytes, expected_port: int | None = None
) -> ResolutionOutcome:
    if not output or len(output) > RESOLVER_OUTPUT_LIMIT_BYTES:
        raise ProbeRuntimeError("resolver worker returned an invalid response")
    try:
        payload = json.loads(
            output.decode("ascii", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite_number,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ProbeRuntimeError(
            "resolver worker returned an invalid response"
        ) from error
    if not isinstance(payload, dict):
        raise ProbeRuntimeError("resolver worker returned an invalid response")
    status = payload.get("status")
    elapsed_ms = payload.get("elapsed_ms")
    if (
        isinstance(elapsed_ms, bool)
        or not isinstance(elapsed_ms, (int, float))
        or not math.isfinite(elapsed_ms)
        or elapsed_ms < 0
    ):
        raise ProbeRuntimeError("resolver worker returned an invalid response")
    if status == RESOLUTION_FAILURE:
        if set(payload) != {"status", "elapsed_ms"}:
            raise ProbeRuntimeError("resolver worker returned an invalid response")
        return ResolutionOutcome((), status, float(elapsed_ms))
    if status != "ok" or set(payload) != {"status", "addresses", "elapsed_ms"}:
        raise ProbeRuntimeError("resolver worker returned an invalid response")
    raw_addresses = payload["addresses"]
    if (
        not isinstance(raw_addresses, list)
        or not 1 <= len(raw_addresses) <= MAX_RESOLVED_ADDRESSES
    ):
        raise ProbeRuntimeError("resolver worker returned an invalid response")

    addresses: list[tuple[int, tuple[object, ...]]] = []
    for raw in raw_addresses:
        if not isinstance(raw, list) or not raw:
            raise ProbeRuntimeError("resolver worker returned an invalid response")
        family = raw[0]
        if family == socket.AF_INET and len(raw) == 3:
            ip, port = raw[1], raw[2]
            socket_address: tuple[object, ...] = (ip, port)
        elif family == socket.AF_INET6 and len(raw) == 5:
            ip, port, flowinfo, scope_id = raw[1:]
            socket_address = (ip, port, flowinfo, scope_id)
        else:
            raise ProbeRuntimeError("resolver worker returned an invalid response")
        if not isinstance(ip, str) or not isinstance(port, int):
            raise ProbeRuntimeError("resolver worker returned an invalid response")
        try:
            socket.inet_pton(family, ip)
        except OSError as error:
            raise ProbeRuntimeError(
                "resolver worker returned an invalid response"
            ) from error
        if not 1 <= port <= 65535 or (
            expected_port is not None and port != expected_port
        ):
            raise ProbeRuntimeError("resolver worker returned an invalid response")
        if family == socket.AF_INET6 and (
            not isinstance(flowinfo, int)
            or not isinstance(scope_id, int)
            or not 0 <= flowinfo <= 1_048_575
            or not 0 <= scope_id <= 4_294_967_295
        ):
            raise ProbeRuntimeError("resolver worker returned an invalid response")
        addresses.append((family, socket_address))
    return ResolutionOutcome(tuple(addresses), None, float(elapsed_ms))


def bounded_resolve(
    host: str, port: int, socket_type: int, timeout_seconds: float
) -> ResolutionOutcome:
    started = time.monotonic()
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            resolver_command(host, port, socket_type),
            cwd=Path(__file__).resolve().parent,
            env=resolver_worker_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        raise ProbeRuntimeError("resolver worker could not be started") from error
    timed_out = False
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            output = b""
        else:
            try:
                output, _stderr = process.communicate(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                output = b""
    except BaseException:
        terminate_resolver_worker(process)
        raise
    if timed_out:
        terminate_resolver_worker(process)
        return ResolutionOutcome(
            (), TIMEOUT_FAILURE, (time.monotonic() - started) * 1000.0
        )
    if process.returncode != 0:
        raise ProbeRuntimeError("resolver worker failed")
    return parse_resolution_output(output, port)


def classify_udp_error(error: OSError) -> str:
    if isinstance(error, (socket.timeout, TimeoutError)):
        return TIMEOUT_FAILURE
    return NETWORK_FAILURE


def udp_attempt(host: str, port: int, timeout_seconds: float) -> ProbeAttempt:
    started = time.monotonic()
    deadline = started + timeout_seconds
    resolution = bounded_resolve(
        host,
        port,
        socket.SOCK_DGRAM,
        max(deadline - time.monotonic(), 0.0),
    )
    if resolution.failure is not None:
        return ProbeAttempt(resolution.elapsed_ms, resolution.failure)

    socket_started = time.monotonic()
    last_failure = NETWORK_FAILURE
    for family, socket_address in resolution.addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_failure = TIMEOUT_FAILURE
            break
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe_socket:
                probe_socket.settimeout(remaining)
                probe_socket.connect(socket_address)
                probe_socket.send(PROBE_BYTES)
                probe_socket.recv(1200)
            return ProbeAttempt(
                resolution.elapsed_ms
                + (time.monotonic() - socket_started) * 1000.0,
                None,
            )
        except OSError as error:
            last_failure = classify_udp_error(error)
            if last_failure == TIMEOUT_FAILURE:
                break

    return ProbeAttempt(
        resolution.elapsed_ms + (time.monotonic() - socket_started) * 1000.0,
        last_failure,
    )


def summarize_attempts(
    attempts: list[ProbeAttempt],
) -> tuple[float, float, dict[str, int]]:
    elapsed = [attempt.elapsed_ms for attempt in attempts]
    failure_counts = {
        kind: sum(attempt.failure == kind for attempt in attempts)
        for kind in FAILURE_KINDS
    }
    return (
        sum(elapsed) / len(elapsed),
        statistics.pstdev(elapsed) if len(elapsed) > 1 else 0.0,
        failure_counts,
    )


def sample_payload(args: argparse.Namespace, host: str) -> dict:
    timeout_count = 1
    blocked_ratio = timeout_count / args.count
    return {
        "schema": "netdiag-adapter-payload/v2",
        "collection_mode": "sample",
        "sample": args.sample,
        "protocol": "QUIC",
        "flow_count": args.count,
        "records": [
            {
                "timestamp": SAMPLE_TIME,
                "latency_ms": 12.0,
                "jitter_ms": 0.0,
                "packet_loss_rate": blocked_ratio * 100.0,
                "retransmission_rate": 0.0,
                "timeout_events": float(timeout_count),
                "retry_events": 0.0,
                "throughput_mbps": 0.0,
                "dns_failure_events": 0.0,
                "tls_failure_events": 0.0,
                "quic_blocked_ratio": blocked_ratio,
            }
        ],
        "measurement_quality": MEASUREMENT_QUALITY,
        "probe_summary": {
            "attempts": args.count,
            "successes": args.count - timeout_count,
            "failure_counts": {
                TIMEOUT_FAILURE: timeout_count,
                RESOLUTION_FAILURE: 0,
                NETWORK_FAILURE: 0,
            },
        },
        "experiment": {
            "scenario_id": args.scenario_id,
            "fault_start": args.fault_start,
            "fault_end": args.fault_end,
            "ground_truth": args.ground_truth,
            "target": f"{host}:{args.port}",
        },
    }


def live_payload(args: argparse.Namespace, host: str) -> dict:
    fault_started = datetime.now(timezone.utc)
    attempts = [
        udp_attempt(host, args.port, args.timeout_secs) for _ in range(args.count)
    ]
    fault_ended = datetime.now(timezone.utc)
    latency, jitter, failure_counts = summarize_attempts(attempts)
    failures = sum(failure_counts.values())
    return {
        "schema": "netdiag-adapter-payload/v2",
        "collection_mode": "live",
        "sample": args.sample,
        "protocol": "QUIC",
        "flow_count": args.count,
        "records": [
            {
                "timestamp": fault_ended.isoformat(),
                "latency_ms": latency,
                "jitter_ms": jitter,
                "packet_loss_rate": failures / args.count * 100.0,
                "retransmission_rate": 0.0,
                "timeout_events": float(failure_counts[TIMEOUT_FAILURE]),
                "retry_events": 0.0,
                "throughput_mbps": 0.0,
                "dns_failure_events": float(failure_counts[RESOLUTION_FAILURE]),
                "tls_failure_events": 0.0,
                "quic_blocked_ratio": failure_counts[TIMEOUT_FAILURE] / args.count,
            }
        ],
        "measurement_quality": MEASUREMENT_QUALITY,
        "probe_summary": {
            "attempts": args.count,
            "successes": args.count - failures,
            "failure_counts": failure_counts,
        },
        "experiment": {
            "scenario_id": args.scenario_id,
            "fault_start": fault_started.isoformat(),
            "fault_end": fault_ended.isoformat(),
            "ground_truth": args.ground_truth,
            "target": f"{host}:{args.port}",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", default=443, type=int)
    parser.add_argument("--count", default=5, type=int)
    parser.add_argument("--timeout-secs", default=1.0, type=float)
    parser.add_argument("--emit-sample", action="store_true")
    parser.add_argument("--sample", default="quic-probe")
    parser.add_argument("--scenario-id", default="manual-quic")
    parser.add_argument("--fault-start", default="")
    parser.add_argument("--fault-end", default="")
    parser.add_argument("--ground-truth", default="normal")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    host = validate_arguments(parser, args)
    try:
        payload = (
            sample_payload(args, host)
            if args.emit_sample
            else live_payload(args, host)
        )
    except ProbeRuntimeError as error:
        parser.exit(1, f"error: {error}\n")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == RESOLVER_WORKER_COMMAND:
        raise SystemExit(resolver_worker_main(sys.argv[2:]))
    raise SystemExit(main())
