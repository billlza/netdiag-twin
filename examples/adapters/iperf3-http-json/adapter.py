#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import selectors
import shutil
import signal
import stat
import subprocess
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path


SAMPLE_TIME = "2026-05-07T09:00:00+00:00"
IPERF_STDOUT_LIMIT_BYTES = 4 * 1024 * 1024
IPERF_STDERR_LIMIT_BYTES = 256 * 1024
IPERF_INPUT_LIMIT_BYTES = 4 * 1024 * 1024
IPERF_SHUTDOWN_TIMEOUT_SECONDS = 0.5
IPERF_POST_EXIT_DRAIN_SECONDS = 0.5
IPERF_READ_CHUNK_BYTES = 64 * 1024
MAX_IPERF_TIMEOUT_SECONDS = 310.0
MAX_IPERF_BITS_PER_SECOND = 1_000_000_000_000_000.0
MAX_IPERF_COUNTER = 1_000_000_000_000_000.0
MAX_IPERF_JITTER_MS = 1_000_000_000.0


def measurement_quality(expected_udp: bool) -> dict[str, str]:
    return {
        "latency_ms": "missing",
        "jitter_ms": "measured" if expected_udp else "missing",
        "packet_loss_rate": "measured" if expected_udp else "missing",
        "retransmission_rate": "missing",
        "timeout_events": "missing",
        "retry_events": "missing" if expected_udp else "estimated",
        "throughput_mbps": "measured",
        "dns_failure_events": "missing",
        "tls_failure_events": "missing",
        "quic_blocked_ratio": "missing",
    }


def preflight_report(args: argparse.Namespace) -> dict:
    mode = "sample" if args.emit_sample else "live"
    input_ok = args.iperf_json is None or iperf_input_is_eligible(args.iperf_json)
    live_required = args.iperf_json is None and mode == "live"
    iperf_ok = not live_required or shutil.which("iperf3") is not None
    fault_window_ok = mode == "sample" or bool(args.fault_start and args.fault_end)
    passed = input_ok and iperf_ok and fault_window_ok
    return {
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "iperf3-http-json",
        "collection_mode": mode,
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
            {
                "name": "fault-window",
                "status": "ok" if fault_window_ok else "error",
                "message": "derived from sample timestamp"
                if mode == "sample"
                else "--fault-start and --fault-end are required for live collection",
            },
        ],
        "health": {"status": "ok" if passed else "error", "source": args.sample},
        "redaction": {"secrets": [], "fields": ["server"]},
    }


def strict_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("iperf3 JSON contains a duplicate object key")
        result[key] = value
    return result


def reject_json_constant(_value: str) -> None:
    raise ValueError("iperf3 JSON contains a non-finite numeric constant")


def parse_iperf_json(text: str) -> dict:
    payload = json.loads(
        text,
        object_pairs_hook=strict_json_object,
        parse_constant=reject_json_constant,
    )
    if not isinstance(payload, dict):
        raise ValueError("iperf3 JSON top level must be an object")
    return payload


def object_value(parent: dict, field: str, context: str) -> dict:
    value = parent.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"iperf3 {context}.{field} must be an object")
    return value


def bounded_number(
    parent: dict,
    field: str,
    context: str,
    minimum: float,
    maximum: float,
) -> float:
    value = parent.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"iperf3 {context}.{field} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(
            f"iperf3 {context}.{field} must be finite and between {minimum:g} and {maximum:g}"
        )
    return number


def normalized_timestamp(payload: dict) -> str:
    start = object_value(payload, "start", "root")
    timestamp = object_value(start, "timestamp", "start")
    if timestamp.get("timesecs") is not None:
        seconds = bounded_number(
            timestamp,
            "timesecs",
            "start.timestamp",
            0.0,
            32_503_680_000.0,
        )
        try:
            return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError) as error:
            raise ValueError("iperf3 start.timestamp.timesecs is out of range") from error

    value = timestamp.get("time")
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128:
        raise ValueError("iperf3 start.timestamp requires bounded time text or timesecs")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError) as error:
            raise ValueError("iperf3 start.timestamp.time is not a supported timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("iperf3 start.timestamp.time must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def record_from_iperf(payload: dict, expected_udp: bool) -> tuple[dict, int]:
    end = object_value(payload, "end", "root")
    streams = end.get("streams", [])
    if not isinstance(streams, list):
        raise ValueError("iperf3 end.streams must be an array")
    if len(streams) > 1024:
        raise ValueError("iperf3 end.streams exceeds the 1024-item limit")
    stream = streams[0] if streams else {}
    if not isinstance(stream, dict):
        raise ValueError("iperf3 end.streams[0] must be an object")
    if expected_udp:
        summary = stream.get("udp") or end.get("sum")
        context = "UDP summary"
    else:
        summary = stream.get("sender") or end.get("sum_sent") or end.get("sum")
        context = "TCP summary"
    if not isinstance(summary, dict):
        raise ValueError(f"iperf3 {context} is missing or not an object")

    bits_per_second = bounded_number(
        summary,
        "bits_per_second",
        context,
        0.0,
        MAX_IPERF_BITS_PER_SECOND,
    )
    jitter_ms = (
        bounded_number(summary, "jitter_ms", context, 0.0, MAX_IPERF_JITTER_MS)
        if expected_udp
        else 0.0
    )
    lost_percent = (
        bounded_number(summary, "lost_percent", context, 0.0, 100.0)
        if expected_udp
        else 0.0
    )
    retransmits = (
        0.0
        if expected_udp
        else bounded_number(summary, "retransmits", context, 0.0, MAX_IPERF_COUNTER)
    )
    return (
        {
            "timestamp": normalized_timestamp(payload),
            "latency_ms": 0.0,
            "jitter_ms": jitter_ms,
            "packet_loss_rate": lost_percent,
            "retransmission_rate": 0.0,
            "timeout_events": 0.0,
            "retry_events": retransmits,
            "throughput_mbps": bits_per_second / 1_000_000.0,
            "dns_failure_events": 0.0,
            "tls_failure_events": 0.0,
            "quic_blocked_ratio": 0.0,
        },
        max(len(streams), 1),
    )


def _signal_process_group(process: subprocess.Popen[bytes], signal_number: int) -> bool:
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        return False
    return True


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=IPERF_SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("iperf3 process group did not stop after SIGKILL") from error


def _cleanup_iperf_process(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector | None,
    streams: list[object],
    *,
    group_shutdown_attempted: bool,
) -> RuntimeError | None:
    failures: list[str] = []
    if not group_shutdown_attempted:
        try:
            _stop_process_group(process)
        except Exception:
            failures.append("process group shutdown failed")
    if selector is not None:
        try:
            selector.close()
        except Exception:
            failures.append("selector close failed")
    for stream in streams:
        try:
            stream.close()
        except Exception:
            failures.append("output pipe close failed")
    if not failures:
        return None
    return RuntimeError("iperf3 cleanup failed: " + "; ".join(dict.fromkeys(failures)))


def run_iperf(command: list[str], timeout_seconds: float) -> str:
    if os.name != "posix":
        raise RuntimeError("live iperf3 collection requires POSIX process-group controls")
    if not command or not all(isinstance(argument, str) and argument for argument in command):
        raise ValueError("iperf3 command must contain non-empty string arguments")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= MAX_IPERF_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "iperf3 timeout must be finite and positive, and no greater than "
            f"{MAX_IPERF_TIMEOUT_SECONDS:g} seconds"
        )
    executable_directory = str(Path(command[0]).resolve().parent)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
        close_fds=True,
        bufsize=0,
        env={"PATH": executable_directory, "LANG": "C", "LC_ALL": "C"},
    )
    stream_list = [
        stream for stream in (process.stdout, process.stderr) if stream is not None
    ]
    selector: selectors.BaseSelector | None = None
    group_shutdown_attempted = False
    primary_failure: BaseException | None = None
    primary_traceback = None
    output: str | None = None
    try:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("failed to create iperf3 output pipes")

        streams = {"stdout": process.stdout, "stderr": process.stderr}
        limits = {
            "stdout": IPERF_STDOUT_LIMIT_BYTES,
            "stderr": IPERF_STDERR_LIMIT_BYTES,
        }
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)

        deadline = time.monotonic() + timeout_seconds
        parent_exited_at: float | None = None
        while selector.get_map():
            now = time.monotonic()
            if process.poll() is not None and parent_exited_at is None:
                parent_exited_at = now
                deadline = min(deadline, now + IPERF_POST_EXIT_DRAIN_SECONDS)
            remaining = deadline - now
            if remaining <= 0:
                reason = (
                    "iperf3 descendants kept output pipes open after the parent exited"
                    if parent_exited_at is not None
                    else f"iperf3 exceeded its {timeout_seconds:g}s deadline"
                )
                raise RuntimeError(reason)
            for key, _ in selector.select(timeout=min(0.1, remaining)):
                name = key.data
                chunk = os.read(key.fileobj.fileno(), IPERF_READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(buffers[name]) + len(chunk) > limits[name]:
                    raise RuntimeError(
                        f"iperf3 {name} exceeded {limits[name]} byte limit"
                    )
                buffers[name].extend(chunk)

        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"iperf3 exceeded its {timeout_seconds:g}s deadline"
            ) from error
        lingering_descendants = _signal_process_group(process, signal.SIGKILL)
        group_shutdown_attempted = True
        if lingering_descendants:
            raise RuntimeError("iperf3 left descendant processes running after exit")

        decoded: dict[str, str] = {}
        for name, payload in buffers.items():
            try:
                decoded[name] = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RuntimeError(f"iperf3 {name} was not valid UTF-8") from error
        if returncode != 0:
            stderr_bytes = len(decoded["stderr"].encode("utf-8"))
            raise RuntimeError(
                f"iperf3 collection failed with exit code {returncode} and {stderr_bytes} stderr bytes"
            )
        if decoded["stderr"].strip():
            raise RuntimeError("iperf3 emitted non-empty stderr on success")
        output = decoded["stdout"]
    except BaseException as error:
        primary_failure = error
        primary_traceback = error.__traceback__

    cleanup_failure = _cleanup_iperf_process(
        process,
        selector,
        stream_list,
        group_shutdown_attempted=group_shutdown_attempted,
    )
    if primary_failure is not None:
        if cleanup_failure is not None:
            raise primary_failure.with_traceback(primary_traceback) from cleanup_failure
        raise primary_failure.with_traceback(primary_traceback)
    if cleanup_failure is not None:
        raise cleanup_failure
    if output is None:
        raise RuntimeError("iperf3 completed without output")
    return output


def iperf_input_is_eligible(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_size <= IPERF_INPUT_LIMIT_BYTES


def read_iperf_json_file(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("failed to open the iperf3 JSON input safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("iperf3 JSON input must be a regular file")
        if metadata.st_size > IPERF_INPUT_LIMIT_BYTES:
            raise RuntimeError(
                f"iperf3 JSON input exceeds {IPERF_INPUT_LIMIT_BYTES} byte limit"
            )
        payload = bytearray()
        while len(payload) <= IPERF_INPUT_LIMIT_BYTES:
            chunk = os.read(
                descriptor,
                min(IPERF_READ_CHUNK_BYTES, IPERF_INPUT_LIMIT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > IPERF_INPUT_LIMIT_BYTES:
            raise RuntimeError(
                f"iperf3 JSON input exceeds {IPERF_INPUT_LIMIT_BYTES} byte limit"
            )
    finally:
        os.close(descriptor)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("iperf3 JSON input is not valid UTF-8") from error
    return parse_iperf_json(text)


def load_iperf_json(args: argparse.Namespace) -> dict:
    if args.iperf_json:
        return read_iperf_json_file(args.iperf_json)
    iperf = shutil.which("iperf3")
    if iperf is None:
        raise RuntimeError("iperf3 executable is unavailable")
    command = [iperf, "-J", "-c", args.server, "-t", str(args.duration_secs)]
    if args.udp:
        command.append("-u")
    return parse_iperf_json(run_iperf(command, args.duration_secs + 10.0))


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

    if not 1 <= args.duration_secs <= 300:
        parser.error("--duration-secs must be between 1 and 300")
    if (
        not args.server
        or len(args.server.encode("utf-8")) > 253
        or any(character.isspace() or not character.isprintable() for character in args.server)
    ):
        parser.error("--server must contain 1..=253 bytes without whitespace or controls")

    if args.preflight:
        print(json.dumps(preflight_report(args), indent=2, allow_nan=False))
        return

    if args.collect and not args.emit_sample and (not args.fault_start or not args.fault_end):
        parser.error("--fault-start and --fault-end are required for live --collect")

    payload = sample_iperf_json(args.udp) if args.emit_sample else load_iperf_json(args)
    record, flow_count = record_from_iperf(payload, args.udp)
    fault_start = args.fault_start or record["timestamp"]
    fault_end = args.fault_end or record["timestamp"]
    print(
        json.dumps(
            {
                "schema": "netdiag-adapter-payload/v2",
                "collection_mode": "sample" if args.emit_sample else "live",
                "sample": args.sample,
                "protocol": "UDP" if args.udp else "TCP",
                "flow_count": flow_count,
                "records": [record],
                "measurement_quality": measurement_quality(args.udp),
                "experiment": {
                    "scenario_id": args.scenario_id,
                    "fault_start": fault_start,
                    "fault_end": fault_end,
                    "ground_truth": args.ground_truth,
                },
            },
            indent=2,
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
