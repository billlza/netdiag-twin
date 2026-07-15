#!/usr/bin/env python3
"""Strict subprocess boundary helpers for adapter contract validation."""

from __future__ import annotations

import math
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Any, Mapping, Sequence

from strict_json import parse_json_strict


ADAPTER_TIMEOUT_SECONDS = 15.0
ADAPTER_STDOUT_LIMIT_BYTES = 4 * 1024 * 1024
ADAPTER_STDERR_LIMIT_BYTES = 256 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_PIPE_CLOSE_TIMEOUT_SECONDS = 0.5

def _signal_process_group(process: subprocess.Popen[bytes], signal_number: int) -> bool:
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        return False
    return True


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=_PIPE_CLOSE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("subprocess group did not stop after SIGKILL") from error


def _cleanup_bounded_process(
    process: subprocess.Popen[bytes],
    streams: Sequence[Any],
    readers: Sequence[threading.Thread],
    read_errors: Sequence[tuple[str, Exception]],
    *,
    group_shutdown_attempted: bool,
) -> RuntimeError | None:
    """Best-effort final cleanup; callers preserve any primary failure."""
    failures: list[str] = []
    if not group_shutdown_attempted:
        try:
            _terminate_process_group(process)
        except Exception:
            failures.append("process group shutdown failed")

    for stream in streams:
        try:
            stream.close()
        except Exception:
            failures.append("output pipe close failed")

    for reader in readers:
        reader.join(timeout=_PIPE_CLOSE_TIMEOUT_SECONDS)
    if any(reader.is_alive() for reader in readers):
        failures.append("output reader shutdown failed")
    if read_errors:
        failures.append("output reader failed")

    if not failures:
        return None
    return RuntimeError("subprocess cleanup failed: " + "; ".join(dict.fromkeys(failures)))


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    stdout_limit_bytes: int,
    stderr_limit_bytes: int,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    """Run a POSIX subprocess with bounded time, output, and process lifetime."""
    if os.name != "posix":
        raise RuntimeError("bounded adapter subprocesses require a POSIX process group")
    if isinstance(command, (str, bytes)) or not command or not all(
        isinstance(argument, str) and argument for argument in command
    ):
        raise ValueError("command must contain non-empty string arguments")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be finite and positive")
    if (
        isinstance(stdout_limit_bytes, bool)
        or not isinstance(stdout_limit_bytes, int)
        or isinstance(stderr_limit_bytes, bool)
        or not isinstance(stderr_limit_bytes, int)
        or stdout_limit_bytes <= 0
        or stderr_limit_bytes <= 0
    ):
        raise ValueError("subprocess output limits must be positive")

    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
        close_fds=True,
        env=dict(environment),
    )
    streams = [stream for stream in (process.stdout, process.stderr) if stream is not None]
    readers: list[threading.Thread] = []
    read_errors: list[tuple[str, Exception]] = []
    group_shutdown_attempted = False
    result: subprocess.CompletedProcess[str] | None = None
    primary_failure: BaseException | None = None
    primary_traceback: TracebackType | None = None

    try:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("failed to create subprocess output pipes")

        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {
            "stdout": stdout_limit_bytes,
            "stderr": stderr_limit_bytes,
        }
        exceeded: list[str] = []
        reader_state_lock = threading.Lock()
        stop_requested = threading.Event()

        def drain(name: str, stream: Any) -> None:
            total = 0
            try:
                while chunk := stream.read(_READ_CHUNK_BYTES):
                    total += len(chunk)
                    remaining = limits[name] - len(buffers[name])
                    if remaining > 0:
                        buffers[name].extend(chunk[:remaining])
                    if total > limits[name]:
                        with reader_state_lock:
                            if name not in exceeded:
                                exceeded.append(name)
                        stop_requested.set()
            except Exception as error:
                with reader_state_lock:
                    read_errors.append((name, error))
                stop_requested.set()
            finally:
                try:
                    stream.close()
                except Exception as error:
                    with reader_state_lock:
                        read_errors.append((name, error))
                    stop_requested.set()

        configured_readers = [
            threading.Thread(
                target=drain,
                args=("stdout", process.stdout),
                name="adapter-stdout-reader",
                daemon=True,
            ),
            threading.Thread(
                target=drain,
                args=("stderr", process.stderr),
                name="adapter-stderr-reader",
                daemon=True,
            ),
        ]
        for reader in configured_readers:
            reader.start()
            readers.append(reader)

        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while process.poll() is None:
            if stop_requested.wait(
                timeout=min(0.05, max(0.0, deadline - time.monotonic()))
            ):
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break

        lingering_descendants = False
        if process.poll() is None:
            _terminate_process_group(process)
        else:
            # A successful adapter must not leave descendants running after its entry point exits.
            lingering_descendants = _signal_process_group(process, signal.SIGKILL)
        group_shutdown_attempted = True

        for reader in readers:
            reader.join(timeout=_PIPE_CLOSE_TIMEOUT_SECONDS)
        if any(reader.is_alive() for reader in readers):
            raise RuntimeError(
                "subprocess output pipes did not close after process-group shutdown"
            )
        if read_errors:
            name, error = read_errors[0]
            raise RuntimeError(f"failed to read subprocess {name}") from error
        if timed_out:
            raise RuntimeError(f"subprocess exceeded {timeout_seconds:g}s deadline")
        if exceeded:
            name = exceeded[0]
            raise RuntimeError(f"subprocess {name} exceeded {limits[name]} byte limit")
        if lingering_descendants:
            raise RuntimeError("subprocess left descendant processes running after exit")

        decoded: dict[str, str] = {}
        for name, payload in buffers.items():
            try:
                decoded[name] = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RuntimeError(f"subprocess {name} was not valid UTF-8") from error
        returncode = process.returncode
        if returncode is None:
            raise RuntimeError("subprocess exited without a return code")
        result = subprocess.CompletedProcess(
            args=list(command),
            returncode=returncode,
            stdout=decoded["stdout"],
            stderr=decoded["stderr"],
        )
    except BaseException as error:
        primary_failure = error
        primary_traceback = error.__traceback__

    cleanup_failure = _cleanup_bounded_process(
        process,
        streams,
        readers,
        read_errors,
        group_shutdown_attempted=group_shutdown_attempted,
    )
    if primary_failure is not None:
        if cleanup_failure is not None:
            raise primary_failure.with_traceback(primary_traceback) from cleanup_failure
        raise primary_failure.with_traceback(primary_traceback)
    if cleanup_failure is not None:
        raise cleanup_failure
    if result is None:
        raise RuntimeError("subprocess completed without a result")
    return result


def validation_python_environment() -> dict[str, str]:
    executable_directory = Path(sys.executable).resolve().parent
    return {
        "PATH": str(executable_directory),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    }


def rust_validation_environment() -> dict[str, str]:
    path = os.environ.get("PATH")
    if not path:
        raise RuntimeError("PATH is required to execute the Rust ingest validator")
    environment = {
        "PATH": path,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name in (
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_NET_OFFLINE",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SDKROOT",
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
    ):
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    return environment


def run_json(adapter_path: Path, args: list[str]) -> Any:
    completed = run_bounded(
        [sys.executable, "-I", "-B", str(adapter_path), *args],
        cwd=adapter_path.parent,
        timeout_seconds=ADAPTER_TIMEOUT_SECONDS,
        stdout_limit_bytes=ADAPTER_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=ADAPTER_STDERR_LIMIT_BYTES,
        environment=validation_python_environment(),
    )
    if completed.returncode != 0:
        stderr_bytes = len(completed.stderr.encode("utf-8"))
        raise RuntimeError(
            f"adapter invocation exited {completed.returncode} with {stderr_bytes} stderr bytes"
        )
    if completed.stderr.strip():
        raise RuntimeError(f"{' '.join(args)} emitted non-empty stderr on success")
    try:
        return parse_json_strict(completed.stdout, source="adapter output")
    except ValueError as error:
        raise RuntimeError(str(error)) from error
