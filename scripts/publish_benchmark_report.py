#!/usr/bin/env python3
"""Publish one validated benchmark report directory without replacement."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


EXPECTED_REPORT_FILES = frozenset({"benchmark_report.json", "benchmark_report.md"})


class BenchmarkReportPublicationError(RuntimeError):
    """The report could not be validated or published safely."""


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise BenchmarkReportPublicationError(f"{label} is unavailable") from error


def _validate_private_directory(path: Path, label: str) -> os.stat_result:
    metadata = _lstat(path, label)
    if not stat.S_ISDIR(metadata.st_mode):
        raise BenchmarkReportPublicationError(f"{label} must be a directory")
    if metadata.st_uid != os.geteuid():
        raise BenchmarkReportPublicationError(
            f"{label} must be owned by the current user"
        )
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BenchmarkReportPublicationError(
            f"{label} must not be group- or world-writable"
        )
    return metadata


def _validate_report_directory(path: Path, label: str) -> os.stat_result:
    directory_metadata = _validate_private_directory(path, label)
    try:
        entries = {entry.name: entry for entry in path.iterdir()}
    except OSError as error:
        raise BenchmarkReportPublicationError(
            f"{label} entries could not be inspected"
        ) from error
    if set(entries) != EXPECTED_REPORT_FILES:
        raise BenchmarkReportPublicationError(
            f"{label} has an unexpected file set"
        )
    for name in sorted(EXPECTED_REPORT_FILES):
        metadata = _lstat(entries[name], f"benchmark report {name}")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise BenchmarkReportPublicationError(
                f"benchmark report {name} must be a non-empty regular file"
            )
        if metadata.st_uid != os.geteuid():
            raise BenchmarkReportPublicationError(
                f"benchmark report {name} must be owned by the current user"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise BenchmarkReportPublicationError(
                f"benchmark report {name} must not be group- or world-writable"
            )
    return directory_metadata


def publish_benchmark_report(source: Path, destination: Path) -> None:
    if os.name != "posix":
        raise BenchmarkReportPublicationError(
            "benchmark report publication requires POSIX rename semantics"
        )
    for path, label in ((source, "source"), (destination, "destination")):
        if not path.is_absolute() or ".." in path.parts:
            raise BenchmarkReportPublicationError(
                f"benchmark report {label} must be a normalized absolute path"
            )

    source_metadata = _validate_report_directory(
        source, "benchmark report source"
    )
    archive = destination.parent
    try:
        archive.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise BenchmarkReportPublicationError(
            "benchmark report archive could not be created"
        ) from error
    _validate_private_directory(archive, "benchmark report archive")

    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise BenchmarkReportPublicationError(
            "benchmark report destination could not be inspected"
        ) from error
    else:
        raise BenchmarkReportPublicationError(
            "refusing to replace an existing benchmark report archive entry"
        )

    try:
        os.rename(source, destination)
    except OSError as error:
        raise BenchmarkReportPublicationError(
            "benchmark report could not be published atomically"
        ) from error

    try:
        source.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise BenchmarkReportPublicationError(
            "benchmark report source could not be checked after publication"
        ) from error
    else:
        raise BenchmarkReportPublicationError(
            "benchmark report source still exists after publication"
        )

    published_metadata = _validate_report_directory(
        destination, "published benchmark report"
    )
    if (published_metadata.st_dev, published_metadata.st_ino) != (
        source_metadata.st_dev,
        source_metadata.st_ino,
    ):
        raise BenchmarkReportPublicationError(
            "published benchmark report identity changed during publication"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="atomically publish a validated benchmark report directory"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)
    try:
        publish_benchmark_report(arguments.source, arguments.destination)
    except BenchmarkReportPublicationError as error:
        print(f"benchmark report publication failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
