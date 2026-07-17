#!/usr/bin/env python3
"""Stable, bounded reads from regular files without following symlinks."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def normalized_relative_parts(value: str, scope: str) -> tuple[str, ...]:
    if not value or "\\" in value or "\0" in value:
        raise ValueError(f"{scope} must be a normalized relative POSIX path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise ValueError(f"{scope} must be a normalized relative POSIX path")
    return relative.parts


def _read_descriptor(descriptor: int, max_bytes: int, scope: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{scope} must be a file (regular and non-symlink)")
    if before.st_size > max_bytes:
        raise ValueError(f"{scope} exceeds the {max_bytes}-byte limit")

    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        value = handle.read(max_bytes + 1)
    after = os.fstat(descriptor)
    if len(value) > max_bytes:
        raise ValueError(f"{scope} exceeds the {max_bytes}-byte limit")
    if len(value) != before.st_size or _fingerprint(before) != _fingerprint(after):
        raise ValueError(f"{scope} changed while being read")
    return value


def read_regular_file(path: Path, max_bytes: int, scope: str) -> bytes:
    """Read one stable regular-file identity, bounded to max_bytes."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    path_metadata: os.stat_result | None = None
    if not no_follow:
        try:
            path_metadata = path.lstat()
        except OSError as error:
            raise ValueError(
                f"{scope} could not be inspected safely (errno={error.errno})"
            ) from error
        if not stat.S_ISREG(path_metadata.st_mode):
            raise ValueError(f"{scope} must be a regular non-symlink file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
        | no_follow
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(
            f"{scope} could not be opened safely (errno={error.errno})"
        ) from error

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{scope} must be a file (regular and non-symlink)")
        if path_metadata is not None and (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise ValueError(f"{scope} identity changed while being opened")
        value = _read_descriptor(descriptor, max_bytes, scope)
    finally:
        os.close(descriptor)
    return value


def read_regular_file_beneath(
    root: Path,
    relative_path: str,
    max_bytes: int,
    scope: str,
) -> bytes:
    """Read a normalized relative file through a no-symlink directory walk."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    parts = normalized_relative_parts(relative_path, scope)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory_flag or os.open not in os.supports_dir_fd:
        raise ValueError(f"{scope} cannot be opened with required path protections")

    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | no_follow | directory_flag
    )
    file_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_NONBLOCK
        | getattr(os, "O_BINARY", 0)
        | no_follow
    )
    open_directories: list[int] = []
    descriptor: int | None = None
    try:
        open_directories.append(os.open(root, directory_flags))
        for component in parts[:-1]:
            open_directories.append(
                os.open(component, directory_flags, dir_fd=open_directories[-1])
            )
        descriptor = os.open(parts[-1], file_flags, dir_fd=open_directories[-1])
        return _read_descriptor(descriptor, max_bytes, scope)
    except OSError as error:
        raise ValueError(
            f"{scope} could not be opened safely (errno={error.errno})"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(open_directories):
            os.close(directory)
