#!/usr/bin/env python3
"""Offline integrity checks for local crates.io patch snapshots."""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from bounded_file import read_regular_file
from strict_json import StrictJsonError, parse_json_bytes_strict


PROVENANCE_FILE = "PATCH_PROVENANCE.json"
SCHEMA = "netdiag-local-patch-provenance/v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_FILES = 20_000
MAX_ARCHIVE_FILE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_CONTENT_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*")


@dataclass(frozen=True)
class PatchProvenance:
    crate: str
    version: str
    relative_root: str
    archive_file_name: str
    archive_sha256: str
    upstream_files: dict[str, str]
    preserved_test_directories: tuple[str, ...]


def exact_keys(
    value: object,
    expected: set[str],
    scope: str,
    failures: list[str],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        failures.append(f"{scope} must be an object")
        return None
    actual = set(value)
    if actual != expected:
        failures.append(
            f"{scope} keys must be exactly {sorted(expected)}; got {sorted(actual)}"
        )
        return None
    return value


def valid_relative_path(value: object, scope: str, failures: list[str]) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        failures.append(f"{scope} must be a non-empty normalized POSIX path")
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        failures.append(f"{scope} must be a normalized relative path: {value!r}")
        return None
    if path.as_posix() != value:
        failures.append(f"{scope} must be normalized: {value!r}")
        return None
    return value


def valid_sha256(value: object, scope: str, failures: list[str]) -> str | None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        failures.append(f"{scope} must be a lowercase SHA-256 digest")
        return None
    return value


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_map(
    value: object,
    scope: str,
    failures: list[str],
) -> dict[str, str]:
    if not isinstance(value, dict):
        failures.append(f"{scope} must be an object of path-to-SHA-256 entries")
        return {}
    result: dict[str, str] = {}
    for raw_path, raw_digest in value.items():
        path = valid_relative_path(raw_path, f"{scope} path", failures)
        digest = valid_sha256(raw_digest, f"{scope}[{raw_path!r}]", failures)
        if path is not None and digest is not None:
            result[path] = digest
    return result


def path_list(value: object, scope: str, failures: list[str]) -> list[str]:
    if not isinstance(value, list):
        failures.append(f"{scope} must be an array of normalized relative paths")
        return []
    result: list[str] = []
    for index, raw_path in enumerate(value):
        path = valid_relative_path(raw_path, f"{scope}[{index}]", failures)
        if path is not None:
            result.append(path)
    if result != sorted(set(result)):
        failures.append(f"{scope} must be sorted and contain no duplicates")
    return result


def local_file_digests(root: Path, failures: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    directories = [root]
    entry_count = 0
    content_bytes = 0
    while directories:
        directory = directories.pop()
        try:
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda entry: entry.name)
        except OSError as error:
            failures.append("could not enumerate local patch directory safely")
            return result
        for entry in entries:
            entry_count += 1
            if entry_count > MAX_ARCHIVE_FILES:
                failures.append(
                    f"local patch entry count exceeds the {MAX_ARCHIVE_FILES}-entry limit"
                )
                return result
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                failures.append(f"could not inspect local patch path {relative}")
                continue
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                failures.append(f"local patch path must be a regular file: {relative}")
                continue
            if relative == PROVENANCE_FILE:
                continue
            try:
                content = read_regular_file(path, MAX_ARCHIVE_FILE_BYTES, relative)
            except (OSError, ValueError) as error:
                failures.append(f"could not hash local patch file {relative}: {error}")
                continue
            content_bytes += len(content)
            if content_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                failures.append("local patch content exceeds the aggregate byte limit")
                return result
            result[relative] = digest_bytes(content)
    return result


def validate_diff(
    root: Path,
    upstream: dict[str, str],
    modified: dict[str, str],
    added: dict[str, str],
    removed: list[str],
    test_directories: list[str],
    failures: list[str],
) -> None:
    upstream_paths = set(upstream)
    modified_paths = set(modified)
    added_paths = set(added)
    removed_paths = set(removed)
    if modified_paths - upstream_paths:
        failures.append("allowed modified paths must exist in the upstream archive")
    if removed_paths - upstream_paths:
        failures.append("allowed removed paths must exist in the upstream archive")
    if added_paths & upstream_paths:
        failures.append("allowed added paths must not exist in the upstream archive")
    if modified_paths & removed_paths:
        failures.append("a path cannot be both modified and removed")
    for path in sorted(modified_paths & upstream_paths):
        if modified[path] == upstream[path]:
            failures.append(f"modified path has unchanged content: {path}")

    discovered_tests = sorted(
        {"tests" for path in upstream if path == "tests" or path.startswith("tests/")}
    )
    if test_directories != discovered_tests:
        failures.append(
            "preserved_test_directories must exactly name every published tests directory; "
            f"expected {discovered_tests}, got {test_directories}"
        )
    for directory in test_directories:
        prefix = f"{directory}/"
        changed_tests = sorted(
            path
            for path in modified_paths | added_paths | removed_paths
            if path == directory or path.startswith(prefix)
        )
        if changed_tests:
            failures.append(
                f"published test directory {directory!r} must remain byte-for-byte intact; "
                f"changed paths: {changed_tests}"
            )

    expected_paths = (upstream_paths - removed_paths) | added_paths
    if "PATCH.md" not in expected_paths:
        failures.append("local patch provenance must retain a hashed PATCH.md")
    local = local_file_digests(root, failures)
    local_paths = set(local)
    missing = sorted(expected_paths - local_paths)
    extra = sorted(local_paths - expected_paths)
    if missing:
        failures.append(f"local patch is missing declared files: {missing}")
    if extra:
        failures.append(f"local patch has undeclared files: {extra}")
    for path in sorted(expected_paths & local_paths):
        expected = modified.get(path, added.get(path, upstream.get(path)))
        if expected is None or local[path] != expected:
            failures.append(f"local patch file digest mismatch: {path}")


def archive_file_digests(
    archive_payload: bytes,
    archive_label: str,
    crate: str,
    version: str,
    failures: list[str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    total_bytes = 0
    entry_count = 0
    prefix = f"{crate}-{version}/"
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r|gz") as bundle:
            for member in bundle:
                entry_count += 1
                if entry_count > MAX_ARCHIVE_FILES:
                    raise ValueError("archive contains too many entries")
                if member.isdir() and member.name.rstrip("/") == prefix.rstrip("/"):
                    continue
                if not member.name.startswith(prefix):
                    raise ValueError(f"archive contains an unsafe entry: {member.name!r}")
                relative = member.name[len(prefix) :]
                if valid_relative_path(relative, "archive member", failures) is None:
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"archive contains an unsafe entry: {member.name!r}")
                if member.size > MAX_ARCHIVE_FILE_BYTES:
                    raise ValueError(f"archive member is too large: {relative}")
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                    raise ValueError("archive expands beyond the content limit")
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError(f"archive member could not be read: {relative}")
                content = source.read(MAX_ARCHIVE_FILE_BYTES + 1)
                if len(content) != member.size:
                    raise ValueError(f"archive member changed size while reading: {relative}")
                if relative in result:
                    raise ValueError(f"archive contains a duplicate path: {relative}")
                result[relative] = digest_bytes(content)
    except (OSError, tarfile.TarError, ValueError) as error:
        failures.append(f"could not validate upstream archive {archive_label}: {error}")
    return result


def validate_one(
    workspace_root: Path,
    crate: str,
    relative_root: str,
    failures: list[str],
    archive_directory: Path | None,
) -> PatchProvenance | None:
    root = workspace_root / relative_root
    manifest_path = root / PROVENANCE_FILE
    try:
        raw = read_regular_file(manifest_path, MAX_MANIFEST_BYTES, str(manifest_path))
        document = parse_json_bytes_strict(raw, source=f"{crate} patch provenance")
    except (OSError, UnicodeError, StrictJsonError, ValueError) as error:
        failures.append(f"could not read {crate} patch provenance: {error}")
        return None
    top = exact_keys(
        document,
        {
            "schema",
            "crate",
            "version",
            "archive",
            "upstream_files",
            "allowed_diff",
            "preserved_test_directories",
        },
        f"{crate} provenance",
        failures,
    )
    if top is None:
        return None
    version = top.get("version")
    if top.get("schema") != SCHEMA:
        failures.append(f"{crate} provenance schema must be {SCHEMA}")
    if top.get("crate") != crate or PACKAGE_NAME.fullmatch(crate) is None:
        failures.append(f"{crate} provenance crate identity does not match the patch")
    if not isinstance(version, str) or not version:
        failures.append(f"{crate} provenance version must be a non-empty string")
        return None
    try:
        cargo_manifest = tomllib.loads(
            read_regular_file(root / "Cargo.toml", MAX_MANIFEST_BYTES, "Cargo.toml").decode(
                "utf-8"
            )
        )
        package = cargo_manifest.get("package", {})
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as error:
        failures.append(f"could not validate {crate} patched Cargo.toml: {error}")
        package = {}
    if not isinstance(package, dict) or package.get("name") != crate:
        failures.append(f"{crate} patched Cargo.toml package name does not match provenance")
    if not isinstance(package, dict) or package.get("version") != version:
        failures.append(f"{crate} patched Cargo.toml version does not match provenance")
    archive = exact_keys(
        top.get("archive"),
        {"file_name", "url", "sha256"},
        f"{crate} provenance archive",
        failures,
    )
    diff = exact_keys(
        top.get("allowed_diff"),
        {"modified", "added", "removed"},
        f"{crate} provenance allowed_diff",
        failures,
    )
    if archive is None or diff is None:
        return None
    archive_file_name = f"{crate}-{version}.crate"
    expected_url = f"https://static.crates.io/crates/{crate}/{archive_file_name}"
    if archive.get("file_name") != archive_file_name:
        failures.append(f"{crate} provenance archive file name must be {archive_file_name}")
    if archive.get("url") != expected_url:
        failures.append(f"{crate} provenance archive URL must be {expected_url}")
    archive_sha256 = valid_sha256(
        archive.get("sha256"), f"{crate} archive sha256", failures
    )
    upstream = digest_map(top.get("upstream_files"), f"{crate} upstream_files", failures)
    modified = digest_map(diff.get("modified"), f"{crate} modified files", failures)
    added = digest_map(diff.get("added"), f"{crate} added files", failures)
    removed = path_list(diff.get("removed"), f"{crate} removed files", failures)
    test_directories = path_list(
        top.get("preserved_test_directories"),
        f"{crate} preserved_test_directories",
        failures,
    )
    validate_diff(root, upstream, modified, added, removed, test_directories, failures)
    if archive_sha256 is None:
        return None
    if archive_directory is not None:
        archive_path = archive_directory / archive_file_name
        try:
            archive_payload = read_regular_file(
                archive_path, MAX_ARCHIVE_BYTES, str(archive_path)
            )
        except (OSError, ValueError) as error:
            failures.append(f"could not hash upstream archive {archive_path}: {error}")
        else:
            actual_archive_sha256 = digest_bytes(archive_payload)
            if actual_archive_sha256 != archive_sha256:
                failures.append(f"upstream archive SHA-256 mismatch: {archive_file_name}")
            archived_files = archive_file_digests(
                archive_payload, str(archive_path), crate, version, failures
            )
            if archived_files != upstream:
                failures.append(
                    f"upstream archive inventory does not match provenance: {archive_file_name}"
                )
    return PatchProvenance(
        crate=crate,
        version=version,
        relative_root=relative_root,
        archive_file_name=archive_file_name,
        archive_sha256=archive_sha256,
        upstream_files=upstream,
        preserved_test_directories=tuple(test_directories),
    )


def validate_patch_provenance(
    workspace_root: Path,
    patches: dict[str, str],
    failures: list[str],
    archive_directory: Path | None = None,
) -> dict[str, PatchProvenance]:
    if archive_directory is not None:
        try:
            metadata = archive_directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or archive_directory.is_symlink():
                raise ValueError("archive directory must be a non-symlink directory")
        except (OSError, ValueError) as error:
            failures.append(f"invalid archive directory {archive_directory}: {error}")
            return {}
    result: dict[str, PatchProvenance] = {}
    for crate, relative_root in sorted(patches.items()):
        provenance = validate_one(
            workspace_root,
            crate,
            relative_root,
            failures,
            archive_directory,
        )
        if provenance is not None:
            result[crate] = provenance
    return result
