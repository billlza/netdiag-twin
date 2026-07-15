#!/usr/bin/env python3
"""Require every workspace package to remain private to the product repository."""

from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def workspace_members(root: Path) -> list[Path]:
    manifest_path = root / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    members = manifest.get("workspace", {}).get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("workspace.members must be a non-empty list")
    resolved: list[Path] = []
    for member in members:
        if not isinstance(member, str) or not member or any(
            character in member for character in "*?["
        ):
            raise ValueError(
                "workspace publish policy requires explicit string member paths"
            )
        relative = Path(member)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe workspace member path: {member}")
        resolved.append(relative)
    return resolved


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    try:
        members = workspace_members(root)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as error:
        return [f"could not load workspace members: {error}"]
    for member in members:
        manifest_path = root / member / "Cargo.toml"
        try:
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            failures.append(f"could not load {manifest_path.relative_to(root)}: {error}")
            continue
        package = manifest.get("package")
        if not isinstance(package, dict) or package.get("publish") is not False:
            failures.append(
                f"workspace package must set publish = false: {manifest_path.relative_to(root)}"
            )
    return failures


def main() -> int:
    failures = validate(ROOT)
    if failures:
        for failure in failures:
            print(f"workspace publish policy failed: {failure}")
        return 1
    print("workspace publish policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
