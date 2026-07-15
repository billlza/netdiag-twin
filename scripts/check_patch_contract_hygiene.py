#!/usr/bin/env python3
"""Require every local crates.io patch to have an explicit executable contract."""

from __future__ import annotations

import argparse
import shlex
import sys
import tomllib
from pathlib import Path
from typing import Any

from check_release_gate_hygiene import (
    logical_cargo_commands,
    shell_function_body,
    uncommented_body,
)
from patch_provenance import PatchProvenance, validate_patch_provenance


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
QUALITY_SCRIPT = ROOT / "scripts" / "check_rust_quality.sh"


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def normalized_relative_path(raw: str, failures: list[str]) -> str | None:
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        failures.append(f"local patch path must stay inside the workspace: {raw}")
        return None
    resolved = (ROOT / path).resolve()
    try:
        relative = resolved.relative_to(ROOT.resolve())
    except ValueError:
        failures.append(f"local patch path escapes the workspace: {raw}")
        return None
    return relative.as_posix()


def string_list(value: object, scope: str, failures: list[str]) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        failures.append(f"{scope} must be an array of strings")
        return []
    return value


def local_patches(
    workspace: dict[str, Any], failures: list[str]
) -> dict[str, str]:
    patch_table = workspace.get("patch", {}).get("crates-io", {})
    if not isinstance(patch_table, dict):
        failures.append("[patch.crates-io] must be a TOML table")
        return {}

    patches: dict[str, str] = {}
    for crate, declaration in patch_table.items():
        if not isinstance(crate, str) or not isinstance(declaration, dict):
            failures.append("[patch.crates-io] entries must be named TOML tables")
            continue
        raw_path = declaration.get("path")
        if raw_path is None:
            continue
        if not isinstance(raw_path, str):
            failures.append(f"local patch {crate} path must be a string")
            continue
        relative = normalized_relative_path(raw_path, failures)
        if relative is not None:
            patches[crate] = relative
    return patches


def validate_patch_manifests(
    patches: dict[str, str], excluded: set[str], failures: list[str]
) -> None:
    for crate, relative in patches.items():
        if relative not in excluded:
            failures.append(
                f"local patch {crate} must be excluded from the root workspace: {relative}"
            )
        manifest_path = ROOT / relative / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(f"local patch {crate} manifest is missing: {manifest_path}")
            continue
        try:
            package = read_toml(manifest_path).get("package", {})
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures.append(f"could not parse local patch {crate} manifest: {error}")
            continue
        if not isinstance(package, dict) or package.get("name") != crate:
            failures.append(
                f"local patch {crate} manifest package.name must match the patched crate"
            )


def contract_packages(
    members: list[str], patched_crates: set[str], failures: list[str]
) -> dict[str, str]:
    owners: dict[str, str] = {}
    for member in members:
        manifest_path = ROOT / member / "Cargo.toml"
        if not manifest_path.is_file():
            continue
        try:
            manifest = read_toml(manifest_path)
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures.append(f"could not parse workspace member {member}: {error}")
            continue
        package = manifest.get("package", {})
        if not isinstance(package, dict):
            continue
        metadata = package.get("metadata", {})
        contract = (
            metadata.get("netdiag-patch-contract", {})
            if isinstance(metadata, dict)
            else {}
        )
        if not isinstance(contract, dict) or "patches" not in contract:
            continue
        package_name = package.get("name")
        if not isinstance(package_name, str):
            failures.append(f"patch contract workspace member has no package.name: {member}")
            continue
        declared = string_list(
            contract.get("patches"),
            f"{package_name} package.metadata.netdiag-patch-contract.patches",
            failures,
        )
        if not declared:
            failures.append(f"patch contract {package_name} must name at least one patch")
        for crate in declared:
            if crate not in patched_crates:
                failures.append(
                    f"patch contract {package_name} names unknown local patch {crate}"
                )
                continue
            previous = owners.get(crate)
            if previous is not None:
                failures.append(
                    f"local patch {crate} has multiple contracts: {previous}, {package_name}"
                )
            else:
                owners[crate] = package_name
    for crate in sorted(patched_crates - owners.keys()):
        failures.append(f"local patch {crate} has no workspace patch contract package")
    return owners


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return []


def option_value(tokens: list[str], option: str) -> str | None:
    try:
        index = tokens.index(option)
    except ValueError:
        return None
    return tokens[index + 1] if index + 1 < len(tokens) else None


def has_metadata_command(commands: list[list[str]], manifest: str) -> bool:
    return any(
        len(tokens) >= 2
        and tokens[0:2] == ["cargo", "metadata"]
        and option_value(tokens, "--manifest-path") == manifest
        and "--no-deps" in tokens
        and "--locked" in tokens
        and "--offline" in tokens
        for tokens in commands
    )


def has_contract_command(
    commands: list[list[str]], subcommand: str, package: str
) -> bool:
    for tokens in commands:
        if len(tokens) < 2 or tokens[0:2] != ["cargo", subcommand]:
            continue
        if option_value(tokens, "-p") != package or "--all-targets" not in tokens:
            continue
        if "--all-features" not in tokens:
            continue
        if subcommand == "clippy":
            try:
                separator = tokens.index("--")
            except ValueError:
                continue
            if tokens[separator + 1 :] != ["-D", "warnings"]:
                continue
        return True
    return False


def has_upstream_test_command(
    commands: list[list[str]],
    subcommand: str,
    manifest: str,
) -> bool:
    for tokens in commands:
        if len(tokens) < 2 or tokens[0:2] != ["cargo", subcommand]:
            continue
        if (
            option_value(tokens, "--manifest-path") != manifest
            or "--locked" not in tokens
            or "--offline" not in tokens
            or "--all-targets" not in tokens
            or "--all-features" not in tokens
        ):
            continue
        if subcommand == "clippy":
            try:
                separator = tokens.index("--")
            except ValueError:
                continue
            if tokens[separator + 1 :] != ["-D", "warnings"]:
                continue
        return True
    return False


def validate_quality_script(
    patches: dict[str, str],
    owners: dict[str, str],
    provenance: dict[str, PatchProvenance],
    failures: list[str],
) -> None:
    try:
        active = uncommented_body(QUALITY_SCRIPT.read_text(encoding="utf-8"))
    except OSError as error:
        failures.append(f"could not read strict quality script: {error}")
        return
    contract_body = shell_function_body(active, "run_patch_contracts")
    strict_body = shell_function_body(active, "run_strict")
    if contract_body is None:
        failures.append("check_rust_quality.sh must define run_patch_contracts")
        return
    if strict_body is None:
        failures.append("check_rust_quality.sh must define run_strict")
    elif not any(
        line.strip().rstrip(";") == "run_patch_contracts"
        for line in strict_body.splitlines()
    ):
        failures.append("check_rust_quality.sh run_strict must invoke run_patch_contracts")

    commands = [
        command_tokens(command) for command in logical_cargo_commands(contract_body)
    ]
    for crate, relative in sorted(patches.items()):
        manifest = f"{relative}/Cargo.toml"
        if not has_metadata_command(commands, manifest):
            failures.append(
                f"run_patch_contracts must parse {crate} independently with "
                f"cargo metadata --locked --offline --no-deps --manifest-path {manifest}"
            )
        package = owners.get(crate)
        if package is None:
            continue
        if not has_contract_command(commands, "test", package):
            failures.append(
                f"run_patch_contracts must test {package} with all targets and features"
            )
        if not has_contract_command(commands, "clippy", package):
            failures.append(
                f"run_patch_contracts must Clippy {package} with all targets/features "
                "and warnings denied"
            )
        patch_provenance = provenance.get(crate)
        if patch_provenance is None or not patch_provenance.preserved_test_directories:
            continue
        if not has_upstream_test_command(commands, "test", manifest):
            failures.append(
                f"run_patch_contracts must execute preserved {crate} upstream tests "
                f"with --locked --offline --manifest-path {manifest} "
                "--all-targets --all-features"
            )
        if not has_upstream_test_command(commands, "clippy", manifest):
            failures.append(
                f"run_patch_contracts must Clippy preserved {crate} upstream tests with "
                f"--locked --offline --manifest-path {manifest} "
                "--all-targets --all-features and warnings denied"
            )


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate local patch provenance and executable contracts"
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        help="also verify exact crates.io archive bytes from this offline directory",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments([] if argv is None else argv)
    failures: list[str] = []
    try:
        workspace = read_toml(WORKSPACE_MANIFEST)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"patch contract hygiene failed: could not parse workspace: {error}")
        return 1

    workspace_table = workspace.get("workspace", {})
    if not isinstance(workspace_table, dict):
        print("patch contract hygiene failed: [workspace] must be a TOML table")
        return 1
    members = string_list(workspace_table.get("members"), "workspace.members", failures)
    excluded = set(
        string_list(workspace_table.get("exclude", []), "workspace.exclude", failures)
    )
    patches = local_patches(workspace, failures)
    validate_patch_manifests(patches, excluded, failures)
    owners = contract_packages(members, set(patches), failures)
    provenance = validate_patch_provenance(
        ROOT,
        patches,
        failures,
        arguments.archive_dir,
    )
    validate_quality_script(patches, owners, provenance, failures)

    if failures:
        for failure in failures:
            print(f"patch contract hygiene failed: {failure}")
        return 1
    print(f"patch contract hygiene passed ({len(patches)} local patches)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
