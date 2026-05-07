#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "examples/adapters/schema/netdiag-adapter-payload.schema.json"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    failed = False

    for name, adapter_path in discover_adapters():
        try:
            payload = emit_sample(adapter_path)
        except RuntimeError as error:
            print(f"{name}: {error}", file=sys.stderr)
            failed = True
            continue

        errors: list[str] = []
        validate(payload, schema, "$", errors)
        if errors:
            failed = True
            print(f"{name}: schema validation failed", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
        else:
            print(f"{name}: ok")

    return 1 if failed else 0


def discover_adapters() -> list[tuple[str, Path]]:
    adapters_dir = ROOT / "examples/adapters"
    adapter_paths = [
        *adapters_dir.glob("*/adapter.py"),
        *adapters_dir.glob("*/exporter.py"),
    ]
    return [(path.parent.name, path) for path in sorted(adapter_paths)]


def emit_sample(adapter_path: Path) -> Any:
    completed = subprocess.run(
        [sys.executable, str(adapter_path), "--emit-sample"],
        cwd=adapter_path.parent,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise RuntimeError(f"--emit-sample exited {completed.returncode}: {stderr}")

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"--emit-sample did not emit JSON: {error}") from error


def validate(instance: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    expected_type = schema.get("type")
    if expected_type and not matches_type(instance, expected_type):
        errors.append(f"{path}: expected {expected_type}, got {type_name(instance)}")
        return

    if isinstance(instance, dict):
        validate_object(instance, schema, path, errors)
    elif isinstance(instance, list):
        validate_array(instance, schema, path, errors)
    elif isinstance(instance, str):
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            errors.append(f"{path}: length must be at least {min_length}")

    if is_json_number(instance):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            errors.append(f"{path}: value must be >= {minimum}")


def validate_object(
    instance: dict[str, Any], schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    for key in schema.get("required", []):
        if key not in instance:
            errors.append(f"{path}: missing required property {key!r}")

    properties = schema.get("properties", {})
    for key, child_schema in properties.items():
        if key in instance:
            validate(instance[key], child_schema, f"{path}.{key}", errors)

    additional_properties = schema.get("additionalProperties", True)
    if additional_properties is False:
        unexpected = sorted(set(instance) - set(properties))
        for key in unexpected:
            errors.append(f"{path}: unexpected property {key!r}")
    elif isinstance(additional_properties, dict):
        for key in sorted(set(instance) - set(properties)):
            validate(instance[key], additional_properties, f"{path}.{key}", errors)


def validate_array(
    instance: list[Any], schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    min_items = schema.get("minItems")
    if min_items is not None and len(instance) < min_items:
        errors.append(f"{path}: expected at least {min_items} item(s)")

    item_schema = schema.get("items")
    if item_schema:
        for index, item in enumerate(instance):
            validate(item, item_schema, f"{path}[{index}]", errors)


def matches_type(instance: Any, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(instance, dict)
    if expected_type == "array":
        return isinstance(instance, list)
    if expected_type == "string":
        return isinstance(instance, str)
    if expected_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected_type == "number":
        return is_json_number(instance)
    if expected_type == "boolean":
        return isinstance(instance, bool)
    if expected_type == "null":
        return instance is None
    raise ValueError(f"unsupported schema type: {expected_type}")


def is_json_number(instance: Any) -> bool:
    return isinstance(instance, (int, float)) and not isinstance(instance, bool)


def type_name(instance: Any) -> str:
    if instance is None:
        return "null"
    if isinstance(instance, bool):
        return "boolean"
    if isinstance(instance, dict):
        return "object"
    if isinstance(instance, list):
        return "array"
    if isinstance(instance, str):
        return "string"
    if isinstance(instance, int):
        return "integer"
    if isinstance(instance, float):
        return "number"
    return type(instance).__name__


if __name__ == "__main__":
    raise SystemExit(main())
