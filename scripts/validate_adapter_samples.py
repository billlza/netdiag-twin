#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from adapter_process import (
    parse_json_strict,
    run_json,
    trusted_rust_ingest_validator,
    validate_rust_ingest,
)
from adapter_quality import validate_declared_measurement_quality
from schema_validation import bounded_validation_errors

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as error:
    raise SystemExit(
        "missing dependency: install jsonschema to validate adapter samples"
    ) from error


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "examples/adapters/schema/netdiag-adapter-payload.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--schema-only",
        action="store_true",
        help="skip Rust ingest validation and only validate JSON schema",
    )
    parser.add_argument(
        "--rust-validator",
        type=Path,
        help="trusted absolute netdiag-cli path built for ingest validation",
    )
    args = parser.parse_args()
    if args.schema_only and args.rust_validator is not None:
        parser.error("--rust-validator cannot be used with --schema-only")
    if not args.schema_only and args.rust_validator is None:
        parser.error("--rust-validator is required unless --schema-only is used")
    rust_validator: Path | None = None
    if args.rust_validator is not None:
        try:
            rust_validator = trusted_rust_ingest_validator(args.rust_validator, ROOT)
        except RuntimeError as error:
            parser.error(str(error))
    schema = parse_json_strict(
        SCHEMA_PATH.read_text(encoding="utf-8"), source="adapter payload schema"
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert_schema_keyword_coverage()
    failed = False

    with tempfile.TemporaryDirectory(prefix="netdiag-adapters-") as tmp:
        tmp_dir = Path(tmp)
        for name, adapter_path in discover_adapters():
            try:
                payload = emit_sample(adapter_path)
                validate_declared_measurement_quality(payload)
            except RuntimeError as error:
                print(f"{name}: {error}", file=sys.stderr)
                failed = True
                continue

            errors = validation_errors(validator, payload)
            if errors:
                failed = True
                print(f"{name}: schema validation failed", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                continue

            if rust_validator is not None:
                sample_path = tmp_dir / f"{name}.json"
                sample_path.write_text(
                    json.dumps(payload, allow_nan=False), encoding="utf-8"
                )
                try:
                    validate_rust_ingest(rust_validator, sample_path, ROOT)
                except RuntimeError as error:
                    failed = True
                    print(f"{name}: Rust ingest validation failed", file=sys.stderr)
                    print(f"  - {error}", file=sys.stderr)
                    continue

            suffix = "schema ok" if args.schema_only else "schema+ingest ok"
            print(f"{name}: {suffix}")

    return 1 if failed else 0


def discover_adapters() -> list[tuple[str, Path]]:
    adapters_dir = ROOT / "examples/adapters"
    adapter_paths = [
        *adapters_dir.glob("*/adapter.py"),
        *adapters_dir.glob("*/exporter.py"),
    ]
    return [(path.parent.name, path) for path in sorted(adapter_paths)]


def emit_sample(adapter_path: Path) -> Any:
    return run_json(adapter_path, ["--emit-sample"])


def validation_errors(validator: Draft202012Validator, instance: Any) -> list[str]:
    return bounded_validation_errors(validator.iter_errors(instance))


def assert_schema_keyword_coverage() -> None:
    cases: list[tuple[str, dict[str, Any], Any]] = [
        ("enum", {"enum": ["ok"]}, "bad"),
        ("format", {"type": "string", "format": "date-time"}, "not-a-timestamp"),
        ("pattern", {"type": "string", "pattern": "^ok$"}, "bad"),
        ("oneOf", {"oneOf": [{"const": "a"}, {"const": "b"}]}, "c"),
        ("anyOf", {"anyOf": [{"const": "a"}, {"const": "b"}]}, "c"),
        ("maximum", {"type": "number", "maximum": 1}, 2),
        ("exclusiveMinimum", {"type": "number", "exclusiveMinimum": 0}, 0),
        (
            "prefixItems",
            {
                "type": "array",
                "prefixItems": [{"type": "string"}, {"type": "integer"}],
                "items": False,
            },
            ["ok", "bad"],
        ),
    ]
    for name, schema, instance in cases:
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        if not list(validator.iter_errors(instance)):
            raise AssertionError(f"schema keyword self-test did not fail for {name}")


if __name__ == "__main__":
    raise SystemExit(main())
