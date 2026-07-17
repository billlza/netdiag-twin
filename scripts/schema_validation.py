#!/usr/bin/env python3
"""Bounded, value-redacting JSON Schema validation diagnostics."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
from typing import Any


SCHEMA_ERROR_DETAIL_LIMIT = 100


def _schema_path(error: Any) -> str:
    components = getattr(error, "absolute_schema_path", ())
    rendered: list[str] = ["#"]
    for component in components:
        if isinstance(component, int):
            rendered.append(f"/{component}")
        elif isinstance(component, str):
            safe = component.replace("~", "~0").replace("/", "~1")
            rendered.append(f"/{safe}")
        else:
            rendered.append("/<component>")
    return "".join(rendered)


def _format_error(error: Any) -> str:
    validator = getattr(error, "validator", None)
    rule = validator if isinstance(validator, str) and validator else "unknown"
    return f"{_schema_path(error)}: schema rule {rule} failed"


def bounded_validation_errors(
    errors: Iterable[Any], *, detail_limit: int = SCHEMA_ERROR_DETAIL_LIMIT
) -> list[str]:
    """Return deterministic diagnostics without materializing an unbounded stream."""
    if isinstance(detail_limit, bool) or not isinstance(detail_limit, int) or detail_limit <= 0:
        raise ValueError("detail_limit must be a positive integer")

    sampled = list(islice(errors, detail_limit + 1))
    truncated = len(sampled) > detail_limit
    sampled = sampled[:detail_limit]
    details = sorted(_format_error(error) for error in sampled)
    if truncated:
        details.append(
            f"additional schema validation errors omitted after {detail_limit} details"
        )
    return details
