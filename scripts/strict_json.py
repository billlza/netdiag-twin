#!/usr/bin/env python3
"""Strict JSON decoding for validation and release-evidence boundaries."""

from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_NUMBER_CHARACTERS = 128


class StrictJsonError(ValueError):
    pass


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StrictJsonError("JSON contains a duplicate object key")
        value[key] = item
    return value


def _reject_non_finite_json_constant(_value: str) -> None:
    raise StrictJsonError("JSON contains a non-finite numeric constant")


def _parse_bounded_integer(value: str) -> int:
    _require_bounded_numeric_token(value)
    try:
        return int(value)
    except (ValueError, OverflowError) as error:
        raise StrictJsonError("JSON contains an invalid integer") from error


def _parse_bounded_finite_float(value: str) -> float:
    _require_bounded_numeric_token(value)
    try:
        parsed = float(value)
    except (ValueError, OverflowError) as error:
        raise StrictJsonError("JSON contains an invalid floating-point number") from error
    if not math.isfinite(parsed):
        raise StrictJsonError("JSON contains a non-finite floating-point number")
    return parsed


def _require_bounded_numeric_token(value: str) -> None:
    if len(value) > MAX_JSON_NUMBER_CHARACTERS:
        raise StrictJsonError(
            f"JSON numeric token exceeds the {MAX_JSON_NUMBER_CHARACTERS}-character limit"
        )


def parse_json_strict(text: str, *, source: str) -> Any:
    """Parse standards-compliant JSON without echoing source-controlled values."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_non_finite_json_constant,
            parse_float=_parse_bounded_finite_float,
            parse_int=_parse_bounded_integer,
        )
    except json.JSONDecodeError as error:
        raise StrictJsonError(
            f"{source} is not valid JSON at line {error.lineno}, column {error.colno}"
        ) from error
    except StrictJsonError as error:
        raise StrictJsonError(f"{source} is not valid strict JSON: {error}") from error
    except (ValueError, OverflowError) as error:
        raise StrictJsonError(f"{source} contains an invalid numeric token") from error


def parse_json_bytes_strict(value: bytes, *, source: str) -> Any:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StrictJsonError(f"{source} is not valid UTF-8 JSON") from error
    return parse_json_strict(text, source=source)
