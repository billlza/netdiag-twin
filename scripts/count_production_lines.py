#!/usr/bin/env python3
"""Count Rust source lines while excluding ``#[cfg(test)] mod tests`` modules."""

from __future__ import annotations

import re
import sys
from pathlib import Path


CFG_TEST_ATTRIBUTE = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
TEST_MODULE = re.compile(r"mod\s+tests\b")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _raise_unterminated(source: str, offset: int, token: str) -> None:
    raise ValueError(
        f"unterminated {token} starting on line {_line_number(source, offset)}"
    )


def _raw_string_end(source: str, start: int) -> int | None:
    """Return the exclusive end of a raw string token starting at ``start``."""

    if source.startswith(("br", "cr"), start):
        marker = start + 2
    elif source.startswith("r", start):
        marker = start + 1
    else:
        return None

    hashes = 0
    while marker + hashes < len(source) and source[marker + hashes] == "#":
        hashes += 1
    quote = marker + hashes
    if quote >= len(source) or source[quote] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    closing = source.find(terminator, quote + 1)
    if closing < 0:
        _raise_unterminated(source, start, "raw string")
    return closing + len(terminator)


def _quoted_string_end(source: str, quote: int) -> int:
    cursor = quote + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
            continue
        if source[cursor] == '"':
            return cursor + 1
        cursor += 1
    _raise_unterminated(source, quote, "string")
    raise AssertionError("unreachable")


def _char_literal_end(source: str, quote: int) -> int | None:
    """Recognize a Rust char literal without mistaking lifetimes for literals."""

    cursor = quote + 1
    if cursor >= len(source) or source[cursor] in "\r\n'":
        return None

    if source[cursor] != "\\":
        cursor += 1
    elif cursor + 1 >= len(source):
        return None
    elif source[cursor + 1] == "x":
        digits = source[cursor + 2 : cursor + 4]
        if len(digits) != 2 or any(digit not in HEX_DIGITS for digit in digits):
            return None
        cursor += 4
    elif source[cursor + 1] == "u" and source.startswith("{", cursor + 2):
        closing = source.find("}", cursor + 3)
        if closing < 0:
            return None
        digits = source[cursor + 3 : closing].replace("_", "")
        if not digits or any(digit not in HEX_DIGITS for digit in digits):
            return None
        cursor = closing + 1
    else:
        cursor += 2

    if cursor < len(source) and source[cursor] == "'":
        return cursor + 1
    return None


def _is_token_boundary(source: str, offset: int) -> bool:
    return offset == 0 or not (source[offset - 1].isalnum() or source[offset - 1] == "_")


def _blank(mask: list[str], start: int, end: int) -> None:
    for offset in range(start, end):
        if mask[offset] not in "\r\n":
            mask[offset] = " "


def mask_rust_non_code(source: str) -> str:
    """Blank Rust comments and literals while preserving offsets and newlines."""

    mask = list(source)
    cursor = 0
    while cursor < len(source):
        if source.startswith("//", cursor):
            end = cursor + 2
            while end < len(source) and source[end] not in "\r\n":
                end += 1
            _blank(mask, cursor, end)
            cursor = end
            continue

        if source.startswith("/*", cursor):
            start = cursor
            depth = 1
            cursor += 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                _raise_unterminated(source, start, "block comment")
            _blank(mask, start, cursor)
            continue

        if _is_token_boundary(source, cursor):
            raw_end = _raw_string_end(source, cursor)
            if raw_end is not None:
                _blank(mask, cursor, raw_end)
                cursor = raw_end
                continue

            if (
                source[cursor] in "bc"
                and cursor + 1 < len(source)
                and source[cursor + 1] == '"'
            ):
                end = _quoted_string_end(source, cursor + 1)
                _blank(mask, cursor, end)
                cursor = end
                continue

            if (
                source[cursor] == "b"
                and cursor + 1 < len(source)
                and source[cursor + 1] == "'"
            ):
                end = _char_literal_end(source, cursor + 1)
                if end is not None:
                    _blank(mask, cursor, end)
                    cursor = end
                    continue

        if source[cursor] == '"':
            end = _quoted_string_end(source, cursor)
            _blank(mask, cursor, end)
            cursor = end
            continue

        if source[cursor] == "'":
            end = _char_literal_end(source, cursor)
            if end is not None:
                _blank(mask, cursor, end)
                cursor = end
                continue

        cursor += 1

    return "".join(mask)


def _skip_whitespace(source: str, offset: int) -> int:
    while offset < len(source) and source[offset].isspace():
        offset += 1
    return offset


def _attribute_end(source: str, offset: int) -> int | None:
    """Return an outer attribute's end, or ``None`` when none starts here."""

    if offset >= len(source) or source[offset] != "#":
        return None
    cursor = _skip_whitespace(source, offset + 1)
    if cursor >= len(source) or source[cursor] != "[":
        return None

    depth = 1
    cursor += 1
    while cursor < len(source) and depth:
        if source[cursor] == "[":
            depth += 1
        elif source[cursor] == "]":
            depth -= 1
        cursor += 1
    if depth:
        raise ValueError(
            "unterminated attribute following #[cfg(test)] "
            f"on line {_line_number(source, offset)}"
        )
    return cursor


def _following_item_start(masked: str, offset: int) -> int:
    cursor = _skip_whitespace(masked, offset)
    while True:
        attribute_end = _attribute_end(masked, cursor)
        if attribute_end is None:
            return cursor
        cursor = _skip_whitespace(masked, attribute_end)


def _inline_module_end(masked: str, opening: int, attribute: int) -> int:
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor + 1
    raise ValueError(
        "unterminated inline #[cfg(test)] mod tests block "
        f"starting on line {_line_number(masked, attribute)}"
    )


def _test_module_ranges(source: str) -> list[tuple[int, int]]:
    masked = mask_rust_non_code(source)
    ranges: list[tuple[int, int]] = []
    cursor = 0
    while match := CFG_TEST_ATTRIBUTE.search(masked, cursor):
        item_start = _following_item_start(masked, match.end())
        module = TEST_MODULE.match(masked, item_start)
        if module is None:
            cursor = match.end()
            continue

        terminator = _skip_whitespace(masked, module.end())
        if terminator >= len(masked):
            raise ValueError(
                "incomplete #[cfg(test)] mod tests declaration "
                f"on line {_line_number(source, match.start())}"
            )
        if masked[terminator] == ";":
            end = terminator + 1
        elif masked[terminator] == "{":
            end = _inline_module_end(masked, terminator, match.start())
        else:
            raise ValueError(
                "expected `;` or `{` after #[cfg(test)] mod tests "
                f"on line {_line_number(source, match.start())}"
            )
        ranges.append((match.start(), end))
        cursor = end
    return ranges


def mask_rust_test_code(source: str) -> str:
    """Blank comments, literals, and ``#[cfg(test)] mod tests`` code."""

    masked = list(mask_rust_non_code(source))
    for start, end in _test_module_ranges(source):
        _blank(masked, start, end)
    return "".join(masked)


def _line_has_only_test_code(
    source: str, start: int, end: int, ranges: list[tuple[int, int]]
) -> bool:
    overlaps: list[tuple[int, int]] = []
    if start == end:
        overlaps = [(left, right) for left, right in ranges if left <= start < right]
    else:
        overlaps = [
            (max(start, left), min(end, right))
            for left, right in ranges
            if left < end and right > start
        ]
    if not overlaps:
        return False

    production_fragments: list[str] = []
    cursor = start
    for left, right in overlaps:
        production_fragments.append(source[cursor:left])
        cursor = max(cursor, right)
    production_fragments.append(source[cursor:end])
    return not "".join(production_fragments).strip()


def count_production_lines(path: Path) -> int:
    source = path.read_text()
    test_ranges = _test_module_ranges(source)
    count = 0
    offset = 0
    for physical_line in source.splitlines(keepends=True):
        content = physical_line.rstrip("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
        content_end = offset + len(content)
        if not _line_has_only_test_code(source, offset, content_end, test_ranges):
            count += 1
        offset += len(physical_line)
    return count


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: count_production_lines.py <rust-source>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        count = count_production_lines(path)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"production line count failed for {path}: {error}", file=sys.stderr)
        return 1
    print(count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
