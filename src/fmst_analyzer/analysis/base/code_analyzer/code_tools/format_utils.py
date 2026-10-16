"""
Formatting utilities for code tool output.

Provides consistent formatting for decompiled code snippets returned by
analyzer tools. All tools use these helpers to produce L{num}: prefixed
output with ... gap markers.
"""
from typing import Optional


def format_code_snippet(
    binary_name: str,
    function_name: str,
    code: str,
    start_line: int = 1,
    total_lines: Optional[int] = None,
    header_suffix: str = "",
) -> str:
    """Format a code snippet with line numbers and gap markers.

    Returns a block like::

        === binary::function (120 lines) ===
        L1: int func(int a1) {
          ...
        L45:   target_call();
          ...

    Args:
        binary_name: Binary containing the function.
        function_name: Decompiled function name.
        code: Raw code text (may be full function or partial range).
        start_line: Line number of the first line in *code*.
        total_lines: Total lines in the full function (for trailing ...).
        header_suffix: Extra text appended to the header (e.g. "(120 lines)").
    """
    lines = code.splitlines()
    if not lines:
        header = f"=== {binary_name}::{function_name}{header_suffix} ==="
        return f"{header}\n  (no code)"

    parts: list[str] = []
    if header_suffix:
        parts.append(f"=== {binary_name}::{function_name} {header_suffix} ===")
    else:
        parts.append(f"=== {binary_name}::{function_name} ===")

    prev_num = 0
    for i, line in enumerate(lines):
        num = start_line + i
        if prev_num > 0 and num > prev_num + 1:
            parts.append("  ...")
        parts.append(f"L{num}: {line}")
        prev_num = num

    # Trailing ... if we know there are more lines
    if total_lines and prev_num < total_lines:
        parts.append("  ...")

    return "\n".join(parts)


def merge_line_ranges(
    usage_lines: list[int],
    context: int = 5,
    total_lines: Optional[int] = None,
) -> list[tuple[int, int]]:
    """Merge overlapping (line +/- context) ranges into continuous spans.

    Example::

        usage_lines=[25, 30], context=5
        -> raw ranges [(20,30), (25,35)]
        -> merged [(20, 35)]

    Args:
        usage_lines: Line numbers of usage sites.
        context: Number of lines before/after each site.
        total_lines: Clamp upper bound to this value.

    Returns:
        Sorted list of (start, end) inclusive ranges.
    """
    if not usage_lines:
        return []

    ranges = []
    for line in sorted(usage_lines):
        start = max(1, line - context)
        end = line + context
        if total_lines:
            end = min(end, total_lines)
        ranges.append((start, end))

    # Merge overlapping / adjacent ranges
    merged: list[tuple[int, int]] = [ranges[0]]
    for start, end in ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    return merged


def extract_merged_snippet(
    all_lines: list[str],
    ranges: list[tuple[int, int]],
) -> str:
    """Extract code from merged ranges, joining with ... gaps.

    Args:
        all_lines: Full function code as list of lines (0-indexed).
        ranges: Sorted (start, end) inclusive ranges (1-indexed).

    Returns:
        Code string with L{num}: prefixes and ... for gaps.
    """
    parts: list[str] = []
    prev_end = 0

    for start, end in ranges:
        if prev_end > 0 and start > prev_end + 1:
            parts.append("  ...")
        for num in range(start, end + 1):
            if num - 1 < len(all_lines):
                parts.append(f"L{num}: {all_lines[num - 1]}")
        prev_end = end

    return "\n".join(parts)
