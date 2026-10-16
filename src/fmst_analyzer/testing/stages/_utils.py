"""Shared utilities for testing stages."""
from __future__ import annotations


def format_fail_detail(prefix: str, value: str) -> str:
    """Format a failure detail so the full value stays readable.

    Single-line values render inline. Multi-line / embedded-newline
    values get placed on subsequent lines with 4-space indent so the
    tail of the string is never swallowed. Use this in testing-stage
    issue lists instead of ``f"prefix: {value[:N]}"`` truncation.
    """
    value = (value or "").rstrip()
    if "\n" in value:
        indented = "\n".join("    " + line for line in value.splitlines())
        return f"{prefix}\n{indented}"
    return f"{prefix}{value}"
