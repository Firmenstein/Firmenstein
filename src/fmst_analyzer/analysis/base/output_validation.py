"""Source/format failures that an Agent can correct in its current session."""
from __future__ import annotations


class OutputValidationError(ValueError):
    """The submitted result violates a proven representation or source contract.

    Tool, provider and implementation failures must not use this marker.
    """


def validate_code_reference(view, *, binary_name: str, function_name: str,
                            line_number: int) -> str:
    """Read a cited function and check its line bounds, not its interpretation.

    A known function without a published source is an evidence-access failure;
    its FileNotFoundError deliberately propagates rather than blaming the output.
    """
    if view.lib_dep_graph.get_node_by_name(binary_name) is None:
        raise OutputValidationError(f"unknown source binary {binary_name!r}; use the source binary identity returned by the code tools")
    if view.get_function_ea(binary_name, function_name) is None:
        raise OutputValidationError(f"unknown source function {binary_name}::{function_name}; use an exact function identity returned by the code tools")
    try:
        code = view.get_full_code(binary_name, function_name)
    except FileNotFoundError as error:
        # An import identity has no local C body by construction. This is a
        # wrong line locator, unlike failure to read an actual function body.
        if view.is_external_function(binary_name, function_name, resolve_thunk=True):
            raise OutputValidationError(
                f"{binary_name}::{function_name}: line_number={line_number} refers to an "
                "external/import symbol or its native linkage thunk with no local decompiled C body. Cite the "
                "inspected caller or the binary that owns the implementation, using "
                "its exact function identity and local line number. Preserve the "
                "observed behavior; do not invent source lines."
            ) from error
        raise
    lines = code.splitlines()
    if not 1 <= line_number <= len(lines):
        raise OutputValidationError(
            f"{binary_name}::{function_name}: line_number={line_number} is outside 1..{len(lines)}; "
            "read the cited function and use its local line numbers"
        )
    return code
