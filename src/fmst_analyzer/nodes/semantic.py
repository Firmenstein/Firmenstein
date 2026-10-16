"""Serializable semantic records extracted from one Hex-Rays CTree snapshot.

These records deliberately contain no IDA runtime objects.  They are stored in
the per-binary graph cache and provide the two structural queries previously
required by production analysis: callsite argument collection and simple intra-procedural
assignment propagation.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional


SEMANTIC_SNAPSHOT_SCHEMA_VERSION = 4
SEMANTIC_RENDERER_VERSION = 1
SUPPORTED_IDA_DOMAIN_VERSION = "0.5.0"


@dataclass(frozen=True)
class CTreeLocation:
    binary_identity: str
    function_ea: int
    snapshot_hash: str
    ctree_index: int
    opcode: int
    source_ea: Optional[int]
    ida_line: int
    ida_column: int
    line_number: int
    column_number: int
    expression_text: str


@dataclass(frozen=True)
class CallsiteArgInfo:
    arg_index: int
    label: str
    code: str
    name: str


@dataclass(frozen=True)
class CallsiteReturnInfo:
    label: str
    code: str
    name: str


@dataclass
class CallsiteInfo:
    line_number: int
    column_number: int
    arguments: List[CallsiteArgInfo] = field(default_factory=list)
    return_info: Optional[CallsiteReturnInfo] = None
    ctree_index: int = -1
    callee_name: str = ""
    callee_ea: Optional[int] = None
    call_kind: str = "direct"
    location: Optional[CTreeLocation] = None


@dataclass(frozen=True)
class PropagationTarget:
    code: str
    name: str
    type: str
    line: int


@dataclass(frozen=True)
class VariableCallsiteInfo:
    line: int
    column: int
    callee: str
    args: List[str]
    arg_index: int


@dataclass
class VariablePropInfo:
    varname: str
    is_parameter: bool
    is_global: bool
    is_return_value: bool
    affects_return_value: bool
    declaration_line: int
    param_index: int
    usage_lines: List[int]
    flows_to: List[PropagationTarget]
    flows_from: List[PropagationTarget]
    callsite_args: List[VariableCallsiteInfo]
    identity: str = ""


@dataclass
class VariablePropResult:
    func_name: str
    initial_var: str
    variables: List[VariablePropInfo]


@dataclass
class FunctionSemanticSnapshot:
    """Pure-Python result of exactly one finalized decompilation."""

    schema_version: int
    renderer_version: int
    ida_version: str
    ida_domain_version: str
    binary_identity: str
    idb_identity: str
    function_ea: int
    snapshot_hash: str
    raw_pseudocode_hash: str
    raw_code: str
    rendered_code_hash: str
    rendered_code: str
    callsites: Dict[int, CallsiteInfo]
    variables: Dict[str, List[VariablePropInfo]]

    def integrity_errors(self) -> List[str]:
        """Return all pure-data invariant violations in this snapshot."""
        errors: List[str] = []
        raw_lines = self.raw_code.splitlines()
        rendered_lines = self.rendered_code.splitlines()
        if len(raw_lines) != len(rendered_lines):
            errors.append(
                f"line count drift: raw={len(raw_lines)}, "
                f"rendered={len(rendered_lines)}"
            )

        for key, info in sorted(self.callsites.items()):
            location = info.location
            if location is None:
                errors.append(f"call {key}: missing CTree location")
                continue
            if key != info.ctree_index or key != location.ctree_index:
                errors.append(f"call {key}: inconsistent CTree index")
            if location.binary_identity != self.binary_identity:
                errors.append(f"call {key}: binary identity mismatch")
            if location.function_ea != self.function_ea:
                errors.append(f"call {key}: function EA mismatch")
            if location.snapshot_hash != self.snapshot_hash:
                errors.append(f"call {key}: snapshot hash mismatch")
            if (info.line_number, info.column_number) != (
                location.line_number,
                location.column_number,
            ):
                errors.append(f"call {key}: display coordinate mismatch")
            if not (1 <= location.ida_line <= len(raw_lines)):
                errors.append(f"call {key}: IDA line outside pseudocode")
            elif not (0 <= location.ida_column <= len(raw_lines[location.ida_line - 1])):
                errors.append(f"call {key}: IDA column outside pseudocode")
            if not (1 <= location.line_number <= len(rendered_lines)):
                errors.append(f"call {key}: rendered line outside C output")
            else:
                line = rendered_lines[location.line_number - 1]
                column = location.column_number
                if not (0 <= column <= len(line)):
                    errors.append(f"call {key}: rendered column outside C output")
                else:
                    expression = location.expression_text
                    exact = line[column:column + len(expression)] == expression
                    visible_prefix = line[column:].rstrip()
                    call_head, separator, _ = expression.partition("(")
                    visible_call_head = (
                        bool(separator and call_head)
                        and line[column:].startswith(f"{call_head}(")
                    )
                    if not exact and (
                        not visible_prefix
                        or not expression.startswith(visible_prefix)
                    ) and not visible_call_head:
                        errors.append(
                            f"call {key}: rendered coordinate does not point "
                            f"at {expression!r}"
                        )
            expected_args = list(range(1, len(info.arguments) + 1))
            actual_args = [argument.arg_index for argument in info.arguments]
            if actual_args != expected_args:
                errors.append(
                    f"call {key}: argument indexes {actual_args}, "
                    f"expected {expected_args}"
                )
            if info.call_kind == "direct" and info.callee_ea is None:
                errors.append(f"call {key}: direct call has no callee EA")
            if info.call_kind in {"helper", "indirect"} and info.callee_ea is not None:
                errors.append(
                    f"call {key}: {info.call_kind} call has a direct callee EA"
                )
            if info.call_kind not in {"direct", "helper", "indirect"}:
                errors.append(f"call {key}: unknown call kind {info.call_kind!r}")

        variable_identities: set[str] = set()
        for display_name, records in sorted(self.variables.items()):
            for record in records:
                if record.varname != display_name:
                    errors.append(
                        f"variable {record.identity}: display-name mismatch"
                    )
                if record.identity in variable_identities:
                    errors.append(
                        f"variable {record.identity}: duplicate identity"
                    )
                variable_identities.add(record.identity)
                line_values = [
                    *record.usage_lines,
                    *(edge.line for edge in record.flows_to),
                    *(edge.line for edge in record.flows_from),
                    *(use.line for use in record.callsite_args),
                ]
                if record.declaration_line != -1:
                    line_values.append(record.declaration_line)
                for line_number in line_values:
                    if not (1 <= line_number <= len(rendered_lines)):
                        errors.append(
                            f"variable {record.identity}: line {line_number} "
                            "outside C output"
                        )
        return errors

    @property
    def is_current(self) -> bool:
        return (
            getattr(self, "schema_version", 0)
            == SEMANTIC_SNAPSHOT_SCHEMA_VERSION
            and getattr(self, "renderer_version", 0)
            == SEMANTIC_RENDERER_VERSION
            and getattr(self, "ida_domain_version", None)
            == SUPPORTED_IDA_DOMAIN_VERSION
        )

    def trace_variable_prop(
        self, func_name: str, initial_var: str
    ) -> VariablePropResult:
        """Return the identifier-connected component around ``initial_var``.

        ``flows_to`` and ``flows_from`` remain direct relationships.  The
        worklist only decides which variable records belong in the result.
        """
        initial = self._unique_variable(initial_var)
        queue = deque([initial.varname])
        seen: set[str] = set()
        result: List[VariablePropInfo] = []

        while queue:
            name = queue.popleft()
            if name in seen:
                continue
            record = self._unique_variable(name)
            seen.add(name)
            result.append(record)
            for edge in (*record.flows_to, *record.flows_from):
                if edge.type == "IDENTIFIER" and edge.name not in seen:
                    queue.append(edge.name)

        result.sort(key=lambda item: (item.varname, item.identity))
        return VariablePropResult(
            func_name=func_name,
            initial_var=initial_var,
            variables=result,
        )

    def _unique_variable(self, name: str) -> VariablePropInfo:
        records = self.variables.get(name, [])
        if not records:
            raise KeyError(name)
        if len(records) != 1:
            identities = sorted(record.identity for record in records)
            raise ValueError(
                f"Variable name {name!r} is ambiguous in function "
                f"0x{self.function_ea:x}: {identities}"
            )
        return records[0]
