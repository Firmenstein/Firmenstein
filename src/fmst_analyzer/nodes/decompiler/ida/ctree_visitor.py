"""Extract callsite and simple variable semantics from one CTree snapshot."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Pattern, Tuple

import idapro  # Initialize native bindings at the backend boundary.
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_bytes
import idaapi
import ida_domain
import idc
import idautils
from ida_domain.pseudocode import PseudocodeFunction
from loguru import logger

from ...callsite import ArgInfo, ArgType, CallSite
from ...semantic import (
    SEMANTIC_SNAPSHOT_SCHEMA_VERSION,
    SEMANTIC_RENDERER_VERSION,
    CTreeLocation,
    CallsiteArgInfo,
    CallsiteInfo,
    CallsiteReturnInfo,
    FunctionSemanticSnapshot,
    PropagationTarget,
    VariableCallsiteInfo,
    VariablePropInfo,
)
from .ida_env import require_argument_hints_disabled
from .text_renderer import Replacement, render_line, render_lines


@dataclass
class _VariableBuilder:
    identity: str
    name: str
    is_parameter: bool
    is_global: bool
    declaration_line: int
    param_index: int
    usage_lines: set[int] = field(default_factory=set)
    flows_to: set[PropagationTarget] = field(default_factory=set)
    flows_from: set[PropagationTarget] = field(default_factory=set)
    callsite_args: Dict[tuple, VariableCallsiteInfo] = field(default_factory=dict)
    is_return_value: bool = False
    affects_return_value: bool = False

    def freeze(self) -> VariablePropInfo:
        return VariablePropInfo(
            varname=self.name,
            is_parameter=self.is_parameter,
            is_global=self.is_global,
            is_return_value=self.is_return_value,
            affects_return_value=self.affects_return_value,
            declaration_line=self.declaration_line,
            param_index=self.param_index,
            usage_lines=sorted(self.usage_lines),
            flows_to=sorted(
                self.flows_to,
                key=lambda item: (item.line, item.type, item.name, item.code),
            ),
            flows_from=sorted(
                self.flows_from,
                key=lambda item: (item.line, item.type, item.name, item.code),
            ),
            callsite_args=sorted(
                self.callsite_args.values(),
                key=lambda item: (
                    item.line, item.column, item.callee, item.arg_index,
                    tuple(item.args),
                ),
            ),
            identity=self.identity,
        )


class CTreeVisitor(ida_hexrays.ctree_visitor_t):
    """One-pass collector bound to a single ``PseudocodeFunction``.

    Final rendering happens after traversal because the complete global-name
    set is needed to render both the emitted C and expression snippets using
    exactly the same substitutions.
    """

    def __init__(
        self,
        pseudocode: PseudocodeFunction,
        *,
        binary_name: str,
        binary_identity: str,
        idb_identity: str,
        func_ea: int,
        func_name: str,
    ) -> None:
        # CV_INSNS means "instructions only" in Hex-Rays and would suppress
        # every expression callback, including cot_call.
        super().__init__(ida_hexrays.CV_FAST)
        self.pseudocode = pseudocode
        self.cfunc = pseudocode.raw_cfunc
        self.binary_name = binary_name
        self.binary_identity = binary_identity
        self.idb_identity = idb_identity
        self.func_ea = func_ea
        self.func_name = func_name

        # Argument-name hints would inject "name: " into the text read below,
        # defeating the verbatim expression match and shifting every column.
        self._assert_argument_hints_disabled()

        # Force ctext generation before any coordinate query.
        self._tagged_lines = [
            self.cfunc.get_pseudocode()[i].line
            for i in range(len(self.cfunc.get_pseudocode()))
        ]
        self._raw_lines = [ida_lines.tag_remove(line) for line in self._tagged_lines]

        self._call_exprs: Dict[int, ida_hexrays.cexpr_t] = {}
        self._assignments: List[ida_hexrays.cexpr_t] = []
        self._returns: List[ida_hexrays.cinsn_t] = []
        self._variable_exprs: List[ida_hexrays.cexpr_t] = []
        self._global_vars: Dict[int, str] = {}
        self._variables: Dict[str, _VariableBuilder] = {}
        self._callee_addrs: set[int] = set()
        self._callsites: Dict[int, CallSite] = {}
        self._linenum_to_callsites: Dict[int, List[CallSite]] = {}
        self._snapshot: Optional[FunctionSemanticSnapshot] = None

        self._init_local_variables()

    @staticmethod
    def _assert_argument_hints_disabled() -> None:
        """Reject a renderer configuration that would corrupt our coordinates.

        ``expression_text``/``column_number`` are derived by matching an
        expression against the rendered line, so the pseudocode text has to be
        the one Firmenstein asked for.  See ``ida_env``.
        """
        require_argument_hints_disabled()

    def _init_local_variables(self) -> None:
        arguments = list(self.pseudocode.arguments)
        argument_indices = {
            variable.name: position
            for position, variable in enumerate(arguments, start=1)
        }
        for index, variable in enumerate(self.pseudocode.local_variables):
            name = variable.name or f"lvar_{index}"
            is_parameter = bool(variable.is_arg)
            self._variables[f"lvar:{index}"] = _VariableBuilder(
                identity=f"lvar:{index}",
                name=name,
                is_parameter=is_parameter,
                is_global=False,
                declaration_line=self._find_declaration_line(
                    name, is_parameter=is_parameter
                ),
                param_index=argument_indices.get(name, -1),
            )

    def _find_declaration_line(self, name: str, *, is_parameter: bool) -> int:
        token = re.compile(rf"\b{re.escape(name)}\b")
        if is_parameter:
            for index, line in enumerate(self._raw_lines, start=1):
                if token.search(line):
                    return index
                if "{" in line:
                    break
            return -1

        declaration = re.compile(
            rf"^\s*[A-Za-z_][\w\s:*]*\b{re.escape(name)}\b"
            rf"(?:\s*\[[^]]+\])?(?:\s*[,;=])"
        )
        for index, line in enumerate(self._raw_lines, start=1):
            if declaration.search(line):
                return index
        return -1

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        if expr.op == ida_hexrays.cot_call:
            if expr.index in self._call_exprs:
                raise RuntimeError(
                    f"Duplicate CTree call index {expr.index} in {self.func_name}"
                )
            self._call_exprs[int(expr.index)] = expr
        if ida_hexrays.is_assignment(expr.op):
            self._assignments.append(expr)
        if expr.op in (ida_hexrays.cot_var, ida_hexrays.cot_obj):
            identity = self._variable_identity(expr)
            if identity is not None:
                self._variable_exprs.append(expr)
                line, _ = self._coords(expr)
                if line > 0:
                    self._variables[identity].usage_lines.add(line)
        return 0

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        if insn.op == ida_hexrays.cit_return:
            self._returns.append(insn)
        return 0

    def finalize(
        self, type_replacements: Iterable[tuple[Pattern[str], str]]
    ) -> FunctionSemanticSnapshot:
        replacements: List[Replacement] = list(type_replacements)
        for original, rendered in sorted(self._global_name_replacements().items()):
            if original != rendered:
                replacements.append(
                    (re.compile(rf"\b{re.escape(original)}\b"), rendered)
                )
        replacements.append((re.compile(r"\b__noreturn\b"), ""))

        rendered_lines = render_lines(self._raw_lines, replacements)
        if len(rendered_lines) != len(self._raw_lines):
            raise RuntimeError("Pseudocode renderer changed the line count")
        rendered_code = "\n".join(line.text for line in rendered_lines)

        raw_hash = hashlib.sha256(
            "\n".join(self._raw_lines).encode("utf-8")
        ).hexdigest()
        structural = "\n".join(
            f"{expr.index}:{expr.op}:{int(expr.ea)}"
            for expr in sorted(
                self._call_exprs.values(), key=lambda item: item.index
            )
        )
        snapshot_hash = hashlib.sha256(
            (raw_hash + "\n" + structural).encode("utf-8")
        ).hexdigest()

        return_receivers = self._collect_return_receivers(replacements)
        direct_returns = self._collect_direct_return_calls()
        semantic_callsites: Dict[int, CallsiteInfo] = {}
        function_chunks = sorted(idautils.Chunks(self.func_ea))

        for ctree_index, expr in sorted(self._call_exprs.items()):
            ida_line, ida_column = self._coords(expr)
            if ida_line <= 0 or ida_column < 0:
                raise RuntimeError(
                    f"Visible call CTree item {ctree_index} in {self.func_name} "
                    "has no pseudocode coordinates"
                )
            raw_expression = expr.dstr()
            display_line, expression_column = self._expression_start_coordinate(
                raw_expression, ida_line, ida_column
            )
            rendered_column = rendered_lines[display_line - 1].rendered_column(
                expression_column
            )
            callee_name, callee_ea, call_kind = self._callee(expr)
            expression_text = self._render_expr(expr, replacements)
            source_ea = (
                None if int(expr.ea) == int(ida_idaapi.BADADDR)
                else int(expr.ea)
            )
            source_in_function = source_ea is not None and any(
                start <= source_ea < end for start, end in function_chunks
            )
            if source_ea is not None and not source_in_function:
                if call_kind == "helper":
                    # Hex-Rays helpers such as JUMPOUT encode their jump
                    # destination in ``expr.ea``.  That is not a source
                    # instruction address and must not be presented as one.
                    source_ea = None
                else:
                    raise RuntimeError(
                        f"Call CTree item {ctree_index} has source EA "
                        f"0x{source_ea:x} outside all chunks of {self.func_name}"
                    )
            location = CTreeLocation(
                binary_identity=self.binary_identity,
                function_ea=self.func_ea,
                snapshot_hash=snapshot_hash,
                ctree_index=ctree_index,
                opcode=int(expr.op),
                source_ea=source_ea,
                ida_line=ida_line,
                ida_column=ida_column,
                line_number=display_line,
                column_number=rendered_column,
                expression_text=expression_text,
            )
            arguments = [
                self._classify_argument(index, arg, replacements)
                for index, arg in enumerate(expr.a, start=1)
            ]
            return_info = return_receivers.get(ctree_index)
            if return_info is None and ctree_index in direct_returns:
                return_info = CallsiteReturnInfo(
                    label="IDENTIFIER", code="DIRECT_RET", name="DIRECT_RET"
                )
            info = CallsiteInfo(
                line_number=display_line,
                column_number=rendered_column,
                arguments=arguments,
                return_info=return_info,
                ctree_index=ctree_index,
                callee_name=callee_name,
                callee_ea=callee_ea,
                call_kind=call_kind,
                location=location,
            )
            semantic_callsites[ctree_index] = info
            self._add_callsite_argument_uses(expr, info, replacements)
            self._callsites[ctree_index] = self._make_callsite(info, expr)
            if callee_ea is not None:
                self._callee_addrs.add(callee_ea)

        self._collect_assignment_flows(replacements)
        self._collect_return_variables()

        frozen_variables: Dict[str, List[VariablePropInfo]] = {}
        for builder in self._variables.values():
            frozen_variables.setdefault(builder.name, []).append(builder.freeze())
        for records in frozen_variables.values():
            records.sort(key=lambda item: item.identity)

        rendered_hash = hashlib.sha256(rendered_code.encode("utf-8")).hexdigest()
        self._snapshot = FunctionSemanticSnapshot(
            schema_version=SEMANTIC_SNAPSHOT_SCHEMA_VERSION,
            renderer_version=SEMANTIC_RENDERER_VERSION,
            ida_version=str(idaapi.get_kernel_version()),
            ida_domain_version=str(ida_domain.__version__),
            binary_identity=self.binary_identity,
            idb_identity=self.idb_identity,
            function_ea=self.func_ea,
            snapshot_hash=snapshot_hash,
            raw_pseudocode_hash=raw_hash,
            raw_code="\n".join(self._raw_lines),
            rendered_code_hash=rendered_hash,
            rendered_code=rendered_code,
            callsites=semantic_callsites,
            variables=frozen_variables,
        )
        self._linenum_to_callsites = {}
        for callsite in self._callsites.values():
            self._linenum_to_callsites.setdefault(
                callsite.line_number, []
            ).append(callsite)
        for callsites in self._linenum_to_callsites.values():
            callsites.sort(key=lambda item: (item.column_number, item.ctree_index))
        return self._snapshot

    def _coords(self, item) -> Tuple[int, int]:
        x, y = self.cfunc.find_item_coords(item)
        if x is None or y is None or x < 0 or y < 0:
            return -1, -1
        if y >= len(self._tagged_lines):
            raise RuntimeError(
                f"CTree coordinate line {y} outside pseudocode for {self.func_name}"
            )
        if self._reverse_mapped_index(x, y) == int(item.index):
            return y + 1, x

        recovered = self._find_reverse_mappable_coords(item)
        if recovered is not None:
            recovered_x, recovered_y = recovered
            return recovered_y + 1, recovered_x

        mapped_index = self._reverse_mapped_index(x, y)
        raise RuntimeError(
            f"CTree reverse mapping mismatch in {self.func_name}: "
            f"expected {item.index}, got {mapped_index} at ({y + 1}, {x})"
        )

    def _reverse_mapped_index(self, x: int, y: int) -> Optional[int]:
        if y < 0 or y >= len(self._tagged_lines) or x < 0:
            return None
        current = ida_hexrays.ctree_item_t()
        ok = self.cfunc.get_line_item(
            self._tagged_lines[y],
            x,
            y >= int(self.cfunc.hdrlines),
            None,
            current,
            None,
        )
        if not ok or not current.is_citem():
            return None
        mapped = current.e if current.citype == ida_hexrays.VDI_EXPR else current.i
        return int(mapped.index) if mapped is not None else None

    def _find_reverse_mappable_coords(self, item) -> Optional[Tuple[int, int]]:
        """Recover IDA's clickable coordinate for a wrapped CTree item.

        ``find_item_coords`` occasionally points at the preceding physical
        line for a call split by a ternary or other multiline expression.
        Recovery is accepted only when ``get_line_item`` maps a visible
        character back to the exact same CTree index.
        """
        expression = item.dstr()
        needles = [expression]
        if getattr(item, "op", None) == ida_hexrays.cot_call:
            callee_text, separator, _ = expression.partition("(")
            callee_text = callee_text.rstrip()
            if separator and callee_text and callee_text not in needles:
                needles.append(callee_text)

        for needle in needles:
            if not needle:
                continue
            for y, line in enumerate(self._raw_lines):
                offset = 0
                while True:
                    start = line.find(needle, offset)
                    if start < 0:
                        break
                    # IDA may attach the call item to the opening parenthesis,
                    # while the callee token maps to its child cot_obj item.
                    end = min(len(line), start + len(needle) + 1)
                    for x in range(start, end):
                        if self._reverse_mapped_index(x, y) == int(item.index):
                            return x, y
                    offset = start + 1
        return None

    def _expression_start_column(
        self, line: str, expression: str, ida_anchor: int
    ) -> int:
        """Locate the full expression containing IDA's clickable anchor.

        ``find_item_coords`` commonly anchors a call on its opening
        parenthesis rather than the callee token.  The raw IDA coordinate is
        retained for ``get_line_item`` round-tripping, while emitted-source
        coordinates point at the beginning of the complete expression.
        """
        starts: List[int] = []
        offset = 0
        while True:
            start = line.find(expression, offset)
            if start < 0:
                break
            starts.append(start)
            offset = start + 1
        containing = [
            start for start in starts
            if start <= ida_anchor < start + len(expression)
        ]
        if len(containing) == 1:
            return containing[0]
        if starts:
            return min(starts, key=lambda start: abs(start - ida_anchor))

        # A long call may be rendered across multiple pseudocode lines while
        # ``dstr()`` returns the complete one-line expression.  The first
        # line still contains the callee token and IDA anchors the CTree item
        # on its opening parenthesis.
        callee_text, separator, _ = expression.partition("(")
        callee_text = callee_text.rstrip()
        if separator and callee_text:
            callee_starts: List[int] = []
            offset = 0
            while True:
                start = line.find(callee_text, offset)
                if start < 0:
                    break
                callee_starts.append(start)
                offset = start + 1
            if callee_starts:
                return min(
                    callee_starts,
                    key=lambda start: abs(
                        start + len(callee_text) - ida_anchor
                    ),
                )

        # A casted function-pointer call starts with parentheses, so splitting
        # at the first ``("" does not yield a useful callee token.  For any
        # wrapped call, find the longest exact prefix of dstr() visible on the
        # anchor line.  The anchor itself has already been round-tripped to the
        # same CTree index by _coords(), which prevents a textual near-match
        # from becoming an object identity.
        prefix_candidates: List[Tuple[int, int]] = []
        for start in range(len(line)):
            if line[start] != expression[0]:
                continue
            length = 0
            while (
                start + length < len(line)
                and length < len(expression)
                and line[start + length] == expression[length]
            ):
                length += 1
            if (
                length >= min(4, len(expression))
                and start <= ida_anchor <= start + length
            ):
                prefix_candidates.append((length, start))
        if prefix_candidates:
            _, start = max(prefix_candidates)
            return start
        # The entire prefix may live on an earlier physical line (notably for
        # casted function-pointer calls wrapped inside a ternary expression).
        # ``_coords()`` has already proven that this visible anchor maps back
        # to the exact CTree index, so retaining that anchor is a sound source
        # coordinate even though it is not the textual start of ``dstr()``.
        if 0 <= ida_anchor < len(line):
            return ida_anchor
        raise RuntimeError(
            f"Cannot locate CTree expression {expression!r} on line "
            f"{line!r} in {self.func_name}"
        )

    def _expression_start_coordinate(
        self, expression: str, ida_line: int, ida_anchor: int
    ) -> Tuple[int, int]:
        """Map a CTree anchor to the first visible line of its call.

        IDA may attach a long string-concatenation call to a continuation line.
        The raw IDA coordinate remains authoritative in ``ida_line`` while the
        published C coordinate should point at the visible callee on the nearest
        preceding line.
        """
        callee_text, separator, _ = expression.partition("(")
        callee_text = callee_text.rstrip()
        current_line = self._raw_lines[ida_line - 1]
        current_column = self._expression_start_column(
            current_line, expression, ida_anchor
        )
        if (
            current_line[current_column:].startswith(expression)
            or (
                separator
                and callee_text
                and current_line[current_column:].startswith(f"{callee_text}(")
            )
        ):
            return ida_line, current_column
        if separator and callee_text:
            for line_index in range(ida_line - 2, -1, -1):
                start = self._raw_lines[line_index].find(callee_text)
                if start >= 0:
                    return line_index + 1, start
        return ida_line, current_column

    def _global_name_replacements(self) -> Dict[str, str]:
        return {
            original: (
                original if original.startswith("GVar_") else f"GVar_{original}"
            )
            for original in self._global_vars.values()
        }

    def _variable_identity(self, expr) -> Optional[str]:
        if expr.op == ida_hexrays.cot_var:
            identity = f"lvar:{int(expr.v.idx)}"
            if identity not in self._variables:
                name = f"lvar_{int(expr.v.idx)}"
                self._variables[identity] = _VariableBuilder(
                    identity=identity,
                    name=name,
                    is_parameter=False,
                    is_global=False,
                    declaration_line=-1,
                    param_index=-1,
                )
            return identity
        if expr.op != ida_hexrays.cot_obj:
            return None
        if self._is_string_literal_object(expr):
            return None
        obj_ea = int(expr.obj_ea)
        if idaapi.get_func(obj_ea) is not None:
            return None
        database_name = idc.get_name(obj_ea)
        displayed_name = ida_lines.tag_remove(expr.dstr()).strip()
        if displayed_name.startswith("::"):
            displayed_name = displayed_name[2:]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", displayed_name):
            displayed_name = database_name
        if not displayed_name:
            return None
        # ``idc.get_name()`` may retain IDB punctuation or leading
        # underscores that Hex-Rays normalizes in pseudocode.  Variable
        # queries and the emitted C file must use the exact same display
        # spelling, while the EA remains the internal identity.
        self._global_vars[obj_ea] = displayed_name
        name = (
            displayed_name
            if displayed_name.startswith("GVar_")
            else f"GVar_{displayed_name}"
        )
        identity = f"global:0x{obj_ea:x}"
        self._variables.setdefault(
            identity,
            _VariableBuilder(
                identity=identity,
                name=name,
                is_parameter=False,
                is_global=True,
                declaration_line=-1,
                param_index=-1,
            ),
        )
        return identity

    def _simple_variable(self, expr) -> Optional[_VariableBuilder]:
        unwrapped = self._unwrap_casts(expr)
        identity = self._variable_identity(unwrapped)
        return self._variables.get(identity) if identity is not None else None

    @staticmethod
    def _is_string_literal_object(expr) -> bool:
        if expr is None or expr.op != ida_hexrays.cot_obj:
            return False
        return ida_bytes.is_strlit(ida_bytes.get_flags(int(expr.obj_ea)))

    @staticmethod
    def _unwrap_casts(expr):
        while expr is not None and expr.op == ida_hexrays.cot_cast:
            expr = expr.x
        return expr

    def _callee(self, expr) -> tuple[str, Optional[int], str]:
        callee = expr.x
        if callee.op == ida_hexrays.cot_obj:
            ea = int(callee.obj_ea)
            target_function = ida_funcs.get_func(ea)
            name = ida_funcs.get_func_name(ea) if target_function else ""
            if target_function is not None and name:
                return name, ea, "direct"
        if callee.op == ida_hexrays.cot_helper:
            return str(callee.helper), None, "helper"
        return f"indirect_call_ctree_{int(expr.index)}", None, "indirect"

    def _render_expr(self, expr, replacements: List[Replacement]) -> str:
        return render_line(expr.dstr(), replacements).text

    def _classify_argument(
        self, index: int, expr, replacements: List[Replacement]
    ) -> CallsiteArgInfo:
        unwrapped = self._unwrap_casts(expr)
        code = self._render_expr(expr, replacements)
        uncast_code = re.sub(r"^(?:\([^()]*\)\s*)+", "", code).lstrip()
        if (
            unwrapped.op in (
                ida_hexrays.cot_num,
                ida_hexrays.cot_fnum,
                ida_hexrays.cot_str,
            )
            or self._is_string_literal_object(unwrapped)
            or (
                len(uncast_code) >= 2
                and uncast_code[0] in {'"', "'"}
                and uncast_code[-1] == uncast_code[0]
            )
        ):
            return CallsiteArgInfo(index, "LITERAL", code, "")
        variable = self._simple_variable(unwrapped)
        if variable is not None:
            label = "GLOBAL" if variable.is_global else "LOCAL"
            return CallsiteArgInfo(index, label, code, variable.name)
        if unwrapped.op == ida_hexrays.cot_call:
            name, _, _ = self._callee(unwrapped)
            return CallsiteArgInfo(index, "CALL", code, name)
        return CallsiteArgInfo(index, "OTHER", code, "")

    def _classify_propagation(
        self, expr, line: int, replacements: List[Replacement]
    ) -> PropagationTarget:
        unwrapped = self._unwrap_casts(expr)
        code = self._render_expr(expr, replacements)
        uncast_code = re.sub(r"^(?:\([^()]*\)\s*)+", "", code).lstrip()
        variable = self._simple_variable(unwrapped)
        if variable is not None:
            return PropagationTarget(code, variable.name, "IDENTIFIER", line)
        if (
            unwrapped.op == ida_hexrays.cot_str
            or self._is_string_literal_object(unwrapped)
            or (
                len(uncast_code) >= 2
                and uncast_code[0] in {'"', "'"}
                and uncast_code[-1] == uncast_code[0]
            )
        ):
            return PropagationTarget(code, "", "LITERAL_STRING", line)
        if unwrapped.op in (ida_hexrays.cot_num, ida_hexrays.cot_fnum):
            return PropagationTarget(code, "", "LITERAL_NUMBER", line)
        if unwrapped.op == ida_hexrays.cot_call:
            name, _, _ = self._callee(unwrapped)
            return PropagationTarget(code, name, "CALL", line)
        return PropagationTarget(code, "", "EXPR", line)

    def _collect_return_receivers(
        self, replacements: List[Replacement]
    ) -> Dict[int, CallsiteReturnInfo]:
        result: Dict[int, CallsiteReturnInfo] = {}
        for assignment in self._assignments:
            if assignment.op != ida_hexrays.cot_asg:
                continue
            rhs = self._unwrap_casts(assignment.y)
            if rhs is None or rhs.op != ida_hexrays.cot_call:
                continue
            lhs = self._simple_variable(assignment.x)
            lhs_code = self._render_expr(assignment.x, replacements)
            result[int(rhs.index)] = CallsiteReturnInfo(
                label="IDENTIFIER" if lhs is not None else "EXPR",
                code=lhs_code,
                name=lhs.name if lhs is not None else "",
            )
        return result

    def _collect_direct_return_calls(self) -> set[int]:
        result: set[int] = set()
        for instruction in self._returns:
            expression = instruction.creturn.expr
            expression = self._unwrap_casts(expression)
            if expression is not None and expression.op == ida_hexrays.cot_call:
                result.add(int(expression.index))
        return result

    def _collect_assignment_flows(
        self, replacements: List[Replacement]
    ) -> None:
        for assignment in self._assignments:
            if assignment.op != ida_hexrays.cot_asg:
                continue
            line, _ = self._coords(assignment)
            lhs = self._simple_variable(assignment.x)
            rhs = self._simple_variable(assignment.y)
            if lhs is not None:
                lhs.flows_from.add(
                    self._classify_propagation(
                        assignment.y, line, replacements
                    )
                )
            if rhs is not None:
                rhs.flows_to.add(
                    self._classify_propagation(
                        assignment.x, line, replacements
                    )
                )

    def _collect_return_variables(self) -> None:
        for instruction in self._returns:
            expression = instruction.creturn.expr
            if expression is None:
                continue
            identities = {
                identity
                for item in self._walk_expression(expression)
                if (identity := self._variable_identity(item)) is not None
            }
            for identity in identities:
                self._variables[identity].affects_return_value = True
            direct = self._simple_variable(expression)
            if direct is not None:
                direct.is_return_value = True

    def _add_callsite_argument_uses(
        self,
        call_expr,
        callsite: CallsiteInfo,
        replacements: List[Replacement],
    ) -> None:
        all_args = [
            self._render_expr(argument, replacements)
            for argument in call_expr.a
        ]
        for arg_index, argument in enumerate(call_expr.a, start=1):
            identities = {
                identity
                for item in self._walk_expression(argument)
                if (identity := self._variable_identity(item)) is not None
            }
            for identity in identities:
                record = VariableCallsiteInfo(
                    line=callsite.line_number,
                    column=callsite.column_number,
                    callee=callsite.callee_name,
                    args=list(all_args),
                    arg_index=arg_index,
                )
                key = (
                    record.line, record.column, record.callee,
                    tuple(record.args), record.arg_index,
                )
                self._variables[identity].callsite_args[key] = record

    def _walk_expression(self, expr) -> Iterator:
        yield expr
        if ida_hexrays.op_uses_x(expr.op):
            yield from self._walk_expression(expr.x)
        if ida_hexrays.op_uses_y(expr.op):
            yield from self._walk_expression(expr.y)
        if ida_hexrays.op_uses_z(expr.op):
            yield from self._walk_expression(expr.z)
        if expr.op == ida_hexrays.cot_call:
            for argument in expr.a:
                yield from self._walk_expression(argument)

    def _make_callsite(self, info: CallsiteInfo, expr) -> CallSite:
        location = info.location
        assert location is not None
        callsite = CallSite(
            binary_name=self.binary_name,
            caller_ea=self.func_ea,
            caller_name=self.func_name,
            callee_ea=info.callee_ea or 0,
            callee_name=info.callee_name,
            callsite_ea=(
                location.source_ea
                if location.source_ea is not None
                else int(ida_idaapi.BADADDR)
            ),
            line_number=info.line_number,
            column_number=info.column_number,
            is_indirect=info.call_kind == "indirect",
            binary_identity=self.binary_identity,
            snapshot_hash=location.snapshot_hash,
            ctree_index=location.ctree_index,
            opcode=location.opcode,
            source_ea=location.source_ea,
            ida_line=location.ida_line,
            ida_column=location.ida_column,
            expression_text=location.expression_text,
            call_kind=info.call_kind,
        )
        args: List[ArgInfo] = []
        for argument in info.arguments:
            if argument.label in ("LOCAL", "GLOBAL"):
                arg_type = (
                    ArgType.GLOBAL if argument.label == "GLOBAL" else ArgType.LOCAL
                )
                value = argument.name
            elif argument.label == "LITERAL":
                arg_type, value = ArgType.LITERAL, argument.code
            elif argument.label == "CALL":
                arg_type, value = ArgType.CALL, argument.code
            else:
                arg_type, value = ArgType.OTHER, argument.code
            args.append(ArgInfo(argument.arg_index, value, arg_type))
        callsite.set_arguments(args)
        if (
            info.return_info is not None
            and info.return_info.label == "IDENTIFIER"
        ):
            return_type = (
                ArgType.GLOBAL
                if info.return_info.name.startswith("GVar_")
                else ArgType.LOCAL
            )
            callsite.set_return_var(
                ArgInfo(-1, info.return_info.name, return_type)
            )
        callsite.is_populated = True
        return callsite

    def get_callsites(self) -> Dict[int, CallSite]:
        return self._callsites

    def build_linenum_to_callsites(self) -> Dict[int, List[CallSite]]:
        return self._linenum_to_callsites

    def get_callee_addrs(self) -> set[int]:
        return self._callee_addrs

    def get_global_vars(self) -> Dict[int, str]:
        return self._global_vars
