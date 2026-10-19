"""Provider-neutral agent facade for firmware code analysis.

Decompiler semantics are available through AnalysisView-bound dynamic tools.
Tasks that also need local artifacts may explicitly receive provider-neutral,
workdir-confined filesystem access and additional read-only roots.

Usage:
    agent = CodeAnalyzerAgent(
        agent_name="MyAgent",
        task_prompt=MY_TASK_PROMPT,
        output_format=MyOutputSchema,
    )
    result = await agent.analyze(
        user_message="Analyze this callsite ...",
        view=view,
        binary_name="httpd",
        function_name="handle_request",
    )
"""
from pathlib import Path
from typing import Callable, Type, Optional, List
from pydantic import BaseModel, ValidationError
from loguru import logger

from fmst_basic.agent.analysis_agent import (
    AgentProviderError,
    FilesystemAccess,
    create_analysis_agent,
)
from fmst_basic.agent.config import DEFAULT_AGENT_PROVIDER
from fmst_basic.agent.skill import AgentSkillSpec
from fmst_basic.agent.trace import AgentTraceHandler

from ..output_validation import OutputValidationError
from .analysis_view import AnalysisView
from .code_tools.analyzer_tools import make_analyzer_tools
from .code_tools.format_utils import format_code_snippet, merge_line_ranges


INITIAL_FULL_FUNCTION_MAX_LINES = 200
INITIAL_FULL_ASSEMBLY_MAX_LINES = 600
INITIAL_FOCUS_CONTEXT_LINES = 5


def _format_initial_function_code(
    binary_name: str,
    function_name: str,
    code: str,
    focus_lines: list[int] | None,
) -> str:
    """Render a complete short function or a coordinate-stable long preview."""
    lines = code.splitlines()
    total_lines = len(lines)
    if total_lines <= INITIAL_FULL_FUNCTION_MAX_LINES or not focus_lines:
        return format_code_snippet(
            binary_name,
            function_name,
            code,
            header_suffix=f"({total_lines} lines)",
        )

    try:
        prototype_end = next(
            index for index, line in enumerate(lines, start=1) if "{" in line
        )
    except StopIteration:
        prototype_end = 1
    ranges = [(1, prototype_end)]
    ranges.extend(merge_line_ranges(
        sorted({line for line in focus_lines if 1 <= line <= total_lines}),
        context=INITIAL_FOCUS_CONTEXT_LINES,
        total_lines=total_lines,
    ))
    if lines and lines[-1].strip() == "}":
        ranges.append((total_lines, total_lines))
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    rendered = [
        f"=== {binary_name}::{function_name} "
        f"({total_lines} lines; prototype + callsite context) ==="
    ]
    previous_end = 0
    for start, end in merged:
        if start > previous_end + 1:
            rendered.append(
                f"  ... (omitted L{previous_end + 1}-L{start - 1}; "
                "full function available via view_function)"
            )
        rendered.extend(
            f"L{line_number}: {lines[line_number - 1]}"
            for line_number in range(start, end + 1)
        )
        previous_end = end
    if previous_end < total_lines:
        rendered.append(
            f"  ... (omitted L{previous_end + 1}-L{total_lines}; "
            "full function available via view_function)"
        )
    shown = sum(end - start + 1 for start, end in merged)
    rendered.insert(
        1,
        f"  (showing {shown} of {total_lines} source lines; "
        "all target callsites are included)",
    )
    return "\n".join(rendered)


# Shared prompt fragment describing decompiled code quirks.
DECOMPILED_CODE_ISSUES = """
<decompiled_code_issues>
The code you will analyze is **sliced decompiled output from decompiler (IDAPro, Ghidra)**.
Decompiler's output is NOT perfect C code. You will encounter:

1. **Type Recovery Issues:**
   - Incorrectly inferred types (e.g., `int` instead of `char*`, `void*` instead of struct pointers)
   - Generic types like `_DWORD`, `_BYTE`, `_QWORD` when the decompiler cannot determine the actual type
   - Missing const qualifiers

2. **Pointer Arithmetic and Struct Access:**
   - Struct field access may appear as: `*(type *)((char *)ptr + OFFSET)`
   - Array indexing may use pointer arithmetic: `*(ptr + i)` instead of `ptr[i]`
   - String operations may appear as byte-level operations

3. **Function Signatures:**
   - May have incorrect parameter types or counts
   - Return types may be wrong
   - Calling conventions may affect how arguments appear

4. **Stack Struct Decomposition:**
   - Structs allocated on the stack are often recovered as multiple independent
     local variables (e.g., `v5`, `v6`, `v7` instead of `struct_t s` with
     `s.field1`, `s.field2`, `s.field3`)
   - Common indicators: pointer arithmetic from a shared base variable
     (`*(type *)(&v5 + offset)`), groups of sequential variables passed together
     to a single function call, or variables block-initialized together
   - When you suspect this, identify which variables likely belong to the same
     original struct and treat them as related during your analysis
   - Distinct decompiler variable names do not prove disjoint memory. When an
     address escapes to a callee or kernel, a nearby local may be a field of the
     same input/output object. Its pre-call initialization does not prove that
     it remains unchanged. Field boundaries and offsets require actual storage
     addresses, access widths, and the pointer passed to the call.
</decompiled_code_issues>
"""

# Shared across every CodeAnalyzerAgent so a task does not silently trust a
# misleading decompiler rendering.  The rule is intentionally about direct
# binary facts only; dynamic environment semantics still require runtime
# evidence or an explicit uncertainty in the owning analyzer's schema.
ASSEMBLY_EVIDENCE_GUIDANCE = """
<assembly_evidence>
Decompiled output is a convenience interpretation, not an authoritative
representation of the binary. If it is missing, contradictory, or ambiguous,
inspect the exact function's persisted assembly with `view_disassembly` (or the
task-specific allowlisted assembly reader); the controller supplies its
filesystem path in the task context. For direct low-level facts, prefer
assembly: call targets, branches, immediates,
register/stack arguments, memory reads/writes, and return or error paths. Cite
the assembly path and instruction address when it resolves the issue. Assembly
branch targets distinguish a failed allocation that reaches cleanup from a
different failed allocation that reaches termination; proximity to the same
error label does not establish the same path. Boolean and pointer arithmetic
must preserve their actual numeric results and byte offsets.
Assembly does not by itself prove dynamic environment semantics; if neither view settles
the question, preserve the uncertainty rather than guessing.
</assembly_evidence>
""".strip()

# Shared prompt fragment requiring schema-constrained final output.
OUTPUT_REQUIREMENT = """
<output_requirement>
When analysis is complete, return the result that matches the supplied output
schema exactly. Do not add prose before or after the structured result.
</output_requirement>
"""


def _summarize_validation_error(error: ValidationError) -> str:
    """Group repeated schema failures while retaining every field location."""
    groups: dict[tuple[str, str], list[tuple[object, ...]]] = {}
    for item in error.errors(include_url=False, include_input=False):
        key = (str(item.get("type", "validation_error")), str(item["msg"]))
        groups.setdefault(key, []).append(tuple(item.get("loc", ())))

    lines = [f"{error.error_count()} validation error(s) in {len(groups)} group(s):"]
    for (error_type, message), locations in groups.items():
        rendered = [".".join(str(part) for part in location) for location in locations]
        location_summary = ", ".join(location or "<root>" for location in rendered)
        lines.append(f"- [{error_type}] {message} @ {location_summary}")
    return "\n".join(lines)


class CodeAnalyzerAgent:
    """Provider-neutral agent with optional AnalysisView-bound code tools."""

    def __init__(
        self,
        agent_name: str,
        task_prompt: str,
        output_format: Type[BaseModel],
        model: str,
        provider: str = DEFAULT_AGENT_PROVIDER,
        extra_tools: Optional[List] = None,
        filesystem_access: FilesystemAccess = "none",
        workdir: Optional[Path] = None,
        readable_roots: Optional[List[Path]] = None,
        include_analyzer_tools: bool = True,
        skills: Optional[List[AgentSkillSpec]] = None,
    ):
        self.agent_name = agent_name
        self.task_prompt = task_prompt
        self.output_format = output_format
        self.model = model
        self.provider = provider
        self.extra_tools = extra_tools or []
        self.filesystem_access = filesystem_access
        self.workdir = workdir
        self.readable_roots = list(readable_roots or [])
        self.include_analyzer_tools = include_analyzer_tools
        self.skills = list(skills or [])

    async def analyze(
        self,
        user_message: str,
        view: AnalysisView,
        binary_name: Optional[str] = None,
        function_name: Optional[str] = None,
        trace_dir: Optional["Path | str"] = None,
        callsite_line: Optional[int] = None,
        trace_name: Optional[str] = None,
        output_validator: Callable[[BaseModel], BaseModel | None] | None = None,
        initial_focus_lines: Optional[List[int]] = None,
    ) -> BaseModel:
        """Run a single analysis and return the structured result.

        Args:
            user_message: Task-specific prompt for the analysis.
            view: the analyzer's code-analysis facade. Tools resolve
                per-binary graph views via ``view.resolve_view(...)``.
            binary_name: Binary containing the target function.
            function_name: The decompiled_name of the target function.
            initial_focus_lines: Lines that must be present in the initial
                preview. Functions longer than 200 lines are represented by
                their prototype plus merged context around these lines.
        """
        # 1. Build the task-scoped agent through the provider boundary.
        all_tools = list(self.extra_tools)
        if self.include_analyzer_tools:
            all_tools = make_analyzer_tools(view) + all_tools
        effective_task_prompt = self.task_prompt
        if "<assembly_evidence>" not in effective_task_prompt:
            effective_task_prompt = (
                f"{effective_task_prompt.rstrip()}\n\n"
                f"{ASSEMBLY_EVIDENCE_GUIDANCE}"
            )
        # 2. Construct user message with initial function code
        initial_code_block = ""
        if binary_name and function_name:
            try:
                initial_code = view.get_full_code(binary_name, function_name)
                initial_code_block = (
                    "\n\n## Initial Function Code\n"
                    + _format_initial_function_code(
                        binary_name, function_name, initial_code,
                        initial_focus_lines,
                    )
                )
            except FileNotFoundError:
                logger.warning(f"Initial function {binary_name}::{function_name} code not found")

        assembly_path: Path | None = None
        initial_assembly_block = ""
        if binary_name and function_name:
            try:
                function_ea = view.get_function_ea(binary_name, function_name)
                if function_ea is not None:
                    assembly_path = view.get_disassembly_path(
                        binary_name, function_ea,
                    )
            except (AttributeError, FileNotFoundError, RuntimeError, ValueError):
                # An assembly hint is useful when available, but absence of a
                # listing must not make unrelated analysis tasks fail. The
                # view_disassembly tool will report the same limitation.
                assembly_path = None
        if assembly_path is not None and assembly_path.is_file():
            listing = assembly_path.read_text(encoding="utf-8")
            line_count = len(listing.splitlines())
            if line_count <= INITIAL_FULL_ASSEMBLY_MAX_LINES:
                initial_assembly_block = (
                    f"\n\n## Initial Function Assembly\n"
                    f"Source: {assembly_path} ({line_count} lines, complete)\n"
                    f"{listing}"
                )
            else:
                initial_assembly_block = (
                    f"\n\n## Initial Function Assembly\n"
                    f"Listing omitted from initial context ({line_count} lines); "
                    f"complete assembly is available via view_disassembly at {assembly_path}."
                )

        context_binary = binary_name or getattr(getattr(view, "root", None), "name", None)
        target_header = ""
        if context_binary or function_name:
            target_header = (
                "\n\n## Initial Target\n"
                f"- Binary: {context_binary or '(unspecified)'}\n"
                f"- Function: {function_name or '(unspecified)'}\n"
            )
            if assembly_path is not None:
                target_header += f"- Assembly fallback: {assembly_path}\n"
            if context_binary:
                try:
                    identity = view.get_binary_elf_identity(context_binary)
                except (AttributeError, FileNotFoundError, RuntimeError, ValueError):
                    target_header += "- Guest ELF identity: unavailable; ABI-dependent constants remain unverified.\n"
                else:
                    target_header += (
                        "- Guest ELF identity: "
                        + ", ".join(f"{key}={value}" for key, value in identity.items())
                        + "\n- Interpret numeric API constants using this guest's Linux ABI.\n"
                    )
                    if identity["machine"] == "MIPS":
                        # Linux arch/mips/include/asm/socket.h; these values
                        # apply to AF_PACKET sockets as well as AF_INET/AF_UNIX.
                        target_header += (
                            "- Linux MIPS socket types: SOCK_DGRAM=1, SOCK_STREAM=2, "
                            "SOCK_RAW=3, SOCK_PACKET=10.\n"
                        )

        full_message = (
            f"{effective_task_prompt}\n\n"
            f"{user_message}"
            f"{target_header}"
            f"{initial_code_block}"
            f"{initial_assembly_block}"
        )

        from ..task_recovery import (
            checkpoint_path, load_checkpoint, record_rejected,
            record_revalidated, store_checkpoint, recovery_available,
        )
        from ..semantic_identity import view_semantic_identity
        checkpoint = checkpoint_path(contract={
            "agent": self.agent_name, "provider": self.provider, "model": self.model,
            "message": full_message, "output_schema": self.output_format.model_json_schema(),
            "tools": [{"name": tool.name, "description": tool.description,
                       "schema": tool.args_schema.model_json_schema()} for tool in all_tools],
            "skills": [skill.trace_identity() for skill in self.skills],
            "filesystem_access": self.filesystem_access, "workdir": str(self.workdir),
            "readable_roots": [str(root) for root in self.readable_roots],
            "semantic_identity": view_semantic_identity(view),
        }) if recovery_available() else None
        recovered = load_checkpoint(checkpoint, self.output_format)
        if recovered is not None:
            try:
                normalized = output_validator(recovered) if output_validator else None
                if normalized is not None:
                    recovered = normalized
            except (OutputValidationError, ValidationError) as error:
                record_rejected(checkpoint, error)
            else:
                record_revalidated(checkpoint)
                return recovered

        agent = create_analysis_agent(
            model=self.model, developer_instructions="", tools=all_tools,
            output_format=self.output_format, workdir=self.workdir,
            filesystem_access=self.filesystem_access, readable_roots=self.readable_roots,
            name=self.agent_name, provider=self.provider, skills=self.skills,
        )

        # 3. Build trace handler if requested
        trace_handler = None
        if trace_dir:
            trace_dir = Path(trace_dir)
            trace_dir.mkdir(parents=True, exist_ok=True)
            if trace_name:
                stem = trace_name
                title = trace_name
            else:
                line_suffix = f"__L{callsite_line}" if callsite_line else ""
                stem = f"{binary_name or 'unnamed'}__{function_name or 'unnamed'}{line_suffix}"
                if binary_name and function_name:
                    title = f"{binary_name}::{function_name}" + (f" L{callsite_line}" if callsite_line else "")
                else:
                    title = stem
            trace_handler = AgentTraceHandler(
                agent_name=self.agent_name,
                md_path=trace_dir / f"{stem}.md",
                title=title,
                model=self.model,
            )

        # 4. Provider failures propagate immediately.  Only structured-output
        # and source/reference constraints receive same-session correction.
        result = None
        output = None
        turn_message = full_message
        from fmst_analyzer.analysis.base.execution import check_analysis_dispatch
        primary_error = None
        try:
            attempt = 0
            while True:
                attempt += 1
                try:
                    check_analysis_dispatch()
                    result = await agent.ainvoke(turn_message, trace=trace_handler)
                except ValidationError as error:
                    validation_summary = _summarize_validation_error(error)
                    logger.warning(
                        f"[CodeAnalyzerAgent] Structured output constraint failed on "
                        f"{binary_name}::{function_name}; requesting correction "
                        f"{attempt}: "
                        f"{validation_summary}"
                    )
                    turn_message = (
                        "Your previous structured output was rejected by the output "
                        "schema or reference constraints. Correct only the reported "
                        "fields and return the complete structured result again.\n\n"
                        f"Validation errors:\n{validation_summary}"
                    )
                    continue
                except ValueError as error:
                    # CodexAnalysisAgent unwraps a completed turn's local
                    # structured-output failure and tags only that cause.
                    # Retry that boundary failure; ordinary controller or
                    # implementation ValueErrors remain terminal.
                    if (
                        getattr(error, "code", None) != "structured_output_error"
                    ):
                        raise
                    logger.warning(
                        f"[CodeAnalyzerAgent] Structured output parsing failed on "
                        f"{binary_name}::{function_name}; requesting correction "
                        f"{attempt}: {error}"
                    )
                    turn_message = (
                        "Your previous response did not contain a valid complete "
                        "structured result. Return the complete result again as "
                        "valid JSON matching the supplied output schema. Do not "
                        "omit required fields or add commentary.\n\n"
                        f"Output parsing error:\n{error}"
                    )
                    continue

                output = result.structured_response
                if output is not None:
                    if output_validator is not None:
                        try:
                            normalized = output_validator(output)
                            if normalized is not None:
                                output = normalized
                        except (OutputValidationError, ValidationError) as error:
                            logger.warning(
                                f"[CodeAnalyzerAgent] Controller validation "
                                f"failed on {binary_name}::{function_name}; requesting "
                                f"correction {attempt}: {error}"
                            )
                            turn_message = (
                                "Your previous structured output failed controller "
                                "validation. Correct the reported issue and return the "
                                "complete structured result again. Preserve supported "
                                "facts and explicit unknowns. Do not invent IDs.\n\n"
                                f"Validation error:\n{error}"
                            )
                            output = None
                            continue
                    break

                raise AgentProviderError(
                    result.text,
                    provider=result.provider,
                    model=self.model,
                )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                await agent.aclose()
            except BaseException as cleanup_error:
                if primary_error is None:
                    raise
                primary_error.add_note(f"Agent close also failed: {type(cleanup_error).__name__}")
            if trace_handler:
                try:
                    trace_handler.write_summary()
                except Exception as recording_error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(f"Trace summary also failed: {type(recording_error).__name__}")

        if output is None:
            raise RuntimeError("Agent returned no structured output")
        store_checkpoint(checkpoint, output)

        logger.info(
            f"CodeAnalyzerAgent completed: {binary_name}::{function_name} → "
            f"{type(output).__name__}"
        )
        return output
