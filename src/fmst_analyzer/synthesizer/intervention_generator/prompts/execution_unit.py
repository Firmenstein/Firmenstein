"""Primary implementation-Agent contract for one Execution Unit."""

import json

from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    DECOMPILED_CODE_ISSUES,
)


EXECUTION_UNIT_TASK_PROMPT = """\
<goal>
Implement the supplied Execution Unit and its caller-visible
MockIIBContextOps test. Apply the attached guestweave-intervention-engineering
Skill and its engineering/ABI references, together with the supplied Core
application contract and generation layout guidance.
</goal>

<criteria>
The structured Intervention Contract is the starting point for this implementation
and its `operations` list is the set of caller-visible behaviors to exercise. The
Plan and Analyzer findings are evidence, not an unquestionable semantic oracle:
when source evidence exposes an assumption, record the assumption in your result
and implement the most useful concrete candidate. The implementation and test
should cover every operation that can be represented with the public IIB API,
including return values, output memory, shared state, native-fallback conditions,
and ABI details. Resolve uncertain pointer, byte-order, and state semantics from
the original code and Analyzer evidence. Tests must express caller-visible
behavior rather than copy the implementation. Never remove, weaken, or replace
an assertion merely to make the implementation pass.
Test the behavior owned by the Intervention; do not reimplement native firmware
control flow in the harness. Native continuation outside MockIIBContextOps is
established from original-code evidence and is validated end to end by the
future Runner.
</criteria>

<boundary>
Only edit the supplied Unit source files and exact test file. The Plan,
Catalog, decompiled code, assembly, Analyzer reports, the Skill, and earlier
Unit files are read-only inputs; immutability does not establish semantic truth.
Do not edit any Plan, Catalog, Analyzer result, or other input artifact.
Do not execute firmware ELF files or modify another Unit. Execution
code may use only the supplied IIB surface and in-memory Unit state, never host
filesystem, network, or process APIs.
</boundary>

<termination>
Stop after replacing all placeholders, running verify_unit, and reviewing the
implementation and assertions against the Plan and source evidence. Return
completed when a concrete implementation and test candidate exists, even if
verify_unit reports a build or test failure. Preserve that failure and the
candidate's limitations; completed does not mean build/test success or runtime
readiness. The current Runner consumes only Units that pass generation checks.
Return unable only when no concrete candidate can be written because an
essential input or target is missing, the Agent is interrupted before producing
files. If an operation is difficult or uncertain, write the most useful bounded
candidate and state the limitation in the completion reason.
</termination>
""" + DECOMPILED_CODE_ISSUES


def build_execution_unit_user_message(
    *,
    target_context: dict,
    unit: dict,
    related_units: list[dict],
    selected_launch: dict | None,
    intervention_files: list[dict],
    test_file: str,
    target_crate_name: str,
    import_paths: list[str],
    manifest_global_state_path: str,
    read_only_context_roots: list[str],
) -> str:
    return EXECUTION_UNIT_TASK_PROMPT + "\n\n" + """Implement this Execution Unit now.

Write the concrete Rust intervention and its caller-visible MockIIBContextOps
test in the supplied writable paths. Use the evidence and paths below as the
task input, then run the bound `verify_unit` tool and review the result before
returning the structured completion signal.

Execution Unit generation input:
""" + json.dumps(
        {
            "target_context": target_context,
            "unit": unit,
            "other_units_in_plan": related_units,
            "selected_launch_recipe": selected_launch,
            "intervention_files": intervention_files,
            "test_file": test_file,
            "target_crate_name": target_crate_name,
            "import_paths": import_paths,
            "manifest_global_state_path": manifest_global_state_path,
            "read_only_context_roots": read_only_context_roots,
        },
        ensure_ascii=False,
        indent=2,
    )


__all__ = [
    "EXECUTION_UNIT_TASK_PROMPT",
    "build_execution_unit_user_message",
]
