"""Single-target Planner using one Agent session and an atomic draft store."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import Field

from fmst_basic.agent import create_analysis_agent
from fmst_basic.agent.config import configured_codex_model_provider
from fmst_basic.agent.tool import tool
from fmst_basic.agent.trace import AgentTraceHandler
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import ASSEMBLY_EVIDENCE_GUIDANCE
from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import make_analyzer_tools
from fmst_analyzer.analysis.base.execution import check_analysis_dispatch
from fmst_analyzer.analysis.base.report_io import write_text
from fmst_analyzer.synthesizer.intervention_skill import REHOSTING_PLANNING_SKILL
from fmst_analyzer.framework import runtime_workspace, guestweave_skill, framework_references

from .behavior_validation import claim_counts, overlap_pairs
from .draft import PlanBatch, PlanDraftStore
from .evidence import make_finding_evidence_tool
from .evidence_runtime import evidence_python_runtime
from .failed_batches import failed_batch_access
from .plan_prompt import PLAN_TASK_PROMPT
from .schema import DECISION_FIELDS, InterventionPlanResult, PlannerExecution, StrictModel


class PlanCompletion(StrictModel):
    revision: int = Field(ge=0, description="Latest accepted draft revision with complete claim accounting and launch assessment.")
    summary: str = Field(min_length=1, description="Brief planning conclusion and remaining semantic blockers; this is not a duplicate Plan.")


def _completion_feedback(store: PlanDraftStore, error: ValueError) -> str:
    return (
        "The Plan is not publishable yet. Keep accepted work in the draft "
        f"(current revision {store.state.revision}); correct any reported draft issues through the tools. "
        "Return the completion as valid JSON matching the supplied schema, without commentary.\n\n"
        + str(error)
    )


def make_plan_tools(store: PlanDraftStore):
    def summary():
        result = store.progress()
        result.pop("findings")
        result["draft_path"] = str(store.path)
        return result

    @tool
    def apply_plan_batch(batch: PlanBatch) -> dict:
        """Atomically add, replace, withdraw or reconfirm a batch of decisions.

        Unmentioned IDs are preserved. A batch may handle several findings or
        revise earlier work. Rejected changes leave the previous revision intact;
        Error feedback saves the original request for read_failed_batches;
        correct reported issues without reconstructing unaffected contents.
        Inspect the latest draft before retrying. This tool validates
        identity and ownership, not the truth of a natural-language conclusion.

        Args:
            batch: Complete replacements keyed by exact stable IDs, removals and the expected draft revision. Only Unit names have build naming constraints; other logical handles are nonblank strings.
        """
        # AgentTool passes validated nested models as plain JSON dictionaries.
        store.apply(PlanBatch.model_validate(batch))
        write_text(store.path.with_suffix(".md"), render_draft_progress(store))
        return summary()

    @tool
    def read_plan(decision_ids: list[str] | None = None, remaining_only: bool = True,
                  offset: int = 0, limit: int = 50) -> dict:
        """Read progress, exact remaining claims and existing decisions.

        The finding page includes total/offset/next_offset. All decision handles
        and summaries remain visible; request IDs for complete contracts and
        scopes before revising them. Completion is computed from decisions,
        never from a model-written marker. Runtime tasks do not close claims.

        Args:
            decision_ids: Return full records for these existing IDs, or summaries of all decisions when omitted.
            remaining_only: Include only findings with unprocessed or review-pending claims.
            offset: Zero-based offset into the filtered finding list.
            limit: Number of findings in this page, between 1 and 100.
        """
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("offset must be nonnegative and limit must be between 1 and 100")
        state, progress = store.state, store.progress()
        records = {key: (field, item) for field in DECISION_FIELDS for key, item in getattr(state, field).items()}
        if decision_ids is not None and (unknown := set(decision_ids) - records.keys()):
            raise ValueError(f"unknown decision IDs: {sorted(unknown)!r}")
        decisions = {}
        for key in (decision_ids if decision_ids is not None else records):
            field, item = records[key]
            decisions[key] = {"kind": field, "record": item.model_dump(mode="json")} if decision_ids is not None else {
                "kind": field, "summary": getattr(item, "summary", getattr(item, "reason", getattr(item, "objective", "")))}
        findings = [(ref, entry) for ref, entry in progress.pop("findings").items()
                    if not remaining_only or entry["status"] != "processed"]
        page = findings[offset:offset + limit]
        return {**progress, "decisions": decisions, "findings": dict(page),
                "showing": len(page), "total": len(findings), "offset": offset,
                "next_offset": offset + len(page) if offset + len(page) < len(findings) else None}

    @tool
    def read_catalog(kind: Literal["finding", "launch", "gap"], ids: list[str]) -> dict:
        """Read complete records omitted from the compact initial Catalog index.

        Finding records include exact source pointers and related findings that
        share evidence. Shared evidence is a hint, not semantic equivalence or
        a requirement to compare every pair. Launch records include original
        commands, scripts and preparation; gaps include their complete reasons.

        Args:
            kind: Which Catalog record kind to read.
            ids: Exact finding refs, launch recipe IDs or gap refs of that kind.
        """
        mapping = {"finding": store.catalog.finding_index, "launch": store.catalog.launch_candidates,
                   "gap": store.catalog.gaps}[kind]
        if unknown := set(ids) - mapping.keys():
            hint = "Copy exact IDs from the initial Catalog index."
            if kind == "finding":
                hint += " All finding IDs are also available via read_plan(remaining_only=False); follow next_offset."
            raise ValueError(f"unknown {kind} IDs: {sorted(unknown)!r}; {hint}")
        result = {"records": {key: mapping[key].model_dump(mode="json") for key in ids}}
        if kind == "finding":
            pairs = overlap_pairs(store.catalog, store.catalog.finding_index)
            result["shared_evidence_with"] = {key: sorted({other for pair in pairs if key in pair for other in pair if other != key}) for key in ids}
        return result

    @tool
    def read_baseline(source_keys: list[str]) -> dict:
        """Read complete implementation sources from the fixed PlanningContext.

        Use the public IIB API to assess whether a proposed operation is
        expressible, and the launch/staging sources to check baseline behavior.
        These are implementation evidence, not observations of this firmware.
        Source text is returned in full and is the same snapshot saved in Plan.

        Args:
            source_keys: Exact keys from planning_context.implementation_sources in the initial input.
        """
        sources = store.state.planning_context.implementation_sources
        if unknown := set(source_keys) - sources.keys():
            raise ValueError(f"unknown baseline source keys: {sorted(unknown)!r}; copy keys from planning_context.implementation_sources")
        return {"sources": {key: sources[key].model_dump(mode="json") for key in source_keys}}

    retain_failure, read_failed_batches = failed_batch_access(store)
    apply_plan_batch.error_context = retain_failure
    return [apply_plan_batch, read_plan, read_catalog, read_baseline, read_failed_batches]


def render_draft_progress(store: PlanDraftStore) -> str:
    progress = store.progress()
    lines = ["# Plan draft", "", f"- revision: {progress['revision']}",
             f"- processed_findings: {progress['processed_findings']} / {progress['finding_count']}",
             f"- decided_claims: {progress['decided_claims']} / {progress['claim_count']}",
             "- This draft is not a published Plan or evidence of runtime readiness.", "",
             "```json", json.dumps(progress, ensure_ascii=False, indent=2), "```", ""]
    return "\n".join(lines)


class PlanAgent:
    def __init__(self, global_config, *, model: str | None = None):
        self.global_config = global_config
        self.model = model or global_config.planner_model

    async def run(self, catalog, resolver, view, store: PlanDraftStore, *, trace_root: Path) -> InterventionPlanResult:
        config = self.global_config
        framework = runtime_workspace(config)
        framework_skill = guestweave_skill(framework)
        rootfs = Path(config.fw_rootfs_path).resolve()
        if not rootfs.is_dir():
            raise ValueError(f"Planner rootfs does not exist: {rootfs}")
        guest_elf_identity = view.get_binary_elf_identity(view.root.name)
        python_runtime, runtime_roots = evidence_python_runtime()
        trace_root.mkdir(parents=True, exist_ok=True)
        trace = AgentTraceHandler(agent_name="PlanAgent", md_path=trace_root / "plan.md", title="Global target Plan", model=self.model)
        agent = create_analysis_agent(model=self.model, developer_instructions="",
            tools=[*make_analyzer_tools(view), make_finding_evidence_tool(resolver, set(catalog.finding_index)), *make_plan_tools(store)],
            output_format=PlanCompletion, workdir=rootfs, filesystem_access="read_shell",
            readable_roots=[Path(path).resolve() for path in (config.decompiled_code_dir, config.disassembled_code_dir) if path] + runtime_roots,
            provider=config.agent_provider, name="PlanAgent", skills=[REHOSTING_PLANNING_SKILL, framework_skill],
            reasoning_effort=config.planner_reasoning_effort)
        inputs = {"catalog_digest": store.state.catalog_digest, "target_identity": catalog.target_identity.model_dump(mode="json"),
                  "guest_elf_identity": guest_elf_identity,
                  "framework_references": framework_references(framework),
                  "service_goal": store.state.service_goal,
                  "planning_context": store.state.planning_context.model_dump(mode="json", exclude={"implementation_sources": {"__all__": {"text"}}}),
                  "launch_candidates": {key: {"executable_path": value.executable_path, "command_template": value.command_template, "applicability": value.applicability} for key, value in catalog.launch_candidates.items()},
                  "gaps": {key: {"source_kind": value.source_kind.value, "source_id": value.source_id, "subject": value.subject} for key, value in catalog.gaps.items()},
                  "finding_index": {key: {"source_kind": value.source_kind.value, "summary": value.summary, "claim_count": claim_counts(resolver, [key])[key]} for key, value in catalog.finding_index.items()},
                  "mechanical_overlap_pair_count": len(overlap_pairs(catalog, catalog.finding_index)),
                  "index_scope": "This is a compact index. Complete claims and selected source records are available through view_finding_evidence; full launch, gap and source index records through read_catalog; full implementation baseline sources through read_baseline. Mechanical overlaps are hints, not a mandatory pairwise checklist.",
                  "filesystem_context": {"rootfs": str(rootfs), "decompiled_code": str(config.decompiled_code_dir), "assembly": str(config.disassembled_code_dir),
                                         "python_runtime": python_runtime},
                  "draft_revision": store.state.revision}
        write_text(trace_root / "input.json", json.dumps(inputs, ensure_ascii=False, indent=2))
        write_text(trace_root / "model.json", json.dumps({"model": self.model, "reasoning_effort": getattr(agent, "reasoning_effort", config.planner_reasoning_effort),
                   "provider": config.agent_provider, "model_provider": configured_codex_model_provider()}, indent=2))
        message = PLAN_TASK_PROMPT + "\n\n" + ASSEMBLY_EVIDENCE_GUIDANCE + "\n\n" + """Create and maintain the evidence-grounded Intervention Plan
for this target. Process the supplied catalog and findings through the planning
tools, preserve accepted draft work, and return the completion signal only when
the current draft is complete or the exact blocking input is recorded.

Target planning input:
""" + json.dumps(inputs, ensure_ascii=False, indent=2)
        write_text(store.path.with_suffix(".md"), render_draft_progress(store))
        try:
            while True:
                check_analysis_dispatch()
                try:
                    result = await agent.ainvoke(message, trace=trace)
                except ValueError as error:
                    # A completed turn can fail local parsing in the adapter.
                    # Only that tagged failure is eligible for correction;
                    # SDK/configuration ValueErrors must still propagate.
                    if getattr(error, "code", None) != "structured_output_error":
                        raise
                    message = _completion_feedback(store, error)
                    continue
                try:
                    completion = result.structured_response
                    if not isinstance(completion, PlanCompletion):
                        raise ValueError("final response must identify the accepted draft revision")
                    if completion.revision != store.state.revision:
                        raise ValueError(f"final revision {completion.revision} differs from current draft {store.state.revision}")
                    state = store.validate_complete()
                except ValueError as error:
                    # Only local structured-output/completion validation is
                    # retryable; SDK/provider failures propagate with the draft.
                    message = _completion_feedback(store, error)
                    continue
                contents = {field: getattr(state, field) for field in DECISION_FIELDS}
                return InterventionPlanResult(**contents, catalog_digest=state.catalog_digest, planning_context=state.planning_context,
                    service_goal=state.service_goal, launch_choice=state.launch_choice, draft_revision=state.revision,
                    claim_counts=claim_counts(resolver, catalog.finding_index),
                    producer=PlannerExecution(model=self.model, reasoning_effort=getattr(agent, "reasoning_effort", config.planner_reasoning_effort),
                        provider=result.provider, model_provider=configured_codex_model_provider(), session_id=result.session_id, turn_id=result.turn_id))
        finally:
            try:
                trace.write_summary()
            finally:
                await agent.aclose()
