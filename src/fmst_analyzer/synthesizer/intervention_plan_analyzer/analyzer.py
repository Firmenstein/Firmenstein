"""Production entry point for one global PlanAgent and its fixed inputs."""
from __future__ import annotations

from pathlib import Path

from fmst_basic.agent.usage_registry import scoped
from fmst_analyzer.framework import runtime_workspace
from fmst_analyzer.analysis.base.artifact_lifecycle import preserve_stage_attempt
from fmst_analyzer.analysis.base.report_io import load_model_json, model_content_sha256
from .catalog import PlanningEvidenceAssembler, PlanningEvidenceCatalog
from .draft import PlanDraft, PlanDraftStore
from .evidence import FindingEvidenceResolver
from .normalization import normalize_unit
from .plan_agent import PlanAgent
from .planning_context import build_planning_context, validate_planning_context
from .behavior_validation import validate_plan_behaviors
from .reports import persist_intervention_plan, render_intervention_plan_markdown
from .schema import DECISION_FIELDS, InterventionPlanResult


class InterventionPlanAnalyzer:
    def __init__(self, global_config, *, model: str | None = None, service_goal: str | None = None):
        self.global_config = global_config
        self.model = model or global_config.planner_model
        self.service_goal = service_goal if service_goal is not None else global_config.rehosting_goal

    @scoped("InterventionPlanAnalyzer")
    @preserve_stage_attempt("plan")
    async def run(self, view) -> tuple[PlanningEvidenceCatalog, InterventionPlanResult]:
        config = self.global_config
        reports_root = config.target_diagnostic_reports_dir()
        catalog = PlanningEvidenceAssembler(reports_root, global_config=config).run()
        resolver = FindingEvidenceResolver(reports_root, catalog)
        context = build_planning_context(runtime_workspace(config))
        def resolve(key, draft, choice):
            return normalize_unit(key, draft, catalog=catalog, resolver=resolver, view=view, launch_choice=choice)
        store = PlanDraftStore(reports_root / "intervention_plan_reports/plan_draft.json", catalog, resolver, context,
                               service_goal=self.service_goal, resolve_unit=resolve)
        plan = await PlanAgent(config, model=self.model).run(catalog, resolver, view, store,
                    trace_root=config.target_agent_debug_dir() / "intervention_plan")
        validate_plan_behaviors(plan, catalog, resolver)
        # A source changed during a long Agent session must not be published.
        if catalog != PlanningEvidenceAssembler(reports_root, global_config=config).assemble():
            raise ValueError("Analyzer sources changed during planning; retain draft and start a new attempt")
        validate_planning_context(plan.planning_context, runtime_workspace(config))
        persist_intervention_plan(reports_root, catalog, plan)
        return load_persisted_intervention_plan(reports_root, global_config=config)


def load_persisted_intervention_plan(reports_root: Path, *, global_config=None,
                                    require_current_implementation: bool = True) -> tuple[PlanningEvidenceCatalog, InterventionPlanResult]:
    """Load a published Plan with exact Analyzer/Catalog/goal binding.

    Downstream execution may explicitly consume a frozen historical Plan after
    runtime implementation changes. Its planning_context remains immutable;
    Generation records the implementation delta in its publication. Planning
    itself retains strict current-implementation validation by default.
    """
    root = Path(reports_root)
    catalog = load_model_json(root / "intervention_planner_inputs/planner_input_catalog.json", PlanningEvidenceCatalog)
    plan = load_model_json(root / "intervention_plan_reports/intervention_plan_result.json", InterventionPlanResult)
    draft_path = root / "intervention_plan_reports/plan_draft.json"
    if draft_path.is_file():
        draft = load_model_json(draft_path, PlanDraft)
        bound_fields = (*DECISION_FIELDS, "catalog_digest", "planning_context", "service_goal", "launch_choice")
        if (draft.review_pending or draft.revision != plan.draft_revision
                or any(getattr(draft, field) != getattr(plan, field) for field in bound_fields)):
            raise ValueError("published Plan differs from the current draft; finalize the revised draft before consumption")
    current = PlanningEvidenceAssembler(root, global_config=global_config).assemble()
    if catalog != current or plan.catalog_digest != model_content_sha256(catalog):
        raise ValueError("persisted Plan Catalog differs from current Analyzer sources; rerun intervention-plan")
    if global_config is not None:
        goal = getattr(global_config, "rehosting_goal", None)
        if goal is not None and goal != plan.service_goal:
            raise ValueError("Plan service goal changed; rerun intervention-plan")
    if require_current_implementation:
        validate_planning_context(plan.planning_context, runtime_workspace(global_config))
    validate_plan_behaviors(plan, catalog, FindingEvidenceResolver(root, catalog))
    render_intervention_plan_markdown(root, catalog, plan)
    return catalog, plan


__all__ = ["InterventionPlanAnalyzer", "load_persisted_intervention_plan"]
