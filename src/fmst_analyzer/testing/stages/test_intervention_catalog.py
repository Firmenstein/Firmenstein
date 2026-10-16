"""Stage: intervention-planner-inputs (pure persisted-JSON projection)."""
from __future__ import annotations

from typing import TYPE_CHECKING, Tuple

from loguru import logger

from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningEvidenceAssembler,
    PlanningEvidenceCatalog,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.reports import (
    render_index,
)

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_intervention_catalog(
    tester: "PipelineTester",
) -> Tuple[bool, str]:
    reports_root = tester.global_config.target_diagnostic_reports_dir()
    try:
        result = PlanningEvidenceAssembler(reports_root, global_config=tester.global_config).run()
    except Exception as exc:
        logger.exception("PlanningEvidenceAssembler raised")
        return False, f"planning evidence assembly raised: {exc!r}"

    issues: list[str] = []
    out_dir = reports_root / "intervention_planner_inputs"
    json_path = out_dir / "planner_input_catalog.json"
    md_path = out_dir / "index.md"
    if not json_path.is_file():
        issues.append(f"missing artifact: {json_path}")
    if not md_path.is_file():
        issues.append(f"missing artifact: {md_path}")
    if json_path.is_file():
        try:
            persisted = PlanningEvidenceCatalog.model_validate_json(
                json_path.read_text(encoding="utf-8")
            )
        except Exception as exc:
            issues.append(f"invalid planner_input_catalog.json: {exc}")
        else:
            if persisted != result:
                issues.append("persisted catalog differs from assembled result")
            if md_path.is_file() and md_path.read_text(
                encoding="utf-8"
            ) != render_index(persisted):
                issues.append("index.md is not a pure rendering of catalog JSON")

    summary = (
        f"{len(result.finding_index)} findings, "
        f"{len(result.launch_candidates)} launch candidates, "
        f"{len(result.gaps)} gaps"
    )
    if issues:
        summary += f"; {len(issues)} problems: " + "; ".join(issues)
    return not issues, summary


__all__ = ["test_intervention_catalog"]
