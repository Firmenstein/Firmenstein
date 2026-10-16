"""Complete pure rendering of the deterministic finding index."""
from fmst_analyzer.analysis.base.finding_reports import render_fields
from .schema import PlanningEvidenceCatalog


def render_index(catalog: PlanningEvidenceCatalog) -> str:
    return ("# Intervention Planning Evidence\n\n"
            "Structured source: [planner_input_catalog.json](planner_input_catalog.json)\n\n"
            + render_fields(catalog.model_dump(mode="json")))


__all__ = ["render_index"]
