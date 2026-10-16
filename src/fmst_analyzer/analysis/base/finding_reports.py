"""Complete, deterministic Markdown views of the shared finding contract."""

import json
import re

from .analysis_finding import AnalysisFinding, validate_finding_map


def _scalar(value: object) -> str:
    text = json.dumps(value, ensure_ascii=False)
    fence = "`" * (1 + max((len(run) for run in re.findall(r"`+", text)), default=0))
    return f"{fence} {text} {fence}"


def _lines(value: object, indent: int = 0) -> list[str]:
    prefix = "  " * indent
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{prefix}- {key}:")
                lines.extend(_lines(item, indent + 1))
            else:
                lines.append(f"{prefix}- {key}: {_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for index, item in enumerate(value):
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}- [{index}]:")
                lines.extend(_lines(item, indent + 1))
            else:
                lines.append(f"{prefix}- {_scalar(item)}")
        return lines
    return [f"{prefix}- {_scalar(value)}"]


def render_finding(finding: AnalysisFinding) -> str:
    """Render every persisted field without consulting source files or Agents."""
    return "\n".join(_lines(finding.model_dump(mode="json"))) + "\n"


def render_fields(document: dict) -> str:
    """Render a JSON object losslessly with its exact schema field labels."""
    return "\n".join(_lines(document)) + "\n"


def render_planning_findings(findings: dict[str, AnalysisFinding]) -> str:
    """Render a Result's findings in stable identity order, including empty maps."""
    validate_finding_map(findings)
    parts = ["## planning_findings", ""]
    if not findings:
        parts.append("`{}`")
    for ref in sorted(findings):
        parts.extend([f"### {ref}", "", render_finding(findings[ref])])
    return "\n".join(parts) + "\n"
