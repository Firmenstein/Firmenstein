"""Pure JSON-to-Markdown rendering for Unit generation artifacts."""

from __future__ import annotations

import re
import hashlib
from pathlib import Path, PurePosixPath
from fmst_basic.utils.archive_paths import resolve_archived_path

from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    model_content_sha256,
    write_model_json,
    write_text,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionContract,
    InterventionPlanResult,
    ResolvedCallsiteAnchor,
    ResolvedFunctionAnchor,
    ResourceAnchor,
)
from .schema import (
    InterventionGenerationResult,
    UnitGenerationReport,
)
from .publication import bind_generation_publication, validate_generation_publication
def _render_behavior_scopes(scopes) -> list[str]:
    lines = ["- behavior_scopes:"]
    for scope in scopes:
        lines.extend([f"  - finding_ref: `{scope.finding_ref}`",
                      f"  - claim_indices: `{scope.claim_indices}`",
                      f"  - applicability: {scope.applicability}"])
    return lines


def _table_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _render_contract(contract: InterventionContract) -> list[str]:
    lines = ["- contract:"]
    for field_name in (
        "applicability",
        "owned_resources",
        "operations",
        "state",
        "native_fallback",
        "required_iib_capabilities",
        "verification",
        "allowed_refinement_scope",
    ):
        values = getattr(contract, field_name)
        lines.append(f"  - {field_name}:")
        if values:
            lines.extend(f"    - {value}" for value in values)
        else:
            lines.append("    - (none)")
    return lines


def render_index(result: InterventionGenerationResult) -> str:
    lines = [
        "# Intervention Generation",
        "",
        "- Structured source of truth: "
        "[`intervention_generation_result.json`](intervention_generation_result.json)",
        "- Consumed intervention plan: "
        "[`intervention_plan_result.json`](../intervention_plan_reports/intervention_plan_result.json)",
        "",
        f"- schema_version: `{result.schema_version}`",
        f"- plan_digest: `{result.plan_digest}`",
        f"- completion_status: `{result.completion_status}`",
        f"- target_binary: `{result.target_binary}`",
        f"- arch: `{result.arch}`",
        f"- total_units: `{result.total_units}`",
        f"- ok_count: `{result.ok_count}`",
        f"- not_ready_count: `{result.not_ready_count}`",
        f"- skipped_count: `{result.skipped_count}`",
        f"- cargo_build_status: `{result.cargo_build_status}`",
        f"- cargo_test_status: `{result.cargo_test_status}`",
        f"- intervention_crate_path: `{result.intervention_crate_path or '(none)'}`",
        f"- test_crate_path: `{result.test_crate_path or '(none)'}`",
        f"- publication.baseline_id: `{result.publication.baseline_id if result.publication else '(checkpoint)'}`",
        f"- publication.baseline_path: `{result.publication.baseline_path if result.publication else '(none)'}`",
        "- implementation_context_changes: " + "; ".join(
            f"{key}: {value.planned_sha256} → {value.observed_sha256}"
            for key, value in result.implementation_context_changes.items()
        ),
        f"- environment.status: `{result.environment.status}`",
        f"- environment.script_path: `{result.environment.script_path or '(none)'}`",
        f"- environment.reason: {result.environment.reason}",
        f"- environment.failure_code: `{result.environment.failure_code or '(none)'}`",
        f"- environment.trace_path: {_path_link(result.environment.trace_path)}",
        "- environment.handoff: `RUNNER_INPUT_READY` means only that the "
        "Environment Agent generated the script; the Generator does not execute "
        "or validate it.",
        "",
        "## source_artifacts",
        "",
        "- catalog: [`planner_input_catalog.json`](../intervention_planner_inputs/planner_input_catalog.json)",
        "- plan: [`intervention_plan_result.json`](../intervention_plan_reports/intervention_plan_result.json)",
        "- ipc: [`ipc_analysis_result.json`](../ipc_reports/ipc_analysis_result.json)",
        "- file: [`file_resolver_result.json`](../file_reports/file_resolver_result.json)",
        "- network: [`network_analysis_result.json`](../network_reports/network_analysis_result.json)",
        "- process: [`process_lifecycle_analysis_result.json`](../process_lifecycle_reports/process_lifecycle_analysis_result.json)",
        "- launch: [`init_launch_analysis_result.json`](../init_launch_reports/init_launch_analysis_result.json)",
    ]
    for label, failure in (
        ("cargo_build_failure", result.cargo_build_failure),
        ("cargo_test_failure", result.cargo_test_failure),
    ):
        lines.extend(["", f"## {label}", ""])
        if failure is None:
            lines.append("(none)")
        else:
            lines.extend([
                f"- phase: `{failure.phase}`",
                f"- file_path: `{failure.file_path or '(none)'}`",
                "- message:",
                "",
                "```text",
                failure.message,
                "```",
            ])
    lines.extend([
        "",
        "## units",
        "",
        "| unit_id | strategy | status | runner_handoff | generated_files | turns | failure_reason | report |",
        "|---|---|---|---|---:|---:|---|---|",
    ])
    for unit in result.units:
        lines.append(
            f"| `{unit.unit_id}` | `{unit.strategy}` | `{unit.status}` | "
            f"`{'RUNNER_INPUT_READY' if unit.status == 'ok' else ('SKIPPED' if unit.status == 'skipped' else 'NOT_READY')}` | "
            f"{len(unit.generated_files)} | {len(unit.round_traces)} | "
            f"{_table_text(unit.failure_reason or '')} | "
            f"[md](units/{unit.report_stem}.md) / "
            f"[json](units/{unit.report_stem}.json) |"
        )
    lines.extend(["", "## environment.unit_ids", ""])
    if not result.environment.unit_ids:
        lines.append("(none)")
    lines.extend(f"- `{unit_id}`" for unit_id in result.environment.unit_ids)
    return "\n".join(lines).rstrip() + "\n"


def render_unit(report: UnitGenerationReport) -> str:
    unit = report.unit
    generation = report.generation
    lines = [
        f"# Unit Generation: {unit.unit_id}",
        "",
        f"- schema_version: `{report.schema_version}`",
        f"- structured_source: "
        f"[`{generation.report_stem}.json`]({generation.report_stem}.json)",
        "- consumed_plan: "
        "[`intervention_plan_result.json`](../../intervention_plan_reports/intervention_plan_result.json)",
        f"- strategy: `{unit.strategy}`",
        f"- status: `{generation.status}`",
        f"- contract_digest: `{generation.contract_digest or '(none)'}`",
        f"- revision_count: `{generation.revision_count}`",
        f"- failure_code: `{generation.failure_code or '(none)'}`",
        f"- failure_reason: {generation.failure_reason or '(none)'}",
        f"- summary: {unit.summary}",
        f"- runner_handoff: `{'RUNNER_INPUT_READY' if generation.status == 'ok' else ('SKIPPED' if generation.status == 'skipped' else 'NOT_READY')}`",
        "- finding_refs:",
    ]
    lines.extend(f"  - `{ref}`" for ref in unit.finding_refs)
    lines.extend(["- anchors:"])
    for anchor in unit.anchors:
        lines.extend(_render_anchor(anchor))
    lines.extend(_render_contract(unit.contract))
    lines.extend(_render_behavior_scopes(unit.behavior_scopes))
    lines.extend(["- generated_files:"])
    if generation.generated_files:
        lines.extend(
            f"  - [`{path}`](<{path}>)" for path in generation.generated_files
        )
    else:
        lines.append("  - (none)")
    lines.extend(["- round_traces:"])
    if not generation.round_traces:
        lines.append("  - (none)")
    for round_trace in generation.round_traces:
        lines.extend([
            f"  - round `{round_trace.round_index}`:",
            f"    - generator: {_path_link(round_trace.generator_trace_path)}",
        ])
    lines.extend([
        "",
        "## environment_script_path",
        "",
        f"`{report.environment_script_path or '(none)'}`",
    ])
    if generation.last_failure_signal is not None:
        failure = generation.last_failure_signal
        lines.extend([
            "",
            "## last_failure_signal",
            "",
            f"- code: `{failure.code}`",
            f"- phase: `{failure.phase}`",
            f"- file_path: `{failure.file_path or '(none)'}`",
            "- message:",
            "",
            "```text",
            failure.message,
            "```",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _render_anchor(anchor) -> list[str]:
    if isinstance(anchor, ResolvedFunctionAnchor):
        return [
            "  - kind: `function`",
            f"    - binary_name: `{anchor.binary_name}`",
            f"    - function_name: `{anchor.function_name}`",
            f"    - function_ea: `{anchor.function_ea:#x}`",
        ]
    if isinstance(anchor, ResourceAnchor):
        return [
            "  - kind: `resource`",
            f"    - resource_kind: `{anchor.resource_kind}`",
            f"    - value: `{anchor.value}`",
            f"    - source_ref: `{anchor.source_ref}`",
        ]
    if isinstance(anchor, ResolvedCallsiteAnchor):
        return [
            "  - kind: `callsite`",
            f"    - callsite_id: `{anchor.callsite_id}`",
            f"    - binary_name: `{anchor.binary_name}`",
            f"    - function_name: `{anchor.function_name}`",
            f"    - function_ea: `{anchor.function_ea:#x}`",
            f"    - snapshot_hash: `{anchor.snapshot_hash}`",
            f"    - ctree_index: `{anchor.ctree_index}`",
            (
                f"    - source_ea: `{anchor.source_ea:#x}`"
                if anchor.source_ea is not None
                else "    - source_ea: `BADADDR`"
            ),
            f"    - line_number: `{anchor.line_number}`",
            f"    - column_number: `{anchor.column_number}`",
            f"    - api_name: `{anchor.api_name}`",
        ]
    raise TypeError(f"unsupported intervention anchor: {type(anchor)!r}")


def _path_link(path: str | None) -> str:
    return f"[`{path}`](<{path}>)" if path else "(none)"


def persist_generation(
    reports_root: Path,
    result: InterventionGenerationResult,
    plan: InterventionPlanResult,
    *,
    snapshot: bool = True,
    runtime_workspace: Path | None = None,
) -> InterventionGenerationResult:
    if result.plan_digest != model_content_sha256(plan):
        raise ValueError("Generation input Plan digest changed before publication")
    out_dir = Path(reports_root) / "intervention_generation_reports"
    if snapshot:
        bind_generation_publication(result, plan, out_dir, runtime_workspace=runtime_workspace)
    units_dir = out_dir / "units"
    units_dir.mkdir(parents=True, exist_ok=True)
    result_path = out_dir / "intervention_generation_result.json"
    write_model_json(result_path, result)
    result = load_model_json(result_path, InterventionGenerationResult)
    for path in units_dir.iterdir():
        if path.is_file() and path.suffix in {".json", ".md"}:
            path.unlink()

    planned_units = {
        unit_id: unit
        for unit_id, unit in plan.units.items()
    }
    for generation in result.units:
        unit = planned_units[generation.unit_id]
        report = UnitGenerationReport(
            unit=unit,
            generation=generation,
            environment_script_path=(
                result.environment.script_path
                if generation.unit_id in result.environment.unit_ids
                else None
            ),
        )
        stem = generation.report_stem
        report_path = units_dir / f"{stem}.json"
        write_model_json(report_path, report)
        report = load_model_json(report_path, UnitGenerationReport)
        write_text(units_dir / f"{stem}.md", render_unit(report))
    write_text(out_dir / "index.md", render_index(result))
    return result


def load_persisted_intervention_generation(
    reports_root: Path,
    plan: InterventionPlanResult,
    *,
    require_complete: bool = False,
) -> InterventionGenerationResult:
    """Load and directly validate Generation against the current Plan."""
    out_dir = Path(reports_root) / "intervention_generation_reports"
    result = load_model_json(
        out_dir / "intervention_generation_result.json",
        InterventionGenerationResult,
    )
    if result.plan_digest != model_content_sha256(plan):
        raise ValueError("Generation input Plan digest changed; regenerate from the current Plan")
    if result.publication is not None:
        validate_generation_publication(result, plan)
    elif require_complete or result.completion_status == "complete":
        raise ValueError("Generation publication receipt is missing")
    if require_complete:
        if result.completion_status != "complete":
            raise ValueError("partial Intervention Generation cannot be consumed")
        if any(item.status == "pending" for item in result.units):
            raise ValueError("Intervention Generation contains unfinished Units")
    planned_units = {
        unit_id: unit
        for unit_id, unit in plan.units.items()
    }
    generated = {item.unit_id: item for item in result.units}
    if set(generated) != set(planned_units):
        raise ValueError("Generation Unit identities differ from the current Plan")
    for unit_id, item in generated.items():
        if item.strategy != planned_units[unit_id].strategy:
            raise ValueError(f"Generation strategy differs for {unit_id}")
        missing = [path for path in item.generated_files if not resolve_archived_path(Path(path)).is_file()]
        if missing and (item.status == "ok" or result.publication is None or
                        not set(str(Path(path).resolve()) for path in missing).issubset(result.publication.missing_files)):
            raise ValueError(
                f"Generation files are missing for {unit_id}: " + ", ".join(missing)
            )
        if item.status == "ok" and not item.generated_files:
            raise ValueError(f"successful Generation has no files for {unit_id}")

    environment_unit_ids = {
        unit_id
        for unit_id, unit in planned_units.items()
        if unit.strategy == "environment_setup"
    }
    if not set(result.environment.unit_ids).issubset(environment_unit_ids):
        raise ValueError("Environment result references non-environment Units")
    if result.environment.status == "completed" and result.environment.unit_ids:
        if not result.environment.script_path or not resolve_archived_path(Path(
            result.environment.script_path
        )).is_file():
            raise ValueError("completed Environment Generation script is missing")

    reports: dict[str, UnitGenerationReport] = {}
    units_dir = out_dir / "units"
    for path in sorted(units_dir.glob("*.json")):
        report = load_model_json(path, UnitGenerationReport)
        unit_id = report.generation.unit_id
        if unit_id in reports:
            raise ValueError(f"duplicate per-Unit Generation report: {unit_id}")
        reports[unit_id] = report
    if set(reports) != set(planned_units):
        raise ValueError("per-Unit Generation reports differ from the current Plan")
    for unit_id, report in reports.items():
        if report.unit != planned_units[unit_id]:
            raise ValueError(f"persisted Unit payload differs from Plan: {unit_id}")
        if report.generation != generated[unit_id]:
            raise ValueError(f"per-Unit Generation status differs: {unit_id}")
        if report.unit.strategy != "environment_setup" and report.generation.status == "ok" and require_complete:
            _validate_completed_round_traces(report)

    write_text(out_dir / "index.md", render_index(result))
    for report in reports.values():
        write_text(
            units_dir / f"{report.generation.report_stem}.md",
            render_unit(report),
        )
    return result


def _validate_completed_round_traces(report: UnitGenerationReport) -> None:
    """Require one complete, ordered Generator trace for every turn.

    A successful persisted Unit is only consumable after its provider turn has
    left an atomic terminal trajectory. Partial checkpoints may carry
    missing paths while a turn is still running, but ``require_complete`` must
    never allow that state through to Runner.
    """
    generation = report.generation
    traces = generation.round_traces
    expected = list(range(1, len(traces) + 1))
    actual = [trace.round_index for trace in traces]
    if not traces or actual != expected:
        raise ValueError(
            f"successful Execution Unit has non-contiguous round traces: "
            f"{generation.unit_id}"
        )
    for trace in traces:
        if not trace.generator_trace_path or not Path(trace.generator_trace_path).is_file():
            raise ValueError(
                f"successful Execution Unit generator trace is missing: "
                f"{generation.unit_id} round {trace.round_index}"
            )


def unit_report_stem(subject: str, unit_id: str) -> str:
    candidate = PurePosixPath(subject.split(",", 1)[0]).name or subject
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", candidate).strip("-._").lower()
    # Finding summaries are model-authored and can be arbitrarily long.
    # Bound the human-readable prefix so the persisted JSON/Markdown pair is
    # portable across filesystems while the Unit suffix keeps it distinct.
    bounded = (slug or "unit")[:70].rstrip("-._") or "unit"
    # Finding summaries are not unique (environment Units often share one),
    # so a short Unit hash is part of the persisted filename.  Keep the
    # human-readable prefix at the end for compatibility with existing links.
    readable_unit = re.sub(r"[^A-Za-z0-9._-]+", "-", unit_id.removeprefix("unit-")).strip("-._") or "unit"
    readable_unit = readable_unit[:10].rstrip("-._") or "unit"
    unit_hash = hashlib.sha256(unit_id.encode("utf-8")).hexdigest()[:8]
    return f"{bounded}__{unit_hash}__{readable_unit}"


__all__ = [
    "load_persisted_intervention_generation",
    "persist_generation",
    "render_index",
    "render_unit",
    "unit_report_stem",
]
