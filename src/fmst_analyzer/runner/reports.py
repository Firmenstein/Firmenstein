"""Pure rendering and persistence for Runner results."""

from __future__ import annotations

from pathlib import Path

from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    write_model_json,
    write_text,
)
from .schema import RehostingResult, RuntimeAttempt


def render_index(result: RehostingResult) -> str:
    lines = [
        "# Rehosting Runner",
        "",
        "- structured_source: "
        "[`rehosting_result.json`](rehosting_result.json)",
        f"- schema_version: `{result.schema_version}`",
        f"- target_binary: `{result.target_binary}`",
        f"- guest_arch: `{result.guest_arch}`",
        f"- selected_recipe_id: `{result.selected_recipe_id or '(none)'}`",
        "- launch_resolution: " + (result.launch_resolution.model_dump_json() if result.launch_resolution else "(none)"),
        f"- status: `{result.status}`",
        f"- stop_reason: `{result.stop_reason or '(none)'}`",
        f"- session_receipt_path: `{result.session_receipt_path or '(none)'}`",
        f"- success_configuration_path: `{result.success_configuration_path or '(none)'}`",
        f"- success_definition: `{result.success_definition}`",
        "- input_request: " + (result.input_request.model_dump_json() if result.input_request else "(none)"),
        "- completion: " + (result.completion.model_dump_json() if result.completion else "(none)"),
        f"- specification_gap: {result.specification_gap or '(none)'}",
        "- adaptation_history:",
        *["  - " + entry.model_dump_json() for entry in result.adaptation_history],
        "- revision_history:",
        *(
            ["  - (none)"]
            if not result.revision_history
            else [
                "  - " + revision.model_dump_json(exclude_none=True)
                for revision in result.revision_history
            ]
        ),
        "- decision_history:",
        *(
            ["  - (none)"]
            if not result.decision_history
            else [
                "  - " + decision.model_dump_json(exclude_none=True)
                for decision in result.decision_history
            ]
        ),
        "- environment_preparation:",
        f"  - status: `{result.environment_preparation.status}`",
        f"  - source_script_path: `{result.environment_preparation.source_script_path or '(none)'}`",
        f"  - application_count: `{result.environment_preparation.application_count}`",
        f"  - failure_reason: {result.environment_preparation.failure_reason or '(none)'}",
        f"- generation_baseline_id: `{result.generation_baseline_id or '(none)'}`",
        f"- generation_baseline_path: `{result.generation_baseline_path or '(none)'}`",
        f"- final_summary: {result.final_summary}",
        "",
        "## attempts",
        "",
    ]
    if not result.attempts:
        lines.append("(none)")
    for attempt in result.attempts:
        lines.extend(_render_attempt(attempt))
    return "\n".join(lines).rstrip() + "\n"


def _render_attempt(attempt: RuntimeAttempt) -> list[str]:
    probe = attempt.probe_result
    lines = [
        f"### attempt {attempt.attempt_number}",
        "",
        f"- adaptation_ids: `{attempt.adaptation_ids}`",
        f"- tree_identity_version: `{attempt.tree_identity_version}`",
        "- experiment: " + (attempt.experiment.model_dump_json() if attempt.experiment else "(none)"),
        "- launch_resolution: " + (attempt.launch_resolution.model_dump_json() if attempt.launch_resolution else "(none)"),
        f"- intervention_sha256: `{attempt.intervention_sha256 or '(none)'}`",
        f"- guest_args: `{attempt.guest_args}`",
        f"- guest_working_directory: `{attempt.guest_working_directory}`",
        f"- guest_environment: `{attempt.guest_environment}`",
        f"- network: `{attempt.network.model_dump_json()}`",
        "- companion_processes:",
        *(
            ["  - (none)"]
            if not attempt.companion_processes
            else [
                "  - " + process.model_dump_json(exclude_none=True)
                for process in attempt.companion_processes
            ]
        ),
        f"- companion_log_paths: `{attempt.companion_log_paths}`",
        f"- ipc: `{attempt.ipc.model_dump_json(exclude_none=True)}`",
        f"- disabled_unit_ids: `{attempt.disabled_unit_ids}`",
        "- rootfs_actions:",
    ]
    if not attempt.rootfs_actions:
        lines.append("  - (none)")
    else:
        lines.extend(
            "  - " + action.model_dump_json(exclude_none=True)
            for action in attempt.rootfs_actions
        )
    lines.extend([
        f"- intervention_source_path: `{attempt.intervention_source_path or '(none)'}`",
        f"- intervention_binary_path: `{attempt.intervention_binary_path or '(none)'}`",
        f"- probe.port: `{attempt.probe.port if attempt.probe else '(none)'}`",
        f"- probe.request_text: `{attempt.probe.request_text if attempt.probe else '(none)'}`",
        f"- probe.response_contains: `{(attempt.probe.response_contains or '(any non-empty response)') if attempt.probe else '(none)'}`",
        f"- scenario: `{attempt.scenario.model_dump_json(exclude_none=True) if attempt.scenario else '(none)'}`",
        "- request_revisions: " + str([item.model_dump(mode="json") for item in attempt.request_revisions]),
        f"- scenario_result.status: `{attempt.scenario_result.status if attempt.scenario_result else '(none)'}`",
        f"- scenario_result.error: {attempt.scenario_result.error if attempt.scenario_result and attempt.scenario_result.error else '(none)'}",
        f"- scenario_result.rejection: {attempt.scenario_result.rejection if attempt.scenario_result and attempt.scenario_result.rejection else '(none)'}",
        f"- scenario_result.observation_assertions_satisfied: `{attempt.scenario_result.observation_assertions_satisfied if attempt.scenario_result else []}`",
        "- scenario_result.observations:",
        *(
            ["  - (none)"]
            if not attempt.scenario_result or not attempt.scenario_result.observations
            else [
                "  - " + observation.model_dump_json(exclude_none=True)
                for observation in attempt.scenario_result.observations
            ]
        ),
        f"- probe_result.connected: `{probe.connected}`",
        f"- probe_result.interacted: `{probe.interacted}`",
        f"- probe_result.attempts: `{probe.attempts}`",
        f"- probe_result.error: {probe.error or '(none)'}",
        f"- probe_result.response_truncated: `{probe.response_truncated}`",
        "- scenario_result.http_framing: " + str([
            {"index": step.index, **step.http_response.model_dump(exclude={"headers_text", "body_text"})}
            for step in (attempt.scenario_result.steps if attempt.scenario_result else [])
            if step.http_response is not None]),
        f"- container_exit_code: `{attempt.container_exit_code if attempt.container_exit_code is not None else '(running at collection)'}`",
        f"- target_exit_code: `{attempt.target_exit_code if attempt.target_exit_code is not None else '(not observed)'}`",
        f"- timed_out: `{attempt.timed_out}`",
        f"- watchdog_triggered: `{attempt.watchdog_triggered}`",
        f"- termination_reason: `{attempt.termination_reason}`",
        f"- watchdog_path: `{attempt.watchdog_path or '(none)'}`",
        f"- outcome: `{attempt.outcome}`",
        f"- runtime_trace_available: `{attempt.runtime_trace_available}`",
        f"- runtime_trace_path: `{attempt.runtime_trace_path}`",
        f"- runtime_trace_paths: `{attempt.runtime_trace_paths}`",
        f"- runtime_trace_context_available: `{attempt.runtime_trace_context_available}`",
        f"- runtime_trace_context_path: `{attempt.runtime_trace_context_path}`",
        f"- runtime_trace_context_error: {attempt.runtime_trace_context_error or '(none)'}",
        f"- runtime_trace_heartbeat_paths: `{attempt.runtime_trace_heartbeat_paths}`",
        f"- rootfs_sha256: `{attempt.rootfs_sha256 or '(none)'}`",
        f"- rootfs_adaptations: `{attempt.rootfs_adaptations}`",
        f"- target_binary_sha256: `{attempt.target_binary_sha256 or '(none)'}`",
        f"- harness_sha256: `{attempt.harness_sha256 or '(none)'}`",
        f"- target_lifecycle_path: `{attempt.target_lifecycle_path or '(none)'}`",
        f"- probe_timeline_path: `{attempt.probe_timeline_path or '(none)'}`",
        f"- container_log_path: `{attempt.container_log_path}`",
        f"- agent_summary: {attempt.agent_summary}",
    ])
    if probe.response_text:
        lines.extend([
            "- probe_result.response_text:",
            "",
            "```text",
            probe.response_text,
            "```",
        ])
    if attempt.scenario_result:
        lines.extend([
            "- scenario_result.steps:",
            *(
                ["  - (none)"]
                if not attempt.scenario_result.steps
                else [
                    "  - " + step.model_dump_json(exclude_none=True)
                    for step in attempt.scenario_result.steps
                ]
            ),
        ])
    lines.append("")
    return lines


def persist_result(reports_root: Path, result: RehostingResult) -> RehostingResult:
    out_dir = Path(reports_root) / "runner_reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    result_path = out_dir / "rehosting_result.json"
    write_model_json(result_path, result)
    result = load_model_json(result_path, RehostingResult)
    write_text(out_dir / "index.md", render_index(result))
    return result


__all__ = ["persist_result", "render_index"]
