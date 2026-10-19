"""Explicit paid/runtime stage consuming persisted Plan and Generation JSON."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from fmst_analyzer.runner import create_runner, runner_succeeded
from fmst_analyzer.runner.task.schema import TaskResult
from fmst_analyzer.framework import runtime_workspace

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_intervention_runner(
    tester: "PipelineTester",
) -> tuple[bool, str]:
    """Prefer bound candidates; hand unrecoverable upstream work to Runner."""
    repair_input = None
    try:
        from fmst_analyzer.runner.repair_intake import UpstreamRepairInput
        source = UpstreamRepairInput.capture(error=RuntimeError("Runner source admission"), stage="input",
                                             rootfs=tester.fw_rootfs_path, target=tester.target_binary_path)
    except Exception as error:
        return False, str(error)
    try:
        await tester.ensure_analysis_view()
        from fmst_analyzer.runner.task.inputs import load_bound_candidate
        load_bound_candidate(tester.global_config.target_diagnostic_reports_dir(), tester.global_config)
    except Exception as error:
        from fmst_analyzer.runner.repair_intake import UpstreamRepairInput, blocks_new_runner, persist_repair_input, persist_pipeline_failure
        try:
            reports = tester.global_config.target_diagnostic_reports_dir()
            persist_pipeline_failure(reports, error, "runner_input_preparation")
            if (getattr(tester.global_config, "runner_backend", "agent_container") != "agent_container"
                    or blocks_new_runner(error)):
                return False, str(error)
            source.validate_source(tester.fw_rootfs_path)
            repair_input = UpstreamRepairInput.capture(error=error, stage="runner_input_preparation",
                                                       rootfs=tester.fw_rootfs_path, target=tester.target_binary_path)
            persist_repair_input(reports, repair_input)
        except Exception as intake_error:
            return False, str(intake_error)
    try:
        source.validate_source(tester.fw_rootfs_path)
        kwargs = {"repair_input": repair_input} if repair_input is not None else {}
        result = await create_runner(tester.global_config).run(
            view=None if repair_input is not None else tester.view,
            rootfs=tester.fw_rootfs_path,
            runtime_workspace=runtime_workspace(tester.global_config),
            **kwargs,
        )
    except Exception as error:
        return False, str(error)
    if isinstance(result, TaskResult):
        return runner_succeeded(result), (
            f"backend={result.backend}, status={result.status}, task_id={result.task_id}, "
            f"container={result.container_id}, reports={result.report_dir}; independent replay not performed"
        )
    return runner_succeeded(result), (
        f"status={result.status}, attempts={len(result.attempts)}, "
        f"reports={tester.global_config.target_diagnostic_reports_dir() / 'runner_reports'}"
    )


__all__ = ["test_intervention_runner"]
