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
    """Run only from exact persisted planning/generation artifacts."""
    await tester.ensure_analysis_view()
    try:
        result = await create_runner(tester.global_config).run(
            view=tester.view,
            rootfs=tester.fw_rootfs_path,
            runtime_workspace=runtime_workspace(tester.global_config),
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
