"""Explicit production entry for the autonomous task-container backend."""
import os
import uuid
from pathlib import Path
from .host import ContainerTask
from .inputs import prepare
from .options import RunnerOptions


class ContainerRehostingRunner:
    def __init__(self, global_config, *, runtime_timeout_seconds=7200.0, max_attempts=None,
                 service_goal=None, delivery_mode=None, resources=None):
        self.config = global_config
        self.timeout = runtime_timeout_seconds
        self.service_goal = service_goal
        self.delivery_mode = delivery_mode
        self.resources = resources
        if max_attempts is not None:
            raise ValueError("agent_container uses a shared time budget; max_attempts is only supported by legacy")

    async def run(self, *, view, rootfs: Path, runtime_workspace: Path):
        # Read once at Runner entry, so a queued pipeline can receive explicit
        # delivery options without restarting its upstream analysis.
        options = RunnerOptions()
        workdir = getattr(self.config, "workdir", None)
        options_path = Path(workdir) / "runner-options.json" if workdir else None
        if options_path is not None and options_path.exists():
            options = RunnerOptions.model_validate_json(options_path.read_text())
        if self.delivery_mode is not None:
            options.delivery_mode = RunnerOptions(delivery_mode=self.delivery_mode).delivery_mode
        if self.resources is not None:
            options.resources = RunnerOptions(resources=self.resources).resources
        output = self.config.target_diagnostic_reports_dir() / "runner_task_reports" / uuid.uuid4().hex
        task = ContainerTask(output=output, target=self.config.current_target,
            image=os.environ.get("FMST_RUNNER_AGENT_IMAGE", "firmenstein/runner-agent:py312-runtime"),
            budget_seconds=self.timeout, delivery_mode=options.delivery_mode, resources=options.resources)
        try:
            task.create()
            spec = prepare(task, config=self.config, view=view, rootfs=rootfs, framework=runtime_workspace,
                           service_goal=self.service_goal)
            task.configure(spec)
            return await task.run()
        except BaseException as error:
            task.result.reason = str(error)
            if task.result.status in {"preparing", "repairing"}:
                import asyncio
                task.stop("cancelled" if isinstance(error, asyncio.CancelledError) else "error")
            raise
