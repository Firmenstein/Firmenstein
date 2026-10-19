"""Firmware analysis, intervention planning, and artifact generation."""

from __future__ import annotations

from pathlib import Path
from typing import List

from loguru import logger

from fmst_basic.utils.file_utils import index_paths_by_basename, resolve_unique_basename

from .analysis.base.code_analyzer.analysis_view import AnalysisView
from .global_config import GlobalConfig
from .framework import runtime_workspace
from .graphs.lib_dep_graph import LibDepGraph
from .nodes.binary import BinaryNode
from .synthesizer.intervention_generator.architecture import detect_generator_arch


class FirmAnalyzer:
    """Run the single production Analyzer → Plan → Unit Generator pipeline."""

    def __init__(
        self,
        firmware_metadata: dict,
        target_binary: str,
        global_config: GlobalConfig,
        skip_synthesis: bool = False,
        run_after_generation: bool = False,
        runner_max_attempts: int | None = None,
        runner_timeout_seconds: float = 7200.0,
    ) -> None:
        self._fw_metadata = firmware_metadata
        self.image_name = firmware_metadata["image_name"]
        self.initial_target_name = target_binary
        self.global_config = global_config
        self.skip_synthesis = skip_synthesis
        self.run_after_generation = run_after_generation
        self.runner_max_attempts = runner_max_attempts
        self.runner_timeout_seconds = runner_timeout_seconds
        self.workdir = global_config.workdir

        self.fw_rootfs_path = Path(firmware_metadata["rootfs_path"])
        self.global_config.fw_rootfs_path = self.fw_rootfs_path
        self.all_binaries: List[str] = firmware_metadata.get("all_binaries", [])
        self.binary_paths_by_name = index_paths_by_basename(
            Path(path) for path in self.all_binaries
        )
        self.initial_target_path = resolve_unique_basename(
            self.initial_target_name,
            self.binary_paths_by_name,
            self.fw_rootfs_path,
            purpose="target binary",
        )
        self.lib_dep_graph: LibDepGraph | None = None
        self._firmware_import_index = None
        self._stage = "input"
        self._runner_entered = False
        self._view_for_runner = None
        self._active_generator = None
        logger.info(
            f"[FirmAnalyzer] image={self.image_name}, "
            f"target={self.initial_target_name}"
        )

    async def run(self) -> None:
        from fmst_basic.FirmProbe.admission import inspect_target_input
        from .analysis.base.report_io import write_model_json, write_text
        from .analysis.base.finding_reports import render_fields
        self.global_config.current_target = self.initial_target_name
        report_dir = self.global_config.target_diagnostic_reports_dir()
        try:
            self._stage = "input"
            admission = inspect_target_input(self.fw_rootfs_path, self.initial_target_path)
            write_model_json(report_dir / "input_admission.json", admission)
            write_text(report_dir / "input_admission.md", "# Analyzer input admission\n\n" + render_fields(admission.model_dump(mode="json")))
            if self.run_after_generation and not self.skip_synthesis:
                from .runner.identity import tree_sha256
                from .analysis.base.input_provenance import file_digest
                from fmst_basic.utils.guest_paths import resolve_guest_file
                selected = resolve_guest_file(self.fw_rootfs_path, admission.resolved_path)
                self._repair_source_identity = {"target_sha256": file_digest(selected[1]),
                                                "rootfs_sha256": tree_sha256(self.fw_rootfs_path)}
            await self._run_pipeline()
        except BaseException as error:
            from .runner.repair_intake import blocks_new_runner, persist_pipeline_failure
            try:
                persist_pipeline_failure(report_dir, error, self._stage)
            except Exception as recording_error:
                error.add_note(f"Failure record could not be saved: {type(recording_error).__name__}")
            if (not isinstance(error, Exception) or self._stage == "input"
                    or not self.run_after_generation or self.skip_synthesis or self._runner_entered
                    or getattr(self.global_config, "runner_backend", "agent_container") != "agent_container"
                    or blocks_new_runner(error)):
                raise
            await self._run_upstream_repair(error)
        logger.info("[FirmAnalyzer] pipeline complete")

    async def _run_pipeline(self) -> None:
        self._stage = "dependency_graph"
        self.lib_dep_graph = LibDepGraph(
            rootfs_path=self.fw_rootfs_path,
            global_config=self.global_config,
            decompiler="ida",
        )
        self.lib_dep_graph.add_binary(self.initial_target_path)
        target = self.lib_dep_graph.get_node_by_name(self.initial_target_name)
        if target is None:
            raise RuntimeError(f"Initial target {self.initial_target_name} not found in LibDepGraph")
        self.global_config.current_target = target.name
        await self._analyze_target(target)

    async def _run_upstream_repair(self, error: Exception) -> None:
        from .runner import create_runner, runner_succeeded
        from .runner.repair_intake import UpstreamRepairInput, persist_repair_input
        from .analysis.base.report_io import write_text
        import json
        repair = UpstreamRepairInput.capture(error=error, stage=self._stage,
                                             rootfs=self.fw_rootfs_path, target=self.initial_target_path)
        repair.generator_materials_current = bool(self._active_generator and
                                                   getattr(self._active_generator, "_generation_started", False))
        if (repair.target_sha256 != self._repair_source_identity["target_sha256"]
                or repair.rootfs_sha256 != self._repair_source_identity["rootfs_sha256"]):
            raise ValueError("Target/rootfs changed during upstream analysis; refusing Runner handoff") from error
        persist_repair_input(self.global_config.target_diagnostic_reports_dir(), repair)
        self._stage, self._runner_entered = "runner", True
        try:
            result = await create_runner(self.global_config, max_attempts=self.runner_max_attempts,
                                         runtime_timeout_seconds=self.runner_timeout_seconds).run(
                view=self._view_for_runner, rootfs=self.fw_rootfs_path,
                runtime_workspace=runtime_workspace(self.global_config), repair_input=repair)
        except BaseException as runner_error:
            from .runner.repair_intake import persist_pipeline_failure
            try:
                persist_pipeline_failure(self.global_config.target_diagnostic_reports_dir() / "runner_handoff_failure",
                                         runner_error, "runner")
            except Exception as recording_error:
                runner_error.add_note("Runner failure record could not be saved: " + type(recording_error).__name__)
            raise
        write_text(self.global_config.target_diagnostic_reports_dir() / "upstream_repair_outcome.json",
                   json.dumps({"schema_version": 1, "failed_stage": repair.failed_stage,
                               "runner_status": result.status, "runner_succeeded": runner_succeeded(result)}, indent=2))
        if not runner_succeeded(result):
            raise RuntimeError(f"Runner ended with status={result.status}; original upstream failure is retained") from error

    async def _analyze_target(self, target: BinaryNode) -> None:
        assert self.lib_dep_graph is not None
        self._stage = "decompile"
        await self.lib_dep_graph.decompile_analysis(target)
        api_dep_graph = self.lib_dep_graph.get_decompiled_adg(target)
        api_dep_graph.dump_full_graph(self.global_config.graph_dots_dir)
        view = AnalysisView(adg=api_dep_graph)
        self._stage = "ctree_validation"
        failures = {
            name: result
            for name, result in view.ctree_integrity_check().items()
            if result.missing_count or result.extra_count
        }
        if failures:
            raise RuntimeError(f"CTree decompile-analysis integrity failed: {failures}")
        self._view_for_runner = view

        await self._run_analyzers(target, view)
        if self.skip_synthesis:
            logger.info("[FirmAnalyzer] skipping intervention planning and generation")
            return
        await self._run_synthesizer(view)

    async def _run_analyzers(self, target: BinaryNode, view: AnalysisView) -> None:
        """Persist the five independent Analyzer JSON sources."""
        from fmst_analyzer.analysis.file_resolver import FileResolver
        from fmst_analyzer.analysis.init_launch import InitLaunchAnalyzer
        from fmst_analyzer.analysis.ipc_analyzer import IPCAnalyzer, PeerMatchingContext
        from fmst_analyzer.analysis.ipc_analyzer.peer import build_firmware_import_index
        from fmst_analyzer.analysis.network_analyzer import NetworkAnalyzer
        from fmst_analyzer.analysis.process_lifecycle import ProcessLifecycleAnalyzer

        if self._firmware_import_index is None:
            self._firmware_import_index = build_firmware_import_index(
                self.fw_rootfs_path
            )
        assert self.lib_dep_graph is not None
        peer_context = PeerMatchingContext(
            lib_dep_graph=self.lib_dep_graph,
            firmware_import_index=self._firmware_import_index,
            main_exec=target.binary_path.resolve(),
            firmware_sha256=self._fw_metadata["sha256"],
            target_argv0=self.initial_target_name,
        )
        self._stage = "ipc"
        ipc = await IPCAnalyzer(self.global_config).run(
            view, peer_context=peer_context
        )
        ipc.execution.require_complete()
        logger.info(
            f"[FirmAnalyzer] IPCAnalyzer: {len(ipc.callsites)} callsites, "
            f"{len(ipc.channels)} channels"
        )
        self._stage = "file"
        file_result = await FileResolver(self.global_config).run(view, phase="full")
        file_result.execution.require_complete()
        logger.info(
            f"[FirmAnalyzer] FileResolver: {len(file_result.callsites)} callsites"
        )
        self._stage = "network"
        network = await NetworkAnalyzer(self.global_config).run(view, phase="full")
        network.execution.require_complete()
        logger.info(
            f"[FirmAnalyzer] NetworkAnalyzer: {len(network.callsites)} callsites, "
            f"{len(network.analyses)} analyses"
        )
        self._stage = "process"
        process = await ProcessLifecycleAnalyzer(self.global_config).run(
            view, phase="full"
        )
        process.execution.require_complete()
        logger.info(
            f"[FirmAnalyzer] ProcessLifecycleAnalyzer: "
            f"{len(process.assessments)} assessments"
        )
        self._stage = "init_launch"
        launch = await InitLaunchAnalyzer(self.global_config).run(target.binary_path)
        launch.execution.require_complete()
        logger.info(
            f"[FirmAnalyzer] InitLaunchAnalyzer: "
            f"{len(launch.launch_recipes)} launch recipes"
        )

    async def _run_synthesizer(self, view: AnalysisView) -> None:
        from fmst_analyzer.synthesizer.intervention_generator import (
            InterventionGenerator,
        )
        from fmst_analyzer.synthesizer.intervention_plan_analyzer import (
            InterventionPlanAnalyzer,
        )

        self._stage = "plan"
        await InterventionPlanAnalyzer(self.global_config).run(view)
        self._stage = "generation"
        self._active_generator = InterventionGenerator(self.global_config)
        result = await self._active_generator.run(
            view=view,
            image_name=self.image_name,
            arch=detect_generator_arch(view.root.binary_path),
            diagnostic_reports_root=(
                self.global_config.target_diagnostic_reports_dir()
            ),
            trace_root=(
                self.global_config.target_agent_debug_dir()
                / "intervention_generator"
            ),
            interventions_root=self.workdir / "interventions",
            test_harnesses_root=self.workdir / "test_harnesses",
            env_scripts_root=self.workdir / "env_scripts",
            iib_api_abspath=runtime_workspace(self.global_config) / "fmst-iib-api",
        )
        if not self.run_after_generation and (result.not_ready_count or result.skipped_count):
            raise RuntimeError(
                f"intervention generation persisted {result.not_ready_count} "
                f"not-ready and {result.skipped_count} skipped Unit(s); "
                "inspect intervention_generation_reports. An explicitly requested "
                "Runner can consume the published candidate for repair."
            )
        if self.run_after_generation:
            # The selected backend consumes the original published candidate.
            # Container success retains the actual interacted-with instance.
            from fmst_analyzer.runner import create_runner, runner_succeeded
            from fmst_analyzer.runner.task.inputs import load_bound_candidate

            self._stage = "runner_input_preparation"
            if getattr(self.global_config, "runner_backend", "agent_container") == "agent_container":
                load_bound_candidate(self.global_config.target_diagnostic_reports_dir(), self.global_config)

            self._stage, self._runner_entered = "runner", True
            runner_result = await create_runner(
                self.global_config,
                max_attempts=self.runner_max_attempts,
                runtime_timeout_seconds=self.runner_timeout_seconds,
            ).run(
                view=view,
                rootfs=self.fw_rootfs_path,
                runtime_workspace=runtime_workspace(self.global_config),
            )
            if not runner_succeeded(runner_result):
                raise RuntimeError(
                    f"Runner ended with status={runner_result.status}; "
                    "inspect runner_task_reports (container) or runner_reports (legacy)"
                )

    @staticmethod
    def _project_root() -> Path:
        return Path(__file__).resolve().parents[2]

    @staticmethod
    def _workspace_root() -> Path:
        """Return the outer workspace that owns Firmenstein and GuestWeave."""
        return FirmAnalyzer._project_root().parent

__all__ = ["FirmAnalyzer"]
