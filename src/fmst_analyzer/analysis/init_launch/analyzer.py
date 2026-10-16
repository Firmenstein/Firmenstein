"""InitLaunchAnalyzer: single-Agent rootfs launch-candidate discovery."""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_tracker, execution_snapshot, record_analysis_execution

from pathlib import Path

from loguru import logger

from fmst_basic.agent.usage_registry import scoped
from fmst_analyzer.analysis.base.artifact_lifecycle import preserve_stage_attempt
from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    write_model_json,
    write_text,
)
from fmst_analyzer.global_config import GlobalConfig

from .analyzer_schema import AnalysisGap, InitLaunchAnalysisResult, INIT_LAUNCH_SCHEMA_VERSION
from .launch_recipe_agent import LaunchRecipeAgent
from .target_identity import (
    enumerate_initialization_roots,
    enumerate_target_identity,
    finding_target_for_identity,
)


class InitLaunchAnalyzer:
    """Find concrete commands that launch one selected target ELF."""

    def __init__(self, global_config: GlobalConfig):
        self.global_config = global_config

    @scoped("InitLaunchAnalyzer")
    @record_analysis_execution
    @preserve_stage_attempt("init_launch")
    async def run(self, target_binary_path: Path, phase: str = "full") -> InitLaunchAnalysisResult:
        if phase not in {"static", "full"}:
            raise ValueError("phase must be 'static' or 'full'")
        rootfs = self._resolve_rootfs_path()
        target = Path(target_binary_path)
        identity = enumerate_target_identity(rootfs, target)
        initialization_roots = enumerate_initialization_roots(rootfs)
        if phase == "static" or not initialization_roots:
            result = InitLaunchAnalysisResult(execution=execution_snapshot(),
                schema_version=INIT_LAUNCH_SCHEMA_VERSION, phase=phase, target_identity=identity,
                finding_target=finding_target_for_identity(rootfs, identity),
                initialization_roots=initialization_roots, planning_findings={},
                analysis_gaps=[AnalysisGap(reason=(
                    "Static discovery identified initialization entries; target launch chains and preparation semantics have not been analyzed."
                    if initialization_roots else
                    "No firmware initialization entry was found; target launch applicability is unknown."
                ))],
            )
            return self.publish_reports(result)
        logger.info(
            f"[InitLaunchAnalyzer] target={identity.selected_rootfs_path!r} "
            f"rootfs={rootfs}"
        )

        agent = LaunchRecipeAgent(global_config=self.global_config)
        result = await execution_tracker().call(
            "launch", identity.selected_rootfs_path, lambda: agent.analyze(
                target_identity=identity,
                rootfs=rootfs,
                initialization_roots=initialization_roots,
                phase=phase,
            ),
        )
        if result is None:
            result = InitLaunchAnalysisResult(
                schema_version=INIT_LAUNCH_SCHEMA_VERSION, phase=phase,
                execution=execution_snapshot(), target_identity=identity,
                finding_target=finding_target_for_identity(rootfs, identity),
                initialization_roots=initialization_roots, planning_findings={},
                analysis_gaps=[],
            )
        result = result.model_copy(update={
            "execution": execution_snapshot(),
            "correction_history": agent.correction_history,
        })
        return self.publish_reports(result)

    def publish_reports(
        self,
        result: InitLaunchAnalysisResult,
        *,
        persist_json: bool = True,
    ) -> InitLaunchAnalysisResult:
        """Publish JSON and deterministic Markdown views for ``result``."""
        if self.global_config.workdir is None:
            logger.warning(
                "[InitLaunchAnalyzer] workdir is None; skipping persistence"
            )
            return result

        from . import reports

        out_dir = (
            self.global_config.target_diagnostic_reports_dir()
            / "init_launch_reports"
        )
        out_dir.mkdir(parents=True, exist_ok=True)

        # Remove prior per-recipe renderings so obsolete recipes cannot
        # survive a rerun. Preserve the top-level JSON bytes when the model is
        # unchanged: downstream Plan cache identity hashes that source file.
        for path in out_dir.iterdir():
            if path.name in {"init_launch_analysis_result.json", "index.md"}:
                continue
            if not persist_json and path.name in {"input_provenance.json", "input_provenance.md"}:
                continue
            removable_suffixes = {".json", ".md"} if persist_json else {".md"}
            if path.is_file() and path.suffix in removable_suffixes:
                path.unlink()
        if persist_json:
            result_path = out_dir / "init_launch_analysis_result.json"
            write_model_json(result_path, result)
            result = load_model_json(result_path, InitLaunchAnalysisResult)

        for recipe in result.launch_recipes.values():
            stem = reports.recipe_report_stem(recipe)
            recipe_path = out_dir / f"{stem}.json"
            if persist_json:
                write_model_json(recipe_path, recipe)
                recipe = load_model_json(recipe_path, type(recipe))
            write_text(out_dir / f"{stem}.md", reports.render_recipe(recipe))

        write_text(out_dir / "index.md", reports.render_index(result))
        logger.info(f"[InitLaunchAnalyzer] persisted output at {out_dir}")
        return result

    def _resolve_rootfs_path(self) -> Path:
        rootfs = self.global_config.fw_rootfs_path
        if rootfs is None:
            raise RuntimeError(
                "InitLaunchAnalyzer requires global_config.fw_rootfs_path"
            )
        path = Path(rootfs).resolve()
        if not path.is_dir():
            raise RuntimeError(f"InitLaunch rootfs is not a directory: {path}")
        return path


__all__ = ["InitLaunchAnalyzer"]
