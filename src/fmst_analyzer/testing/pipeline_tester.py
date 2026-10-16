from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import List

from loguru import logger

from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.graphs.lib_dep_graph import LibDepGraph
from fmst_analyzer.graphs.api_dep_graph import ApiDepGraph
from fmst_analyzer.nodes.binary import BinaryNode
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.input_provenance import cache_matches_inputs
from fmst_basic.utils.file_utils import (
    index_paths_by_basename,
    resolve_unique_basename,
)

from .stages import STAGE_REGISTRY, STAGE_ORDER


@dataclass
class _AnalyzerMetaShim:
    """Backward-compat shim exposing the metadata fields that test stages
    used to read from `tester.analyzer.foo`. After the multi-target refactor
    PipelineTester no longer instantiates a FirmAnalyzer up front (FirmAnalyzer
    is now per-target and async-construction-heavy), but the test stages
    themselves don't need a real analyzer — they only need the firmware
    metadata. Stages can keep using `tester.analyzer.target_binary_name` etc.
    """
    target_binary_name: str
    fw_rootfs_path: Path
    candidate_binary_paths: List[Path] = field(default_factory=list)
    binary_name2path: dict = field(default_factory=dict)


def _cache_matches_phase(result: object, requested_phase: str) -> bool:
    """Accept only new caches that explicitly record the requested phase."""
    fields_set = getattr(result, "model_fields_set", set())
    return (
        "phase" in fields_set
        and getattr(result, "phase", None) == requested_phase
        and getattr(getattr(result, "execution", None), "status", None) == "complete"
    )


class PipelineTester:
    """Pipeline smoke test runner.

    Loads firmware metadata, builds the firmware-wide LibDepGraph, then
    projects an ApiDepGraph rooted at the test target on demand. Stages
    consume `tester.lib_dep_graph` / `tester.api_dep_graph` / `tester.view`.
    """

    def _inputs_match(self, stage, phase, result):
        return cache_matches_inputs(self.global_config, stage, phase, self.target_binary_path,
                                    result, rootfs=getattr(self, "fw_rootfs_path", None))

    def __init__(self,
                 firmware_metadata: dict,
                 target_binary: str,
                 global_config: GlobalConfig,
                 clear_graph_cache: bool = False):
        self.image_name = firmware_metadata["image_name"]
        self.arch = firmware_metadata.get("arch")
        self.firmware_sha256 = firmware_metadata["sha256"]
        self.target_binary_name = target_binary
        self.global_config = global_config
        self.clear_graph_cache = clear_graph_cache

        self.fw_rootfs_path = Path(firmware_metadata["rootfs_path"])
        # Expose to GlobalConfig so analyzers (FileResolver) can reach it
        # without having to plumb through the call chain.
        self.global_config.fw_rootfs_path = self.fw_rootfs_path
        all_binaries: List[str] = firmware_metadata.get("all_binaries", [])
        self.binary_paths_by_name = index_paths_by_basename(
            Path(path) for path in all_binaries
        )
        self.binary_name2path = {
            name: paths[0]
            for name, paths in self.binary_paths_by_name.items()
            if len(paths) == 1
        }
        self.target_binary_path = resolve_unique_basename(
            target_binary,
            self.binary_paths_by_name,
            self.fw_rootfs_path,
            purpose="test target binary",
        )
        self.candidate_binary_paths: List[Path] = [self.target_binary_path]

        # Scope per-target output dirs (diagnostic_reports / agent_debug)
        # under <workdir>/<kind>/<target>/. Test subcommand is single-target,
        # so this can be set at construction time.
        self.global_config.current_target = self.target_binary_path.name

        # Backward-compat shim for old test stages still reading
        # `tester.analyzer.target_binary_name` etc.
        self.analyzer = _AnalyzerMetaShim(
            target_binary_name=self.target_binary_name,
            fw_rootfs_path=self.fw_rootfs_path,
            candidate_binary_paths=self.candidate_binary_paths,
            binary_name2path=self.binary_name2path,
        )

        # Pipeline artifacts — populated by stages or ensure_* methods
        self.lib_dep_graph: LibDepGraph = None
        self.api_dep_graph: ApiDepGraph = None
        self.target_binary_node: BinaryNode = None
        self.view: AnalysisView = None
        self._ipc_result: dict[str, object] = {}
        # Separate cache slots per phase so the static-only stage doesn't
        # hand a phase="full" result to a later consumer (and vice versa).
        self._file_resolver_result: dict[str, object] = {}
        self._network_analyzer_result: dict[str, object] = {}
        self._process_lifecycle_result: dict[str, object] = {}
        self._init_launch_result: dict[str, object] = {}

    async def run(self, stages: List[str]):
        """Run requested stages sequentially, stop on first failure."""
        if stages == ["all"]:
            stages = list(STAGE_ORDER)

        results = {}
        for stage in stages:
            if stage not in STAGE_REGISTRY:
                logger.error(f"[TEST] Unknown stage: {stage}")
                results[stage] = (False, f"unknown stage")
                break

            handler = STAGE_REGISTRY[stage]
            logger.info(f"[TEST] Running stage: {stage}")
            try:
                passed, detail = await handler(self)
            except Exception as e:
                logger.exception(f"[TEST] Stage {stage} raised exception")
                passed, detail = False, f"exception: {e}"

            results[stage] = (passed, detail)
            status = "PASS" if passed else "FAIL"
            logger.info(f"[TEST] {stage} ... {status} ({detail})")

            if not passed:
                logger.error(f"[TEST] Stopping at failed stage: {stage}")
                break

        # Summary
        total = len(results)
        passed_count = sum(1 for p, _ in results.values() if p)
        logger.info(f"[TEST] === {passed_count}/{total} stages passed ===")
        return results

    # ------------------------------------------------------------------
    # Lazy ensure_* helpers
    # ------------------------------------------------------------------

    async def ensure_lib_dep_graph(self) -> LibDepGraph:
        """Build (or load from cache) the LibDepGraph rooted at the test target."""
        if self.lib_dep_graph is None:
            from fmst_basic.FirmProbe.admission import inspect_target_input
            from fmst_analyzer.analysis.base.report_io import write_model_json
            admission = inspect_target_input(self.fw_rootfs_path, self.target_binary_path)
            write_model_json(self.global_config.target_diagnostic_reports_dir() / "input_admission.json", admission)
            self.lib_dep_graph = LibDepGraph(
                rootfs_path=self.fw_rootfs_path,
                global_config=self.global_config,
                decompiler="ida",
                use_cache=not self.clear_graph_cache,
            )
            for path in self.candidate_binary_paths:
                self.lib_dep_graph.add_binary(path)
            self.target_binary_node = self.lib_dep_graph.get_node_by_name(
                self.target_binary_name
            )
            if self.target_binary_node is None:
                raise RuntimeError(
                    f"Target {self.target_binary_name} not found in LibDepGraph"
                )
        return self.lib_dep_graph

    async def ensure_api_dep_graph(self) -> ApiDepGraph:
        """Decompile the test target as an analysis root and return its ADG.
        Cascade decompilation handles CallGraph + CTree snapshots and generated
        code artifacts for every binary in scope."""
        await self.ensure_lib_dep_graph()
        if self.api_dep_graph is None:
            await self.lib_dep_graph.decompile_analysis(
                self.target_binary_node,
            )
            self.api_dep_graph = self.lib_dep_graph.get_decompiled_adg(
                self.target_binary_node,
            )
        return self.api_dep_graph

    # Convenience aliases used by some stages
    async def ensure_graphs(self):
        await self.ensure_lib_dep_graph()
        await self.ensure_api_dep_graph()

    async def ensure_analysis_view(self):
        """Create the single query handle for the target-rooted ADG."""
        await self.ensure_api_dep_graph()
        if self.view is None:
            self.view = AnalysisView(adg=self.api_dep_graph)

    async def ensure_ipc_result(self, phase: str = "full"):
        """Run (or return cached) IPCAnalyzer result for the current target.

        ``phase='static'`` guarantees zero Agent turns. ``phase='full'``
        includes Site Resolution and assembly-only direct-peer verification.

        Caching layers (in priority order):
            1. Process-level cache in ``self._ipc_result``, keyed by phase.
            2. Disk cache at
               ``diagnostic_reports/ipc_reports/ipc_analysis_result.json``.
               Both the explicit phase and schema version must match;
               an empty full result is still a valid full-phase cache.
            3. Fresh run: ensure graphs + CTree semantics and invoke IPCAnalyzer
               with the appropriate ``peer_context``.
        """
        from fmst_analyzer.analysis.ipc_analyzer import (
            IPCAnalyzer,
            IPCAnalysisResult,
            IPC_ANALYSIS_SCHEMA_VERSION,
            PeerMatchingContext,
        )
        from fmst_analyzer.analysis.ipc_analyzer.peer import (
            build_firmware_import_index,
        )
        from fmst_analyzer.analysis.ipc_analyzer.reports import persist_result

        if phase not in {"static", "full"}:
            raise ValueError("IPC phase must be 'static' or 'full'")

        expected_target = IPCAnalyzer._target_process(
            self.fw_rootfs_path.resolve(), self.target_binary_path.resolve(),
            argv0=self.target_binary_name,
        )

        def _matches_cache(result: IPCAnalysisResult) -> bool:
            return (
                result.phase.value == phase
                and result.execution.status == "complete"
                and result.schema_version == IPC_ANALYSIS_SCHEMA_VERSION
                and result.target_process == expected_target
                and result.firmware_sha256 == self.firmware_sha256
                and self._inputs_match("ipc", phase, result)
            )

        cached = self._ipc_result.get(phase)
        if cached is not None and _matches_cache(cached):
            return cached

        if self.global_config.workdir is not None:
            ipc_reports_dir = (
                self.global_config.target_diagnostic_reports_dir() / "ipc_reports"
            )
            json_path = ipc_reports_dir / "ipc_analysis_result.json"
            if json_path.exists():
                try:
                    raw = json.loads(json_path.read_text(encoding="utf-8"))
                    cached_phase = raw.get("phase")
                    cached_schema = raw.get("schema_version")
                    if (
                        cached_phase != phase
                        or cached_schema != IPC_ANALYSIS_SCHEMA_VERSION
                    ):
                        logger.info(
                            f"[ensure_ipc_result] cached JSON is incompatible "
                            f"(phase={cached_phase}, schema={cached_schema}); "
                            f"requested phase={phase}, schema="
                            f"{IPC_ANALYSIS_SCHEMA_VERSION}; rerunning IPCAnalyzer"
                        )
                        result = None
                    else:
                        result = IPCAnalysisResult.model_validate(raw)
                except Exception as exc:
                    logger.warning(
                        f"[ensure_ipc_result] failed to load cached JSON "
                        f"at {json_path}: {exc}; falling through to rerun"
                    )
                else:
                    if result is not None and _matches_cache(result):
                        logger.info(
                            f"[ensure_ipc_result] reusing cached "
                            f"ipc_analysis_result.json "
                            f"({len(result.callsites)} callsites, "
                            f"{len(result.channels)} channels); "
                            f"skipping IPCAnalyzer run (phase={phase})"
                        )
                        persist_result(result, ipc_reports_dir, persist_json=False)
                        self._ipc_result[phase] = result
                        return result
            elif ipc_reports_dir.exists():
                # Legacy-md-only detection looks under callsites/ now;
                # bare *.md at the root (pre-C layout) still signals
                # the old format.
                legacy = any(
                    p for p in ipc_reports_dir.glob("*.md") if p.name != "index.md"
                )
                new_layout_without_json = (
                    ipc_reports_dir / "callsites"
                ).exists() and not json_path.exists()
                if legacy or new_layout_without_json:
                    logger.warning(
                        f"[ensure_ipc_result] found md reports at "
                        f"{ipc_reports_dir} but no ipc_analysis_result.json; "
                        f"cannot rehydrate the structured IPC result from md. "
                        f"Rerunning IPCAnalyzer — this will regenerate both."
                    )

        await self.ensure_analysis_view()
        analyzer = IPCAnalyzer(self.global_config)

        logger.info(
            f"[ensure_ipc_result] building FirmwareImportIndex on "
            f"{self.fw_rootfs_path}"
        )
        firmware_import_index = build_firmware_import_index(self.fw_rootfs_path)
        peer_context = PeerMatchingContext(
            lib_dep_graph=self.lib_dep_graph,
            firmware_import_index=firmware_import_index,
            main_exec=self.target_binary_path.resolve(),
            firmware_sha256=self.firmware_sha256,
            target_argv0=self.target_binary_name,
        )

        result = await analyzer.run(
            self.view,
            peer_context=peer_context,
            phase=phase,
        )
        self._ipc_result[phase] = result
        return result

    async def ensure_file_resolver_result(self, phase: str = "full"):
        """Run (or return cached) FileResolver result for the current target.

        phase="static" runs through Node 4.5 and persists (no LLM);
        phase="full" runs
        the whole pipeline. The cache is keyed on phase so the static
        stage never silently hands a truncated result to a consumer
        expecting agent reports. This helper never triggers IPCAnalyzer;
        FileResolver optionally reads a previously persisted IPC JSON.
        """
        from fmst_analyzer.analysis.file_resolver import (
            FileResolver,
            FileResolverResult,
        )
        from fmst_analyzer.analysis.base.finding_binding import FindingTarget

        expected_target = FindingTarget.from_file(self.fw_rootfs_path, self.target_binary_path)
        cached = self._file_resolver_result.get(phase)
        if cached is not None and _cache_matches_phase(cached, phase) and cached.finding_target == expected_target and self._inputs_match("file", phase, cached):
            return cached

        if self.global_config.workdir is not None:
            json_path = (
                self.global_config.target_diagnostic_reports_dir()
                / "file_reports"
                / "file_resolver_result.json"
            )
            if json_path.exists():
                try:
                    result = FileResolverResult.model_validate_json(
                        json_path.read_text(encoding="utf-8")
                    )
                except Exception as exc:
                    logger.warning(
                        f"[ensure_file_resolver_result] failed to load "
                        f"cached JSON at {json_path}: {exc}; rerunning"
                    )
                else:
                    if _cache_matches_phase(result, phase) and result.finding_target == expected_target and self._inputs_match("file", phase, result):
                        logger.info(
                            "[ensure_file_resolver_result] reusing cached "
                            f"phase={phase} result from {json_path}"
                        )
                        # JSON is the source of truth.  Re-publish the pure
                        # Markdown/per-resource views on every disk-cache hit
                        # so renderer changes cannot leave stale reports.
                        FileResolver(self.global_config).publish_reports(
                            result, persist_json=False
                        )
                        self._file_resolver_result[phase] = result
                        return result
                    logger.info(
                        "[ensure_file_resolver_result] cached identity, phase, execution "
                        "or input provenance does not match the current request; rerunning"
                    )

        await self.ensure_analysis_view()
        resolver = FileResolver(self.global_config)
        result = await resolver.run(self.view, phase=phase)
        self._file_resolver_result[phase] = result
        return result

    async def ensure_network_analyzer_result(self, phase: str = "full"):
        """Run (or return cached) NetworkAnalyzer result for the current target.

        NetworkAnalyzer reads optional IPC/File coverage from persisted JSON.
        This helper never chain-triggers either upstream analyzer.
        """
        from fmst_analyzer.analysis.network_analyzer import NetworkAnalyzer
        from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
            NETWORK_ANALYSIS_SCHEMA_VERSION,
            NetworkAnalysisResult,
        )

        from fmst_analyzer.analysis.base.finding_binding import FindingTarget

        expected_target = FindingTarget.from_file(self.fw_rootfs_path, self.target_binary_path)
        cached = self._network_analyzer_result.get(phase)
        if cached is not None and _cache_matches_phase(cached, phase) and cached.finding_target == expected_target and self._inputs_match("network", phase, cached):
            return cached

        # Reuse only a cache that explicitly records the requested phase.
        # Output cardinality cannot identify the phase: a valid full run
        # may produce zero network interactions.
        if self.global_config.workdir is not None:
            reports_dir = (
                self.global_config.target_diagnostic_reports_dir()
                / "network_reports"
            )
            json_path = reports_dir / "network_analysis_result.json"
            if json_path.exists():
                try:
                    result = NetworkAnalysisResult.model_validate_json(
                        json_path.read_text(encoding="utf-8")
                    )
                except Exception as exc:
                    logger.warning(
                        f"[ensure_network_analyzer_result] failed to load "
                        f"cached JSON at {json_path}: {exc}; falling "
                        f"through to rerun"
                    )
                else:
                    if (
                        result.schema_version == NETWORK_ANALYSIS_SCHEMA_VERSION
                        and _cache_matches_phase(result, phase)
                        and result.finding_target == expected_target
                        and self._inputs_match("network", phase, result)
                    ):
                        logger.info(
                            f"[ensure_network_analyzer_result] reusing cached "
                            f"network_analysis_result.json "
                            f"({len(result.callsites)} callsites, "
                            f"{len(result.analyses)} analyses); "
                            f"skipping NetworkAnalyzer run"
                        )
                        NetworkAnalyzer(self.global_config).publish_reports(
                            result, persist_json=False
                        )
                        self._network_analyzer_result[phase] = result
                        return result
                    cached_phase = (
                        result.phase
                        if "phase" in result.model_fields_set
                        else "legacy"
                    )
                    logger.info(
                        f"[ensure_network_analyzer_result] cached JSON phase="
                        f"{cached_phase!r} does not match requested phase="
                        f"{phase!r}; rerunning NetworkAnalyzer"
                    )

        await self.ensure_analysis_view()
        analyzer = NetworkAnalyzer(self.global_config)
        result = await analyzer.run(
            self.view,
            phase=phase,
        )
        self._network_analyzer_result[phase] = result
        return result

    async def ensure_process_lifecycle_result(self, phase: str = "full"):
        """Run or reuse ProcessLifecycleAnalyzer for the current target.

        The analyzer reads optional upstream coverage from persisted IPC,
        File, and Network JSON. This helper never chain-triggers those stages.
        Cache identity includes both schema version and requested phase.
        """
        from fmst_analyzer.analysis.process_lifecycle import (
            PROCESS_LIFECYCLE_SCHEMA_VERSION,
            ProcessLifecycleAnalysisResult,
            ProcessLifecycleAnalyzer,
        )
        from fmst_analyzer.analysis.base.finding_binding import FindingTarget

        if phase not in {"static", "full"}:
            raise ValueError("phase must be 'static' or 'full'")
        expected_target = FindingTarget.from_file(self.fw_rootfs_path, self.target_binary_path)

        cached = self._process_lifecycle_result.get(phase)
        if cached is not None and _cache_matches_phase(cached, phase) and cached.finding_target == expected_target and self._inputs_match("process", phase, cached):
            return cached

        # Reuse only a cache that explicitly records the requested phase.
        # Empty issue sets are valid in either phase.
        if self.global_config.workdir is not None:
            reports_dir = (
                self.global_config.target_diagnostic_reports_dir()
                / "process_lifecycle_reports"
            )
            json_path = reports_dir / "process_lifecycle_analysis_result.json"
            if json_path.exists():
                try:
                    result = ProcessLifecycleAnalysisResult.model_validate_json(
                        json_path.read_text(encoding="utf-8")
                    )
                except Exception as exc:
                    logger.warning(
                        f"[ensure_process_lifecycle_result] failed to load "
                        f"cached JSON at {json_path}: {exc}; falling "
                        f"through to rerun"
                    )
                else:
                    if (
                        result.schema_version
                        == PROCESS_LIFECYCLE_SCHEMA_VERSION
                        and _cache_matches_phase(result, phase)
                        and result.finding_target == expected_target
                        and self._inputs_match("process", phase, result)
                    ):
                        logger.info(
                            f"[ensure_process_lifecycle_result] reusing cached "
                            f"process_lifecycle_analysis_result.json "
                            f"({len(result.callsites)} callsites, "
                            f"{len(result.assessments)} assessments); skipping "
                            f"ProcessLifecycleAnalyzer run"
                        )
                        ProcessLifecycleAnalyzer(self.global_config).publish_reports(
                            result, persist_json=False
                        )
                        self._process_lifecycle_result[phase] = result
                        return result
                    cached_phase = (
                        result.phase
                        if "phase" in result.model_fields_set
                        else "legacy"
                    )
                    logger.info(
                        f"[ensure_process_lifecycle_result] cached JSON phase="
                        f"{cached_phase!r} does not match requested phase="
                        f"{phase!r}; rerunning ProcessLifecycleAnalyzer"
                    )

        await self.ensure_analysis_view()
        analyzer = ProcessLifecycleAnalyzer(self.global_config)
        result = await analyzer.run(
            self.view,
            phase=phase,
        )
        self._process_lifecycle_result[phase] = result
        return result

    async def ensure_init_launch_result(self, phase: str = "full"):
        """Run or load rootfs-only launch-candidate discovery."""
        from fmst_analyzer.analysis.init_launch import InitLaunchAnalyzer
        from fmst_analyzer.analysis.init_launch.analyzer_schema import (
            InitLaunchAnalysisResult,
        )
        from fmst_analyzer.analysis.init_launch.target_identity import (
            enumerate_target_identity,
            finding_target_for_identity,
        )

        if phase not in {"static", "full"}:
            raise ValueError("phase must be 'static' or 'full'")

        rootfs = self.global_config.fw_rootfs_path
        if rootfs is None:
            raise RuntimeError(
                "InitLaunch cache validation requires fw_rootfs_path"
            )
        expected_identity = enumerate_target_identity(
            Path(rootfs), self.target_binary_path,
        )
        expected_target = finding_target_for_identity(Path(rootfs), expected_identity)
        cached = self._init_launch_result.get(phase)
        if (cached is not None and cached.target_identity == expected_identity
                and cached.finding_target == expected_target and _cache_matches_phase(cached, phase)
                and self._inputs_match("init_launch", phase, cached)):
            return cached

        if self.global_config.workdir is not None:
            reports_dir = (
                self.global_config.target_diagnostic_reports_dir()
                / "init_launch_reports"
            )
            json_path = reports_dir / "init_launch_analysis_result.json"
            if json_path.exists():
                try:
                    result = InitLaunchAnalysisResult.model_validate_json(
                        json_path.read_text(encoding="utf-8")
                    )
                except Exception as exc:
                    logger.warning(
                        f"[ensure_init_launch_result] failed to load "
                        f"cached JSON at {json_path}: {exc}; falling "
                        f"through to rerun"
                    )
                else:
                    if (result.target_identity == expected_identity
                            and result.finding_target == expected_target
                            and _cache_matches_phase(result, phase)
                            and self._inputs_match("init_launch", phase, result)):
                        logger.info(
                            f"[ensure_init_launch_result] reusing schema {result.schema_version} phase={phase} "
                            f"cache with {len(result.launch_recipes)} recipes"
                        )
                        InitLaunchAnalyzer(self.global_config).publish_reports(
                            result, persist_json=False
                        )
                        self._init_launch_result[phase] = result
                        return result
                    logger.info(
                        "[ensure_init_launch_result] cached target identity "
                        "or phase does not match selected target; rerunning"
                    )

        analyzer = InitLaunchAnalyzer(self.global_config)
        result = await analyzer.run(self.target_binary_path, phase=phase)
        self._init_launch_result[phase] = result
        return result
