"""Deterministic IPC anchors plus bounded Agent semantics."""

from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_tracker, execution_snapshot, record_analysis_execution

import asyncio
import hashlib
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from fmst_basic.agent.analysis_agent import (
    gather_agent_tasks,
)
from fmst_basic.agent.usage_registry import scoped
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICallResolver
from fmst_analyzer.analysis.base.artifact_lifecycle import preserve_stage_attempt
from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.graphs.lib_dep_graph import LibDepGraph

from .agent_schema import (
    PeerVerificationOutput,
)
from .candidate_index import ChannelCandidateIndex, mechanism_primitives
from .collector import StaticIPCCollector, group_callsites_by_function
from .controller import IPCResultController
from .peer.firmware_import_index import FirmwareImportIndex
from .peer_verification import PeerVerificationAgent
from .reports import persist_result
from .schema import (
    AnalysisPhase,
    IPCAnalysisResult,
    IPCChannel,
    LocalImpact,
    PeerCandidateEvidence,
    PeerRequirement,
    TargetProcess,
)
from .site_resolution import SiteResolutionAgent


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class PeerMatchingContext:
    """Firmware-wide backends and identities used to verify direct peers."""

    lib_dep_graph: LibDepGraph
    firmware_import_index: FirmwareImportIndex
    main_exec: Path
    firmware_sha256: str
    target_argv0: str | None = None


class IPCAnalyzer:
    """Verify one target's direct IPC peers and target-local dependency impact."""

    def __init__(self, global_config: GlobalConfig) -> None:
        self.global_config = global_config
        self.execution = execution_tracker()
        self._site_agent = SiteResolutionAgent(global_config)
        self._peer_agent = PeerVerificationAgent(global_config)

    @scoped("IPCAnalyzer")
    @record_analysis_execution
    @preserve_stage_attempt("ipc")
    async def run(
        self,
        view: AnalysisView,
        peer_context: PeerMatchingContext,
        *,
        phase: str | AnalysisPhase = AnalysisPhase.FULL,
    ) -> IPCAnalysisResult:
        phase = AnalysisPhase(phase)
        self.execution = execution_tracker()
        rootfs = Path(self.global_config.fw_rootfs_path).absolute().resolve()
        main_exec = Path(peer_context.main_exec).absolute().resolve()
        target_process = self._target_process(
            rootfs,
            main_exec,
            argv0=peer_context.target_argv0,
        )
        controller = IPCResultController(rootfs)
        candidate_index = ChannelCandidateIndex(
            rootfs, peer_context.firmware_import_index,
        )
        aggregate = await self._analyze_process(
            view=view,
            target_process=target_process,
            phase=phase,
            peer_context=peer_context,
            candidate_index=candidate_index,
            controller=controller,
        )

        aggregate = persist_result(
            aggregate,
            self.global_config.target_diagnostic_reports_dir() / "ipc_reports",
        )
        logger.info(
            "[IPCAnalyzer] {} verified peers, {} callsites, {} channels, {} unresolved items",
            sum(
                candidate.status.value.startswith("verified")
                for channel in aggregate.channels
                for candidate in channel.peer_candidates
            ),
            len(aggregate.callsites),
            len(aggregate.channels),
            len(aggregate.unresolved_items),
        )
        return aggregate

    async def _analyze_process(
        self,
        *,
        view: AnalysisView,
        target_process: TargetProcess,
        phase: AnalysisPhase,
        peer_context: PeerMatchingContext,
        candidate_index: ChannelCandidateIndex,
        controller: IPCResultController,
    ) -> IPCAnalysisResult:
        collector = StaticIPCCollector(
            Path(self.global_config.fw_rootfs_path),
            peer_context.firmware_sha256,
            peer_context.firmware_import_index,
        )
        collected = collector.collect_process(view, target_process)
        facts = collected.callsites
        logger.info(
            "[IPC anchor scope] {} anchors, {} directly attached auxiliary "
            "callsites, {} unrelated auxiliary callsites ignored",
            len(facts),
            sum(len(items) for items in collected.auxiliary_by_function.values()),
            collected.ignored_auxiliary_count,
        )
        static_result = collector.static_result(
            target_process,
            facts,
            semantic_unresolved_items=collector.collect_semantic_unresolved_items(
                view, target_process,
            ),
        )
        if phase is AnalysisPhase.STATIC:
            return static_result

        grouped = group_callsites_by_function(facts)
        concurrency = max(1, self.global_config.agent_concurrency_limit)
        semaphore = asyncio.Semaphore(concurrency)
        trace_dir = self._trace_dir("site_resolution")

        async def resolve(function_key, members):
            async with semaphore:
                tracker = self.execution
                group_id = str(function_key)
                output = await tracker.call("site", group_id, lambda: self._site_agent.resolve_function(
                    phase=AnalysisPhase.FULL,
                    view=view,
                    target_process=target_process,
                    callsites=members,
                    auxiliary_callsites=collected.auxiliary_by_function.get(function_key, []),
                    trace_dir=trace_dir,
                ))
                # The one function query accounts for each exact candidate it analyzed.
                outcome = tracker.record.tasks.pop(f"site:{group_id}")
                for fact in members:
                    tracker.record.tasks[f"site:{fact.callsite_id}"] = outcome.model_copy(
                        update={"subject_id": fact.callsite_id},
                    )
                return output

        completed = await gather_agent_tasks(
            *(resolve(key, members) for key, members in grouped.items())
        )
        outputs = completed
        auxiliary_callsites = [
            fact
            for items in collected.auxiliary_by_function.values()
            for fact in items
        ]
        result = controller.merge_site_resolutions(
            static_result,
            [output for output in outputs if output is not None],
            auxiliary_callsites=auxiliary_callsites,
            coverage_resolver=CoveredAPICallResolver(view),
        )

        # Site Resolution already answers whether target-local code consumes
        # peer availability/data.  A channel whose dependency is explicitly
        # ``none/none`` cannot affect this target, so searching the firmware
        # for an opposite endpoint would only spend structural-analysis cost
        # on a fire-and-forget notification.  Unknown or incomplete
        # assessments remain assessable; uncertainty is never treated as a
        # negative result.
        dependency_by_channel = {
            dependency.channel_id: dependency
            for dependency in result.dependency_assessments
        }
        assessable_channels = []
        for channel in result.channels:
            if not mechanism_primitives(channel.mechanism):
                continue
            dependency = dependency_by_channel.get(channel.channel_id)
            if dependency is not None and (
                dependency.peer_requirement is PeerRequirement.NONE
                and dependency.local_impact is LocalImpact.NONE
            ):
                continue
            assessable_channels.append(channel)
        candidate_batch = candidate_index.prepare_many(
            assessable_channels,
            peer_context.lib_dep_graph,
            exclude_paths={target_process.executable_path},
        )
        logger.info(
            "[IPC candidate index] {} deterministic structural candidates "
            "across {} channels",
            sum(
                len(items)
                for items in candidate_batch.candidates_by_channel.values()
            ),
            len(assessable_channels),
        )
        for channel in assessable_channels:
            result = controller.attach_retrieval_candidates(
                result,
                channel.channel_id,
                candidate_batch.candidates_by_channel[channel.channel_id],
            )
            result = controller.attach_candidate_coverage_gaps(
                result,
                channel.channel_id,
                candidate_batch.gaps_by_channel[channel.channel_id],
            )

        logger.info(
            "[IPC peer] {} unique provider-entry/caller matched candidates are "
            "ready for source-backed review",
            len({
                candidate.executable_path
                for candidates in candidate_batch.candidates_by_channel.values()
                for candidate in candidates
            }),
        )
        current_channels = {
            channel.channel_id: channel for channel in result.channels
        }
        verifications = await self._verify_peers(
            view=view,
            target_process=result.target_process,
            channels=[
                current_channels[channel.channel_id]
                for channel in assessable_channels
                if candidate_batch.candidates_by_channel.get(channel.channel_id)
            ],
            prepared_candidates=candidate_batch.candidates_by_channel,
            peer_context=peer_context,
            candidate_index=candidate_index,
            phase=phase,
        )
        for channel_id, verification in verifications:
            if verification is not None:
                result = controller.merge_peer_verification(result, channel_id, verification)
        result = result.model_copy(update={"execution": execution_snapshot()})
        return result

    async def _verify_peers(
        self,
        *,
        view: AnalysisView,
        target_process: TargetProcess,
        channels: list[IPCChannel],
        prepared_candidates: dict[str, list[PeerCandidateEvidence]],
        peer_context: PeerMatchingContext,
        candidate_index: ChannelCandidateIndex,
        phase: AnalysisPhase,
    ) -> list[tuple[str, PeerVerificationOutput | None]]:
        """Run independent source-backed peer verifications concurrently."""
        if phase is not AnalysisPhase.FULL:
            return []
        concurrency = max(1, self.global_config.agent_concurrency_limit)
        logger.info(
            "[IPC peer verification] running {} source-backed Agent tasks "
            "with concurrency={}",
            len(channels),
            concurrency,
        )
        semaphore = asyncio.Semaphore(concurrency)
        trace_dir = self._trace_dir("peer_verification")

        async def assess(channel: IPCChannel):
            async with semaphore:
                output = await self.execution.call(
                    "peer", channel.channel_id, lambda: self._peer_agent.verify_channel(
                        phase=AnalysisPhase.FULL,
                        view=view,
                        firmware_index=peer_context.firmware_import_index,
                        firmware_sha256=peer_context.firmware_sha256,
                        rootfs=Path(self.global_config.fw_rootfs_path),
                        target_process=target_process,
                        channel=channel,
                        candidates=prepared_candidates.get(channel.channel_id, []),
                        trace_dir=trace_dir,
                        source_function_lookup=lambda path, name: candidate_index.source_function(
                            path, name, peer_context.lib_dep_graph,
                        ),
                    ),
                )
                return channel.channel_id, output

        completed = await gather_agent_tasks(
            *(assess(channel) for channel in channels)
        )
        return sorted(completed, key=lambda item: item[0])

    def _trace_dir(self, stage: str) -> Path | None:
        if not self.global_config.workdir or not self.global_config.current_target:
            return None
        path = self.global_config.target_agent_debug_dir() / "ipc" / stage
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _target_process(
        rootfs: Path,
        executable: Path,
        *,
        argv0: str | None = None,
    ) -> TargetProcess:
        relative = executable.relative_to(rootfs).as_posix()
        sha = _sha256(executable)
        return TargetProcess(
            executable_path=relative,
            executable_sha256=sha,
            argv0=argv0 or executable.name,
        )


__all__ = ["IPCAnalyzer", "PeerMatchingContext"]
