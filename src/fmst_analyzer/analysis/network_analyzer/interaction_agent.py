"""Layered resource-root discovery with bounded parallel fallback."""
from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from pathlib import Path

from loguru import logger

from fmst_basic.agent.analysis_agent import gather_agent_tasks
from fmst_analyzer.analysis.base.execution import execution_tracker
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    CodeAnalyzerAgent,
)
from fmst_analyzer.analysis.base.coverage_flow import resolve_coverage_flows
from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICallResolver
from fmst_analyzer.global_config import GlobalConfig

from .analyzer_schema import (
    NetworkCallsite,
    NetworkResourceAgentResult,
)
from .controller import (
    finalize_resource_result,
    normalize_resource_result,
    validate_resource_result,
)
from .findings import NetworkInteractionResult
from .interaction_prompt import NETWORK_INTERACTION_TASK


_SOCKET_ROOT_APIS = frozenset({"socket", "socketpair"})
_ACCEPTED_SOCKET_ROOT_APIS = frozenset({"accept", "accept4"})
_SELF_CONTAINED_FAMILIES = frozenset({
    "resolver",
    "host_query",
    "protocol_query",
    "service_query",
    "interface",
})
_PARALLEL_WAVES = (
    "socket",
    "accepted_socket",
    "environment_query",
)


def resource_seed_sort_key(fact: NetworkCallsite) -> tuple:
    """Return deterministic layered-wave then code-location order."""
    priority = resource_anchor_wave(fact)
    location = fact.location
    return (
        priority,
        location.binary_path,
        location.function_ea,
        location.ctree_index,
        fact.api_name,
        fact.callsite_id,
    )


def resource_anchor_wave(fact: NetworkCallsite) -> int:
    """Return the semantic scheduling wave for one network callsite.

    Socket constructors run first, then accepted sockets and fd-less queries.
    These priorities never exclude a seed: observation of one invocation does
    not establish complete coverage of every context of a shared helper.
    """
    if fact.api_name in _SOCKET_ROOT_APIS:
        return 0
    if fact.api_name in _ACCEPTED_SOCKET_ROOT_APIS:
        return 1
    if fact.api_family in _SELF_CONTAINED_FAMILIES:
        return 2
    return len(_PARALLEL_WAVES)


def _catalog_entry(fact: NetworkCallsite) -> dict:
    location = fact.location
    return {
        "callsite_id": fact.callsite_id,
        "binary_name": location.binary_name,
        "function_name": location.function_name,
        "line_number": location.line_number,
        "column_number": location.column_number,
        "api_name": fact.api_name,
        "expression_text": fact.expression_text,
        "return_expression": fact.return_expression,
    }


def _trace_component(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9_.@+-]+", "_", value).strip("_")
    return rendered or "unnamed"


class NetworkInteractionAgent:
    def __init__(
        self,
        global_config: GlobalConfig,
        concurrency_sem: asyncio.Semaphore,
    ) -> None:
        self.global_config = global_config
        self.concurrency_sem = concurrency_sem
        self.execution = execution_tracker()
        self._coverage_resolver_by_view: dict[int, CoveredAPICallResolver] = {}

    def _coverage_resolver(
        self, view: AnalysisView,
    ) -> CoveredAPICallResolver:
        key = id(view)
        if key not in self._coverage_resolver_by_view:
            self._coverage_resolver_by_view[key] = CoveredAPICallResolver(view)
        return self._coverage_resolver_by_view[key]

    async def analyze(
        self,
        view: AnalysisView,
        root_binary: str,
        callsites: list[NetworkCallsite],
        *,
        phase: str = "full",
    ) -> list[NetworkInteractionResult]:
        if phase != "full":
            return []
        by_id = {fact.callsite_id: fact for fact in callsites}
        if len(by_id) != len(callsites):
            raise ValueError("Network callsite catalog contains duplicate identities")
        catalog = sorted(callsites, key=resource_seed_sort_key)
        analyses: list[NetworkInteractionResult] = []
        wave_counts = Counter(
            _PARALLEL_WAVES[wave]
            for fact in callsites
            if (wave := resource_anchor_wave(fact)) < len(_PARALLEL_WAVES)
        )
        logger.info(
            f"[NetworkInteractionAgent] starting resource discovery for "
            f"{len(callsites)} callsites "
            f"(socket={wave_counts['socket']}, "
            f"accepted_socket={wave_counts['accepted_socket']}, "
            f"environment_query={wave_counts['environment_query']})"
        )

        for wave, wave_name in enumerate(_PARALLEL_WAVES):
            seeds = [
                fact for fact in catalog if resource_anchor_wave(fact) == wave
            ]
            if phase != "full" or not seeds:
                continue
            batches = await self._run_anchor_wave(
                view,
                root_binary,
                seeds,
                catalog,
                wave_name=wave_name, phase=phase,
            )
            for _, batch in batches:
                analyses.extend(batch)
        analyses.extend(await self._run_fallback_wave(
            view,
            root_binary,
            [fact for fact in catalog if resource_anchor_wave(fact) == len(_PARALLEL_WAVES)],
            phase=phase, catalog=catalog,
        ))
        final_covered = {
            callsite_id
            for analysis in analyses
            for callsite_id in analysis.analysis.callsite_ids
        }
        missing = sorted(set(by_id) - final_covered - self.execution.record.unsuccessful_subjects("network"))
        if missing:
            raise RuntimeError(
                "resource-anchor analysis failed to cover catalog callsites: "
                f"{missing}"
            )
        return sorted(analyses, key=lambda item: item.analysis.interaction_id)

    async def _run_fallback_wave(
        self,
        view: AnalysisView,
        root_binary: str,
        fallback: list[NetworkCallsite],
        *, phase: str, catalog: list[NetworkCallsite] | None = None,
    ) -> list[NetworkInteractionResult]:
        """Analyze independent orphan operations with bounded concurrency."""
        if phase != "full":
            return []
        if fallback:
            logger.info(
                f"[NetworkInteractionAgent] launching fallback wave with "
                f"{len(fallback)} orphan callsites"
            )
        batches = await self._run_anchor_wave(
            view,
            root_binary,
            sorted(fallback, key=resource_seed_sort_key),
            sorted(catalog if catalog is not None else fallback, key=resource_seed_sort_key),
            wave_name="fallback", phase=phase,
        )
        return [
            analysis
            for _, batch in batches
            for analysis in batch
        ]

    async def _run_anchor_wave(
        self,
        view: AnalysisView,
        root_binary: str,
        seeds: list[NetworkCallsite],
        catalog: list[NetworkCallsite],
        *,
        wave_name: str,
        phase: str,
    ) -> list[tuple[NetworkCallsite, list[NetworkInteractionResult]]]:
        """Analyze independent anchors concurrently against one catalog."""
        if phase != "full" or not seeds:
            return []

        async def run_one(seed: NetworkCallsite) -> list[NetworkInteractionResult]:
            result = await self.execution.call(
                "network", seed.callsite_id, lambda: self._analyze_resource(
                    view,
                    root_binary,
                    seed,
                    catalog, phase=phase,
                ),
            )
            return result or []

        logger.info(
            f"[NetworkInteractionAgent] launching {wave_name} wave with "
            f"{len(seeds)} anchors"
        )
        results = await gather_agent_tasks(*(run_one(seed) for seed in seeds))
        return list(zip(seeds, results, strict=True))

    async def _analyze_resource(
        self,
        view: AnalysisView,
        root_binary: str,
        seed: NetworkCallsite,
        catalog: list[NetworkCallsite],
        *, phase: str,
    ) -> list[NetworkInteractionResult]:
        if phase != "full":
            return []
        location = seed.location
        seed_json = json.dumps(
            seed.model_dump(mode="json"), ensure_ascii=False, indent=2
        )
        catalog_json = json.dumps(
            [_catalog_entry(fact) for fact in catalog],
            ensure_ascii=False,
            indent=2,
        )
        _, total_sites = view.collect_effective_callsites(
            location.binary_name, location.function_name, max_sites=0,
        )
        target_sites, _ = view.collect_effective_callsites(
            location.binary_name, location.function_name, max_sites=total_sites,
        )
        target_context = {
            "analyzed_process": root_binary,
            "representative_target_decision_points": [
                site.model_dump(mode="json") for site in target_sites
            ],
            "scope": (
                "These are structural navigation candidates, not proof of argument/branch "
                "feasibility or an exhaustive list of invocations within each function. "
                "These callers are navigation starting points, not process entry points or "
                "terminal observations. For a seed in a library, library callers returned "
                "by navigation tools need a path from the analyzed process before they "
                "can define a target interaction."
            ),
        }
        user_message = (
            f"## Process analysis scope\n{json.dumps(target_context, ensure_ascii=False, indent=2)}\n\n"
            f"## Callsite catalog\n{catalog_json}\n\n"
            f"## Seed callsite\n{seed_json}"
        )
        trace_dir: Path | None = None
        if self.global_config.workdir is not None:
            trace_dir = (
                self.global_config.target_agent_debug_dir()
                / "network_analyzer"
                / "resources"
            )
        digest = seed.callsite_id.rsplit(":", 1)[-1]
        trace_name = (
            f"{_trace_component(location.binary_name)}__"
            f"resource__{digest}"
        )
        agent = CodeAnalyzerAgent(
            agent_name="NetworkInteractionAgent",
            task_prompt=NETWORK_INTERACTION_TASK,
            output_format=NetworkResourceAgentResult,
            model=self.global_config.diagnosis_model,
            provider=self.global_config.agent_provider,
        )

        def validator(output) -> None:
            validate_resource_result(
                output,
                seed.callsite_id,
                catalog,
                view,
            )

        async with self.concurrency_sem:
            self.execution.check_dispatch()
            output = await agent.analyze(
                user_message=user_message,
                view=view,
                binary_name=location.binary_name,
                function_name=location.function_name,
                trace_dir=trace_dir,
                trace_name=trace_name,
                callsite_line=location.line_number,
                initial_focus_lines=[location.line_number],
                output_validator=validator,
            )
        output = normalize_resource_result(output, catalog, view=view)
        resolver = self._coverage_resolver(view)
        output = output.model_copy(update={
            "analyses": [
                draft.model_copy(update={
                    "coverage_flows": resolve_coverage_flows(
                        resolver, draft.coverage_flows,
                    ),
                })
                for draft in output.analyses
            ],
        })
        return finalize_resource_result(root_binary, seed.callsite_id, output)


__all__ = [
    "NetworkInteractionAgent",
    "resource_anchor_wave",
    "resource_seed_sort_key",
]
