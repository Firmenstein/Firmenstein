"""Deterministic static candidate collection for IPCAnalyzer."""

from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_snapshot

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.nodes.common import FunctionAttr

from .identity import callsite_id, unresolved_item_id
from .peer.firmware_import_index import FirmwareImportIndex
from .registry import INTERACTION_APIS, InteractionRole
from .schema import (
    APIBindingKind,
    APISymbolBinding,
    AnalysisPhase,
    CallsiteAccounting,
    CallsiteDisposition,
    CallsiteFact,
    CodeLocation,
    IPCAnalysisResult,
    IPC_ANALYSIS_SCHEMA_VERSION,
    TargetProcess,
    UnresolvedItem,
    RawArgument,
    VerificationStatus,
)


FunctionKey = tuple[str, int, str]


@dataclass(frozen=True)
class CollectedInteractionFacts:
    """Resource anchors plus directly related non-anchor code context."""

    callsites: list[CallsiteFact]
    auxiliary_by_function: dict[FunctionKey, list[CallsiteFact]]
    ignored_auxiliary_count: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fact_sort_key(fact: CallsiteFact) -> tuple[str, int, int, str]:
    return (
        fact.location.binary_path,
        fact.location.function_ea,
        fact.location.ctree_index,
        fact.callee_name,
    )


def _function_key(fact: CallsiteFact) -> FunctionKey:
    return (
        fact.location.binary_path,
        fact.location.function_ea,
        fact.location.snapshot_hash,
    )


def _direct_identifier(expression: str | None) -> str | None:
    if expression is None:
        return None
    value = expression.strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        return None
    return value


def _semantic_snapshot(view: AnalysisView, fact: CallsiteFact):
    getter = getattr(view, "_get_callgraph_for_binary", None)
    if getter is None:
        return None
    callgraph = getter(Path(fact.location.binary_path).name)
    if callgraph is None:
        return None
    try:
        function = callgraph.get_node_by_ea(fact.location.function_ea)
    except ValueError:
        return None
    snapshot = getattr(function, "semantic_snapshot", None)
    if snapshot is None or snapshot.snapshot_hash != fact.location.snapshot_hash:
        return None
    return snapshot


def _component_for_expression(
    view: AnalysisView,
    fact: CallsiteFact,
    expression: str | None,
) -> frozenset[str]:
    identifier = _direct_identifier(expression)
    if identifier is None:
        return frozenset()
    snapshot = _semantic_snapshot(view, fact)
    if snapshot is None:
        return frozenset()
    try:
        records = snapshot.trace_variable_prop("<ipc-anchor-filter>", identifier).variables
    except (KeyError, ValueError):
        return frozenset()
    return frozenset(
        getattr(record, "identity", "") or record.varname
        for record in records
    )


def _anchor_handle_expression(fact: CallsiteFact) -> str | None:
    if fact.api_family == "socket_endpoint":
        return fact.arguments[0].expression if fact.arguments else None
    if fact.callee_name in {
        "shmget", "msgget", "semget", "shm_open", "mq_open", "sem_open",
    }:
        return fact.return_expression
    if INTERACTION_APIS[fact.callee_name].role is InteractionRole.FALLBACK_ACCESSOR:
        return fact.arguments[0].expression if fact.arguments else None
    return None


def _auxiliary_handle_expression(fact: CallsiteFact) -> str | None:
    if fact.callee_name in {"socket", "ftok"}:
        return fact.return_expression
    return fact.arguments[0].expression if fact.arguments else None


def _matching_anchor_ids(
    view: AnalysisView,
    auxiliary: CallsiteFact,
    anchors: list[CallsiteFact],
) -> list[str]:
    """Return anchors related by the existing direct-variable component only."""
    if auxiliary.callee_name == "ftok":
        auxiliary_component = _component_for_expression(
            view, auxiliary, auxiliary.return_expression,
        )
        if not auxiliary_component:
            return []
        matches = []
        for anchor in anchors:
            if _function_key(anchor) != _function_key(auxiliary):
                continue
            if not anchor.api_family.startswith("sysv_") or not anchor.arguments:
                continue
            key_component = _component_for_expression(
                view, anchor, anchor.arguments[0].expression,
            )
            if auxiliary_component & key_component:
                matches.append(anchor.callsite_id)
        return sorted(matches)

    auxiliary_component = _component_for_expression(
        view, auxiliary, _auxiliary_handle_expression(auxiliary),
    )
    if not auxiliary_component:
        return []
    matches = []
    for anchor in anchors:
        if (
            _function_key(anchor) != _function_key(auxiliary)
            or anchor.api_family != auxiliary.api_family
        ):
            continue
        anchor_component = _component_for_expression(
            view, anchor, _anchor_handle_expression(anchor),
        )
        if auxiliary_component & anchor_component:
            matches.append(anchor.callsite_id)
    return sorted(matches)


class StaticIPCCollector:
    """Collect immutable interaction-call facts without invoking an Agent."""

    def __init__(
        self,
        rootfs: Path,
        firmware_sha256: str,
        firmware_import_index: FirmwareImportIndex,
    ) -> None:
        self.rootfs = Path(rootfs).absolute().resolve()
        self.firmware_sha256 = firmware_sha256
        self.firmware_import_index = firmware_import_index
        self._hash_cache: dict[Path, str] = {}

    def collect_process(
        self,
        view: AnalysisView,
        target_process: TargetProcess,
    ) -> CollectedInteractionFacts:
        facts: dict[str, CallsiteFact] = {}
        for api_name in sorted(INTERACTION_APIS):
            api = INTERACTION_APIS[api_name]
            for callsite in view.collect_api_callsites(api_name):
                binary = view.lib_dep_graph.get_node_by_name(callsite.binary_name)
                if binary is None:
                    raise RuntimeError(
                        f"Callsite binary {callsite.binary_name!r} is absent from LibDepGraph"
                    )
                binary_path = Path(binary.binary_path).absolute().resolve()
                relative_path = self._relative(binary_path)
                binary_sha256 = self._hash(binary_path)
                if callsite.snapshot_hash is None or callsite.ctree_index is None:
                    raise RuntimeError(
                        f"Callsite {callsite} lacks immutable CTree snapshot identity"
                    )
                function_name = view.get_decompiled_name(
                    callsite.binary_name, callsite.caller_ea,
                )
                identity = callsite_id(
                    relative_path,
                    binary_sha256,
                    callsite.caller_ea,
                    callsite.snapshot_hash,
                    callsite.ctree_index,
                )
                fact = CallsiteFact(
                    callsite_id=identity,
                    location=CodeLocation(
                        binary_path=relative_path,
                        binary_sha256=binary_sha256,
                        function_name=function_name,
                        function_ea=callsite.caller_ea,
                        snapshot_hash=callsite.snapshot_hash,
                        ctree_index=callsite.ctree_index,
                        source_ea=callsite.source_ea,
                        line_number=callsite.line_number,
                        column_number=callsite.column_number,
                    ),
                    api_family=api.family,
                    mechanism_hint=api.mechanism_hint,
                    callee_name=callsite.callee_name,
                    call_kind=callsite.call_kind,
                    expression_text=callsite.expression_text,
                    arguments=[
                        RawArgument(
                            index=argument.index,
                            expression=argument.value,
                        )
                        for argument in sorted(
                            callsite.args, key=lambda argument: argument.index,
                        )
                    ],
                    return_expression=(
                        callsite.return_var.value
                        if callsite.return_var is not None
                        else None
                    ),
                    api_binding=self._api_symbol_binding(
                        view,
                        callsite.binary_name,
                        binary_path,
                        callsite.callee_name,
                        callsite.call_kind,
                    ),
                )
                previous = facts.get(identity)
                if previous is not None and previous != fact:
                    raise RuntimeError(f"Conflicting facts for callsite identity {identity}")
                facts[identity] = fact
        ordered = sorted(
            facts.values(),
            key=lambda fact: (
                fact.location.binary_path,
                fact.location.function_ea,
                fact.location.ctree_index,
                fact.callee_name,
            ),
        )
        anchors = [
            fact for fact in ordered
            if INTERACTION_APIS[fact.callee_name].role
            is InteractionRole.RESOURCE_ANCHOR
        ]
        fallback_accessors = [
            fact for fact in ordered
            if INTERACTION_APIS[fact.callee_name].role
            is InteractionRole.FALLBACK_ACCESSOR
        ]
        auxiliary = [
            fact for fact in ordered
            if INTERACTION_APIS[fact.callee_name].role
            is InteractionRole.AUXILIARY
        ]

        # An accessor is a candidate only when the existing direct-variable
        # graph cannot tie it to exactly one resource getter/open in the same
        # CTree snapshot. This preserves opaque external shmid/queue/semaphore
        # entry points without sending every ordinary operation to an Agent.
        for fact in fallback_accessors:
            matches = _matching_anchor_ids(view, fact, anchors)
            if len(matches) == 1:
                auxiliary.append(fact)
            else:
                anchors.append(fact)

        anchors.sort(key=_fact_sort_key)
        auxiliary_by_function: dict[FunctionKey, list[CallsiteFact]] = defaultdict(list)
        ignored = 0
        for fact in auxiliary:
            matches = _matching_anchor_ids(view, fact, anchors)
            if matches:
                auxiliary_by_function[_function_key(fact)].append(fact)
            else:
                ignored += 1
        return CollectedInteractionFacts(
            callsites=anchors,
            auxiliary_by_function={
                key: sorted(items, key=_fact_sort_key)
                for key, items in sorted(auxiliary_by_function.items())
            },
            ignored_auxiliary_count=ignored,
        )

    def static_result(
        self,
        target_process: TargetProcess,
        callsites: list[CallsiteFact],
        semantic_unresolved_items: list[UnresolvedItem] | None = None,
    ) -> IPCAnalysisResult:
        unresolved_items: list[UnresolvedItem] = list(
            semantic_unresolved_items or []
        )
        accounting: list[CallsiteAccounting] = []
        grouped = group_callsites_by_function(callsites)
        unresolved_by_callsite: dict[str, str] = {}
        for key, members in grouped.items():
            subject_id = f"{key[0]}::{key[1]}::{key[2]}"
            identity = unresolved_item_id(
                "function", subject_id, "site_resolution_required",
            )
            unresolved_items.append(UnresolvedItem(
                unresolved_item_id=identity,
                subject_kind="function",
                subject_id=subject_id,
                reason="Full phase Site Resolution Agent has not analyzed this function.",
                missing_evidence=[
                    "resource identity and interaction semantics for candidate callsites",
                ],
                runtime_evidence_requests=[],
            ))
            for member in members:
                unresolved_by_callsite[member.callsite_id] = identity

        for fact in callsites:
            accounting.append(CallsiteAccounting(
                callsite_id=fact.callsite_id,
                disposition=CallsiteDisposition.UNRESOLVED,
                endpoint_ids=[],
                unresolved_item_ids=[unresolved_by_callsite[fact.callsite_id]],
                reason="Static phase records the candidate without interpreting its arguments.",
            ))

        return IPCAnalysisResult(execution=execution_snapshot(),
            schema_version=IPC_ANALYSIS_SCHEMA_VERSION,
            phase=AnalysisPhase.STATIC,
            firmware_sha256=self.firmware_sha256,
            target_process=target_process,
            planning_findings={},
            callsites=callsites,
            channels=[],
            dependency_assessments=[],
            unresolved_items=unresolved_items,
            callsite_accounting=accounting,
        )

    def collect_semantic_unresolved_items(
        self,
        view: AnalysisView,
        target_process: TargetProcess,
    ) -> list[UnresolvedItem]:
        """Expose every explicitly recorded Hex-Rays failure to IPC output."""
        entries: list[UnresolvedItem] = []
        for binary, callgraph in view.adg.get_binary_callgraphs().items():
            relative = self._relative(Path(binary.binary_path).absolute().resolve())
            for failure in callgraph.semantic_failures:
                subject_id = (
                    f"{target_process.executable_path}::{relative}::"
                    f"{failure.function_ea:#x}"
                )
                identity = unresolved_item_id(
                    "function", subject_id, "ctree_snapshot_unavailable",
                )
                entries.append(UnresolvedItem(
                    unresolved_item_id=identity,
                    subject_kind="function",
                    subject_id=subject_id,
                    reason=(
                        f"IDA could not produce a CTree semantic snapshot for "
                        f"{relative}::{failure.function_name}; IPC callsites in "
                        "this function are not statically enumerable."
                    ),
                    missing_evidence=[failure.error],
                    runtime_evidence_requests=[],
                ))
        return sorted(entries, key=lambda item: item.unresolved_item_id)

    def _api_symbol_binding(
        self,
        view: AnalysisView,
        binary_name: str,
        binary_path: Path,
        callee_name: str,
        call_kind: str,
    ) -> APISymbolBinding:
        # Undefined dynamic symbols are an exact ELF fact.  Their eventual
        # provider is deliberately not inferred here: symbol interposition,
        # loader scope, dlopen, and missing runtime libraries make that a
        # semantic/runtime question rather than a universally exact static one.
        if binary_path in self.firmware_import_index.symbol_to_elfs.get(
            callee_name, set(),
        ):
            return APISymbolBinding(
                kind=APIBindingKind.DYNAMIC_IMPORT,
                symbol=callee_name,
                binary_path=None,
                binary_sha256=None,
                status=VerificationStatus.VERIFIED_STATIC,
                reason=(
                    "source ELF declares this symbol undefined in its dynamic "
                    "symbol table; runtime provider intentionally not inferred"
                ),
            )

        if call_kind != "direct":
            return APISymbolBinding(
                kind=APIBindingKind.UNRESOLVED,
                symbol=callee_name,
                binary_path=None,
                binary_sha256=None,
                status=VerificationStatus.UNRESOLVED,
                reason=f"{call_kind} CTree call has no exact local definition binding",
            )

        callgraph = view.lib_dep_graph.get_callgraph_by_name(binary_name)
        if callgraph is None or not callgraph.has_node_by_name(callee_name):
            return APISymbolBinding(
                kind=APIBindingKind.UNRESOLVED,
                symbol=callee_name,
                binary_path=None,
                binary_sha256=None,
                status=VerificationStatus.UNRESOLVED,
                reason="callee is absent from the onboarded CallGraph",
            )
        try:
            callee = callgraph.get_node_by_name(callee_name)
        except ValueError as error:
            return APISymbolBinding(
                kind=APIBindingKind.UNRESOLVED,
                symbol=callee_name,
                binary_path=None,
                binary_sha256=None,
                status=VerificationStatus.UNRESOLVED,
                reason=f"callee lookup is ambiguous: {error}",
            )

        if not callee.has_attr(FunctionAttr.EXTERNAL):
            binary = view.lib_dep_graph.get_node_by_name(binary_name)
            assert binary is not None
            path = Path(binary.binary_path).absolute().resolve()
            return APISymbolBinding(
                kind=APIBindingKind.IN_BINARY,
                symbol=callee_name,
                binary_path=self._relative(path),
                binary_sha256=self._hash(path),
                status=VerificationStatus.VERIFIED_STATIC,
                reason="callee has an in-binary implementation",
            )

        return APISymbolBinding(
            kind=APIBindingKind.UNRESOLVED,
            symbol=callee_name,
            binary_path=None,
            binary_sha256=None,
            status=VerificationStatus.UNRESOLVED,
            reason=(
                "callee is not a proven local definition and the source ELF "
                "does not expose a matching undefined dynamic symbol"
            ),
        )

    def _relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.rootfs).as_posix()
        except ValueError as error:
            raise ValueError(f"ELF path escapes firmware rootfs: {path}") from error

    def _hash(self, path: Path) -> str:
        if path not in self._hash_cache:
            self._hash_cache[path] = _sha256(path)
        return self._hash_cache[path]


def group_callsites_by_function(
    callsites: list[CallsiteFact],
) -> dict[FunctionKey, list[CallsiteFact]]:
    grouped: dict[FunctionKey, list[CallsiteFact]] = defaultdict(list)
    for fact in callsites:
        grouped[_function_key(fact)].append(fact)
    return {
        key: sorted(value, key=lambda fact: fact.location.ctree_index)
        for key, value in sorted(grouped.items())
    }


__all__ = [
    "CollectedInteractionFacts",
    "StaticIPCCollector",
    "group_callsites_by_function",
]
