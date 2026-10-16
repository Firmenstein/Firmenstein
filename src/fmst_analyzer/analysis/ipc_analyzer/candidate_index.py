"""Deterministic provider-entry/caller matching for one IPC Channel.

LIEF identifies user-space providers and actual symbol importers. IDA's
structural graph then proves a direct executable-to-endpoint witness without
invoking Hex-Rays. Shared-library membership is capability evidence only; it
never makes every linker a process candidate.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import re

import lief
import networkx as nx

from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.graphs.base_graph import EdgeType
from fmst_analyzer.graphs.lib_dep_graph import LibDepGraph
from fmst_analyzer.nodes.common import FunctionAttr

from .peer._lief_lock import LIEF_PARSE_LOCK
from .peer.firmware_import_index import FirmwareImportIndex
from .schema import (
    CandidateSource,
    EndpointCallPath,
    EndpointRole,
    IdentifierRelation,
    IPCChannel,
    IPCMechanism,
    PeerCandidateEvidence,
    PeerEndpointLocation,
    StructuralFunctionRef,
)


_ENDPOINT_PRIMITIVES: dict[IPCMechanism, tuple[str, ...]] = {
    IPCMechanism.SYSV_SHM: ("shmget",),
    IPCMechanism.SYSV_MSG: ("msgget",),
    IPCMechanism.SYSV_SEM: ("semget",),
    IPCMechanism.POSIX_SHM: ("shm_open",),
    IPCMechanism.POSIX_MQ: ("mq_open",),
    IPCMechanism.POSIX_SEM: ("sem_open",),
    IPCMechanism.UDS: ("bind", "connect", "sendto", "sendmsg"),
    IPCMechanism.LOOPBACK_SOCKET: ("bind", "connect", "sendto", "sendmsg"),
    IPCMechanism.FIFO: ("mkfifo", "mkfifoat", "open", "openat", "fopen"),
}

_NAMED_RESOURCE_KINDS: dict[IPCMechanism, frozenset[str]] = {
    IPCMechanism.UDS: frozenset({"uds_path"}),
    IPCMechanism.FIFO: frozenset({"fifo_path"}),
    IPCMechanism.POSIX_SHM: frozenset({"posix_name", "posix_shm_name"}),
    IPCMechanism.POSIX_MQ: frozenset({"posix_name", "posix_mq_name"}),
    IPCMechanism.POSIX_SEM: frozenset({"posix_name", "posix_sem_name"}),
}

_CONSTANT_SECTIONS = (".rodata", ".data", ".sdata", ".data.rel.ro")

_SOURCE_PRIORITY = {
    CandidateSource.CONSTANT_INTERSECTION: 0,
    CandidateSource.MECHANISM_FALLBACK: 1,
}


def mechanism_primitives(mechanism: IPCMechanism) -> tuple[str, ...]:
    return _ENDPOINT_PRIMITIVES.get(mechanism, ())


def role_compatible_primitives(channel: IPCChannel) -> tuple[str, ...]:
    primitives = mechanism_primitives(channel.mechanism)
    if channel.mechanism not in {
        IPCMechanism.UDS,
        IPCMechanism.LOOPBACK_SOCKET,
    }:
        return primitives

    roles = {endpoint.role for endpoint in channel.endpoints}
    if not roles or roles & {EndpointRole.UNKNOWN, EndpointRole.PEER}:
        return primitives

    compatible: set[str] = set()
    if roles & {
        EndpointRole.CLIENT,
        EndpointRole.SENDER,
        EndpointRole.ACCESSOR,
    }:
        compatible.add("bind")
    if roles & {
        EndpointRole.SERVER,
        EndpointRole.RECEIVER,
        EndpointRole.CREATOR,
    }:
        compatible.update({"connect", "sendto", "sendmsg"})
    return tuple(
        primitive for primitive in primitives if primitive in compatible
    ) or primitives


@dataclass(frozen=True)
class CandidateCoverageGap:
    reason_code: str
    reason: str
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True)
class CandidateIndexBatch:
    candidates_by_channel: dict[str, list[PeerCandidateEvidence]]
    gaps_by_channel: dict[str, list[CandidateCoverageGap]]


@dataclass(frozen=True)
class _ExecutableClosure:
    members: frozenset[Path]
    dependency_gaps: tuple[CandidateCoverageGap, ...]


@dataclass(frozen=True)
class _ProviderLead:
    path: Path
    source: CandidateSource


@dataclass(frozen=True)
class _ProviderEndpoint:
    provider_path: Path
    entry_symbol: str | None
    entry_ea: int
    endpoint_ea: int
    endpoint_name: str
    primitive: str
    witness_eas: tuple[int, ...]


class ChannelCandidateIndex:
    """Build process-owned endpoint paths without candidate decompilation."""

    def __init__(self, rootfs: Path, index: FirmwareImportIndex) -> None:
        self.rootfs = Path(rootfs).absolute().resolve()
        self.index = index
        self._providers_by_name = self._provider_candidates()
        self._closures = {
            path: self._build_executable_closure(path)
            for path, kind in self.index.elf_kind.items()
            if kind == "exec"
        }
        # Cheap firmware-wide meet-in-the-middle index, built once and reused
        # by every Channel.  provider -> executable -> uniquely-resolved
        # provider exports imported by that executable's custom closure.
        self._provider_entry_callers = self._build_provider_entry_callers()
        self._constant_cache: dict[Path, bytes] = {}
        self._string_xref_cache: dict[Path, dict] = {}
        self._disassembly_cache: dict[tuple[Path, int], str] = {}
        self._structural_roots: dict[Path, tuple[object, object]] = {}
        # Candidate inspection must not turn every firmware-wide fallback
        # executable into a persistent LibDepGraph root.  Keep temporary
        # BinaryNodes here and publish assembly only after a witness survives
        # the provider/export/caller intersection.
        self._candidate_nodes: dict[Path, object] = {}
        self._published_structural: set[Path] = set()
        self._provider_graph_cache: dict[
            Path, tuple[nx.DiGraph, nx.DiGraph, dict[object, int]]
        ] = {}

    def prepare_many(
        self,
        channels: Iterable[IPCChannel],
        lib_dep_graph: LibDepGraph,
        *,
        exclude_paths: set[str] | None = None,
    ) -> CandidateIndexBatch:
        """Prepare all channels with provider-first, caller-directed matching."""
        channel_list = list(channels)
        channel_ids = [channel.channel_id for channel in channel_list]
        if len(channel_ids) != len(set(channel_ids)):
            raise ValueError("channel IDs must be unique for batch candidate lookup")
        excluded = {path.lstrip("/") for path in (exclude_paths or set())}

        candidates: dict[str, list[PeerCandidateEvidence]] = {}
        gaps: dict[str, list[CandidateCoverageGap]] = {}
        for channel in channel_list:
            current, current_gaps = self._prepare_channel(
                channel, lib_dep_graph, excluded,
            )
            candidates[channel.channel_id] = current
            gaps[channel.channel_id] = current_gaps
        return CandidateIndexBatch(candidates, gaps)

    def _prepare_channel(
        self,
        channel: IPCChannel,
        lib_dep_graph: LibDepGraph,
        excluded: set[str],
    ) -> tuple[list[PeerCandidateEvidence], list[CandidateCoverageGap]]:
        leads = self._provider_leads(channel)
        named_constants = self._named_constants(channel)
        constant_owners = self._constant_owners(channel)
        gaps: dict[tuple[str, str], CandidateCoverageGap] = {}
        endpoints: list[tuple[_ProviderEndpoint, CandidateSource]] = []
        # Only closures that participate in this Channel's constant/capability
        # search can affect its candidate universe. Firmware-wide closure gaps
        # are not copied into every Channel.
        relevant_closure_roots = {
            *constant_owners,
            *(lead.path for lead in leads),
        }
        for root in relevant_closure_roots:
            closure = self._closures.get(root)
            if closure is None:
                closure = self._build_dependency_closure(root)
            for gap in closure.dependency_gaps:
                gaps[(gap.reason_code, gap.reason)] = gap

        if channel.mechanism is IPCMechanism.FIFO and not self._named_constants(
            channel,
        ):
            self._record_gap(
                gaps,
                "dynamic_fifo_identifier_unresolved",
                "A runtime-built FIFO path has no bounded peer candidate universe.",
                (
                    "The target-side FIFO expression needs runtime argv/config provenance before an opposite executable can be inspected.",
                ),
            )
            self._append_global_coverage_gaps(gaps)
            return [], sorted(
                gaps.values(), key=lambda item: (item.reason_code, item.reason),
            )

        for lead in leads:
            try:
                provider, adg = self._ensure_structural_root(
                    lead.path,
                    lib_dep_graph,
                    # Provider endpoint discovery is entirely intra-binary:
                    # it walks the provider's structural CallGraph from its
                    # exported entries to the primitive call.  Do not build
                    # the provider's DT_NEEDED closure/ADG here.  The
                    # cross-binary ADG is only needed later for an executable
                    # whose imported entry survives the LIEF intersection.
                    expand_dependencies=False,
                )
                found = self._provider_endpoints(channel, provider, adg)
            except Exception as exc:
                self._record_gap(
                    gaps,
                    "provider_structural_analysis_failed",
                    f"{self._relative(lead.path)} could not complete structural analysis.",
                    (f"{type(exc).__name__}: {exc}",),
                )
                continue
            if not found:
                self._record_gap(
                    gaps,
                    "provider_endpoint_unresolved",
                    f"{self._relative(lead.path)} imports compatible primitives but no direct endpoint caller was recovered.",
                    ("IDA structural call edges do not expose a compatible primitive callsite.",),
                )
                continue
            endpoints.extend((endpoint, lead.source) for endpoint in found)

        jobs: dict[Path, list[tuple[_ProviderEndpoint, CandidateSource]]] = (
            defaultdict(list)
        )
        for endpoint, source in endpoints:
            provider_kind = self.index.elf_kind.get(endpoint.provider_path)
            if provider_kind == "exec":
                relative = self._relative(endpoint.provider_path)
                if relative not in excluded:
                    jobs[endpoint.provider_path].append((endpoint, source))
                continue
            if endpoint.entry_symbol is None:
                self._record_gap(
                    gaps,
                    "provider_entry_unresolved",
                    f"{self._relative(endpoint.provider_path)} endpoint has no exported entry.",
                    ("No dynamic function export reaches the endpoint callsite.",),
                )
                continue
            for executable, imported_entries in self._provider_entry_callers.get(
                endpoint.provider_path, {},
            ).items():
                closure = self._closures[executable]
                relative = self._relative(executable)
                if relative in excluded:
                    continue
                if named_constants and not constant_owners.intersection(
                    closure.members,
                ):
                    continue
                for gap in closure.dependency_gaps:
                    gaps[(gap.reason_code, gap.reason)] = gap
                if endpoint.entry_symbol in imported_entries:
                    jobs[executable].append((endpoint, source))

        if named_constants:
            capable = self._mechanism_capable_paths(channel)
            selected = {lead.path for lead in leads}
            deferred_count = len(capable - selected)
            if deferred_count:
                self._record_gap(
                    gaps,
                    "dynamic_identifier_fallback_deferred",
                    (
                        f"{deferred_count} mechanism-capable ELFs without the "
                        "complete named Channel identifier were not opened in IDA."
                    ),
                    (
                        "Runtime construction of the same identifier remains possible; this is an unresolved coverage item, not a static rejection.",
                    ),
                )

        by_path: dict[str, PeerCandidateEvidence] = {}
        for executable in sorted(jobs, key=self._relative):
            relative = self._relative(executable)
            try:
                root, adg = self._ensure_structural_root(
                    executable,
                    lib_dep_graph,
                    # Imported provider entries require the executable's
                    # closure and cross-binary ADG in the original design.
                    # The executable's IDA structural CallGraph already
                    # contains the direct PLT/extern edge for an imported
                    # entry, so it is sufficient (and avoids loading the
                    # executable's unrelated DT_NEEDED subtree) here too.
                    expand_dependencies=False,
                )
            except Exception as exc:
                self._record_gap(
                    gaps,
                    "candidate_structural_analysis_failed",
                    f"{relative} could not complete structural analysis.",
                    (f"{type(exc).__name__}: {exc}",),
                )
                continue

            paths: list[EndpointCallPath] = []
            sources: list[CandidateSource] = []
            for endpoint, source in jobs[executable]:
                recovered = self._candidate_paths(
                    channel, root, endpoint, adg, lib_dep_graph,
                )
                if recovered:
                    paths.extend(recovered)
                    sources.append(source)
                else:
                    self._record_gap(
                        gaps,
                        "candidate_call_path_unresolved",
                        f"{relative} imports a provider entry but no process-owned direct path reaches its endpoint.",
                        (
                            "An indirect call, dead import, unresolved thunk, or dynamic loader edge may explain the missing path.",
                        ),
                    )
            if not paths:
                continue
            self._publish_candidate_assembly(
                executable, root, paths, lib_dep_graph,
            )
            unique_paths = {
                item.model_dump_json(): item for item in paths
            }
            ordered_paths = sorted(
                unique_paths.values(), key=self._endpoint_path_sort_key,
            )
            source = min(sources, key=_SOURCE_PRIORITY.__getitem__)
            if any(
                path.identifier_relation is IdentifierRelation.EXACT
                for path in ordered_paths
            ):
                source = CandidateSource.CONSTANT_INTERSECTION
            by_path[relative] = PeerCandidateEvidence(
                executable_path=relative,
                source=source,
                reasons=[
                    "IDA structural CALL/IMPL edges connect executable code to a compatible endpoint primitive."
                ],
                call_paths=ordered_paths,
            )

        self._append_global_coverage_gaps(gaps)
        if not by_path:
            self._record_gap(
                gaps,
                "no_indexed_candidate",
                "Provider-entry/caller matching found no inspectable executable candidate.",
                (
                    "A static link, raw syscall, dynamic loader edge, opaque indirect call, or runtime-built identifier may be invisible.",
                ),
            )
        ordered = sorted(
            by_path.values(),
            key=lambda item: (_SOURCE_PRIORITY[item.source], item.executable_path),
        )
        return ordered, sorted(
            gaps.values(), key=lambda item: (item.reason_code, item.reason),
        )

    def _ensure_structural_root(
        self,
        path: Path,
        lib_dep_graph: LibDepGraph,
        *,
        expand_dependencies: bool | None = None,
    ) -> tuple[object, object]:
        """Create one structural root projection at most once per run."""
        resolved = Path(path).absolute().resolve()
        cached = self._structural_roots.get(resolved)
        if cached is not None:
            return cached
        # For a direct executable endpoint, the primitive call is already an
        # external/PLT edge in that executable.  A full DT_NEEDED closure is
        # only required for a shared provider whose exported wrapper must be
        # resolved.  Keep executable candidates root-only so a generic socket
        # import cannot pull hundreds of unrelated libraries into IDA.
        if expand_dependencies is None:
            expand_dependencies = self.index.elf_kind.get(resolved) != "exec"

        # Production candidate inspection is deliberately ephemeral.  The
        # provider endpoint and executable import edge are both available in
        # their individual structural CallGraphs; no DT_NEEDED expansion or
        # cross-binary ADG is needed.  Reuse LibDepGraph's cache-aware loader
        # without registering the exploratory root in the target graph.
        load_binary = getattr(lib_dep_graph, "_load_or_create_binary", None)
        ensure_callgraph = getattr(lib_dep_graph, "_ensure_structural_callgraph", None)
        if load_binary is not None and ensure_callgraph is not None:
            root = self._candidate_nodes.get(resolved)
            if root is None:
                root = load_binary(resolved)
                ensure_callgraph(root)
                self._candidate_nodes[resolved] = root
            if not getattr(root, "structural_ready", False):
                raise RuntimeError(
                    f"{self._relative(resolved)} has no structural CallGraph"
                )
            # The real path never constructs an ADG for a candidate.  Keep
            # the mocked ADG fallback below for lightweight unit fixtures.
            adg = None
            if not expand_dependencies:
                get_adg = getattr(lib_dep_graph, "get_structural_adg", None)
                if get_adg is not None:
                    try:
                        adg = get_adg(root)
                    except Exception:
                        adg = None
            value = (root, adg)
            self._structural_roots[resolved] = value
            return value

        root = lib_dep_graph.add_binary(
            resolved,
            expand_dependencies=expand_dependencies,
            build_structural_adg=expand_dependencies,
        )
        if not root.structural_ready:
            raise RuntimeError(f"{self._relative(resolved)} has no structural CallGraph")
        adg = (
            lib_dep_graph.get_structural_adg(root)
            if expand_dependencies
            else None
        )
        # Lightweight test/fallback graph implementations may expose an
        # already-built ADG even when they do not model the new root-only
        # onboarding flag.  Reuse it when available; the production
        # LibDepGraph returns no ADG for a root-only candidate.
        if adg is None and not expand_dependencies:
            get_adg = getattr(lib_dep_graph, "get_structural_adg", None)
            if get_adg is not None:
                try:
                    adg = get_adg(root)
                except Exception:
                    adg = None
        value = (root, adg)
        self._structural_roots[resolved] = value
        return value

    def _publish_candidate_assembly(
        self,
        executable: Path,
        root,
        paths: list[EndpointCallPath],
        lib_dep_graph: LibDepGraph,
    ) -> None:
        """Publish `.s` only for a candidate with a concrete witness."""
        owners = {executable.absolute().resolve()}
        for path in paths:
            owners.update(
                self.rootfs / hop.binary_path
                for hop in path.call_path
                if not Path(hop.binary_path).is_absolute()
            )
        for owner_path in owners:
            owner_path = owner_path.absolute().resolve()
            if owner_path in self._published_structural:
                continue
            owner = self._candidate_nodes.get(owner_path)
            if owner is None:
                owner = self._binary_for_path(owner_path, lib_dep_graph)
            if owner is None or not getattr(owner, "structural_ready", False):
                continue
            global_config = getattr(lib_dep_graph, "_global_config", None)
            disassembled_dir = getattr(global_config, "disassembled_code_dir", None)
            if disassembled_dir is None:
                continue
            owner.call_graph.dump_disassembled_code(
                disassembled_dir / "ipc" / owner._source_sha256,
                artifact_level="structural",
            )
            self._published_structural.add(owner_path)

    def _provider_leads(self, channel: IPCChannel) -> list[_ProviderLead]:
        constants = self._named_constants(channel)
        capable = self._mechanism_capable_paths(channel)

        # A stable named identifier gives us a substantially stronger and
        # cheaper starting point than a firmware-wide primitive import.  The
        # identifier may live in the executable/upper wrapper while bind(2)
        # lives in a lower custom provider, so intersect the identifier owner
        # with its deterministic DT_NEEDED closure rather than requiring both
        # facts in one ELF.
        if constants:
            owners = self._constant_owners(channel)
            selected: set[Path] = set()
            for owner in owners:
                closure = (
                    self._closures[owner]
                    if self.index.elf_kind.get(owner) == "exec"
                    else self._build_dependency_closure(owner)
                )
                selected.update(capable & set(closure.members))
            return [
                _ProviderLead(
                    path=path,
                    source=CandidateSource.CONSTANT_INTERSECTION,
                )
                for path in sorted(selected, key=self._relative)
            ]

        # Numeric and runtime-built identifiers cannot be searched safely as
        # raw bytes.  Keep the complete role-compatible mechanism fallback;
        # later provider-entry/caller intersection prevents a shared wrapper
        # from being broadcast to every linker.
        leads: list[_ProviderLead] = []
        for path in sorted(capable, key=self._relative):
            leads.append(_ProviderLead(
                path=path,
                source=CandidateSource.MECHANISM_FALLBACK,
            ))
        return leads

    def _mechanism_capable_paths(self, channel: IPCChannel) -> set[Path]:
        primitives = set(role_compatible_primitives(channel))
        return {
            path
            for path in self.index.elf_kind
            if not self._is_default_library(path.name)
            and (
                self.index.elf_kind.get(path) == "exec"
                or path in self._provider_entry_callers
            )
            and any(
                path in self.index.symbol_to_elfs.get(primitive, set())
                for primitive in primitives
            )
        }

    def _build_provider_entry_callers(
        self,
    ) -> dict[Path, dict[Path, frozenset[str]]]:
        """Precompute the LIEF-only provider-export/caller intersection.

        An imported symbol is assigned only when exactly one member of the
        executable's resolved custom-library closure defines it.  Merely
        loading a provider therefore never authorizes IDA analysis; at least
        one closure member must actually import one of that provider's dynamic
        function exports.
        """
        undefined_by_elf = {
            path: set(symbols)
            for path, symbols in self.index.undefined_functions_per_elf.items()
        }
        # Backward compatibility for synthetic indices and old in-memory
        # fixtures that only populate the reverse map.
        for symbol, importers in self.index.symbol_to_elfs.items():
            for importer in importers:
                undefined_by_elf.setdefault(importer, set()).add(symbol)

        defined_by_symbol: dict[str, set[Path]] = defaultdict(set)
        for provider, symbols in self.index.defined_functions_per_elf.items():
            for symbol in symbols:
                defined_by_symbol[symbol].add(provider)

        intersections: dict[Path, dict[Path, set[str]]] = defaultdict(
            lambda: defaultdict(set),
        )
        for executable, closure in self._closures.items():
            members = set(closure.members)
            for importer in members:
                for symbol in undefined_by_elf.get(importer, set()):
                    providers = defined_by_symbol.get(symbol, set()) & members
                    if len(providers) != 1:
                        continue
                    provider = next(iter(providers))
                    if self.index.elf_kind.get(provider) != "so":
                        continue
                    intersections[provider][executable].add(symbol)

        result = {
            provider: {
                executable: frozenset(symbols)
                for executable, symbols in sorted(
                    callers.items(), key=lambda item: self._relative(item[0]),
                )
            }
            for provider, callers in sorted(
                intersections.items(), key=lambda item: self._relative(item[0]),
            )
        }
        return result

    def _constant_owners(self, channel: IPCChannel) -> set[Path]:
        constants = self._named_constants(channel)
        if not constants:
            return set()
        return {
            path
            for path in self.index.elf_kind
            if any(
                value.encode("utf-8", errors="ignore") + b"\0"
                in self._constant_section_bytes(path)
                for value in constants
                if value
            )
        }

    def _provider_endpoints(self, channel, provider, _adg) -> list[_ProviderEndpoint]:
        primitives = set(role_compatible_primitives(channel))
        callgraph = provider._call_graph
        if callgraph is None:
            return []
        internal_graph, condensed, component_of = self._provider_call_graph(
            provider,
        )
        endpoint_calls: list[tuple[object, str]] = []
        for function in sorted(
            callgraph.get_nodes(), key=lambda item: (item.ea, item.name),
        ):
            if (
                function.has_attr(FunctionAttr.EXTERNAL)
                or function.has_attr(FunctionAttr.PLT)
            ):
                continue
            for callee in callgraph.get_structural_callees_of(function):
                primitive = self._normalize_symbol(callee.name)
                if primitive in primitives and (
                    callee.has_attr(FunctionAttr.EXTERNAL)
                    or callee.has_attr(FunctionAttr.PLT)
                ):
                    endpoint_calls.append((function, primitive))

        exported_by_ea = {
            function.ea: function
            for function in provider.exported_funcs.values()
            if self._normalize_symbol(function.name)
            in self.index.defined_functions_per_elf.get(
                provider.binary_path.absolute().resolve(), set(),
            )
        }
        provider_kind = self.index.elf_kind.get(
            provider.binary_path.absolute().resolve(),
        )
        results: list[_ProviderEndpoint] = []
        for endpoint_function, primitive in endpoint_calls:
            if provider_kind == "exec":
                results.append(_ProviderEndpoint(
                    provider_path=provider.binary_path.absolute().resolve(),
                    entry_symbol=None,
                    entry_ea=endpoint_function.ea,
                    endpoint_ea=endpoint_function.ea,
                    endpoint_name=endpoint_function.name,
                    primitive=primitive,
                    witness_eas=(endpoint_function.ea,),
                ))
                continue
            endpoint_component = component_of.get(endpoint_function)
            if endpoint_component is None:
                continue
            reachable_components = {
                endpoint_component,
                *nx.ancestors(condensed, endpoint_component),
            }
            for entry in sorted(exported_by_ea.values(), key=lambda item: item.ea):
                if component_of.get(entry) not in reachable_components:
                    continue
                witness = self._shortest_direct_call_path(
                    internal_graph, entry, endpoint_function,
                )
                if witness is None:
                    continue
                results.append(_ProviderEndpoint(
                    provider_path=provider.binary_path.absolute().resolve(),
                    entry_symbol=self._normalize_symbol(entry.name),
                    entry_ea=entry.ea,
                    endpoint_ea=endpoint_function.ea,
                    endpoint_name=endpoint_function.name,
                    primitive=primitive,
                    witness_eas=tuple(item.ea for item in witness),
                ))
        unique = {
            (
                item.provider_path,
                item.entry_symbol,
                item.entry_ea,
                item.endpoint_ea,
                item.primitive,
            ): item
            for item in results
        }
        return [unique[key] for key in sorted(unique, key=repr)]

    def _provider_call_graph(
        self, provider,
    ) -> tuple[nx.DiGraph, nx.DiGraph, dict[object, int]]:
        """Return one cached provider-internal CALL graph and SCC DAG."""
        path = provider.binary_path.absolute().resolve()
        cached = self._provider_graph_cache.get(path)
        if cached is not None:
            return cached

        callgraph = provider._call_graph
        graph = nx.DiGraph()
        internal = sorted(
            (
                function
                for function in callgraph.get_nodes()
                if not function.has_attr(FunctionAttr.EXTERNAL)
                and not function.has_attr(FunctionAttr.PLT)
                and function.module == provider.name
            ),
            key=self._function_sort_key,
        )
        graph.add_nodes_from(internal)
        internal_set = set(internal)
        for caller in internal:
            callees = sorted(
                (
                    callee
                    for callee in callgraph.get_structural_callees_of(caller)
                    if callee in internal_set
                ),
                key=self._function_sort_key,
            )
            graph.add_edges_from((caller, callee) for callee in callees)

        condensed = nx.condensation(graph)
        component_of = dict(condensed.graph.get("mapping", {}))
        value = (graph, condensed, component_of)
        self._provider_graph_cache[path] = value
        return value

    def _shortest_direct_call_path(self, graph, start, target):
        """Stable shortest witness in one provider's direct CALL graph."""
        queue = deque([start])
        parent = {start: None}
        while queue:
            current = queue.popleft()
            if current == target:
                path = []
                cursor = current
                while cursor is not None:
                    path.append(cursor)
                    cursor = parent[cursor]
                return list(reversed(path))
            for successor in sorted(
                graph.successors(current), key=self._function_sort_key,
            ):
                if successor in parent:
                    continue
                parent[successor] = current
                queue.append(successor)
        return None

    def _candidate_paths(
        self,
        channel: IPCChannel,
        root,
        endpoint: _ProviderEndpoint,
        adg,
        lib_dep_graph: LibDepGraph,
    ) -> list[EndpointCallPath]:
        provider = self._binary_for_path(endpoint.provider_path, lib_dep_graph)
        if (
            provider is None
            or provider.binary_path.absolute().resolve() != endpoint.provider_path
        ):
            return []
        try:
            entry_function = provider.get_function_by_ea(endpoint.entry_ea)
            endpoint_function = provider.get_function_by_ea(endpoint.endpoint_ea)
        except RuntimeError:
            return []
        starts = [
            function
            for function in root.all_funcs.values()
            if function.has_attr(FunctionAttr.TEXT)
            and not function.has_attr(FunctionAttr.EXTERNAL)
            and not function.has_attr(FunctionAttr.PLT)
        ]
        if endpoint.entry_symbol is None:
            # A direct executable endpoint has no imported provider entry.
            # Its endpoint function is itself the witness root, so no
            # cross-binary ADG is needed (and none was built for the cheap
            # root-only onboarding path).
            prefix = [entry_function]
        else:
            # An imported provider entry is represented in the executable's
            # structural CallGraph as an external/PLT callee.  Finding a
            # direct path to that edge does not require a cross-binary ADG;
            # the provider witness was already recovered from the provider's
            # own graph and LIEF established the unique DT_NEEDED import.
            prefix = self._shortest_import_call_path(
                root, endpoint.entry_symbol,
            )
            # Keep the ADG fallback for old synthetic fixtures that only
            # provide a mocked cross-binary graph.  Real roots never build it.
            if prefix is None and adg is not None:
                prefix = self._shortest_path(adg, starts, entry_function)
        if prefix is None:
            return []
        try:
            provider_witness = [
                provider.get_function_by_ea(ea) for ea in endpoint.witness_eas
            ]
        except RuntimeError:
            return []
        if (
            not provider_witness
            or provider_witness[0] != entry_function
            or provider_witness[-1] != endpoint_function
        ):
            return []
        direct = [*prefix, *provider_witness[1:]]

        constants = self._named_constants(channel)
        exact_paths: list[EndpointCallPath] = []
        if constants:
            # The witness spans only this executable and endpoint provider.
            # Exploratory peers are deliberately absent from the target graph.
            scope = {root, provider}
            for owner in sorted(scope, key=lambda item: self._relative(item.binary_path)):
                if not owner.structural_ready:
                    continue
                xrefs = self._string_xrefs(owner)
                for identifier in constants:
                    for xref in xrefs.get(identifier, []):
                        try:
                            function_ea = int(xref["func_ea"], 16)
                            xref_ea = int(xref["ea"], 16)
                            identifier_function = owner.get_function_by_ea(function_ea)
                        except (KeyError, TypeError, ValueError, RuntimeError):
                            continue
                        if identifier_function not in direct:
                            continue
                        relation = (
                            IdentifierRelation.EXACT
                            if identifier_function == endpoint_function
                            else IdentifierRelation.CALLER_SUPPLIED
                        )
                        exact_paths.append(self._make_endpoint_path(
                            direct,
                            endpoint,
                            lib_dep_graph,
                            relation,
                            identifier=identifier,
                            identifier_xref_ea=xref_ea,
                            missing_evidence=(
                                []
                                if relation is IdentifierRelation.EXACT
                                else [
                                    "The Channel identifier is visible in an upstream caller; assembly inspection must verify its parameter flow into the endpoint wrapper."
                                ]
                            ),
                        ))
        if exact_paths:
            return exact_paths

        loopback_match = self._local_loopback_match(
            channel, root, direct, endpoint, lib_dep_graph,
        )
        if loopback_match is not None:
            identifier, evidence_ea, matched_witness = loopback_match
            return [self._make_endpoint_path(
                matched_witness,
                endpoint,
                lib_dep_graph,
                IdentifierRelation.CALLER_SUPPLIED,
                identifier=identifier,
                identifier_xref_ea=evidence_ea,
                missing_evidence=["Address/port co-occurrence is a retrieval hint; verify argument flow in source."],
            )]

        return [self._make_endpoint_path(
            direct,
            endpoint,
            lib_dep_graph,
            IdentifierRelation.UNRESOLVED,
            missing_evidence=[
                "The direct endpoint path is visible, but structural analysis does not tie the complete typed Channel identifier to it."
            ],
        )]

    def _local_loopback_match(
        self,
        channel: IPCChannel,
        root,
        witness,
        endpoint: _ProviderEndpoint,
        lib_dep_graph: LibDepGraph,
    ) -> tuple[str, int | None, list] | None:
        """Recognize the common literal address/port form near a call edge.

        This is deliberately not general constant propagation.  It accepts a
        numeric endpoint only when the target port and a loopback address occur
        in the same small IDA instruction window around a witnessed call.
        Unknown or caller-computed values remain unresolved for the Peer Agent.
        """
        if channel.mechanism is not IPCMechanism.LOOPBACK_SOCKET:
            return None
        ports = {
            int(resource.canonical_value, 10)
            for resource in channel.resources
            if resource.kind == "socket_port"
            and resource.canonical_value is not None
            and resource.canonical_value.isdecimal()
        }
        if len(ports) != 1:
            return None
        port = next(iter(ports))
        if not 0 <= port <= 65535:
            return None
        expected_addresses = {
            resource.canonical_value
            for resource in channel.resources
            if resource.kind == "loopback_address"
            and resource.canonical_value
        }

        edges = [
            (caller, callee.name)
            for caller, callee in zip(witness, witness[1:])
        ]
        edges.append((witness[-1], endpoint.primitive))
        for caller, callee_name in edges:
            listing = self._function_disassembly(caller, lib_dep_graph)
            match = self._match_loopback_call_window(
                listing, callee_name, port, expected_addresses,
            )
            if match is not None:
                address, evidence_ea = match
                return f"{address}:{port}", evidence_ea, list(witness)

        # A direct executable endpoint often receives its address and port in
        # a thin local wrapper (for example init_listener("127.0.0.1", 40500)).
        # The executable case has no exported provider entry, so inspect only
        # structural callers in the same binary, to a small fixed depth.
        if endpoint.provider_path == root.binary_path.absolute().resolve():
            callgraph = root._call_graph
            endpoint_function = witness[-1]
            pending = deque([(endpoint_function, [endpoint_function], 0)])
            visited = {endpoint_function}
            while pending:
                current, suffix, depth = pending.popleft()
                if depth >= 4:
                    continue
                for caller in sorted(
                    callgraph.get_callers_of(current),
                    key=self._function_sort_key,
                ):
                    if caller.module != root.name or caller in visited:
                        continue
                    visited.add(caller)
                    caller_listing = self._function_disassembly(
                        caller, lib_dep_graph,
                    )
                    match = self._match_loopback_call_window(
                        caller_listing,
                        current.name,
                        port,
                        expected_addresses,
                    )
                    candidate_witness = [caller, *suffix]
                    if match is not None:
                        address, evidence_ea = match
                        return (
                            f"{address}:{port}",
                            evidence_ea,
                            candidate_witness,
                        )
                    pending.append((caller, candidate_witness, depth + 1))
        return None

    def _shortest_import_call_path(
        self, root, imported_symbol: str | None,
    ):
        """Find an executable-local path to one imported PLT/extern symbol.

        The provider/export intersection has already proven that this symbol
        is supplied by a unique custom library in the executable's LIEF
        closure.  The remaining structural fact is only whether an internal
        function reaches that import edge.  Walking the executable's own
        CallGraph is both cheaper and less stateful than constructing a
        cross-binary ApiDepGraph for every fallback candidate.
        """
        if not imported_symbol:
            return None
        callgraph = getattr(root, "_call_graph", None)
        if callgraph is None:
            return None
        normalized = self._normalize_symbol(imported_symbol)
        starts = sorted(
            (
                function
                for function in callgraph.get_nodes()
                if function.has_attr(FunctionAttr.TEXT)
                and not function.has_attr(FunctionAttr.EXTERNAL)
                and not function.has_attr(FunctionAttr.PLT)
            ),
            key=self._function_sort_key,
        )
        queue = deque(starts)
        parent = {node: None for node in starts}
        while queue:
            current = queue.popleft()
            successors = sorted(
                callgraph.get_structural_callees_of(current),
                key=self._function_sort_key,
            )
            for successor in successors:
                if (
                    self._normalize_symbol(successor.name) == normalized
                    and (
                        successor.has_attr(FunctionAttr.EXTERNAL)
                        or successor.has_attr(FunctionAttr.PLT)
                    )
                ):
                    path = [current, successor]
                    cursor = current
                    while parent[cursor] is not None:
                        cursor = parent[cursor]
                        path.append(cursor)
                    return list(reversed(path))
                if successor.has_attr(FunctionAttr.EXTERNAL) or successor.has_attr(
                    FunctionAttr.PLT,
                ):
                    continue
                if successor in parent:
                    continue
                parent[successor] = current
                queue.append(successor)
        return None

    def _function_disassembly(self, function, lib_dep_graph: LibDepGraph) -> str:
        owner = self._binary_for_function(function, lib_dep_graph)
        if owner is None:
            return ""
        path = owner.binary_path.absolute().resolve()
        key = (path, function.ea)
        cached = self._disassembly_cache.get(key)
        if cached is not None:
            return cached
        owner.activate()
        try:
            listing = function.get_disassembly()
        finally:
            owner.deactivate()
        self._disassembly_cache[key] = listing
        return listing

    @staticmethod
    def _match_loopback_call_window(
        listing: str,
        callee_name: str,
        port: int,
        expected_addresses: set[str],
    ) -> tuple[str, int | None] | None:
        rows: list[tuple[int, str]] = []
        for line in listing.splitlines():
            match = re.match(r"^0x([0-9a-fA-F]+):\s+(.*)$", line)
            if match is None:
                continue
            text = re.sub(
                r"^(?:[0-9a-fA-F]{2}\s+)+", "", match.group(2),
            ).strip()
            rows.append((int(match.group(1), 16), text))

        normalized_callee = ChannelCandidateIndex._normalize_symbol(callee_name)
        call_indexes = [
            index
            for index, (_ea, text) in enumerate(rows)
            if normalized_callee
            and normalized_callee in ChannelCandidateIndex._normalize_symbol(text)
        ]
        if not call_indexes:
            return None

        swapped = int.from_bytes(port.to_bytes(2, "big"), "little")
        port_values = {port, swapped}
        port_tokens = {
            *(str(value) for value in port_values),
            *(f"0x{value:x}" for value in port_values),
        }
        token_pattern = re.compile(
            r"(?<![0-9A-Za-z_])(?:"
            + "|".join(re.escape(token) for token in sorted(port_tokens))
            + r")(?![0-9A-Za-z_])",
            re.IGNORECASE,
        )
        quoted_loopback = re.compile(r'"(127(?:\.[0-9]{1,3}){3}|::1)"')
        packed_loopback = re.compile(
            r"(?<![0-9A-Fa-f])0x(?:0?100007f|7f000001)(?![0-9A-Fa-f])",
            re.IGNORECASE,
        )

        for call_index in call_indexes:
            window = rows[max(0, call_index - 20):call_index + 5]
            text = "\n".join(item[1] for item in window)
            if token_pattern.search(text) is None:
                continue
            address_match = quoted_loopback.search(text)
            address = address_match.group(1) if address_match else None
            if address is None and packed_loopback.search(text):
                address = "127.0.0.1"
            if address is None:
                continue
            if expected_addresses and address not in expected_addresses:
                continue
            return address, rows[call_index][0]
        return None

    def _make_endpoint_path(
        self,
        witness,
        endpoint: _ProviderEndpoint,
        lib_dep_graph: LibDepGraph,
        relation: IdentifierRelation,
        *,
        identifier: str | None = None,
        identifier_xref_ea: int | None = None,
        missing_evidence: list[str] | None = None,
    ) -> EndpointCallPath:
        refs = [
            self._function_ref(function, lib_dep_graph) for function in witness
        ]
        endpoint_ref = refs[-1]
        return EndpointCallPath(
            entry=refs[0],
            call_path=refs,
            endpoint=PeerEndpointLocation(
                binary_path=endpoint_ref.binary_path,
                function_name=endpoint_ref.function_name,
                function_ea=endpoint_ref.function_ea,
                line_number=None,
                primitive=endpoint.primitive,
            ),
            identifier_relation=relation,
            identifier=identifier,
            identifier_xref_ea=identifier_xref_ea,
            missing_evidence=missing_evidence or [],
        )

    def _function_ref(
        self, function, lib_dep_graph: LibDepGraph,
    ) -> StructuralFunctionRef:
        owner = self._binary_for_function(function, lib_dep_graph)
        if owner is None:
            raise RuntimeError(
                f"Function owner {function.module!r} is absent from LibDepGraph"
            )
        return StructuralFunctionRef(
            binary_path=self._relative(owner.binary_path),
            function_name=function.name,
            function_ea=function.ea,
        )

    def source_function(self, path: Path, name: str, lib_dep_graph: LibDepGraph):
        """Resolve a source identity from the binary's function index, not candidate paths.

        Index/source failures propagate. A missing function name is distinct
        from an existing function whose assembly has not been published.
        """
        root, _ = self._ensure_structural_root(
            path, lib_dep_graph, expand_dependencies=False,
        )
        graph = root.call_graph
        return graph.get_node_by_name(name) if graph.has_node_by_name(name) else None

    def _binary_for_path(self, path: Path, lib_dep_graph: LibDepGraph):
        resolved = Path(path).absolute().resolve()
        candidate = self._candidate_nodes.get(resolved)
        if candidate is not None:
            return candidate
        get_node = getattr(lib_dep_graph, "get_node_by_name", None)
        if get_node is None:
            return None
        node = get_node(resolved.name)
        if node is None:
            return None
        try:
            if node.binary_path.absolute().resolve() != resolved:
                return None
        except (AttributeError, OSError):
            return None
        return node

    def _binary_for_function(self, function, lib_dep_graph: LibDepGraph):
        """Resolve the node that owns this exact function, never its basename."""
        nodes = list(self._candidate_nodes.values())
        get_node = getattr(lib_dep_graph, "get_node_by_name", None)
        if get_node is not None:
            node = get_node(function.module)
            if node is not None:
                nodes.append(node)
        owners = {
            node.binary_path.resolve(): node
            for node in nodes
            if node.all_funcs.get(function.ea) is function
        }
        if len(owners) > 1:
            raise RuntimeError(
                f"Function {function.module}::{function.name}@{function.ea:x} "
                f"has multiple source owners: {sorted(map(str, owners))}"
            )
        return next(iter(owners.values()), None)

    def _shortest_path(
        self,
        adg,
        starts,
        target,
        *,
        allowed_module: str | None = None,
    ):
        ordered_starts = sorted(set(starts), key=self._function_sort_key)
        queue = deque(ordered_starts)
        parent = {node: None for node in ordered_starts}
        while queue:
            current = queue.popleft()
            if current == target:
                path = []
                cursor = current
                while cursor is not None:
                    path.append(cursor)
                    cursor = parent[cursor]
                return list(reversed(path))
            successors = {
                *adg.get_successors_by_type(current, EdgeType.CALL),
                *adg.get_successors_by_type(current, EdgeType.IMPL),
            }
            for successor in sorted(successors, key=self._function_sort_key):
                if (
                    allowed_module is not None
                    and successor.module != allowed_module
                ):
                        continue
                if successor in parent:
                    continue
                parent[successor] = current
                queue.append(successor)
        return None

    def _string_xrefs(self, binary) -> dict:
        path = binary.binary_path.absolute().resolve()
        cached = self._string_xref_cache.get(path)
        if cached is not None:
            return cached
        binary.activate()
        try:
            value = binary.extract_string_xrefs()
        finally:
            binary.deactivate()
        self._string_xref_cache[path] = value
        return value

    def _append_global_coverage_gaps(
        self,
        gaps: dict[tuple[str, str], CandidateCoverageGap],
    ) -> None:
        if self.index.unparseable_elfs:
            paths = tuple(sorted(self._relative(path) for path in self.index.unparseable_elfs))
            self._record_gap(
                gaps,
                "unparseable_userspace_elfs",
                "LIEF could not index every ELF in the frozen rootfs.",
                tuple(f"No IPC facts are available for {path}." for path in paths),
            )
        dynamic_loaders = sorted({
            self._relative(path)
            for symbol in ("dlopen", "dlsym")
            for path in self.index.symbol_to_elfs.get(symbol, set())
            if self.index.elf_kind.get(path) in {"exec", "so"}
        })
        if dynamic_loaders:
            self._record_gap(
                gaps,
                "dynamic_loader_edges",
                "Dynamic loader calls may bypass DT_NEEDED/import matching.",
                tuple(f"{path} imports dlopen/dlsym." for path in dynamic_loaders),
            )

    @staticmethod
    def _record_gap(gaps, code, reason, missing) -> None:
        gap = CandidateCoverageGap(code, reason, tuple(missing))
        gaps[(code, reason)] = gap

    def _provider_candidates(self) -> dict[str, set[Path]]:
        providers: dict[str, set[Path]] = defaultdict(set)
        for name, paths in self.index.soname_candidates.items():
            providers[name].update(paths)
        for path, kind in self.index.elf_kind.items():
            if kind == "so":
                providers[path.name].add(path)
        return providers

    def _build_executable_closure(self, executable: Path) -> _ExecutableClosure:
        return self._build_dependency_closure(executable)

    def _build_dependency_closure(self, root: Path) -> _ExecutableClosure:
        """Resolve one ELF's unique custom DT_NEEDED closure.

        The same loader rule applies to executables and upper provider
        libraries.  Keeping this as an ELF-only operation lets named Channel
        constants lead us to the lower endpoint provider before any IDB is
        opened.
        """
        members = {root}
        pending = deque([root])
        gaps: dict[tuple[str, str], CandidateCoverageGap] = {}
        while pending:
            user = pending.popleft()
            for needed in self.index.dt_needed_per_elf.get(user, []):
                if self._is_default_library(needed):
                    continue
                providers = self._providers_by_name.get(needed, set())
                if len(providers) == 1:
                    provider = next(iter(providers))
                    if provider not in members:
                        members.add(provider)
                        pending.append(provider)
                    continue
                relative_user = self._relative(user)
                if len(providers) > 1:
                    paths = tuple(sorted(self._relative(path) for path in providers))
                    gap = CandidateCoverageGap(
                        "ambiguous_provider",
                        f"{relative_user} has ambiguous DT_NEEDED provider {needed!r}.",
                        tuple(f"Loader selection between {path} is unresolved." for path in paths),
                    )
                else:
                    gap = CandidateCoverageGap(
                        "missing_provider",
                        f"{relative_user} depends on absent provider {needed!r}.",
                        ("The missing custom library may hide endpoint capability or identifier construction.",),
                    )
                gaps[(gap.reason_code, gap.reason)] = gap
        return _ExecutableClosure(
            members=frozenset(members),
            dependency_gaps=tuple(sorted(
                gaps.values(), key=lambda item: (item.reason_code, item.reason),
            )),
        )

    def _named_constants(self, channel: IPCChannel) -> tuple[str, ...]:
        kinds = _NAMED_RESOURCE_KINDS.get(channel.mechanism)
        if kinds is None:
            return ()
        return tuple(sorted({
            resource.canonical_value
            for resource in channel.resources
            if resource.kind in kinds and resource.canonical_value
        }))

    def _constant_section_bytes(self, path: Path) -> bytes:
        cached = self._constant_cache.get(path)
        if cached is not None:
            return cached
        chunks: list[bytes] = []
        try:
            with LIEF_PARSE_LOCK:
                binary = lief.ELF.parse(str(path))
        except Exception:
            binary = None
        if binary is not None:
            for section_name in _CONSTANT_SECTIONS:
                try:
                    section = binary.get_section(section_name)
                    if section is not None:
                        chunks.append(bytes(section.content))
                except Exception:
                    continue
        value = b"".join(chunks)
        self._constant_cache[path] = value
        return value

    @staticmethod
    def _normalize_symbol(name: str) -> str:
        if "@" in name:
            name = name.split("@", 1)[0]
        for prefix in ("__imp_", "j_", "."):
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name

    @staticmethod
    def _function_sort_key(function) -> tuple[str, int, str]:
        return function.module, function.ea, function.name

    @staticmethod
    def _endpoint_path_sort_key(path: EndpointCallPath):
        return (
            0 if path.identifier_relation is IdentifierRelation.EXACT else 1,
            tuple(
                (item.binary_path, item.function_ea, item.function_name)
                for item in path.call_path
            ),
            path.endpoint.primitive,
        )

    @staticmethod
    def _is_default_library(name: str) -> bool:
        return any(marker in name for marker in GlobalConfig.DEFAULT_LIB)

    def _relative(self, path: Path) -> str:
        absolute = Path(path).absolute().resolve()
        try:
            return absolute.relative_to(self.rootfs).as_posix()
        except ValueError:
            return absolute.as_posix()


__all__ = [
    "CandidateCoverageGap",
    "CandidateIndexBatch",
    "ChannelCandidateIndex",
    "mechanism_primitives",
    "role_compatible_primitives",
]
