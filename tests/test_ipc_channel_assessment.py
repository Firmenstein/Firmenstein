"""Tests for provider-entry/caller matching and Peer Verification."""

from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError

import asyncio
import hashlib
from collections import defaultdict
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
from dotenv import load_dotenv

load_dotenv()

from _g2_fixtures import ipc_topology_findings

from fmst_analyzer.analysis.ipc_analyzer.agent_schema import CandidateVerdict  # noqa: E402
from fmst_analyzer.analysis.ipc_analyzer.analyzer import (  # noqa: E402
    IPCAnalyzer,
    PeerMatchingContext,
)
from fmst_analyzer.analysis.ipc_analyzer.candidate_index import (  # noqa: E402
    ChannelCandidateIndex,
)
from fmst_analyzer.analysis.ipc_analyzer.controller import IPCResultController  # noqa: E402
from fmst_analyzer.analysis.ipc_analyzer.peer.firmware_import_index import (  # noqa: E402
    FirmwareImportIndex,
    build_firmware_import_index,
)
from fmst_analyzer.analysis.ipc_analyzer.peer_verification import (  # noqa: E402
    PeerVerificationAgent,
    _candidate_assembly_files,
    _make_assembly_reader,
)
from fmst_analyzer.analysis.ipc_analyzer.schema import (  # noqa: E402
    APIBindingKind,
    APISymbolBinding,
    AnalysisPhase,
    CandidateSource,
    Endpoint,
    EndpointCallPath,
    EndpointRole,
    IdentifierRelation,
    IPCAnalysisResult,
    IPCChannel,
    IPCMechanism,
    IPC_ANALYSIS_SCHEMA_VERSION,
    PeerCandidateEvidence,
    PeerEndpointLocation,
    ResourceIdentity,
    StructuralFunctionRef,
    TargetProcess,
    VerificationStatus,
)
from fmst_analyzer.graphs.base_graph import EdgeType  # noqa: E402
from fmst_analyzer.nodes.common import FunctionAttr  # noqa: E402


def _target() -> TargetProcess:
    return TargetProcess(
        executable_path="usr/sbin/httpd",
        executable_sha256="a" * 64,
        argv0="httpd",
    )


def _endpoint(role: EndpointRole) -> Endpoint:
    return Endpoint(
        identity_resource_keys=["resource:demo"],
        endpoint_id="endpoint:demo",
        callsite_id="callsite:demo",
        role=role,
        api_binding=APISymbolBinding(
            kind=APIBindingKind.DYNAMIC_IMPORT,
            symbol="connect",
            status=VerificationStatus.VERIFIED_STATIC,
            reason="undefined dynamic symbol",
        ),
        wrapper_path=[],
        coverage_claims=[],
        status=VerificationStatus.VERIFIED_AGENT,
        evidence=[],
        missing_evidence=[],
    )


def _channel(
    *,
    mechanism: IPCMechanism = IPCMechanism.UDS,
    value: str | None = "/tmp/demo.sock",
    kind: str = "uds_path",
    role: EndpointRole | None = None,
    channel_id: str = "channel:demo",
) -> IPCChannel:
    return IPCChannel(
        channel_id=channel_id,
        mechanism=mechanism,
        resources=[ResourceIdentity(
            resource_key="resource:demo",
            kind=kind,
            canonical_value=value,
            expressions=[value or "runtime_value"],
            status=(
                VerificationStatus.VERIFIED_AGENT
                if value is not None
                else VerificationStatus.UNRESOLVED
            ),
            evidence=[],
            missing_evidence=[] if value is not None else ["runtime value"],
        )],
        endpoints=[] if role is None else [_endpoint(role)],
        retrieval_candidates=[],
        peer_candidates=[],
        status=(
            VerificationStatus.VERIFIED_AGENT
            if value is not None
            else VerificationStatus.UNRESOLVED
        ),
        missing_evidence=[] if value is not None else ["runtime value"],
    )


def _write(rootfs: Path, relative: str) -> Path:
    path = rootfs / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF")
    return path.resolve()


@pytest.mark.external
def test_et_rel_kernel_module_is_ignored_not_unparseable(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    source = tmp_path / "module.c"
    source.write_text("int module_value;\n", encoding="utf-8")
    module = rootfs / "lib/modules/demo.ko"
    module.parent.mkdir(parents=True)
    subprocess.run(
        ["gcc", "-c", str(source), "-o", str(module)],
        check=True,
        capture_output=True,
    )

    index = build_firmware_import_index(rootfs)

    assert module in index.ignored_elfs
    assert module not in index.unparseable_elfs
    assert module not in index.elf_kind


def test_damaged_kernel_module_is_ignored_not_unparseable(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    module = _write(rootfs, "lib/modules/damaged.ko")

    index = build_firmware_import_index(rootfs)

    assert module in index.ignored_elfs
    assert module not in index.unparseable_elfs


class _Function:
    def __init__(
        self,
        module: str,
        name: str,
        ea: int,
        *,
        attrs: set[FunctionAttr] | None = None,
    ) -> None:
        self.module = module
        self.name = name
        self.ea = ea
        self._attrs = attrs or {FunctionAttr.TEXT}

    def has_attr(self, attr) -> bool:
        return attr in self._attrs

    def __hash__(self) -> int:
        return hash((self.module, self.ea))


class _CallGraph:
    def __init__(self, functions, calls) -> None:
        self._functions = set(functions)
        self._calls = calls

    def get_nodes(self):
        return set(self._functions)

    def get_structural_callees_of(self, function):
        return list(self._calls.get(function, ()))

    def get_callers_of(self, function):
        return [
            caller
            for caller, callees in self._calls.items()
            if function in callees
        ]


class _ADG:
    def __init__(self, calls=(), impls=()) -> None:
        self._edges = defaultdict(lambda: defaultdict(set))
        for source, target in calls:
            self._edges[source][EdgeType.CALL].add(target)
        for source, target in impls:
            self._edges[source][EdgeType.IMPL].add(target)

    def get_successors_by_type(self, function, edge_type):
        return set(self._edges[function][edge_type])


class _Binary:
    structural_ready = True
    semantic_ready = False

    def __init__(self, path, functions, calls=(), exports=(), xrefs=None) -> None:
        self.binary_path = path
        self.name = path.name
        self.all_funcs = {function.ea: function for function in functions}
        self.exported_funcs = {function.ea: function for function in exports}
        self._call_graph = _CallGraph(functions, defaultdict(list, calls))
        self._xrefs = xrefs or {}

    def get_function_by_ea(self, ea):
        try:
            return self.all_funcs[ea]
        except KeyError as exc:
            raise RuntimeError(ea) from exc

    def activate(self):
        return None

    def deactivate(self):
        return None

    def extract_string_xrefs(self):
        return self._xrefs


class _Graph:
    def __init__(self, binaries, adg, closures) -> None:
        self.by_path = {binary.binary_path: binary for binary in binaries}
        self.by_name = {binary.name: binary for binary in binaries}
        self.adg = adg
        self.closures = closures
        self.added = []

    def add_binary(
        self,
        path,
        *,
        expand_dependencies=True,
        build_structural_adg=True,
    ):
        resolved = Path(path).resolve()
        self.added.append(resolved)
        return self.by_path[resolved]

    def get_structural_adg(self, _root):
        return self.adg

    def get_node_by_name(self, name):
        return self.by_name.get(name)

    def transitive_closure_from(self, root):
        return set(self.closures[root.binary_path])


def _shared_provider_fixture(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    first_path = _write(rootfs, "usr/sbin/first")
    second_path = _write(rootfs, "usr/sbin/second")
    unrelated_path = _write(rootfs, "usr/sbin/unrelated")
    provider_path = _write(rootfs, "lib/libipc.so")

    first_main = _Function("first", "main", 0x1000)
    first_import = _Function(
        "first", "start_a", 0x1100, attrs={FunctionAttr.EXTERNAL},
    )
    second_main = _Function("second", "main", 0x1200)
    unrelated_main = _Function("unrelated", "main", 0x1300)
    unrelated_import = _Function(
        "unrelated", "unrelated_api", 0x1400,
        attrs={FunctionAttr.EXTERNAL},
    )
    start_a = _Function("libipc.so", "start_a", 0x2000)
    start_b = _Function("libipc.so", "start_b", 0x2100)
    serve = _Function("libipc.so", "serve", 0x2200)
    unrelated_api = _Function("libipc.so", "unrelated_api", 0x2250)
    bind = _Function(
        "libipc.so", "bind", 0x2300, attrs={FunctionAttr.EXTERNAL},
    )
    first = _Binary(first_path, [first_main, first_import])
    second = _Binary(second_path, [second_main])
    unrelated = _Binary(
        unrelated_path, [unrelated_main, unrelated_import],
    )
    provider = _Binary(
        provider_path,
        [start_a, start_b, serve, unrelated_api, bind],
        calls={start_a: [serve], start_b: [serve], serve: [bind]},
        exports=[start_a, start_b, unrelated_api],
        xrefs={
            "/tmp/demo.sock": [{
                "func": "serve", "func_ea": "0x2200", "ea": "0x2210",
            }],
        },
    )
    adg = _ADG(
        calls=[
            (first_main, first_import),
            (start_a, serve),
            (start_b, serve),
            (serve, bind),
        ],
        impls=[(first_import, start_a)],
    )
    graph = _Graph(
        [first, second, unrelated, provider],
        adg,
        {
            first_path: {first, provider},
            second_path: {second, provider},
            unrelated_path: {unrelated, provider},
            provider_path: {provider},
        },
    )
    index = FirmwareImportIndex(
        elf_kind={
            first_path: "exec",
            second_path: "exec",
            unrelated_path: "exec",
            provider_path: "so",
        },
        soname_candidates={"libipc.so": {provider_path}},
        dt_needed_per_elf={
            first_path: ["libipc.so"],
            second_path: ["libipc.so"],
            unrelated_path: ["libipc.so"],
        },
        symbol_to_elfs={
            "bind": {provider_path},
            "start_a": {first_path},
            "unrelated_api": {unrelated_path},
        },
        defined_functions_per_elf={
            provider_path: {"start_a", "start_b", "unrelated_api"},
        },
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)
    candidate_index._constant_section_bytes = (
        lambda path: b"/tmp/demo.sock\0" if path == provider_path else b""
    )
    return rootfs, candidate_index, graph


def test_multiple_exported_entries_use_actual_caller_intersection(tmp_path: Path) -> None:
    _rootfs, candidate_index, graph = _shared_provider_fixture(tmp_path)

    batch = candidate_index.prepare_many(
        [_channel(role=EndpointRole.CLIENT)], graph,
    )
    candidates = batch.candidates_by_channel["channel:demo"]

    assert [item.executable_path for item in candidates] == ["usr/sbin/first"]
    assert len(candidates[0].call_paths) == 1
    path = candidates[0].call_paths[0]
    assert [item.function_name for item in path.call_path] == [
        "main", "start_a", "start_a", "serve",
    ]
    assert path.identifier_relation is IdentifierRelation.EXACT
    assert path.identifier == "/tmp/demo.sock"


def test_named_peer_remains_outside_target_graph(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    peer_path = _write(rootfs, "userfs/bin/cfg_manager")
    serve = _Function("cfg_manager", "serve", 0x1000)
    bind = _Function("cfg_manager", "bind", 0x2000, attrs={FunctionAttr.EXTERNAL})
    peer = _Binary(peer_path, [serve, bind], calls={serve: [bind]}, xrefs={
        "/tmp/tcapi_sock": [{"func": "serve", "func_ea": "0x1000", "ea": "0x1010"}],
    })
    graph = _Graph([], _ADG(), {})
    graph._load_or_create_binary = lambda path: peer
    graph._ensure_structural_callgraph = lambda binary: None
    index = ChannelCandidateIndex(rootfs, FirmwareImportIndex(
        elf_kind={peer_path: "exec"}, symbol_to_elfs={"bind": {peer_path}},
    ))
    index._constant_section_bytes = lambda path: b"/tmp/tcapi_sock\0"

    candidates = index.prepare_many([
        _channel(value="/tmp/tcapi_sock", role=EndpointRole.CLIENT),
    ], graph).candidates_by_channel["channel:demo"]

    assert [item.executable_path for item in candidates] == ["userfs/bin/cfg_manager"]
    path, = candidates[0].call_paths
    assert path.identifier_relation is IdentifierRelation.EXACT
    assert path.identifier == "/tmp/tcapi_sock"
    assert not graph.by_name and not graph.added


def test_named_shared_provider_uses_ephemeral_witness_owners(tmp_path: Path) -> None:
    _rootfs, index, graph = _shared_provider_fixture(tmp_path)
    graph._load_or_create_binary = lambda path: graph.by_path[path]
    graph._ensure_structural_callgraph = lambda binary: None
    graph.by_name.clear()
    graph.closures.clear()

    candidates = index.prepare_many([
        _channel(role=EndpointRole.CLIENT),
    ], graph).candidates_by_channel["channel:demo"]

    assert [item.executable_path for item in candidates] == ["usr/sbin/first"]
    path, = candidates[0].call_paths
    assert path.identifier_relation is IdentifierRelation.EXACT
    assert path.endpoint.binary_path == "lib/libipc.so"
    assert not graph.by_name and not graph.added


def test_shared_provider_does_not_fan_out_to_link_only_executable(tmp_path: Path) -> None:
    _rootfs, candidate_index, graph = _shared_provider_fixture(tmp_path)

    candidates = candidate_index.prepare_many(
        [_channel(role=EndpointRole.CLIENT)], graph,
    ).candidates_by_channel["channel:demo"]

    assert {item.executable_path for item in candidates} == {"usr/sbin/first"}
    assert not any(path.name == "second" for path in graph.added)
    assert not any(path.name == "unrelated" for path in graph.added)


def test_provider_without_any_export_caller_is_rejected_before_ida(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    executable = _write(rootfs, "usr/sbin/link_only")
    provider = _write(rootfs, "lib/libunused.so")
    index = FirmwareImportIndex(
        elf_kind={executable: "exec", provider: "so"},
        soname_candidates={"libunused.so": {provider}},
        dt_needed_per_elf={executable: ["libunused.so"]},
        symbol_to_elfs={"bind": {provider}},
        defined_functions_per_elf={provider: {"open_endpoint"}},
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)

    assert candidate_index._provider_leads(
        _channel(
            mechanism=IPCMechanism.LOOPBACK_SOCKET,
            value="554",
            kind="socket_port",
        ),
    ) == []
    assert provider not in candidate_index._provider_entry_callers


def test_transitive_library_import_maps_provider_to_executable_before_ida(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    executable = _write(rootfs, "usr/sbin/service")
    upper = _write(rootfs, "lib/libupper.so")
    provider = _write(rootfs, "lib/libendpoint.so")
    index = FirmwareImportIndex(
        elf_kind={executable: "exec", upper: "so", provider: "so"},
        soname_candidates={
            "libupper.so": {upper},
            "libendpoint.so": {provider},
        },
        dt_needed_per_elf={
            executable: ["libupper.so"],
            upper: ["libendpoint.so"],
        },
        symbol_to_elfs={
            "bind": {provider},
            "endpoint_entry": {upper},
        },
        defined_functions_per_elf={provider: {"endpoint_entry"}},
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)

    assert candidate_index._provider_entry_callers == {
        provider: {executable: frozenset({"endpoint_entry"})},
    }


def test_named_identifier_owner_selects_endpoint_provider_in_its_closure(
    tmp_path: Path,
) -> None:
    _rootfs, candidate_index, graph = _shared_provider_fixture(tmp_path)
    first_path = graph.by_name["first"].binary_path
    provider_path = graph.by_name["libipc.so"].binary_path
    candidate_index._constant_section_bytes = (
        lambda path: b"/tmp/demo.sock\0" if path == first_path else b""
    )

    leads = candidate_index._provider_leads(
        _channel(role=EndpointRole.CLIENT),
    )

    assert [(lead.path, lead.source) for lead in leads] == [
        (provider_path, CandidateSource.CONSTANT_INTERSECTION),
    ]


def test_named_identifier_defers_dynamic_provider_without_rejecting_it(
    tmp_path: Path,
) -> None:
    _rootfs, candidate_index, graph = _shared_provider_fixture(tmp_path)
    provider_path = graph.by_name["libipc.so"].binary_path
    dynamic_provider = _write(tmp_path / "rootfs", "lib/libdynamic.so")
    second_path = graph.by_name["second"].binary_path
    index = candidate_index.index
    index.elf_kind[dynamic_provider] = "so"
    index.soname_candidates["libdynamic.so"] = {dynamic_provider}
    index.dt_needed_per_elf[second_path] = ["libdynamic.so"]
    index.symbol_to_elfs["bind"].add(dynamic_provider)
    index.symbol_to_elfs["dynamic_entry"] = {second_path}
    index.defined_functions_per_elf[dynamic_provider] = {"dynamic_entry"}
    candidate_index = ChannelCandidateIndex(tmp_path / "rootfs", index)
    candidate_index._constant_section_bytes = (
        lambda path: b"/tmp/demo.sock\0" if path == provider_path else b""
    )

    channel = _channel(role=EndpointRole.CLIENT)
    leads = candidate_index._provider_leads(
        channel,
    )

    assert [(lead.path, lead.source) for lead in leads] == [
        (provider_path, CandidateSource.CONSTANT_INTERSECTION),
    ]
    batch = candidate_index.prepare_many([channel], graph)
    gaps = batch.gaps_by_channel[channel.channel_id]
    assert any(
        gap.reason_code == "dynamic_identifier_fallback_deferred"
        and "not a static rejection" in gap.missing_evidence[0]
        for gap in gaps
    )


def test_identifier_in_actual_caller_is_typed_caller_supplied(tmp_path: Path) -> None:
    _rootfs, candidate_index, graph = _shared_provider_fixture(tmp_path)
    first = graph.by_name["first"]
    provider = graph.by_name["libipc.so"]
    first._xrefs = {
        "/tmp/demo.sock": [{
            "func": "main", "func_ea": "0x1000", "ea": "0x1010",
        }],
    }
    provider._xrefs = {}
    first_path = first.binary_path
    provider_path = provider.binary_path
    candidate_index._constant_section_bytes = (
        lambda path: b"/tmp/demo.sock\0" if path == first_path else b""
    )

    candidates = candidate_index.prepare_many(
        [_channel(role=EndpointRole.CLIENT)], graph,
    ).candidates_by_channel["channel:demo"]

    assert len(candidates) == 1
    path = candidates[0].call_paths[0]
    assert path.identifier_relation is IdentifierRelation.CALLER_SUPPLIED
    assert path.identifier == "/tmp/demo.sock"
    assert path.identifier_xref_ea == 0x1010


def test_provider_scc_does_not_choose_one_outer_wrapper(tmp_path: Path) -> None:
    _rootfs, candidate_index, graph = _shared_provider_fixture(tmp_path)
    provider = graph.by_name["libipc.so"]
    start_a = provider.get_function_by_ea(0x2000)
    start_b = provider.get_function_by_ea(0x2100)
    graph.adg._edges[start_a][EdgeType.CALL].add(start_b)
    graph.adg._edges[start_b][EdgeType.CALL].add(start_a)
    provider._call_graph._calls[start_a].append(start_b)
    provider._call_graph._calls[start_b].append(start_a)

    endpoints = candidate_index._provider_endpoints(
        _channel(role=EndpointRole.CLIENT), provider, graph.adg,
    )

    assert {item.entry_symbol for item in endpoints} == {"start_a", "start_b"}


def test_ambiguous_provider_is_unresolved_not_guessed(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    peer = _write(rootfs, "usr/sbin/peer")
    first = _write(rootfs, "lib/a/libdup.so")
    second = _write(rootfs, "lib/b/libdup.so")
    index = FirmwareImportIndex(
        elf_kind={peer: "exec", first: "so", second: "so"},
        soname_candidates={"libdup.so": {first, second}},
        dt_needed_per_elf={peer: ["libdup.so"]},
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)
    candidate_index._constant_section_bytes = (
        lambda path: b"/tmp/demo.sock\0" if path == peer else b""
    )
    gaps = {
        gap.reason_code
        for gap in candidate_index._closures[peer].dependency_gaps
    }
    assert gaps == {"ambiguous_provider"}

    graph = SimpleNamespace(add_binary=lambda _path: pytest.fail(
        "ambiguous provider must not reach structural onboarding"
    ))
    batch = candidate_index.prepare_many(
        [_channel(role=EndpointRole.CLIENT)], graph,
    )
    assert "ambiguous_provider" in {
        gap.reason_code
        for gap in batch.gaps_by_channel["channel:demo"]
    }


def test_unrelated_executable_closure_gap_does_not_affect_channel(
    tmp_path: Path,
    monkeypatch,
) -> None:
    rootfs = tmp_path / "rootfs"
    relevant = _write(rootfs, "usr/sbin/relevant")
    unrelated = _write(rootfs, "usr/sbin/unrelated")
    index = FirmwareImportIndex(
        elf_kind={relevant: "exec", unrelated: "exec"},
        symbol_to_elfs={"bind": {relevant}},
        dt_needed_per_elf={unrelated: ["libmissing.so"]},
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)
    candidate_index._constant_section_bytes = (
        lambda path: b"/tmp/demo.sock\0" if path == relevant else b""
    )
    root = SimpleNamespace(binary_path=relevant, structural_ready=True)
    monkeypatch.setattr(
        candidate_index,
        "_ensure_structural_root",
        lambda _path, _graph, **_kwargs: (root, SimpleNamespace()),
    )
    monkeypatch.setattr(
        candidate_index,
        "_provider_endpoints",
        lambda *_args: [],
    )

    batch = candidate_index.prepare_many(
        [_channel(role=EndpointRole.CLIENT)], SimpleNamespace(),
    )

    reasons = {
        gap.reason for gap in batch.gaps_by_channel["channel:demo"]
    }
    assert not any("libmissing.so" in reason for reason in reasons)


@pytest.mark.parametrize(
    ("mechanism", "primitive", "kind", "value"),
    [
        (IPCMechanism.SYSV_SHM, "shmget", "sysv_key", "1001"),
        (IPCMechanism.LOOPBACK_SOCKET, "bind", "socket_port", "554"),
    ],
)
def test_numeric_and_loopback_keep_mechanism_provider(
    tmp_path: Path,
    mechanism: IPCMechanism,
    primitive: str,
    kind: str,
    value: str | None,
) -> None:
    rootfs = tmp_path / "rootfs"
    peer = _write(rootfs, "usr/sbin/peer")
    index = FirmwareImportIndex(
        elf_kind={peer: "exec"}, symbol_to_elfs={primitive: {peer}},
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)
    leads = candidate_index._provider_leads(
        _channel(mechanism=mechanism, kind=kind, value=value),
    )
    assert [(item.path, item.source) for item in leads] == [
        (peer, CandidateSource.MECHANISM_FALLBACK),
    ]


def test_local_loopback_match_accepts_literal_wrapper_arguments() -> None:
    listing = """\
0x0040f68c:  10 f2 44 24  addiu   $a0, $v0, (a127001 - 0x450000) # "127.0.0.1"
0x0040f690:  34 9e 05 34  li      $a1, 0x9E34
0x0040f69c:  8c f3 59 24  addiu   $t9, $v0, (sub_40F38C - 0x410000)
0x0040f6a0:  09 f8 20 03  jalr    $t9  # sub_40F38C
"""

    assert ChannelCandidateIndex._match_loopback_call_window(
        listing, "sub_40F38C", 40500, {"127.0.0.1"},
    ) == ("127.0.0.1", 0x40F69C)


def test_local_loopback_match_accepts_network_order_sockaddr_port() -> None:
    listing = """\
0x00026768:  00 01 02 3c 7f 00 42 34  li      $v0, 0x100007F
0x00026770:  24 00 a2 af              sw      $v0, 0x30+var_10.sa_data+2($sp)
0x00026778:  9e 34 02 24              li      $v0, 0x349E
0x00026784:  22 00 a2 a7              sh      $v0, 0x30+var_10.sa_data($sp)
0x000267a4:  09 f8 20 03              jalr    $t9  # sendto
"""

    assert ChannelCandidateIndex._match_loopback_call_window(
        listing, "sendto", 40500, set(),
    ) == ("127.0.0.1", 0x267A4)


def test_local_loopback_match_does_not_guess_without_complete_pair() -> None:
    wrong_port = """\
0x0040f68c:  10 f2 44 24  addiu   $a0, $v0, (a127001 - 0x450000) # "127.0.0.1"
0x0040f690:  40 9e 05 34  li      $a1, 0x9E40
0x0040f6a0:  09 f8 20 03  jalr    $t9  # sub_40F38C
"""
    missing_address = """\
0x0040f690:  34 9e 05 34  li      $a1, 0x9E34
0x0040f6a0:  09 f8 20 03  jalr    $t9  # sub_40F38C
"""

    assert ChannelCandidateIndex._match_loopback_call_window(
        wrong_port, "sub_40F38C", 40500, set(),
    ) is None
    assert ChannelCandidateIndex._match_loopback_call_window(
        missing_address, "sub_40F38C", 40500, set(),
    ) is None


def test_local_loopback_match_checks_direct_executable_caller(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    executable = _write(rootfs, "bin/wps_monitor")
    init = _Function("wps_monitor", "init_listener", 0x1000)
    endpoint_function = _Function("wps_monitor", "make_listener", 0x2000)
    root = _Binary(
        executable,
        [init, endpoint_function],
        calls={init: [endpoint_function]},
    )
    graph = _Graph([root], _ADG(), {executable: {root}})
    index = ChannelCandidateIndex(
        rootfs,
        FirmwareImportIndex(elf_kind={executable: "exec"}),
    )
    index._function_disassembly = lambda function, _graph: (
        """\
0x00001000:  10 f2 44 24  addiu   $a0, $v0, (a127001 - 0x450000) # "127.0.0.1"
0x00001004:  34 9e 05 34  li      $a1, 0x9E34
0x00001008:  09 f8 20 03  jalr    $t9  # make_listener
"""
        if function is init
        else ""
    )

    match = index._local_loopback_match(
        _channel(
            mechanism=IPCMechanism.LOOPBACK_SOCKET,
            kind="socket_port",
            value="40500",
        ),
        root,
        [endpoint_function],
        SimpleNamespace(
            provider_path=executable,
            primitive="bind",
        ),
        graph,
    )

    assert match == (
        "127.0.0.1:40500",
        0x1008,
        [init, endpoint_function],
    )


def test_loopback_exact_candidate_does_not_prune_unresolved_candidate(
    tmp_path: Path, monkeypatch,
) -> None:
    rootfs = tmp_path / "rootfs"
    exact = _write(rootfs, "usr/sbin/exact")
    unresolved = _write(rootfs, "usr/sbin/unresolved")
    index = ChannelCandidateIndex(
        rootfs,
        FirmwareImportIndex(elf_kind={exact: "exec", unresolved: "exec"}),
    )
    endpoint_by_path = {
        path: SimpleNamespace(
            provider_path=path,
            entry_symbol=None,
            entry_ea=0x1000,
            endpoint_ea=0x1000,
            endpoint_name="open_channel",
            primitive="bind",
            witness_eas=(0x1000,),
        )
        for path in (exact, unresolved)
    }
    roots = {
        path: SimpleNamespace(
            binary_path=path,
            structural_ready=True,
        )
        for path in (exact, unresolved)
    }
    monkeypatch.setattr(
        index,
        "_provider_leads",
        lambda _channel: [
            SimpleNamespace(path=exact, source=CandidateSource.MECHANISM_FALLBACK),
            SimpleNamespace(path=unresolved, source=CandidateSource.MECHANISM_FALLBACK),
        ],
    )
    monkeypatch.setattr(
        index,
        "_ensure_structural_root",
        lambda path, _graph, **_kwargs: (roots[path], SimpleNamespace()),
    )
    monkeypatch.setattr(
        index,
        "_provider_endpoints",
        lambda _channel, provider, _adg: [
            endpoint_by_path[provider.binary_path]
        ],
    )
    exact_path = _path().model_copy(update={
        "identifier_relation": IdentifierRelation.EXACT,
        "identifier": "127.0.0.1:40500",
        "identifier_xref_ea": 0x1010,
        "missing_evidence": [],
    })
    unresolved_path = _path().model_copy(update={
        "entry": _path().entry.model_copy(update={
            "binary_path": "usr/sbin/unresolved",
        }),
        "call_path": [_path().call_path[0].model_copy(update={
            "binary_path": "usr/sbin/unresolved",
        })],
        "endpoint": _path().endpoint.model_copy(update={
            "binary_path": "usr/sbin/unresolved",
        }),
        "identifier_relation": IdentifierRelation.UNRESOLVED,
        "identifier": None,
        "identifier_xref_ea": None,
        "missing_evidence": ["runtime-built endpoint"],
    })
    monkeypatch.setattr(
        index,
        "_candidate_paths",
        lambda _channel, root, *_args: [
            exact_path if root.binary_path == exact else unresolved_path
        ],
    )

    candidates = index.prepare_many([
        _channel(
            mechanism=IPCMechanism.LOOPBACK_SOCKET,
            kind="socket_port",
            value="40500",
        ),
    ], SimpleNamespace()).candidates_by_channel["channel:demo"]

    assert [item.executable_path for item in candidates] == [
        "usr/sbin/exact",
        "usr/sbin/unresolved",
    ]


def test_dynamic_fifo_without_identifier_is_unresolved_before_onboarding(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    peer = _write(rootfs, "usr/sbin/peer")
    index = FirmwareImportIndex(
        elf_kind={peer: "exec"}, symbol_to_elfs={"open": {peer}},
    )
    candidate_index = ChannelCandidateIndex(rootfs, index)
    graph = SimpleNamespace(add_binary=lambda _path: pytest.fail(
        "dynamic FIFO must not trigger unbounded structural onboarding"
    ))

    batch = candidate_index.prepare_many([
        _channel(
            mechanism=IPCMechanism.FIFO,
            kind="fifo_path",
            value=None,
        ),
    ], graph)

    assert batch.candidates_by_channel["channel:demo"] == []
    assert {
        gap.reason_code for gap in batch.gaps_by_channel["channel:demo"]
    } == {"dynamic_fifo_identifier_unresolved"}


def _path() -> EndpointCallPath:
    ref = StructuralFunctionRef(
        binary_path="usr/sbin/peer",
        function_name="open_channel",
        function_ea=0x1000,
    )
    return EndpointCallPath(
        entry=ref,
        call_path=[ref],
        endpoint=PeerEndpointLocation(
            binary_path=ref.binary_path,
            function_name=ref.function_name,
            function_ea=ref.function_ea,
            line_number=None,
            primitive="bind",
        ),
        identifier_relation=IdentifierRelation.EXACT,
        identifier="/tmp/demo.sock",
        identifier_xref_ea=0x1010,
        missing_evidence=[],
    )


def test_controller_merges_candidate_source_and_typed_paths(tmp_path: Path) -> None:
    result = IPCAnalysisResult(execution={"tasks": {}},
        schema_version=IPC_ANALYSIS_SCHEMA_VERSION,
        phase=AnalysisPhase.FULL,
        firmware_sha256="f" * 64,
        target_process=_target(),
        planning_findings=ipc_topology_findings(_target(), [_channel()]),
        callsites=[],
        channels=[_channel().model_copy(update={
            "retrieval_candidates": [PeerCandidateEvidence(
                executable_path="usr/sbin/peer",
                source=CandidateSource.MECHANISM_FALLBACK,
                reasons=["endpoint capability"],
            )],
        })],
        dependency_assessments=[],
        unresolved_items=[],
        callsite_accounting=[],
    )
    updated = IPCResultController(tmp_path).attach_retrieval_candidates(
        result,
        "channel:demo",
        [PeerCandidateEvidence(
            executable_path="usr/sbin/peer",
            source=CandidateSource.CONSTANT_INTERSECTION,
            reasons=["direct path"],
            call_paths=[_path()],
        )],
    )
    candidate = updated.channels[0].retrieval_candidates[0]
    assert candidate.source is CandidateSource.CONSTANT_INTERSECTION
    assert candidate.reasons == ["direct path", "endpoint capability"]
    assert candidate.call_paths == [_path()]


def test_peer_agent_static_gates() -> None:
    agent = PeerVerificationAgent.__new__(PeerVerificationAgent)
    agent.global_config = SimpleNamespace(diagnosis_model="unused")
    common = dict(
        view=SimpleNamespace(),
        firmware_index=FirmwareImportIndex(),
        firmware_sha256="f" * 64,
        rootfs=Path("/not/read"),
        target_process=_target(),
        channel=_channel(),
        candidates=[],
        trace_dir=None,
    )
    assert asyncio.run(agent.verify_channel(phase=AnalysisPhase.STATIC, **common)) is None
    assert asyncio.run(agent.verify_channel(phase=AnalysisPhase.FULL, **common)) is None


def test_candidate_assembly_files_use_typed_path(tmp_path: Path) -> None:
    assembly_root = tmp_path / "disassembled_code"
    assembly = assembly_root / "peer/open_channel@1000.s"
    assembly.parent.mkdir(parents=True)
    rootfs = tmp_path / "rootfs"
    source = _write(rootfs, "usr/sbin/peer")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    assembly.write_text(f"; source_sha256: {source_hash}\n0x1000: nop\n", encoding="utf-8")
    function = SimpleNamespace(
        structural_artifact_stem="open_channel@1000",
        artifact_stem="open_channel",
    )
    binary = SimpleNamespace(
        name="peer",
        binary_path=source,
        semantic_ready=False,
        get_function_by_ea=lambda ea: function if ea == 0x1000 else None,
    )
    view = SimpleNamespace(lib_dep_graph=SimpleNamespace(
        get_node_by_name=lambda name: binary if name == "peer" else None,
    ))
    candidate = PeerCandidateEvidence(
        executable_path="usr/sbin/peer",
        source=CandidateSource.CONSTANT_INTERSECTION,
        reasons=["direct path"],
        call_paths=[_path()],
    )
    assert _candidate_assembly_files(candidate, view, assembly_root, rootfs) == [
        "peer/open_channel@1000.s",
    ]


def test_candidate_assembly_files_resolve_ephemeral_binary_without_graph_node(
    tmp_path: Path,
) -> None:
    assembly_root = tmp_path / "disassembled_code"
    assembly = assembly_root / "peer/open_channel@1000.s"
    assembly.parent.mkdir(parents=True)
    rootfs = tmp_path / "rootfs"
    source = _write(rootfs, "usr/sbin/peer")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    assembly.write_text(f"; source_sha256: {source_hash}\n0x1000: nop\n", encoding="utf-8")
    candidate = PeerCandidateEvidence(
        executable_path="usr/sbin/peer",
        source=CandidateSource.CONSTANT_INTERSECTION,
        reasons=["temporary candidate"],
        call_paths=[_path()],
    )
    view = SimpleNamespace(lib_dep_graph=SimpleNamespace(
        get_node_by_name=lambda name: None,
    ))

    assert _candidate_assembly_files(candidate, view, assembly_root, rootfs) == [
        "peer/open_channel@1000.s",
    ]


def test_peer_assembly_reader_enforces_exact_controller_allowlist(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "peer/open_channel.s"
    denied = tmp_path / "target/main.s"
    allowed.parent.mkdir(parents=True)
    denied.parent.mkdir(parents=True)
    allowed.write_text("allowed\n", encoding="utf-8")
    denied.write_text("denied\n", encoding="utf-8")
    reader = _make_assembly_reader(tmp_path, {"peer/open_channel.s"})

    assert reader.invoke({"path": "peer/open_channel.s"}) == "allowed"
    assert "outside this Channel evidence set" in reader.invoke({
        "path": "target/main.s",
    })
    assert "escapes" in reader.invoke({
        "path": "../secret.s",
    })


def test_peer_verifications_run_bounded(tmp_path: Path) -> None:
    class FakePeerAgent:
        def __init__(self) -> None:
            self.active = 0
            self.peak = 0

        async def verify_channel(self, **kwargs):
            self.active += 1
            self.peak = max(self.peak, self.active)
            await asyncio.sleep(0.01)
            self.active -= 1
            return SimpleNamespace(channel_id=kwargs["channel"].channel_id)

    channels = [_channel(channel_id=f"channel:{name}") for name in "cab"]
    analyzer = IPCAnalyzer.__new__(IPCAnalyzer)
    from fmst_analyzer.analysis.base.execution import ExecutionTracker
    analyzer.execution = ExecutionTracker()
    analyzer.global_config = SimpleNamespace(
        agent_concurrency_limit=2,
        fw_rootfs_path=tmp_path,
        workdir=None,
        current_target=None,
    )
    analyzer._peer_agent = FakePeerAgent()
    context = PeerMatchingContext(
        lib_dep_graph=SimpleNamespace(),
        firmware_import_index=FirmwareImportIndex(),
        main_exec=tmp_path / "httpd",
        firmware_sha256="f" * 64,
    )
    completed = asyncio.run(analyzer._verify_peers(
        phase=AnalysisPhase.FULL,
        view=SimpleNamespace(),
        target_process=_target(),
        channels=channels,
        prepared_candidates={channel.channel_id: [SimpleNamespace()] for channel in channels},
        peer_context=context,
        candidate_index=None,
    ))
    assert analyzer._peer_agent.peak == 2
    assert [identity for identity, _ in completed] == [
        "channel:a", "channel:b", "channel:c",
    ]


def test_peer_verification_failure_remains_channel_local(tmp_path: Path) -> None:
    class FakePeerAgent:
        async def verify_channel(self, **kwargs):
            identity = kwargs["channel"].channel_id
            if identity == "channel:b":
                raise OutputValidationError("missing endpoint accounting")
            return SimpleNamespace(channel_id=identity)

    channels = [_channel(channel_id=f"channel:{name}") for name in "ba"]
    analyzer = IPCAnalyzer.__new__(IPCAnalyzer)
    from fmst_analyzer.analysis.base.execution import ExecutionTracker
    analyzer.execution = ExecutionTracker()
    analyzer.global_config = SimpleNamespace(
        agent_concurrency_limit=2,
        fw_rootfs_path=tmp_path,
        workdir=None,
        current_target=None,
    )
    analyzer._peer_agent = FakePeerAgent()
    context = PeerMatchingContext(
        lib_dep_graph=SimpleNamespace(),
        firmware_import_index=FirmwareImportIndex(),
        main_exec=tmp_path / "httpd",
        firmware_sha256="f" * 64,
    )
    completed = asyncio.run(analyzer._verify_peers(
        phase=AnalysisPhase.FULL,
        view=SimpleNamespace(),
        target_process=_target(),
        channels=channels,
        prepared_candidates={channel.channel_id: [SimpleNamespace()] for channel in channels},
        peer_context=context,
        candidate_index=None,
    ))
    assert not isinstance(completed[0][1], Exception)
    assert completed[1][1] is None
    outcome = analyzer.execution.record.tasks[f"peer:{completed[1][0]}"]
    assert outcome.status == "failed"
    assert outcome.failure.kind == "invalid_output"
    assert analyzer.execution.record.status == "partial"


def test_peer_agent_rejects_non_candidate_verdict(tmp_path: Path) -> None:
    peer = _write(tmp_path, "usr/sbin/peer")
    finding = SimpleNamespace(
        executable_path="usr/sbin/peer",
        argv0="peer",
        verdict=CandidateVerdict.REJECTED,
        evidence=[],
        endpoint_locations=[],
    )
    with pytest.raises(ValueError, match="exactly the controller candidate set"):
        PeerVerificationAgent._validate_output(
            SimpleNamespace(peer_findings=[finding]),
            channel=_channel(),
            firmware_index=FirmwareImportIndex(elf_kind={peer: "exec"}),
            rootfs=tmp_path,
            candidate_paths=set(),
        )


@pytest.mark.parametrize("verdict", [CandidateVerdict.VERIFIED, CandidateVerdict.REJECTED])
def test_peer_agent_accepts_decision_without_controller_endpoint_path(
    tmp_path: Path, verdict: CandidateVerdict,
) -> None:
    peer = _write(tmp_path, "usr/sbin/peer")
    finding = SimpleNamespace(
        executable_path="usr/sbin/peer",
        argv0="peer",
        verdict=verdict,
        evidence=[],
        endpoint_locations=[SimpleNamespace(
            binary_path="usr/sbin/peer",
            function_name="open_channel",
            function_ea=0x1000,
            primitive="bind",
        )],
    )
    PeerVerificationAgent._validate_output(
        SimpleNamespace(peer_findings=[finding]),
        channel=_channel(),
        firmware_index=FirmwareImportIndex(elf_kind={peer: "exec"}),
        rootfs=tmp_path,
        candidate_paths={"usr/sbin/peer"},
    )


@pytest.mark.parametrize(
    "verdict", [CandidateVerdict.REJECTED, CandidateVerdict.UNRESOLVED],
)
def test_peer_agent_accepts_additional_existing_endpoint_path(
    tmp_path: Path, verdict: CandidateVerdict,
) -> None:
    peer = _write(tmp_path, "usr/sbin/peer")
    bogus = _write(tmp_path, "usr/sbin/bogus")
    finding = SimpleNamespace(
        executable_path="usr/sbin/peer",
        argv0="peer",
        verdict=verdict,
        evidence=[],
        endpoint_locations=[SimpleNamespace(
            binary_path="usr/sbin/bogus",
            function_name="invented",
            function_ea=0x9999,
            primitive="connect",
        )],
    )

    PeerVerificationAgent._validate_output(
        SimpleNamespace(peer_findings=[finding]),
        channel=_channel(role=EndpointRole.CLIENT),
        firmware_index=FirmwareImportIndex(elf_kind={
            peer: "exec",
            bogus: "exec",
        }),
        rootfs=tmp_path,
        candidate_paths={"usr/sbin/peer"},
    )


def test_peer_agent_accepts_evidence_outside_candidate_paths(
    tmp_path: Path,
) -> None:
    peer = _write(tmp_path, "usr/sbin/peer")
    _write(tmp_path, "etc/unrelated.conf")
    finding = SimpleNamespace(
        executable_path="usr/sbin/peer",
        argv0="peer",
        verdict=CandidateVerdict.REJECTED,
        evidence=[SimpleNamespace(
            binary_path="etc/unrelated.conf",
            callsite_id=None,
        )],
        endpoint_locations=[],
    )

    PeerVerificationAgent._validate_output(
        SimpleNamespace(peer_findings=[finding]),
        channel=_channel(role=EndpointRole.CLIENT),
        firmware_index=FirmwareImportIndex(elf_kind={peer: "exec"}),
        rootfs=tmp_path,
        candidate_paths={"usr/sbin/peer"},
    )


def test_candidate_function_owner_is_not_selected_by_basename(tmp_path):
    rootfs = tmp_path / "rootfs"
    first_path = _write(rootfs, "sbin/peer")
    second_path = _write(rootfs, "usr/sbin/peer")
    functions = [_Function("peer", "open_channel", 0x1000) for _ in range(2)]
    owners = [_Binary(path, [fn]) for path, fn in zip((first_path, second_path), functions)]
    index = ChannelCandidateIndex(rootfs, FirmwareImportIndex())
    index._candidate_nodes = dict(zip((first_path, second_path), owners))
    graph = SimpleNamespace(get_node_by_name=lambda _name: owners[0])
    active = []
    for owner, fn in zip(owners, functions):
        owner.activate = lambda owner=owner: active.append(owner)
        owner.deactivate = lambda owner=owner: active.remove(owner)
        fn.get_disassembly = lambda owner=owner: str(active[-1].binary_path) if active[-1] is owner else pytest.fail("wrong owner")
    assert index._function_ref(functions[1], graph).binary_path == "usr/sbin/peer"
    assert index._function_disassembly(functions[1], graph) == str(second_path)
    assert index._function_disassembly(functions[0], graph) == str(first_path)
    assert active == []


def test_candidate_assembly_source_identity_rejects_same_name_other_binary(tmp_path):
    rootfs = tmp_path / "rootfs"
    source = _write(rootfs, "usr/sbin/peer")
    other = _write(rootfs, "sbin/peer")
    other.write_bytes(b"different ELF")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    other_hash = hashlib.sha256(other.read_bytes()).hexdigest()
    assembly_root = tmp_path / "assembly"
    wrong = assembly_root / "peer/open_channel@1000.s"
    wrong.parent.mkdir(parents=True)
    wrong.write_text(f"; source_sha256: {other_hash}\n0x1000: wrong\n")
    view = SimpleNamespace(lib_dep_graph=SimpleNamespace(get_node_by_name=lambda name: SimpleNamespace(binary_path=other)))
    candidate = PeerCandidateEvidence(executable_path="usr/sbin/peer", source=CandidateSource.CONSTANT_INTERSECTION, reasons=["candidate"], call_paths=[_path()])
    assert _candidate_assembly_files(candidate, view, assembly_root, rootfs) == []
    right = assembly_root / "ipc" / source_hash / "peer/open_channel@1000.s"
    right.parent.mkdir(parents=True)
    right.write_text(f"; source_sha256: {source_hash}\n0x1000: right\n")
    assert _candidate_assembly_files(candidate, view, assembly_root, rootfs) == [right.relative_to(assembly_root).as_posix()]
    assert wrong.is_file()
