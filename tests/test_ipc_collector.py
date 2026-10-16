"""Tests for deterministic IPC anchor collection."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv

load_dotenv()

from fmst_analyzer.analysis.ipc_analyzer.collector import (  # noqa: E402
    StaticIPCCollector,
    group_callsites_by_function,
)
from fmst_analyzer.analysis.ipc_analyzer.registry import (  # noqa: E402
    INTERACTION_APIS,
    InteractionRole,
)
from fmst_analyzer.analysis.ipc_analyzer.peer.firmware_import_index import (  # noqa: E402
    FirmwareImportIndex,
)
from fmst_analyzer.analysis.ipc_analyzer.schema import (  # noqa: E402
    APIBindingKind,
    AnalysisPhase,
    CallsiteDisposition,
    TargetProcess,
    VerificationStatus,
)
from fmst_analyzer.nodes.callsite import ArgInfo, ArgType, CallSite  # noqa: E402


class _PltFunctionMisclassifiedAsLocal:
    def has_attr(self, _attribute) -> bool:
        return False


class _CallGraph:
    def has_node_by_name(self, name: str) -> bool:
        return name in {"connect", "kill"}

    def get_node_by_name(self, _name: str):
        return _PltFunctionMisclassifiedAsLocal()


class _LibDepGraph:
    def __init__(self, binary_path: Path, provider_path: Path):
        self.binary = SimpleNamespace(binary_path=binary_path)
        self.provider = SimpleNamespace(binary_path=provider_path)

    def get_node_by_name(self, name: str):
        if name == "httpd":
            return self.binary
        return None

    def get_callgraph_by_name(self, name: str):
        return _CallGraph() if name == "httpd" else None


class _View:
    def __init__(
        self,
        lib_dep_graph: _LibDepGraph,
        callsites: dict[str, list[CallSite]],
        snapshot=None,
    ):
        self.lib_dep_graph = lib_dep_graph
        self.adg = SimpleNamespace()
        self.callsites = callsites
        self.snapshot = snapshot

    def collect_api_callsites(self, api_name: str):
        return list(self.callsites.get(api_name, []))

    @staticmethod
    def get_decompiled_name(_binary_name: str, _function_ea: int) -> str:
        return "main"

    def _get_callgraph_for_binary(self, _binary_name: str):
        if self.snapshot is None:
            return None
        node = SimpleNamespace(semantic_snapshot=self.snapshot)
        return SimpleNamespace(get_node_by_ea=lambda _ea: node)


def _callsite(callee: str, ctree_index: int, expression: str) -> CallSite:
    site = CallSite(
        binary_name="httpd",
        caller_ea=0x1000,
        caller_name="main",
        callee_ea=0,
        callee_name=callee,
        callsite_ea=0x1010 + ctree_index * 4,
        line_number=10 + ctree_index,
        column_number=2,
        binary_identity="/rootfs/usr/sbin/httpd:sha",
        snapshot_hash="b" * 64,
        ctree_index=ctree_index,
        source_ea=0x1010 + ctree_index * 4,
        expression_text=expression,
        call_kind="direct",
    )
    site.set_arguments([
        ArgInfo(index=1, value="fd", type=ArgType.LOCAL),
        ArgInfo(index=2, value="&addr", type=ArgType.OTHER),
    ])
    site.set_return_var(ArgInfo(index=-1, value="result", type=ArgType.LOCAL))
    site.is_populated = True
    return site


def _with_handle(site: CallSite, argument: str, result: str | None) -> CallSite:
    site.set_arguments([
        ArgInfo(index=1, value=argument, type=ArgType.LOCAL),
        ArgInfo(index=2, value="&addr", type=ArgType.OTHER),
    ])
    site.set_return_var(
        ArgInfo(index=-1, value=result, type=ArgType.LOCAL)
        if result is not None else None
    )
    return site


class _Snapshot:
    snapshot_hash = "b" * 64

    def trace_variable_prop(self, _function_name: str, identifier: str):
        return SimpleNamespace(variables=[SimpleNamespace(
            identity=f"lvar:{identifier}", varname=identifier,
        )])


def test_registry_covers_rehosting_relevant_ipc_families_only() -> None:
    assert INTERACTION_APIS["connect"].family == "socket_endpoint"
    assert INTERACTION_APIS["shmat"].family == "sysv_shm"
    assert INTERACTION_APIS["connect"].role is InteractionRole.RESOURCE_ANCHOR
    assert INTERACTION_APIS["send"].role is InteractionRole.AUXILIARY
    assert INTERACTION_APIS["recv"].role is InteractionRole.AUXILIARY
    assert INTERACTION_APIS["shmat"].role is InteractionRole.FALLBACK_ACCESSOR
    assert "kill" not in INTERACTION_APIS
    assert "signal" not in INTERACTION_APIS
    assert "sigaction" not in INTERACTION_APIS
    assert "fork" not in INTERACTION_APIS
    assert "execve" not in INTERACTION_APIS
    assert "system" not in INTERACTION_APIS
    assert "popen" not in INTERACTION_APIS
    assert "pipe" not in INTERACTION_APIS
    assert "socketpair" not in INTERACTION_APIS


def test_collector_preserves_ctree_facts_and_groups_by_function(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    binary = rootfs / "usr/sbin/httpd"
    provider = rootfs / "lib/libc.so.0"
    binary.parent.mkdir(parents=True)
    provider.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELFhttpd")
    provider.write_bytes(b"\x7fELFlibc")

    graph = _LibDepGraph(binary, provider)
    view = _View(graph, {
        "connect": [_callsite("connect", 3, "connect(fd, &addr, 16)")],
        "kill": [_callsite("kill", 9, "kill(pid, 10)")],
    })
    role = TargetProcess(
        executable_path="usr/sbin/httpd",
        executable_sha256="a" * 64,
        argv0="httpd",
    )

    import_index = FirmwareImportIndex(
        symbol_to_elfs={"connect": {binary}, "kill": {binary}},
    )
    collector = StaticIPCCollector(rootfs, "f" * 64, import_index)
    first = collector.collect_process(view, role)
    second = collector.collect_process(view, role)

    assert first == second
    assert [fact.callee_name for fact in first.callsites] == ["connect"]
    assert len({fact.callsite_id for fact in first.callsites}) == 1
    assert all(
        fact.location.binary_path == "usr/sbin/httpd"
        for fact in first.callsites
    )
    assert first.callsites[0].arguments[1].expression == "&addr"
    assert first.callsites[0].api_binding.kind is APIBindingKind.DYNAMIC_IMPORT
    assert first.callsites[0].api_binding.binary_path is None
    assert first.callsites[0].api_binding.status is VerificationStatus.VERIFIED_STATIC
    assert "undefined in its dynamic symbol table" in first.callsites[0].api_binding.reason

    grouped = group_callsites_by_function(first.callsites)
    assert len(grouped) == 1
    assert [fact.location.ctree_index for fact in next(iter(grouped.values()))] == [3]

    static = collector.static_result(role, first.callsites)
    assert static.phase is AnalysisPhase.STATIC
    assert static.target_process == role
    assert len(static.unresolved_items) == 1
    assert all(
        item.disposition is CallsiteDisposition.UNRESOLVED
        for item in static.callsite_accounting
    )
    assert len({
        item.unresolved_item_ids[0] for item in static.callsite_accounting
    }) == 1


def test_collector_keeps_only_anchor_and_attaches_same_handle_operations(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    binary = rootfs / "usr/sbin/httpd"
    provider = rootfs / "lib/libc.so.0"
    binary.parent.mkdir(parents=True)
    provider.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELFhttpd")
    provider.write_bytes(b"\x7fELFlibc")

    socket_call = _with_handle(
        _callsite("socket", 1, "fd = socket(2, 1, 0)"), "2", "fd",
    )
    connect_call = _with_handle(
        _callsite("connect", 2, "connect(fd, &addr, 16)"), "fd", "result",
    )
    send_call = _with_handle(
        _callsite("send", 3, "send(fd, buf, len, 0)"), "fd", "result",
    )
    graph = _LibDepGraph(binary, provider)
    view = _View(
        graph,
        {"socket": [socket_call], "connect": [connect_call], "send": [send_call]},
        snapshot=_Snapshot(),
    )
    index = FirmwareImportIndex(symbol_to_elfs={
        "socket": {binary}, "connect": {binary}, "send": {binary},
    })
    role = TargetProcess(
        executable_path="usr/sbin/httpd",
        executable_sha256="a" * 64,
        argv0="httpd",
    )

    collected = StaticIPCCollector(rootfs, "f" * 64, index).collect_process(
        view, role,
    )

    assert [fact.callee_name for fact in collected.callsites] == ["connect"]
    assert [
        fact.callee_name
        for facts in collected.auxiliary_by_function.values()
        for fact in facts
    ] == ["socket", "send"]
    assert collected.ignored_auxiliary_count == 0


def test_accessor_is_promoted_only_without_a_unique_getter_flow(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    binary = rootfs / "usr/sbin/httpd"
    provider = rootfs / "lib/libc.so.0"
    binary.parent.mkdir(parents=True)
    provider.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELFhttpd")
    provider.write_bytes(b"\x7fELFlibc")
    getter = _with_handle(
        _callsite("shmget", 1, "shmid = shmget(1234, 528, 0)"),
        "1234", "shmid",
    )
    attached = _with_handle(
        _callsite("shmat", 2, "ptr = shmat(shmid, 0, 0)"),
        "shmid", "ptr",
    )
    orphan = _with_handle(
        _callsite("shmat", 3, "other = shmat(external_id, 0, 0)"),
        "external_id", "other",
    )
    graph = _LibDepGraph(binary, provider)
    view = _View(
        graph,
        {"shmget": [getter], "shmat": [attached, orphan]},
        snapshot=_Snapshot(),
    )
    index = FirmwareImportIndex(symbol_to_elfs={
        "shmget": {binary}, "shmat": {binary},
    })
    role = TargetProcess(
        executable_path="usr/sbin/httpd",
        executable_sha256="a" * 64,
        argv0="httpd",
    )

    collected = StaticIPCCollector(rootfs, "f" * 64, index).collect_process(
        view, role,
    )

    assert [fact.callee_name for fact in collected.callsites] == [
        "shmget", "shmat",
    ]
    auxiliary = [
        fact
        for facts in collected.auxiliary_by_function.values()
        for fact in facts
    ]
    assert [fact.location.ctree_index for fact in auxiliary] == [2]
