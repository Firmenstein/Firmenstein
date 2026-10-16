"""Static-phase side-effect gate and independent candidate collection."""
import asyncio
import pytest
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.network_analyzer.analyzer import (
    NetworkAnalyzer,
)
from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    IdentityResolution,
    NetworkAnalysisResult,
    NetworkAPIBinding,
    NetworkCallsite,
    NetworkCodeLocation,
    NetworkDisposition,
    NetworkIdentity,
    NetworkInteractionAnalysis,
    NetworkInteractionKind,
)
from fmst_analyzer.graphs.api_dep_graph import ImplStatus
from fmst_analyzer.nodes.callsite import ArgInfo, ArgType, CallSite




def _result(**fields):
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics
    from fmst_analyzer.analysis.network_analyzer.findings import NetworkInteractionResult, build_findings
    target = FindingTarget(path="usr/sbin/" + fields["root_binary"], sha256="a" * 64)
    outcomes = [NetworkInteractionResult(item, FindingSemantics(**dict(summary="Synthetic fixture; behavior unassessed.",
        claims=[dict(kind="unknown", statement="No semantic analysis in this fixture.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[])))
                for item in fields.get("analyses", [])]
    return NetworkAnalysisResult(execution={"tasks": {}},
        schema_version=fields.pop("schema_version", 11), finding_target=target,
        planning_findings=build_findings(target, outcomes), **fields,
    )

def _fact():
    return NetworkCallsite(
        callsite_id="cs1",
        location=NetworkCodeLocation(
            binary_name="httpd",
            binary_path="usr/sbin/httpd",
            binary_sha256="a" * 64,
            function_name="main",
            function_ea=0x1000,
            snapshot_hash="b" * 64,
            ctree_index=1,
            line_number=2,
            column_number=0,
        ),
        api_name="ioctl",
        api_family="ioctl",
        api_binding=NetworkAPIBinding(
            symbol="ioctl", call_kind="direct", verified=True,
        ),
        expression_text="ioctl(fd, req)",
        arguments=[],
    )


class _Config:
    workdir = None
    agent_concurrency_limit = 10


class _Root:
    name = "httpd"


class _View:
    root = _Root()



@pytest.fixture(autouse=True)
def _selected_target(tmp_path, monkeypatch):
    rootfs = tmp_path / "target-rootfs"
    target = rootfs / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"synthetic target")
    monkeypatch.setattr(_Config, "fw_rootfs_path", rootfs, raising=False)
    monkeypatch.setattr(_Root, "binary_path", target, raising=False)

def test_static_phase_never_constructs_agent(monkeypatch):
    analyzer = NetworkAnalyzer(_Config())
    fact = _fact()
    monkeypatch.setattr(analyzer, "_collect_callsites", lambda view: {"cs1": fact})

    class _Forbidden:
        def __init__(self, *args, **kwargs):
            raise AssertionError("static phase constructed an Agent")

    import fmst_analyzer.analysis.network_analyzer.analyzer as module
    monkeypatch.setattr(module, "NetworkInteractionAgent", _Forbidden)
    result = asyncio.run(analyzer.run(_View(), phase="static"))
    assert result.pending_callsite_ids == ["cs1"]
    assert result.analyses == []


def test_interaction_node_itself_gates_static_phase(monkeypatch):
    from fmst_analyzer.analysis.network_analyzer import interaction_agent

    def forbidden(*args, **kwargs):
        raise AssertionError("static node attempted Agent work")

    monkeypatch.setattr(interaction_agent, "CodeAnalyzerAgent", forbidden)
    agent = interaction_agent.NetworkInteractionAgent(_Config(), asyncio.Semaphore(1))
    # Exercise the node directly, bypassing NetworkAnalyzer.run's outer gate.
    result = asyncio.run(agent.analyze(_View(), "httpd", [_fact()], phase="static"))
    assert result == []


def test_collection_keeps_reachable_custom_library_callsite(tmp_path):
    rootfs = tmp_path / "rootfs"
    binary_path = rootfs / "lib" / "libvendor.so"
    binary_path.parent.mkdir(parents=True)
    binary_path.write_bytes(b"ELF fixture")

    class _ConfigWithRoot(_Config):
        fw_rootfs_path = rootfs

    class _External:
        module = "libvendor.so"
        name = "__imp_connect"
        ea = 0

        def has_attr(self, attr):
            return True

    class _ADG:
        def get_reachable_nodes(self):
            return [_External()]

        def get_impl_status(self, node):
            return ImplStatus.DEFAULT_LIB

    class _Binary:
        def __init__(self, path):
            self.binary_path = path

    class _LDG:
        def get_node_by_name(self, name):
            return _Binary(binary_path) if name == "libvendor.so" else None

    callsite = CallSite(
        binary_name="libvendor.so",
        caller_ea=0x2000,
        caller_name="vendor_connect",
        callee_ea=0,
        callee_name="connect",
        callsite_ea=0x2010,
        line_number=7,
        column_number=3,
        snapshot_hash="c" * 64,
        ctree_index=9,
        source_ea=0x2010,
        expression_text="connect(fd, addr, len)",
        call_kind="direct",
    )
    callsite.set_arguments([
        ArgInfo(1, "fd", ArgType.LOCAL),
        ArgInfo(2, "addr", ArgType.LOCAL),
        ArgInfo(3, "len", ArgType.LOCAL),
    ])

    class _CollectView:
        adg = _ADG()
        lib_dep_graph = _LDG()

        def collect_api_callsites(self, api):
            return [callsite] if api == "connect" else []

        def get_decompiled_name(self, binary, ea):
            return "vendor_connect"

    facts = NetworkAnalyzer(_ConfigWithRoot())._collect_callsites(_CollectView())
    assert len(facts) == 1
    fact = next(iter(facts.values()))
    assert fact.location.binary_name == "libvendor.so"
    assert fact.location.binary_path == "lib/libvendor.so"
    assert fact.api_name == "connect"


def test_static_persistence_removes_previous_full_interaction_pages(tmp_path):
    reports_root = tmp_path / "diagnostic_reports" / "httpd"

    class _DiskConfig(_Config):
        workdir = tmp_path

        def target_diagnostic_reports_dir(self):
            return reports_root

    fact = _fact()
    analysis = NetworkInteractionAnalysis(
        context_anchor=dict(binary_name="httpd", function_name="main", line_number=1, column_number=0),
        applicability="Synthetic source context for this structural test.",
        interaction_id="network:" + "c" * 24,
        anchor_callsite_id=fact.callsite_id,
        callsite_ids=[fact.callsite_id],
        disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.INTERFACE_QUERY,
        identity=NetworkIdentity(
            resolution=IdentityResolution.PARTIAL,
            interface="fd-derived interface",
            operation="ioctl",
        ),

        summary="The ioctl queries interface state.",
    )
    analyzer = NetworkAnalyzer(_DiskConfig())
    unresolved = NetworkInteractionAnalysis(
        context_anchor=None,
        applicability="Synthetic source context for this structural test.",
        interaction_id="network:" + "d" * 24,
        anchor_callsite_id=fact.callsite_id,
        callsite_ids=[fact.callsite_id],
        disposition=NetworkDisposition.UNRESOLVED,
        summary="The descriptor owner is unresolved.",
        missing_evidence=["descriptor creation site"],
    )
    analyzer.publish_reports(_result(
        phase="full",
        root_binary="httpd",
        callsites={fact.callsite_id: fact},
        analyses=[analysis, unresolved],
    ))
    out_dir = reports_root / "network_reports"
    detail_files = set(out_dir.glob("interface_query__*.*"))
    assert len(detail_files) == 2
    unresolved_files = set(out_dir.glob("unresolved__*.*"))
    assert len(unresolved_files) == 2
    stale_json = out_dir / "resolver__stale.json"
    stale_md = out_dir / "resolver__stale.md"
    unrelated = out_dir / "notes.txt"
    stale_json.write_text("{}", encoding="utf-8")
    stale_md.write_text("stale", encoding="utf-8")
    unrelated.write_text("keep", encoding="utf-8")

    original = _result(
        phase="static",
        root_binary="httpd",
        callsites={fact.callsite_id: fact},
        pending_callsite_ids=[fact.callsite_id],
    )
    published = analyzer.publish_reports(original)
    reloaded = NetworkAnalysisResult.model_validate_json(
        (out_dir / "network_analysis_result.json").read_text(encoding="utf-8")
    )
    assert published == reloaded
    assert published is not original
    assert not set(out_dir.glob("interface_query__*.*"))
    assert not set(out_dir.glob("unresolved__*.*"))
    assert not stale_json.exists()
    assert not stale_md.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"
