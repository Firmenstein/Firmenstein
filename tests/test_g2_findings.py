"""Current Analyzer findings: provenance, rejection boundaries and pure replay."""
import asyncio
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from fmst_analyzer.analysis.base.analysis_finding import resolve_evidence_ref


FIXTURES = Path(__file__).parent / "fixtures/g2"
HISTORICAL_MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
CURRENT_FIXTURES = FIXTURES.parent / "g2_integrity"
CURRENT_MANIFEST = json.loads((CURRENT_FIXTURES / "manifest.json").read_text())
MANIFEST = dict(HISTORICAL_MANIFEST)
for section in ("entries", "report_entries"):
    replacements = {entry["path"]: entry for entry in CURRENT_MANIFEST[section]}
    MANIFEST[section] = [replacements.get(entry["path"], entry) for entry in HISTORICAL_MANIFEST[section]]


def _fixture(entry, field="path"):
    root = FIXTURES.parent / entry.get("fixture_version", "g2")
    return root / entry[field]


def _symbol(value):
    module, name = value.split(":")
    return getattr(importlib.import_module(module), name)


def _load(name):
    entry = next(item for item in MANIFEST["entries"] if item["path"] == name + ".json")
    return _symbol(entry["model"]).model_validate_json(_fixture(entry).read_text())


@pytest.mark.parametrize("entry", MANIFEST["entries"] + MANIFEST.get("report_entries", []), ids=lambda entry: entry["path"])
def test_frozen_current_results_replay_every_finding_field(entry):
    raw = _fixture(entry).read_bytes()
    markdown = _fixture(entry, "markdown").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
    assert hashlib.sha256(markdown).hexdigest() == entry["markdown_sha256"]
    model_type = _symbol(entry["model"])
    result = model_type.model_validate_json(raw)
    assert result.model_dump(mode="json") == json.loads(raw)
    assert model_type.model_validate_json(result.model_dump_json()) == result
    before = result.model_dump_json()
    assert _symbol(entry["renderer"])(result) == markdown.decode()
    assert result.model_dump_json() == before
    for key, finding in getattr(result, "planning_findings", {}).items():
        assert finding.finding_ref == key
        for claim in finding.claims:
            for ref in claim.evidence_refs:
                resolve_evidence_ref(json.loads(raw), ref)
        for label in ("finding_ref", "summary", "boundary", "anchors", "claims", "domain"):
            assert label in markdown.decode()


@pytest.mark.parametrize("entry", [entry for section in ("entries", "report_entries")
    for entry in HISTORICAL_MANIFEST[section] if entry["path"].startswith(("init_", "network_", "file_"))], ids=lambda item: item["path"])
def test_retired_context_schemas_are_preserved_and_rejected(entry):
    raw = (FIXTURES / entry["path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
    assert hashlib.sha256((FIXTURES / entry["markdown"]).read_bytes()).hexdigest() == entry["markdown_sha256"]
    with pytest.raises(ValidationError):
        _symbol(entry["model"]).model_validate_json(raw)


@pytest.mark.parametrize("name", ["process_full", "init_full", "file_full", "network_full", "ipc_full"])
@pytest.mark.parametrize("field", ["schema_version", "phase", "planning_findings", "finding_target"])
def test_current_result_does_not_default_missing_contract_fields(name, field):
    result = _load(name)
    payload = result.model_dump(mode="json")
    if name.startswith("ipc") and field == "finding_target":
        field = "target_process"
    payload.pop(field)
    with pytest.raises(ValidationError, match=field):
        type(result).model_validate(payload)


@pytest.mark.parametrize("name", ["process_full", "init_full", "file_full", "network_full", "ipc_full"])
@pytest.mark.parametrize("corruption", ["source", "key", "domain", "anchor", "evidence", "reachability", "coverage"])
def test_result_rejects_wrong_source_identity_or_dangling_references(name, corruption):
    result = _load(name)
    payload = result.model_dump(mode="json")
    key, finding = next(iter(payload["planning_findings"].items()))
    if corruption == "source":
        if name.startswith("ipc"):
            payload["target_process"]["executable_sha256"] = "b" * 64
        else:
            payload["finding_target"]["sha256"] = "b" * 64
    elif corruption == "key":
        payload["planning_findings"][key + "0"] = payload["planning_findings"].pop(key)
    elif corruption == "domain":
        identity = {"process": "callsite_id", "init": "recipe_id", "file": "resource_id",
                    "network": "interaction_id", "ipc": "channel_id"}[name.split("_")[0]]
        finding["domain"][identity] = "another-subject"
    elif corruption == "anchor":
        finding["boundary"]["anchors"][0]["ref"] = "/finding_target/path"
    elif corruption == "evidence":
        finding["claims"][0]["evidence_refs"] = ["/finding_target/path"]
    else:
        finding["boundary"][corruption + "_refs"] = ["/finding_target/path"]
    with pytest.raises(ValidationError):
        type(result).model_validate(payload)


def test_real_process_retains_identity_and_correct_cli_lifecycle_semantics():
    static, full = _load("process_static"), _load("process_full")
    assert static.planning_findings.keys() == full.planning_findings.keys()
    assert all(claim.kind == "unknown" for item in static.planning_findings.values() for claim in item.claims)
    assert {item.disposition.value for item in full.assessments.values()} == {"expected_lifecycle"}
    claims = next(iter(full.planning_findings.values())).claims
    assert {item.kind for item in claims} == {"guarantee", "state", "fallback", "unknown"}
    assert "after earlier dispatch operations" in next(item.statement for item in claims if item.kind == "state")
    assert "exit(0)" in (FIXTURES / "nvram_usage.c").read_text()
    assert "v3 = (const char *)*v4" in (FIXTURES / "nvram_main.c").read_text()
    # Every real Agent code citation refers to a captured source line.
    for assessment in full.assessments.values():
        for evidence in assessment.evidence:
            lines = (FIXTURES / f"nvram_{evidence.function_name}.c").read_text().splitlines()
            assert 1 <= evidence.line_number <= len(lines)
            if evidence.api_name:
                assert evidence.api_name in lines[evidence.line_number - 1]


def test_inner_process_and_launch_nodes_gate_before_agent_construction(tmp_path, monkeypatch):
    from fmst_analyzer.analysis.process_lifecycle.process_lifecycle_agent import ProcessLifecycleAgent
    from fmst_analyzer.analysis.init_launch.launch_recipe_agent import LaunchRecipeAgent

    def forbidden(*args, **kwargs):
        raise AssertionError("Agent constructed during static phase")

    monkeypatch.setattr("fmst_analyzer.analysis.process_lifecycle.process_lifecycle_agent.CodeAnalyzerAgent", forbidden)
    monkeypatch.setattr("fmst_analyzer.analysis.init_launch.launch_recipe_agent.create_analysis_agent", forbidden)
    config = SimpleNamespace(diagnosis_model="test", workdir=None)
    with pytest.raises(ValueError, match="full phase"):
        asyncio.run(ProcessLifecycleAgent(config, asyncio.Semaphore(1))._analyze_one(None, None, phase="static"))
    with pytest.raises(ValueError, match="full phase"):
        asyncio.run(LaunchRecipeAgent(config).analyze(None, tmp_path, [], phase="static"))


def test_init_static_stage_never_dispatches_and_full_does_not_reuse_static_cache(tmp_path, monkeypatch):
    from fmst_analyzer.analysis.init_launch.analyzer import InitLaunchAnalyzer
    from fmst_analyzer.analysis.init_launch.launch_recipe_agent import LaunchRecipeAgent
    from fmst_analyzer.testing.pipeline_tester import PipelineTester

    rootfs = tmp_path / "rootfs"
    target = rootfs / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"target bytes; no host binary needed")
    (rootfs / "etc").mkdir()
    (rootfs / "etc/rcS").write_text("/usr/sbin/httpd\n")
    config = SimpleNamespace(
        fw_rootfs_path=rootfs, workdir=tmp_path,
        target_diagnostic_reports_dir=lambda: tmp_path / "reports",
    )
    dispatch = AsyncMock(side_effect=AssertionError("Agent dispatched in static phase"))
    monkeypatch.setattr(LaunchRecipeAgent, "analyze", dispatch)
    static = asyncio.run(InitLaunchAnalyzer(config).run(target, phase="static"))
    dispatch.assert_not_awaited()
    assert static.initialization_roots == ["etc/rcS"]
    assert static.analysis_gaps and static.planning_findings == {}

    expected = static.model_copy(update={"phase": "full"})
    run = AsyncMock(return_value=expected)
    monkeypatch.setattr(InitLaunchAnalyzer, "run", run)
    tester = object.__new__(PipelineTester)
    tester._init_launch_result = {"static": static}
    tester.target_binary_path = target
    tester.global_config = config
    assert asyncio.run(tester.ensure_init_launch_result(phase="full")) == expected
    run.assert_awaited_once_with(target, phase="full")


@pytest.mark.parametrize("name", ["file", "network", "ipc", "process", "init"])
def test_current_producers_reject_previous_version(name):
    result = _load(name + "_static")
    raw = result.model_dump(mode="json")
    raw["schema_version"] -= 1
    with pytest.raises(ValidationError, match="schema_version"):
        type(result).model_validate(raw)


@pytest.mark.parametrize("entry", MANIFEST.get("rejected_entries", []), ids=lambda item: item["path"])
def test_historical_invalid_result_is_rejected_without_rewriting_claims(entry):
    raw = (FIXTURES / entry["path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
    # A retired Network version is rejected before checking its malformed citation.
    match = None if any(kind in entry["model"] for kind in ("network_analyzer", "file_resolver")) else entry["expected_error"]
    with pytest.raises(ValidationError, match=match):
        _symbol(entry["model"]).model_validate_json(raw)


@pytest.mark.parametrize("name", ["file", "network", "ipc", "process"])
def test_empty_full_and_static_are_explicitly_distinct(name):
    static, full = _load(name + "_empty_static"), _load(name + "_empty_full")
    assert static.planning_findings == full.planning_findings == {}
    assert static.phase == "static" and full.phase == "full"
    assert type(full).model_validate_json(full.model_dump_json()) == full


def test_frozen_code_sources_and_real_file_resource_identity():
    for entry in MANIFEST["source_artifacts"]:
        assert hashlib.sha256((FIXTURES / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    static, full = _load("file_static"), _load("file_full")
    assert static.planning_findings.keys() == full.planning_findings.keys()
    assert {item.domain.path for item in full.planning_findings.values()} == {"/dev/console", "/dev/nvram"}
    assert len(full.resource_reports) == 2 and full.execution.status == "complete"
    # The large resource actually exercised map/reduce; the small one used
    # the single-call path, yet both preserve exactly one resource identity.
    assert sorted(len(report.callsite_reports) for report in full.resource_reports.values()) == [1, 11]


def test_real_ipc_preserves_target_local_behavior_and_peer_gap():
    result = _load("ipc_full")
    assert len(result.channels) == len(result.planning_findings) == 1
    dependency = result.dependency_assessments[0]
    assert dependency.peer_requirement.value == "availability"
    assert dependency.local_impact.value == "operation_affected"
    assert result.unresolved_items
    helper = (FIXTURES / "sources/l2tp-control/sub_4008D0.c").read_text()
    caller = (FIXTURES / "sources/l2tp-control/main.c").read_text()
    assert '"/var/run/l2tpctrl"' in helper and "writev(fd, &iovec, 2)" in helper
    assert "read(fd, buf" in caller
    # Agent stopped at the helper. Its empty reachability refs must not be
    # presented by the harness as a proven complete caller lifecycle.
    finding = next(iter(result.planning_findings.values()))
    assert finding.boundary.reachability_refs == []
    assert any(claim.kind == "unknown" for claim in finding.claims)


def test_binding_after_reordering_preserves_source_subject():
    from fmst_analyzer.analysis.base.finding_binding import FindingSemantics
    from fmst_analyzer.analysis.network_analyzer.analyzer_schema import NetworkInteractionAnalysis
    from fmst_analyzer.analysis.network_analyzer.findings import NetworkInteractionResult
    from fmst_analyzer.analysis.network_analyzer.findings import build_findings
    from fmst_analyzer.analysis.ipc_analyzer.findings import build_findings as ipc_findings, channel_finding_ref

    network = _load("network_static")
    outcomes = []
    for index, fact in enumerate(network.callsites.values()):
        reason = f"Descriptor origin unavailable for {fact.callsite_id}"
        analysis = NetworkInteractionAnalysis(interaction_id=f"network:{index:024x}",
            anchor_callsite_id=fact.callsite_id, callsite_ids=[fact.callsite_id],
            context_anchor=None, applicability="Context not established by this fixture.",
            disposition="unresolved", summary=reason, missing_evidence=[reason])
        semantics = FindingSemantics(summary=reason,
            claims=[dict(kind="unknown", unknown_kind="semantics", statement=reason, evidence_refs=["/missing_evidence/0"])],
            reachability_refs=[], coverage_refs=[])
        outcomes.append(NetworkInteractionResult(analysis, semantics))
    original = build_findings(network.finding_target, outcomes)
    outcomes.reverse()
    rebound = build_findings(network.finding_target, outcomes)
    assert original.keys() == rebound.keys()
    document = {"analyses": [item.analysis.model_dump(mode="json") for item in outcomes]}
    for finding in rebound.values():
        claim = finding.claims[0]
        assert resolve_evidence_ref(document, claim.evidence_refs[0]) == claim.statement

    ipc = _load("ipc_full")
    channel = ipc.channels[0]
    dependency = ipc.dependency_assessments[0]
    other_channel = channel.model_copy(update={"channel_id": "other-channel"})
    other_dependency = dependency.model_copy(update={"dependency_id": "other-dependency", "channel_id": "other-channel"})
    semantics = {item.dependency_id: FindingSemantics(
        summary=item.dependency_id, claims=[dict(kind="unknown", unknown_kind="semantics",
            statement=item.channel_id, evidence_refs=["/evidence/0"])], reachability_refs=[], coverage_refs=[],
    ) for item in (dependency, other_dependency)}
    first = ipc_findings(ipc.target_process, [channel, other_channel], [dependency, other_dependency], semantics)
    second = ipc_findings(ipc.target_process, [other_channel, channel], [other_dependency, dependency], semantics)
    assert first.keys() == second.keys()
    document = {"channels": [other_channel.model_dump(mode="json"), channel.model_dump(mode="json")],
                "dependency_assessments": [other_dependency.model_dump(mode="json"), dependency.model_dump(mode="json")]}
    for finding in second.values():
        assert resolve_evidence_ref(document, finding.boundary.anchors[0].ref)["channel_id"] == finding.domain.channel_id
        ref = finding.claims[0].evidence_refs[0].rsplit("/evidence", 1)[0]
        assert resolve_evidence_ref(document, ref)["channel_id"] == finding.domain.channel_id
    other_argv0 = ipc.target_process.model_copy(update={"argv0": "other-applet"})
    assert channel_finding_ref(ipc.target_process, channel.channel_id) != channel_finding_ref(other_argv0, channel.channel_id)


def test_semantic_classification_does_not_rename_network_resource():
    from fmst_analyzer.analysis.network_analyzer.controller import stable_interaction_id
    from fmst_analyzer.analysis.network_analyzer.analyzer_schema import NetworkDisposition
    result = _load("network_full")
    draft = result.analyses[0]
    changed = draft.model_copy(update={"disposition": NetworkDisposition.NOT_NETWORK, "summary": "New evidence"})
    assert stable_interaction_id(result.root_binary, draft.anchor_callsite_id, draft) == stable_interaction_id(result.root_binary, draft.anchor_callsite_id, changed)


def test_inner_file_network_and_ipc_nodes_gate_before_accessing_backends():
    from fmst_analyzer.analysis.file_resolver.analyzer import FileResolver
    from fmst_analyzer.analysis.file_resolver.resource_analysis_agent import FileResourceAnalysisAgent
    from fmst_analyzer.analysis.network_analyzer.interaction_agent import NetworkInteractionAgent
    from fmst_analyzer.analysis.ipc_analyzer.analyzer import IPCAnalyzer
    from fmst_analyzer.analysis.ipc_analyzer.site_resolution import SiteResolutionAgent
    from fmst_analyzer.analysis.ipc_analyzer.peer_verification import PeerVerificationAgent
    from fmst_analyzer.analysis.ipc_analyzer.schema import AnalysisPhase

    # Uninitialized objects intentionally have no model, tools or semaphore.
    # An inner node that touches a backend before its phase gate will fail.
    file = object.__new__(FileResourceAnalysisAgent)
    calls = [file.analyze_resource(None, None, phase="static"),
             file._analyze_small_group(None, None, [], None, {}, phase="static"),
             file._analyze_large_group(None, None, [], None, {}, phase="static"),
             file._run_map_worker(None, None, 0, [], None, phase="static"),
             file._run_reduce(None, None, [], None, phase="static")]
    for call in calls:
        with pytest.raises(ValueError, match="full phase"):
            asyncio.run(call)
    assert asyncio.run(object.__new__(FileResolver)._node5_analyze_resources(None, {"test": None}, phase="static")) == {}
    network = object.__new__(NetworkInteractionAgent)
    assert asyncio.run(network._analyze_resource(None, "test", None, [], phase="static")) == []
    assert asyncio.run(network._run_anchor_wave(None, "test", [None], [], wave_name="socket", phase="static")) == []
    assert asyncio.run(network._run_fallback_wave(None, "test", [None], phase="static")) == []
    assert asyncio.run(object.__new__(IPCAnalyzer)._verify_peers(view=None, target_process=None, channels=[None],
        prepared_candidates={}, peer_context=None, candidate_index=None, phase=AnalysisPhase.STATIC)) == []
    assert asyncio.run(object.__new__(SiteResolutionAgent).resolve_function(phase=AnalysisPhase.STATIC,
        view=None, target_process=None, callsites=[None], trace_dir=None)) is None
    assert asyncio.run(object.__new__(PeerVerificationAgent).verify_channel(phase=AnalysisPhase.STATIC,
        view=None, firmware_index=None, firmware_sha256="", rootfs=None, target_process=None,
        channel=None, candidates=[None], trace_dir=None)) is None


@pytest.mark.parametrize("kind", ["file", "network", "process", "ipc"])
@pytest.mark.parametrize("cache", ["memory", "disk"])
@pytest.mark.parametrize("change", ["content", "path", "phase"])
def test_cache_rejects_wrong_target_or_phase(tmp_path, kind, cache, change):
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget
    from fmst_analyzer.testing.pipeline_tester import PipelineTester

    rootfs = tmp_path / "rootfs"
    target = rootfs / "sbin/target"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"portable target bytes")
    identity = FindingTarget.from_file(rootfs, target)
    result = _load(kind + "_empty_static")
    data = result.model_dump(mode="json")
    if kind == "ipc":
        data["target_process"] = dict(executable_path=identity.path, executable_sha256=identity.sha256, argv0="target")
    else:
        data["finding_target"] = identity.model_dump()
    if change == "phase":
        data["phase"] = "full"
    result = type(result).model_validate(data)
    if change == "content":
        target.write_bytes(b"replaced target bytes")
    elif change == "path":
        other = rootfs / "sbin/other"
        other.write_bytes(target.read_bytes())
        target = other
    helper, folder, filename, cache_attr = {
        "file": ("file_resolver", "file_reports", "file_resolver_result.json", "_file_resolver_result"),
        "network": ("network_analyzer", "network_reports", "network_analysis_result.json", "_network_analyzer_result"),
        "process": ("process_lifecycle", "process_lifecycle_reports", "process_lifecycle_analysis_result.json", "_process_lifecycle_result"),
        "ipc": ("ipc", "ipc_reports", "ipc_analysis_result.json", "_ipc_result"),
    }[kind]
    tester = object.__new__(PipelineTester)
    tester.fw_rootfs_path, tester.target_binary_path = rootfs, target
    tester.target_binary_name = "target"
    tester.firmware_sha256 = data.get("firmware_sha256")
    tester.global_config = SimpleNamespace(workdir=tmp_path, target_diagnostic_reports_dir=lambda: tmp_path)
    setattr(tester, cache_attr, {"static": result} if cache == "memory" else {})
    if cache == "disk":
        (tmp_path / folder).mkdir()
        (tmp_path / folder / filename).write_text(result.model_dump_json())
    tester.ensure_analysis_view = AsyncMock(side_effect=RuntimeError("expected cache miss"))
    with pytest.raises(RuntimeError, match="expected cache miss"):
        asyncio.run(getattr(tester, "ensure_" + helper + "_result")(phase="static"))
    tester.ensure_analysis_view.assert_awaited_once()


@pytest.mark.parametrize("change", ["firmware", "argv0"])
def test_ipc_memory_cache_includes_firmware_and_applet(tmp_path, change):
    from fmst_analyzer.testing.pipeline_tester import PipelineTester
    from fmst_analyzer.analysis.ipc_analyzer.analyzer import IPCAnalyzer
    target = tmp_path / "target"
    target.write_bytes(b"same executable, different invocation")
    result = _load("ipc_empty_static")
    result.target_process = IPCAnalyzer._target_process(tmp_path, target, argv0="target")
    tester = object.__new__(PipelineTester)
    tester.fw_rootfs_path, tester.target_binary_path = tmp_path, target
    tester.target_binary_name = "other-applet" if change == "argv0" else "target"
    tester.firmware_sha256 = "0" * 64 if change == "firmware" else result.firmware_sha256
    tester._ipc_result = {"static": result}
    tester.global_config = SimpleNamespace(workdir=None)
    tester.ensure_analysis_view = AsyncMock(side_effect=RuntimeError("expected cache miss"))
    with pytest.raises(RuntimeError, match="expected cache miss"):
        asyncio.run(tester.ensure_ipc_result(phase="static"))
