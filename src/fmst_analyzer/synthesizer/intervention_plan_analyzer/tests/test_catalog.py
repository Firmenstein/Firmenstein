"""Planning catalog projection and report tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fmst_analyzer.analysis.base.report_schema import CallSiteReport
from fmst_analyzer.analysis.file_resolver import (
    FileCallsite,
    FileResolverResult,
    FileResource,
    FileResourceClass,
    FileResourceReport,
)
from fmst_analyzer.analysis.init_launch import (
    InitLaunchAnalysisResult,
    LaunchRecipe,
    SourceSnippet,
    TargetIdentity,
)
from fmst_analyzer.analysis.ipc_analyzer.schema import (
    APIBindingKind,
    APISymbolBinding,
    AnalysisPhase,
    CallsiteAccounting,
    CallsiteDisposition,
    CallsiteFact,
    CodeLocation,
    DependencyAssessment,
    Endpoint,
    EndpointRole,
    EvidenceCitation,
    IPCAnalysisResult,
    IPCMechanism,
    IPCChannel,
    IPC_ANALYSIS_SCHEMA_VERSION,
    LocalImpact,
    PeerCandidateAssessment,
    PeerEndpointLocation,
    PeerRequirement,
    RawArgument,
    ResourceIdentity,
    TargetProcess,
    VerificationStatus,
)
from fmst_analyzer.analysis.network_analyzer import (
    NETWORK_ANALYSIS_SCHEMA_VERSION,
    IdentityResolution,
    NetworkAnalysisResult,
    NetworkCallsite,
    NetworkDisposition,
    NetworkIdentity,
    NetworkInteractionAnalysis,
    NetworkInteractionKind,
)
from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    NetworkAPIBinding,
    NetworkCodeLocation,
)
from fmst_analyzer.analysis.process_lifecycle import (
    PROCESS_LIFECYCLE_SCHEMA_VERSION,
    ProcessCodeEvidence,
    ProcessEventAssessment,
    ProcessEventCallsite,
    ProcessEventDisposition,
    ProcessEventKind,
    ProcessLifecycleAnalysisResult,
    ProcessTriggerInput,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningEvidenceAssembler,
    PlanningEvidenceCatalog,
    SourceKind,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.reports import (
    render_index,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import (
    FindingEvidenceResolver,
)


TARGET_SHA = "1" * 64
FIRMWARE_SHA = "2" * 64


def _file_result(*, phase: str = "full") -> FileResolverResult:
    callsite = FileCallsite(
        callsite_id="file-callsite",
        candidate_idx=0,
        profile_key="file-callsite#0",
        binary_name="httpd",
        function_name="main",
        function_ea=0x1000,
        snapshot_hash="file-snapshot",
        line_number=10,
        column_number=4,
        callsite_ea=0x1010,
        ctree_index=2,
        api_name="open",
        path_arg_index=1,
        requested_path="/dev/nvram",
        path_value="/dev/nvram",
        path_kind="concrete",
        resolution_source="literal_static",
        resource_class=FileResourceClass.PSEUDO_FS_DEV,
        resource_group_id="file_dev_nvram",
    )
    resource = FileResource(
        resource_group_id="file_dev_nvram",
        path_value="/dev/nvram",
        path_kind="concrete",
        resource_class=FileResourceClass.PSEUDO_FS_DEV,
        callsites=[callsite],
    )
    report = FileResourceReport(
        resource_group_id="file_dev_nvram",
        primary_path="/dev/nvram",
        resource_class=FileResourceClass.PSEUDO_FS_DEV,
        callsite_reports=[
            CallSiteReport(
                callsite_id="file-callsite",
                containing_function_purpose="opens nvram",
                setup_details="read-only open",
                usage_reports=[],
            )
        ],

        coverage_flows=[],
        summary="The service requires the nvram device during startup.",
    )
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics
    from fmst_analyzer.analysis.file_resolver.findings import FileResourceAnalysis, build_findings
    target = FindingTarget(path="usr/sbin/httpd", sha256=TARGET_SHA)
    analyses = {resource.resource_group_id: FileResourceAnalysis(report, FindingSemantics(
        summary=report.summary,
        claims=[dict(kind="unknown", statement="Catalog test does not assess resource semantics.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[],
    ))} if phase == "full" else {}
    return FileResolverResult(execution={"tasks": {}},
        schema_version=12,
        finding_target=target,
        planning_findings=build_findings(target, {resource.resource_group_id: resource}, analyses),
        phase=phase,
        root_binary="httpd",
        callsites={callsite.profile_key: callsite},
        resources={resource.resource_group_id: resource},
        resource_reports=(
            {report.resource_group_id: report} if phase == "full" else {}
        ),
    )


def _ipc_result() -> IPCAnalysisResult:
    binding = APISymbolBinding(
        kind=APIBindingKind.DYNAMIC_IMPORT,
        symbol="connect",
        status=VerificationStatus.VERIFIED_STATIC,
        reason="undefined dynamic symbol",
    )
    callsite = CallsiteFact(
        callsite_id="ipc-callsite",
        location=CodeLocation(
            binary_path="usr/sbin/httpd",
            binary_sha256=TARGET_SHA,
            function_name="main",
            function_ea=0x1000,
            snapshot_hash="ipc-snapshot",
            ctree_index=3,
            source_ea=0x1020,
            line_number=20,
            column_number=2,
        ),
        api_family="ipc-v1",
        mechanism_hint=IPCMechanism.UDS,
        callee_name="connect",
        call_kind="direct",
        expression_text='connect(fd, "/var/run/peer.sock", 16)',
        arguments=[RawArgument(index=1, expression="fd")],
        api_binding=binding,
    )
    endpoint = Endpoint(
        identity_resource_keys=["uds-path"],
        endpoint_id="endpoint-target",
        callsite_id=callsite.callsite_id,
        role=EndpointRole.CLIENT,
        api_binding=binding,
        status=VerificationStatus.VERIFIED_AGENT,
        evidence=[],
    )
    peer = PeerCandidateAssessment(
        executable_path="usr/sbin/peer",
        executable_sha256="3" * 64,
        argv0="peer",
        role=EndpointRole.SERVER,
        endpoint_locations=[
            PeerEndpointLocation(
                binary_path="usr/sbin/peer",
                function_name="main",
                function_ea=0x2000,
                line_number=8,
                primitive="bind",
            )
        ],
        status=VerificationStatus.VERIFIED_AGENT,
        reason="binds the matching UDS path",
        evidence=[],
    )
    channel = IPCChannel(
        channel_id="channel-uds",
        mechanism=IPCMechanism.UDS,
        resources=[
            ResourceIdentity(
                resource_key="uds-path",
                kind="uds_path",
                canonical_value="/var/run/peer.sock",
                expressions=['"/var/run/peer.sock"'],
                status=VerificationStatus.VERIFIED_AGENT,
                evidence=[],
            )
        ],
        endpoints=[endpoint],
        peer_candidates=[peer],
        status=VerificationStatus.VERIFIED_AGENT,
    )
    dependency = DependencyAssessment(
        dependency_id="dependency-uds",
        channel_id=channel.channel_id,
        consumer_endpoint_ids=[endpoint.endpoint_id],
        peer_requirement=PeerRequirement.AVAILABILITY,
        local_impact=LocalImpact.PROCESS_BLOCKED,
        summary="httpd startup requires the peer UDS endpoint.",
        status=VerificationStatus.VERIFIED_AGENT,
        evidence=[
            EvidenceCitation(
                claim="connect failure reaches startup exit",
                binary_path="usr/sbin/httpd",
                function_name="main",
                function_ea=0x1000,
                line_number=20,
                callsite_id=callsite.callsite_id,
            )
        ],
    )
    from fmst_analyzer.analysis.base.finding_binding import FindingSemantics
    from fmst_analyzer.analysis.ipc_analyzer.findings import build_findings
    target = TargetProcess(executable_path="usr/sbin/httpd", executable_sha256=TARGET_SHA, argv0="httpd")
    semantics = FindingSemantics(
        summary="Synthetic IPC dependency fixture.",
        claims=[dict(kind="unknown", statement="Catalog tests do not assess IPC semantic behavior.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[],
    )
    return IPCAnalysisResult(execution={"tasks": {}},
        schema_version=IPC_ANALYSIS_SCHEMA_VERSION,
        planning_findings=build_findings(target, [channel], [dependency], {dependency.dependency_id: semantics}),
        phase=AnalysisPhase.FULL,
        firmware_sha256=FIRMWARE_SHA,
        target_process=TargetProcess(
            executable_path="usr/sbin/httpd",
            executable_sha256=TARGET_SHA,
            argv0="httpd",
        ),
        callsites=[callsite],
        channels=[channel],
        dependency_assessments=[dependency],
        unresolved_items=[],
        callsite_accounting=[
            CallsiteAccounting(
                callsite_id=callsite.callsite_id,
                disposition=CallsiteDisposition.CHANNEL_ENDPOINT,
                endpoint_ids=[endpoint.endpoint_id],
                reason="verified endpoint",
            )
        ],
    )


def _network_result() -> NetworkAnalysisResult:
    callsite = NetworkCallsite(
        callsite_id="network-callsite",
        location=NetworkCodeLocation(
            binary_name="httpd",
            binary_path="usr/sbin/httpd",
            binary_sha256=TARGET_SHA,
            function_name="serve",
            function_ea=0x1100,
            snapshot_hash="network-snapshot",
            ctree_index=4,
            source_ea=0x1120,
            line_number=30,
            column_number=6,
        ),
        api_name="bind",
        api_family="socket_endpoint",
        api_binding=NetworkAPIBinding(
            symbol="bind",
            call_kind="direct",
            verified=True,
        ),
        expression_text="bind(fd, addr, 16)",
        arguments=[],
    )
    analysis = NetworkInteractionAnalysis(
        context_anchor=dict(binary_name="httpd", function_name="main", line_number=1, column_number=0),
        applicability="Synthetic source context for this structural test.",
        interaction_id="network-listener",
        anchor_callsite_id=callsite.callsite_id,
        callsite_ids=[callsite.callsite_id],
        disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.LISTENER,
        identity=NetworkIdentity(
            resolution=IdentityResolution.EXACT,
            family="AF_INET",
            socket_type="SOCK_STREAM",
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=80,
        ),

        summary="httpd creates a TCP listener on port 80.",
    )
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics
    from fmst_analyzer.analysis.network_analyzer.findings import NetworkInteractionResult, build_findings
    target = FindingTarget(path="usr/sbin/httpd", sha256=TARGET_SHA)
    findings = build_findings(target, [NetworkInteractionResult(analysis, FindingSemantics(**dict(summary="Synthetic fixture; behavior unassessed.",
        claims=[dict(kind="unknown", statement="No semantic analysis in this fixture.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[])))])
    return NetworkAnalysisResult(execution={"tasks": {}},
        schema_version=NETWORK_ANALYSIS_SCHEMA_VERSION,
        finding_target=target, planning_findings=findings,
        phase="full",
        root_binary="httpd",
        callsites={callsite.callsite_id: callsite},
        analyses=[analysis],
    )


def _process_result() -> ProcessLifecycleAnalysisResult:
    callsite = ProcessEventCallsite(
        callsite_id="process-callsite",
        binary_name="httpd",
        function_name="main",
        function_ea=0x1000,
        snapshot_hash="process-snapshot",
        ctree_index=5,
        source_ea=0x1030,
        line_number=40,
        column_number=8,
        api_name="exit",
        event_kind=ProcessEventKind.TERMINATION,
    )
    assessment = ProcessEventAssessment(
        callsite_id=callsite.callsite_id,
        disposition=ProcessEventDisposition.STARTUP_BLOCKER,
        trigger_inputs=[
            ProcessTriggerInput(
                kind="path",
                value="/etc/httpd.conf",
                summary="missing configuration reaches exit",
            )
        ],
        summary="Missing configuration terminates startup.",
        evidence=[
            ProcessCodeEvidence(
                claim="startup exit",
                binary_name="httpd",
                function_name="main",
                line_number=40,
                api_name="exit",
            )
        ],
    )
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics
    from fmst_analyzer.analysis.process_lifecycle.findings import ProcessEventAnalysis, build_findings
    target = FindingTarget(path="usr/sbin/httpd", sha256=TARGET_SHA)
    semantics = FindingSemantics.model_validate({
        "summary": assessment.summary,
        "claims": [{"kind": "guarantee", "statement": "Configuration failure terminates startup.",
                    "evidence_refs": ["/evidence/0"], "unknown_kind": None}],
        "reachability_refs": ["/evidence/0"], "coverage_refs": [],
    })
    return ProcessLifecycleAnalysisResult(execution={"tasks": {}},
        finding_target=target,
        planning_findings=build_findings(target, {callsite.callsite_id: callsite}, {},
                                         {callsite.callsite_id: ProcessEventAnalysis(assessment, semantics)}),
        schema_version=PROCESS_LIFECYCLE_SCHEMA_VERSION,
        phase="full",
        root_binary="httpd",
        callsites={callsite.callsite_id: callsite},
        assessments={assessment.callsite_id: assessment},
    )


def _init_result() -> InitLaunchAnalysisResult:
    site = SourceSnippet(
        path="etc/init.d/httpd",
        location="line 12",
        text="/usr/sbin/httpd -f /etc/httpd.conf &",
    )
    recipe = LaunchRecipe(
        recipe_id="launch-httpd",
        launch_site=site,
        context_anchor=site,
        applicability="The initialization entry directly invokes the selected target.",
        executable_path="usr/sbin/httpd",
        command_template=["/usr/sbin/httpd", "-f", "/etc/httpd.conf"],
        initialization_chain=[site],
        preparation_actions=[],
    )
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics, bind_finding
    from fmst_analyzer.analysis.base.analysis_finding import FindingAnchor, InitLaunchFindingDomain
    target = FindingTarget(path="usr/sbin/httpd", sha256=TARGET_SHA)
    finding = bind_finding(
        target=target, source="init_launch", source_id=recipe.recipe_id,
        semantics=FindingSemantics.model_validate({
            "summary": "Source-backed httpd launch.",
            "claims": [{"kind": "guarantee", "statement": "The script attempts the httpd invocation.",
                        "evidence_refs": ["/launch_site"], "unknown_kind": None}],
            "reachability_refs": ["/initialization_chain/0"], "coverage_refs": [],
        }),
        record_ref="/launch_recipes/launch-httpd", boundary_kind="environment",
        anchors=[FindingAnchor(kind="environment", ref="/launch_recipes/launch-httpd/launch_site"),
                 FindingAnchor(kind="environment", ref="/launch_recipes/launch-httpd/context_anchor")],
        domain=InitLaunchFindingDomain(kind="init_launch", recipe_id=recipe.recipe_id, preparation_refs=[]),
    )
    return InitLaunchAnalysisResult(execution={"tasks": {}},
        schema_version=7, phase="full", initialization_roots=[site.path],
        finding_target=target, planning_findings={finding.finding_ref: finding},
        target_identity=TargetIdentity(
            target_basename="httpd",
            selected_rootfs_path="usr/sbin/httpd",
            target_aliases=[],
        ),
        launch_recipes={recipe.recipe_id: recipe},
    )


def _write_sources(
    root: Path,
    *,
    ipc: IPCAnalysisResult | None = None,
    file_result: FileResolverResult | None = None,
    network: NetworkAnalysisResult | None = None,
    process: ProcessLifecycleAnalysisResult | None = None,
    init_launch: InitLaunchAnalysisResult | None = None,
) -> None:
    sources = {
        "ipc_reports/ipc_analysis_result.json": ipc or _ipc_result(),
        "file_reports/file_resolver_result.json": file_result or _file_result(),
        "network_reports/network_analysis_result.json": network or _network_result(),
        "process_lifecycle_reports/process_lifecycle_analysis_result.json": (
            process or _process_result()
        ),
        "init_launch_reports/init_launch_analysis_result.json": (
            init_launch or _init_result()
        ),
    }
    for relative, result in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        from fmst_analyzer.analysis.base.input_provenance import ANALYZER_FILES, AnalysisInputs, publish_receipt
        stage = next(key for key, value in ANALYZER_FILES.items() if value == relative)
        phase = result.phase.value if hasattr(result.phase, "value") else result.phase
        publish_receipt(path, result, AnalysisInputs(stage=stage, phase=phase,
            target_path="usr/sbin/httpd", target_sha256=TARGET_SHA, rootfs_sha256=FIRMWARE_SHA,
            implementation_sha256="0" * 64, settings={"fixture": "synthetic offline contract test"}))


def test_assembles_all_five_sources_and_persists_pure_rendering(tmp_path: Path):
    _write_sources(tmp_path)

    catalog = PlanningEvidenceAssembler(tmp_path).run()

    assert set(catalog.source_artifacts) == set(SourceKind)
    assert {item.source_kind for item in catalog.finding_index.values()} == set(SourceKind)
    assert list(catalog.launch_candidates) == ["launch-httpd"]
    assert catalog.target_identity.selected_rootfs_path == "usr/sbin/httpd"
    assert catalog.target_identity.executable_sha256 == TARGET_SHA
    resolver = FindingEvidenceResolver(tmp_path, catalog)
    ipc_ref = next(item.finding_ref for item in catalog.finding_index.values() if item.source_kind is SourceKind.IPC)
    evidence = resolver.finding_evidence(ipc_ref)
    assert evidence["records"]["/channels/0"] == _ipc_result().channels[0].model_dump(mode="json")
    file_index = next(item for item in catalog.finding_index.values() if item.source_kind is SourceKind.FILE)
    assert "path:/dev/nvram" in file_index.anchor_keys
    assert not catalog.gaps

    out_dir = tmp_path / "intervention_planner_inputs"
    persisted = PlanningEvidenceCatalog.model_validate_json(
        (out_dir / "planner_input_catalog.json").read_text(encoding="utf-8")
    )
    assert persisted == catalog
    assert (out_dir / "index.md").read_text(encoding="utf-8") == render_index(
        persisted
    )


def test_finding_evidence_reads_exact_records_and_does_not_alias_cached_values(
    tmp_path: Path,
):
    _write_sources(tmp_path)
    catalog = PlanningEvidenceAssembler(tmp_path).assemble()
    finding = next(
        item for item in catalog.finding_index.values()
        if item.source_kind is SourceKind.PROCESS
    )
    resolver = FindingEvidenceResolver(tmp_path, catalog)
    evidence = resolver.finding_evidence(finding.finding_ref)
    expected = _process_result().assessments[finding.source_id].model_dump(mode="json")
    assert evidence["records"]["/assessments/" + finding.source_id] == expected
    evidence["records"].clear()
    assert resolver.finding_evidence(finding.finding_ref)["records"]


def test_target_path_mismatch_fails_before_persisting(tmp_path: Path):
    init_launch = _init_result().model_copy(deep=True)
    init_launch.target_identity.selected_rootfs_path = "usr/libexec/httpd"
    _write_sources(tmp_path, init_launch=init_launch)

    with pytest.raises(ValueError, match="finding target disagrees|target paths disagree"):
        PlanningEvidenceAssembler(tmp_path).run()

    assert not (tmp_path / "intervention_planner_inputs").exists()


def test_static_source_is_rejected(tmp_path: Path):
    _write_sources(tmp_path, file_result=_file_result(phase="static"))

    with pytest.raises(ValueError, match="requires full analyzer results"):
        PlanningEvidenceAssembler(tmp_path).assemble()


def test_missing_source_fails_explicitly(tmp_path: Path):
    _write_sources(tmp_path)
    (tmp_path / "network_reports/network_analysis_result.json").unlink()

    with pytest.raises(FileNotFoundError, match="required JSON artifact is missing"):
        PlanningEvidenceAssembler(tmp_path).assemble()


def test_source_artifact_pins_content_hash_and_stable_relative_path(tmp_path: Path):
    import hashlib
    _write_sources(tmp_path)
    catalog = PlanningEvidenceAssembler(tmp_path).assemble()
    raw = json.loads(catalog.model_dump_json())
    assert raw["source_artifacts"]["ipc"]["relative_path"] == (
        "ipc_reports/ipc_analysis_result.json"
    )
    assert raw["source_artifacts"]["ipc"]["content_sha256"] == hashlib.sha256(
        (tmp_path / "ipc_reports/ipc_analysis_result.json").read_bytes()).hexdigest()


def test_conditional_file_finding_is_not_filtered_or_rewritten(tmp_path: Path):
    file_result = _file_result()
    finding = next(iter(file_result.planning_findings.values()))
    finding.claims[0].statement = "When creating the resource, it need not exist; a later read requires the created data."
    _write_sources(tmp_path, file_result=file_result)

    catalog = PlanningEvidenceAssembler(tmp_path).assemble()

    evidence = FindingEvidenceResolver(tmp_path, catalog).finding_evidence(finding.finding_ref)
    assert evidence["finding"]["claims"] == [claim.model_dump(mode="json") for claim in finding.claims]


def test_network_ipc_observation_remains_indexed_without_forced_handoff(tmp_path: Path):
    network = _network_result()
    original = network.analyses[0]
    network.analyses = [
        NetworkInteractionAnalysis(
            context_anchor=dict(binary_name="httpd", function_name="main", line_number=1, column_number=0),
            applicability="Synthetic source context for this structural test.",
            interaction_id="network-internal-ipc",
            anchor_callsite_id=original.anchor_callsite_id,
            callsite_ids=original.callsite_ids,
            disposition=NetworkDisposition.INTERNAL_IPC,
            summary="The endpoint is an AF_UNIX IPC resource.",
        )
    ]
    finding = next(iter(network.planning_findings.values()))
    identity = network.finding_target.ref("network", "network-internal-ipc")
    finding = finding.model_copy(update={
        "finding_ref": identity,
        "domain": finding.domain.model_copy(update={
            "interaction_id": "network-internal-ipc", "interaction_kind": None,
        }),
    })
    network.planning_findings = {identity: finding}
    _write_sources(tmp_path, network=network)

    catalog = PlanningEvidenceAssembler(tmp_path).assemble()

    assert any(
        item.source_kind is SourceKind.NETWORK
        for item in catalog.finding_index.values()
    )
    assert not any("owning IPC/File result" in reason for gap in catalog.gaps.values() for reason in gap.reasons)
