"""Tests for the persisted IPC analysis contract."""

from __future__ import annotations

from pathlib import Path

import pytest
from dotenv import load_dotenv
from pydantic import ValidationError

load_dotenv()

from _g2_fixtures import unknown_semantics, ipc_topology_findings

from fmst_analyzer.analysis.ipc_analyzer.agent_schema import (  # noqa: E402
    AgentResourceFinding,
    CandidateVerdict,
    PeerFinding,
    PeerVerificationOutput,
    SiteCallsiteFinding,
    SiteDependencyFinding,
    SiteResolutionOutput,
    TerminationCallsiteDraft,
)
from fmst_analyzer.analysis.ipc_analyzer.analyzer import IPCAnalyzer  # noqa: E402
from fmst_analyzer.analysis.ipc_analyzer.controller import (  # noqa: E402
    IPCResultController,
)
from fmst_analyzer.analysis.ipc_analyzer.candidate_index import (  # noqa: E402
    CandidateCoverageGap,
)
from fmst_analyzer.analysis.ipc_analyzer.reports import (  # noqa: E402
    persist_result,
    render_index,
    render_unresolved_items,
)
from fmst_analyzer.analysis.ipc_analyzer.schema import (  # noqa: E402
    APIBindingKind,
    APISymbolBinding,
    AnalysisPhase,
    CandidateSource,
    CallsiteAccounting,
    CallsiteDisposition,
    CallsiteFact,
    CodeLocation,
    Endpoint,
    EndpointRole,
    EvidenceCitation,
    IPCAnalysisResult,
    IPCCallsiteReport,
    IPCChannel,
    IPCChannelReport,
    IPCMechanism,
    IPC_ANALYSIS_SCHEMA_VERSION,
    LocalImpact,
    PeerCandidateAssessment,
    PeerEndpointLocation,
    PeerCandidateEvidence,
    PeerRequirement,
    TargetProcess,
    UnresolvedItem,
    RawArgument,
    ResourceIdentity,
    VerificationStatus,
)
from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICall  # noqa: E402


def _target(path: str = "usr/sbin/httpd") -> TargetProcess:
    return TargetProcess(
        executable_path=path,
        executable_sha256="a" * 64,
        argv0=Path(path).name,
    )


def _citation(path: str, callsite_id: str | None = None) -> EvidenceCitation:
    return EvidenceCitation(
        claim="inspected endpoint or target-local branch",
        binary_path=path,
        function_name="main",
        line_number=1,
        callsite_id=callsite_id,
    )


def _result() -> IPCAnalysisResult:
    target = _target()
    callsite = CallsiteFact(
        callsite_id="callsite:connect",
        location=CodeLocation(
            binary_path=target.executable_path,
            binary_sha256=target.executable_sha256,
            function_name="main",
            function_ea=0x1000,
            snapshot_hash="b" * 64,
            ctree_index=7,
            source_ea=0x1010,
            line_number=1,
            column_number=0,
        ),
        api_family="socket_address_anchor",
        mechanism_hint=IPCMechanism.UDS,
        callee_name="connect",
        call_kind="direct",
        expression_text="connect(fd, &addr, 16)",
        arguments=[RawArgument(index=1, expression="fd")],
        return_expression="rc",
        api_binding=APISymbolBinding(
            kind=APIBindingKind.DYNAMIC_IMPORT,
            symbol="connect",
            binary_path=None,
            binary_sha256=None,
            status=VerificationStatus.VERIFIED_STATIC,
            reason="undefined dynamic symbol",
        ),
    )
    endpoint = Endpoint(
        identity_resource_keys=["resource:demo"],
        endpoint_id="endpoint:connect",
        callsite_id=callsite.callsite_id,
        role=EndpointRole.CLIENT,
        api_binding=callsite.api_binding,
        wrapper_path=[],
        coverage_claims=[],
        status=VerificationStatus.VERIFIED_AGENT,
        evidence=[_citation(target.executable_path, callsite.callsite_id)],
        missing_evidence=[],
    )
    channel = IPCChannel(
        channel_id="channel:demo",
        mechanism=IPCMechanism.UDS,
        resources=[ResourceIdentity(
            resource_key="resource:demo",
            kind="uds_path",
            canonical_value="/tmp/demo.sock",
            expressions=['addr.sun_path = "/tmp/demo.sock"'],
            status=VerificationStatus.VERIFIED_AGENT,
            evidence=[_citation(target.executable_path, callsite.callsite_id)],
            missing_evidence=[],
        )],
        endpoints=[endpoint],
        retrieval_candidates=[],
        peer_candidates=[],
        status=VerificationStatus.VERIFIED_AGENT,
        missing_evidence=[],
    )
    return IPCAnalysisResult(execution={"tasks": {}},
        schema_version=IPC_ANALYSIS_SCHEMA_VERSION,
        phase=AnalysisPhase.FULL,
        firmware_sha256="c" * 64,
        target_process=target,
        planning_findings=ipc_topology_findings(target, [channel]),
        callsites=[callsite],
        channels=[channel],
        dependency_assessments=[],
        unresolved_items=[],
        callsite_accounting=[CallsiteAccounting(
            callsite_id=callsite.callsite_id,
            disposition=CallsiteDisposition.CHANNEL_ENDPOINT,
            endpoint_ids=[endpoint.endpoint_id],
            unresolved_item_ids=[],
            reason="resolved UDS endpoint",
        )],
    )


def _output() -> PeerVerificationOutput:
    return PeerVerificationOutput(
        peer_findings=[PeerFinding(
            executable_path="usr/sbin/peer",
            argv0="peer",
            verdict=CandidateVerdict.VERIFIED,
            role=EndpointRole.SERVER,
            endpoint_locations=[PeerEndpointLocation(
                binary_path="usr/sbin/peer",
                function_name="main",
                line_number=1,
                primitive="bind",
            )],
            summary="peer binds the same UDS path",
            evidence=[_citation("usr/sbin/peer")],
            missing_evidence=[],
        )],
    )


def _static_result() -> IPCAnalysisResult:
    callsite = _result().callsites[0]
    unresolved = UnresolvedItem(
        unresolved_item_id="unresolved:site",
        subject_kind="function",
        subject_id="usr/sbin/httpd::main",
        reason="site resolution pending",
        missing_evidence=["resource identity"],
        runtime_evidence_requests=[],
    )
    return IPCAnalysisResult(execution={"tasks": {}},
        schema_version=IPC_ANALYSIS_SCHEMA_VERSION,
        phase=AnalysisPhase.STATIC,
        firmware_sha256="c" * 64,
        target_process=_target(),
        planning_findings={},
        callsites=[callsite],
        channels=[],
        dependency_assessments=[],
        unresolved_items=[unresolved],
        callsite_accounting=[CallsiteAccounting(
            callsite_id=callsite.callsite_id,
            disposition=CallsiteDisposition.UNRESOLVED,
            endpoint_ids=[],
            unresolved_item_ids=[unresolved.unresolved_item_id],
            reason="site resolution pending",
        )],
    )


def _site_output(
    covered_callsite_ids: list[str],
    *,
    peer_requirement: PeerRequirement = PeerRequirement.DATA,
    local_impact: LocalImpact = LocalImpact.OPERATION_AFFECTED,
    missing_evidence: list[str] | None = None,
    termination_callsites: list[TerminationCallsiteDraft] | None = None,
) -> SiteResolutionOutput:
    callsite = _static_result().callsites[0]
    evidence = [_citation(callsite.location.binary_path, callsite.callsite_id)]
    missing = missing_evidence or []
    return SiteResolutionOutput(callsite_findings=[SiteCallsiteFinding(
        identity_resource_indices=[0],
        callsite_id=callsite.callsite_id,
        disposition=CallsiteDisposition.CHANNEL_ENDPOINT,
        mechanism=IPCMechanism.UDS,
        endpoint_role=EndpointRole.CLIENT,
        resources=[AgentResourceFinding(
            kind="uds_path",
            canonical_value="/tmp/demo.sock",
            expression='addr.sun_path = "/tmp/demo.sock"',
            evidence=evidence,
            missing_evidence=[],
        )],
        wrapper_path=[],
        covered_callsite_ids=covered_callsite_ids,
        dependency=SiteDependencyFinding(
            finding=unknown_semantics(),
            peer_requirement=peer_requirement,
            local_impact=local_impact,
            summary="target consumes the opposite endpoint reply",
            evidence=[] if missing else evidence,
            termination_callsites=termination_callsites or [],
            missing_evidence=missing,
        ),
        summary="target connects to the local UDS endpoint",
        evidence=evidence,
        missing_evidence=[],
    )])


def _site_merged(
    tmp_path: Path,
    *,
    peer_requirement: PeerRequirement = PeerRequirement.DATA,
    local_impact: LocalImpact = LocalImpact.OPERATION_AFFECTED,
    missing_evidence: list[str] | None = None,
) -> IPCAnalysisResult:
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"\x7fELF")
    return IPCResultController(tmp_path).merge_site_resolutions(
        _static_result(),
        [_site_output(
            [],
            peer_requirement=peer_requirement,
            local_impact=local_impact,
            missing_evidence=missing_evidence,
        )],
    )


def _auxiliary_fact() -> CallsiteFact:
    callsite = _static_result().callsites[0]
    return callsite.model_copy(update={
        "callsite_id": "callsite:send",
        "location": callsite.location.model_copy(update={
            "ctree_index": 8,
            "source_ea": 0x1020,
            "line_number": 2,
        }),
        "api_family": "socket_io",
        "callee_name": "send",
        "expression_text": "send(fd, buf, len, 0)",
        "api_binding": callsite.api_binding.model_copy(update={"symbol": "send"}),
    })


def test_site_controller_derives_resource_status_and_coverage(tmp_path: Path) -> None:
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELF")
    auxiliary = _auxiliary_fact()

    merged = IPCResultController(tmp_path).merge_site_resolutions(
        _static_result(),
        [_site_output([auxiliary.callsite_id])],
        auxiliary_callsites=[auxiliary],
    )

    channel = merged.channels[0]
    assert channel.resources[0].status is VerificationStatus.VERIFIED_AGENT
    covered = channel.endpoints[0].coverage_claims
    assert [(item.api_name, item.line_number) for item in covered] == [
        ("connect", 1),
        ("send", 2),
    ]
    assert merged.covered_api_calls == covered


def test_site_controller_adds_only_resolved_termination_coverage(
    tmp_path: Path,
) -> None:
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELF")
    termination = TerminationCallsiteDraft(
        binary_name="httpd",
        function_name="main",
        line_number=10,
        column_number=4,
        api_name="exit",
        reason="termination: exit when the UDS connection is unavailable",
    )

    class Resolver:
        @staticmethod
        def resolve(item):
            return item.model_copy(update={
                "function_ea": 0x1000,
                "snapshot_hash": "b" * 64,
                "ctree_index": 99,
                "source_ea": 0x1090,
            })

    merged = IPCResultController(tmp_path).merge_site_resolutions(
        _static_result(),
        [_site_output(
            [],
            local_impact=LocalImpact.PROCESS_BLOCKED,
            termination_callsites=[termination],
        )],
        coverage_resolver=Resolver(),
    )

    assert [
        (item.api_name, item.ctree_index)
        for item in merged.covered_api_calls
    ] == [("connect", 7), ("exit", 99)]


def test_ipc_coverage_preserves_unknown_and_known_display_columns() -> None:
    result = _result()
    observations = [CoveredAPICall(
        binary_name="httpd", function_name="main", api_name="connect",
        line_number=1, column_number=column, reason="Connect to local peer.",
    ) for column in (None, 0)]
    result.channels[0].endpoints[0].coverage_claims = observations
    loaded = IPCAnalysisResult.model_validate_json(result.model_dump_json())
    assert loaded == result
    assert {claim.column_number for claim in loaded.covered_api_calls} == {None, 0}
    observations.reverse()
    assert result.covered_api_calls == loaded.covered_api_calls


def test_cross_analyzer_coverage_requires_proven_ipc_ownership() -> None:
    result = _result()
    callsite = result.callsites[0]
    location = callsite.location
    claim = CoveredAPICall(
        binary_name=Path(location.binary_path).name,
        function_name=location.function_name,
        api_name=callsite.callee_name,
        line_number=location.line_number,
        column_number=location.column_number,
        function_ea=location.function_ea,
        snapshot_hash=location.snapshot_hash,
        ctree_index=location.ctree_index,
        source_ea=location.source_ea,
        reason="inspected socket endpoint",
    )
    channel = result.channels[0]
    endpoint = channel.endpoints[0].model_copy(
        update={"coverage_claims": [claim]}
    )

    owned = result.model_copy(update={
        "channels": [channel.model_copy(update={"endpoints": [endpoint]})],
    })
    assert owned.covered_api_calls == [claim]

    for mechanism in (
        IPCMechanism.UNKNOWN,
        IPCMechanism.EXTERNAL_NETWORK,
        IPCMechanism.KERNEL_CHANNEL,
    ):
        unowned = result.model_copy(update={
            "channels": [channel.model_copy(update={
                "mechanism": mechanism,
                "endpoints": [endpoint],
            })],
        })
        assert unowned.covered_api_calls == []


def test_site_controller_merges_resource_evidence_from_all_endpoints(
    tmp_path: Path,
) -> None:
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELF")
    static = _static_result()
    first_callsite = static.callsites[0]
    second_callsite = first_callsite.model_copy(update={
        "callsite_id": "callsite:connect2",
        "location": first_callsite.location.model_copy(update={
            "ctree_index": 8,
            "source_ea": 0x1020,
            "line_number": 2,
        }),
    })
    second_unresolved = UnresolvedItem(
        unresolved_item_id="unresolved:site2",
        subject_kind="function",
        subject_id="usr/sbin/httpd::second",
        reason="site resolution pending",
        missing_evidence=["resource identity"],
        runtime_evidence_requests=[],
    )
    static_data = static.model_dump(exclude={"covered_api_calls"})
    static_data.update({
        "callsites": [first_callsite, second_callsite],
        "unresolved_items": [*static.unresolved_items, second_unresolved],
        "callsite_accounting": [
            *static.callsite_accounting,
            CallsiteAccounting(
                callsite_id=second_callsite.callsite_id,
                disposition=CallsiteDisposition.UNRESOLVED,
                endpoint_ids=[],
                unresolved_item_ids=[second_unresolved.unresolved_item_id],
                reason="site resolution pending",
            ),
        ],
    })
    second_evidence = _citation(
        second_callsite.location.binary_path,
        second_callsite.callsite_id,
    )
    first_finding = _site_output([]).callsite_findings[0]
    second_finding = first_finding.model_copy(update={
        "callsite_id": second_callsite.callsite_id,
        "resources": [first_finding.resources[0].model_copy(update={
            "expression": 'other_addr.sun_path = "/tmp/demo.sock"',
            "evidence": [second_evidence],
        })],
        "dependency": first_finding.dependency.model_copy(update={
            "evidence": [second_evidence],
        }),
        "summary": "second target callsite connects to the same UDS endpoint",
        "evidence": [second_evidence],
    })

    merged = IPCResultController(tmp_path).merge_site_resolutions(
        IPCAnalysisResult.model_validate(static_data),
        [SiteResolutionOutput(callsite_findings=[
            first_finding,
            second_finding,
        ])],
    )

    assert len(merged.channels) == 1
    resource = merged.channels[0].resources[0]
    assert resource.expressions == [
        'addr.sun_path = "/tmp/demo.sock"',
        'other_addr.sun_path = "/tmp/demo.sock"',
    ]
    assert {item.callsite_id for item in resource.evidence} == {
        first_callsite.callsite_id,
        second_callsite.callsite_id,
    }


def test_site_controller_rejects_unknown_coverage_id(tmp_path: Path) -> None:
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELF")

    with pytest.raises(ValueError, match="unknown auxiliary callsites"):
        IPCResultController(tmp_path).merge_site_resolutions(
            _static_result(),
            [_site_output(["callsite:invented"])],
            auxiliary_callsites=[_auxiliary_fact()],
        )


def test_resource_resolution_is_derived_from_missing_evidence() -> None:
    with pytest.raises(ValidationError, match="must name missing_evidence"):
        AgentResourceFinding(
            kind="uds_path",
            canonical_value=None,
            expression="runtime_path",
            evidence=[],
            missing_evidence=[],
        )


def test_site_agent_schema_omits_controller_derived_fields() -> None:
    schema = SiteResolutionOutput.model_json_schema()
    definitions = schema["$defs"]

    assert "contradictions" not in schema["properties"]
    resource_properties = definitions["AgentResourceFinding"]["properties"]
    assert "resolved" not in resource_properties
    finding_properties = definitions["SiteCallsiteFinding"]["properties"]
    assert "coverage_claims" not in finding_properties
    assert "covered_callsite_ids" in finding_properties
    assert "dependency" in finding_properties

    peer_properties = PeerVerificationOutput.model_json_schema()["properties"]
    assert set(peer_properties) == {"peer_findings"}


def test_controller_keeps_peer_and_dependency_judgment_independent(tmp_path: Path) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")

    site_result = _site_merged(tmp_path)
    merged = IPCResultController(tmp_path).merge_peer_verification(
        site_result, site_result.channels[0].channel_id, _output(),
    )

    assert merged.target_process == _target()
    assert merged.channels[0].peer_candidates[0].executable_path == "usr/sbin/peer"
    assert not hasattr(merged.channels[0].peer_candidates[0], "process_role_id")
    dependency = merged.dependency_assessments[0]
    assert dependency.peer_requirement is PeerRequirement.DATA
    assert dependency.local_impact is LocalImpact.OPERATION_AFFECTED
    assert dependency.status is VerificationStatus.VERIFIED_AGENT
    serialized = merged.model_dump(mode="json")
    assert "handling" not in serialized["dependency_assessments"][0]
    assert "required_process_role_ids" not in serialized["dependency_assessments"][0]


def test_verified_peer_does_not_require_known_argv0(tmp_path: Path) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")
    output = _output()
    output.peer_findings[0] = output.peer_findings[0].model_copy(
        update={"argv0": None},
    )

    merged = IPCResultController(tmp_path).merge_peer_verification(
        _result(), "channel:demo", output,
    )

    assert merged.channels[0].peer_candidates[0].argv0 is None


def test_verified_peer_can_have_no_target_local_requirement(tmp_path: Path) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")

    site_result = _site_merged(
        tmp_path,
        peer_requirement=PeerRequirement.NONE,
        local_impact=LocalImpact.NONE,
    )
    merged = IPCResultController(tmp_path).merge_peer_verification(
        site_result,
        site_result.channels[0].channel_id,
        _output(),
    )

    assert merged.channels[0].peer_candidates[0].status is VerificationStatus.VERIFIED_AGENT
    assert merged.dependency_assessments[0].peer_requirement is PeerRequirement.NONE
    assert merged.dependency_assessments[0].local_impact is LocalImpact.NONE


def test_unresolved_channel_cannot_produce_verified_peer(tmp_path: Path) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")

    site_result = _site_merged(tmp_path)
    channel = site_result.channels[0]
    unresolved_resource = channel.resources[0].model_copy(update={
        "canonical_value": None,
        "status": VerificationStatus.UNRESOLVED,
        "missing_evidence": ["target resource identifier is contradictory"],
    })
    unresolved_channel = channel.model_copy(update={
        "resources": [unresolved_resource],
        "status": VerificationStatus.UNRESOLVED,
        "missing_evidence": ["resource identity remains unresolved"],
    })
    site_result = site_result.model_copy(update={
        "channels": [unresolved_channel],
    })

    merged = IPCResultController(tmp_path).merge_peer_verification(
        site_result,
        unresolved_channel.channel_id,
        _output(),
    )

    peer = merged.channels[0].peer_candidates[0]
    assert peer.status is VerificationStatus.VERIFIED_AGENT
    assert peer.missing_evidence == []
    assert merged.dependency_assessments == site_result.dependency_assessments
    assert merged.channels[0].missing_evidence == unresolved_channel.missing_evidence


def test_schema_rejects_verified_peer_on_unresolved_channel() -> None:
    channel = _result().channels[0]
    verified_peer = PeerCandidateAssessment(
        executable_path="usr/sbin/peer",
        executable_sha256="d" * 64,
        argv0=None,
        role=EndpointRole.SERVER,
        endpoint_locations=[PeerEndpointLocation(
            binary_path="usr/sbin/peer",
            function_name="main",
            line_number=1,
            primitive="bind",
        )],
        status=VerificationStatus.VERIFIED_AGENT,
        reason="peer endpoint matches",
        evidence=[_citation("usr/sbin/peer")],
        missing_evidence=[],
    )

    IPCChannel.model_validate({
        **channel.model_dump(),
        "status": VerificationStatus.UNRESOLVED,
        "missing_evidence": ["target Channel identity remains unresolved"],
        "peer_candidates": [verified_peer.model_dump()],
    })


def test_unknown_dependency_requires_missing_evidence_and_is_unresolved(tmp_path: Path) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")

    merged = _site_merged(
        tmp_path,
        peer_requirement=PeerRequirement.UNKNOWN,
        local_impact=LocalImpact.UNKNOWN,
        missing_evidence=["opaque wrapper return path"],
    )

    assert merged.dependency_assessments[0].status is VerificationStatus.UNRESOLVED
    assert any(
        item.subject_kind == "dependency" for item in merged.unresolved_items
    )


def test_direct_result_has_no_recursive_process_role_collection() -> None:
    data = _result().model_dump(exclude={"covered_api_calls"})
    data["process_roles"] = [_target("usr/sbin/peer").model_dump()]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        IPCAnalysisResult.model_validate(data)


def test_complete_dependency_cannot_carry_missing_evidence() -> None:
    SiteDependencyFinding(
        finding=unknown_semantics(),
        peer_requirement=PeerRequirement.AVAILABILITY,
        local_impact=LocalImpact.PROCESS_BLOCKED,
        summary="connect failure exits the service",
        evidence=[_citation("usr/sbin/httpd", "callsite:connect")],
        missing_evidence=["contradictory missing fact"],
    )


def test_channel_endpoint_requires_site_dependency() -> None:
    data = _site_output([]).callsite_findings[0].model_dump()
    data["dependency"] = None
    with pytest.raises(ValidationError, match="requires a target-local dependency"):
        SiteCallsiteFinding.model_validate(data)


def test_site_output_rejects_duplicate_semantic_endpoint_context() -> None:
    first = _site_output([]).callsite_findings[0]
    duplicate = first.model_copy(update={
        "resources": [first.resources[0].model_copy(update={
            "expression": 'other_addr.sun_path = "/tmp/demo.sock"',
        })],
        "summary": "same endpoint restated with a different expression",
    })

    with pytest.raises(ValidationError, match="duplicate endpoint context"):
        SiteResolutionOutput(callsite_findings=[first, duplicate])


def test_mixed_contexts_preserve_observations_and_are_order_independent(tmp_path):
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"fixture")
    first = _site_output([]).callsite_findings[0]
    external = SiteCallsiteFinding.model_validate({**first.model_dump(),
        "disposition": CallsiteDisposition.NOT_FIRMWARE_IPC,
        "mechanism": IPCMechanism.EXTERNAL_NETWORK, "resources": [],
        "identity_resource_indices": [], "dependency": None,
        "summary": "same helper participates in an external invocation"})
    unknown = SiteCallsiteFinding.model_validate({**external.model_dump(),
        "disposition": CallsiteDisposition.UNRESOLVED, "mechanism": IPCMechanism.UNKNOWN,
        "missing_evidence": ["another invocation's resource cannot be established"],
        "summary": "unknown invocation retained"})
    controller = IPCResultController(tmp_path)
    left = controller.merge_site_resolutions(_static_result(), [SiteResolutionOutput(callsite_findings=[first, external, unknown])])
    right = controller.merge_site_resolutions(_static_result(), [SiteResolutionOutput(callsite_findings=[unknown, external, first])])
    assert left == right
    assert IPCAnalysisResult.model_validate_json(left.model_dump_json()) == left
    accounting = left.callsite_accounting[0]
    assert accounting.disposition is CallsiteDisposition.MIXED
    assert len(accounting.contexts) == 3 and len(left.channels) == 1
    assert {context.summary for context in accounting.contexts} == {first.summary, external.summary, unknown.summary}
    assert len(accounting.endpoint_ids) == 1 and len(accounting.unresolved_item_ids) == 1
    assert len(left.planning_findings) == 1
    # Reports remain pure JSON-derived views, including excluded/unknown contexts.
    persist_result(left, tmp_path / "reports")
    pages = [page for page in (tmp_path / "reports/callsites").glob("*.md") if page.name != "index.md"]
    assert pages and all(summary in pages[0].read_text() for summary in (first.summary, external.summary, unknown.summary))


def test_duplicate_non_endpoint_contexts_are_rejected(tmp_path):
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"fixture")
    first = _site_output([]).callsite_findings[0]
    external = SiteCallsiteFinding.model_validate({**first.model_dump(),
        "disposition": CallsiteDisposition.NOT_FIRMWARE_IPC, "resources": [],
        "identity_resource_indices": [], "dependency": None})
    with pytest.raises(ValidationError, match="duplicate endpoint context"):
        SiteResolutionOutput(callsite_findings=[external, external])
    with pytest.raises(ValidationError, match="duplicate endpoint context"):
        IPCResultController(tmp_path).merge_site_resolutions(_static_result(),
            [SiteResolutionOutput(callsite_findings=[external]), SiteResolutionOutput(callsite_findings=[external])])


@pytest.mark.parametrize("duplicate", [False, True])
def test_site_context_handles_resolved_and_unknown_resources(duplicate: bool) -> None:
    first = _site_output([]).callsite_findings[0]
    resolved = first.resources[0].model_copy(update={
        "kind": "sysv_key", "canonical_value": "15002",
    })
    unknown = resolved.model_copy(update={
        "canonical_value": None,
        "expression": "shared_header->semaphore",
        "missing_evidence": ["runtime semaphore identifier is unavailable"],
    })
    first = first.model_copy(update={
        "mechanism": IPCMechanism.SYSV_SHM,
        "resources": [resolved, unknown],
    })
    second = first.model_copy(update={
        "resources": [
            unknown,
            resolved if duplicate else resolved.model_copy(update={
                "canonical_value": "15004",
            }),
        ],
        "identity_resource_indices": [1],
    })

    if duplicate:
        with pytest.raises(ValidationError, match="duplicate endpoint context"):
            SiteResolutionOutput(callsite_findings=[first, second])
    else:
        output = SiteResolutionOutput(callsite_findings=[first, second])
        assert SiteResolutionOutput.model_validate_json(output.model_dump_json()) == output
        assert output.callsite_findings[0].resources[1].canonical_value is None


def test_target_process_preserves_explicit_multicall_argv0(tmp_path: Path) -> None:
    target = tmp_path / "sbin/rc"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELF")

    process = IPCAnalyzer._target_process(
        tmp_path.resolve(), target.resolve(), argv0="init",
    )

    assert process.executable_path == "sbin/rc"
    assert process.argv0 == "init"


def test_failed_channel_does_not_discard_independent_channel_results(
    tmp_path: Path,
) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")
    base = _result()
    other_endpoint = base.channels[0].endpoints[0].model_copy(update={
        "endpoint_id": "endpoint:other",
    })
    other = base.channels[0].model_copy(update={
        "channel_id": "channel:other",
        "endpoints": [other_endpoint],
    })
    data = base.model_dump(exclude={"covered_api_calls"})
    data["channels"] = [base.channels[0], other]
    data["planning_findings"] = ipc_topology_findings(base.target_process, data["channels"])
    data["callsite_accounting"][0]["endpoint_ids"] = [
        "endpoint:connect", "endpoint:other",
    ]
    result = IPCAnalysisResult.model_validate(data)
    controller = IPCResultController(tmp_path)

    merged = controller.mark_peer_verification_unresolved(
        result,
        "channel:demo",
        reason="peer verification failed",
        missing_evidence=["invalid peer evidence"],
    )

    assert {channel.channel_id for channel in merged.channels} == {
        "channel:demo", "channel:other",
    }
    assert merged.unresolved_items[0].subject_id == "channel:demo"
    assert merged.unresolved_items[0].affected_channel_ids == ["channel:demo"]
    assert merged.unresolved_items[0].missing_evidence == ["invalid peer evidence"]


def test_candidate_gap_is_stored_once_with_all_affected_channels(
    tmp_path: Path,
) -> None:
    base = _result()
    other_endpoint = base.channels[0].endpoints[0].model_copy(update={
        "endpoint_id": "endpoint:other",
    })
    other = base.channels[0].model_copy(update={
        "channel_id": "channel:other",
        "endpoints": [other_endpoint],
    })
    data = base.model_dump(exclude={"covered_api_calls"})
    data["channels"] = [base.channels[0], other]
    data["planning_findings"] = ipc_topology_findings(base.target_process, data["channels"])
    data["callsite_accounting"][0]["endpoint_ids"] = [
        "endpoint:connect", "endpoint:other",
    ]
    result = IPCAnalysisResult.model_validate(data)
    controller = IPCResultController(tmp_path)
    gap = CandidateCoverageGap(
        reason_code="missing_provider",
        reason="peer depends on absent provider 'libipc.so'.",
        missing_evidence=("The missing provider may hide an endpoint.",),
    )

    result = controller.attach_candidate_coverage_gaps(
        result, "channel:demo", [gap],
    )
    result = controller.attach_candidate_coverage_gaps(
        result, "channel:other", [gap],
    )

    assert len(result.unresolved_items) == 1
    assert result.unresolved_items[0].affected_channel_ids == [
        "channel:demo", "channel:other",
    ]


def test_failed_peer_verification_preserves_site_dependency(tmp_path: Path) -> None:
    result = _site_merged(tmp_path)
    channel_identity = result.channels[0].channel_id

    merged = IPCResultController(tmp_path).mark_peer_verification_unresolved(
        result,
        channel_identity,
        reason="invalid peer evidence",
        missing_evidence=["candidate assembly is incomplete"],
    )

    assert merged.dependency_assessments == result.dependency_assessments


def test_ipc_result_round_trip_preserves_candidate_source() -> None:
    result = _result()
    result.channels[0].retrieval_candidates = [PeerCandidateEvidence(
        executable_path="usr/sbin/peer",
        source=CandidateSource.CONSTANT_INTERSECTION,
        reasons=["endpoint capability and exact identifier"],
    )]

    replayed = IPCAnalysisResult.model_validate_json(result.model_dump_json())

    assert replayed == result
    assert (
        replayed.channels[0].retrieval_candidates[0].source
        is CandidateSource.CONSTANT_INTERSECTION
    )


def test_persisted_schema_uses_unresolved_item_names_only() -> None:
    payload = _static_result().model_dump_json()

    assert '"unresolved_items"' in payload
    assert '"unresolved_item_ids"' in payload
    assert '"frontier"' not in payload


def test_persist_result_replaces_legacy_frontier_report(tmp_path: Path) -> None:
    legacy = tmp_path / "frontier.md"
    legacy.write_text("legacy", encoding="utf-8")

    original = _static_result()
    published = persist_result(original, tmp_path)
    reloaded = IPCAnalysisResult.model_validate_json(
        (tmp_path / "ipc_analysis_result.json").read_text(encoding="utf-8")
    )

    assert not legacy.exists()
    assert published == reloaded
    assert published is not original
    assert (tmp_path / "unresolved_items.md").is_file()
    assert (tmp_path / "callsites" / "index.md").is_file()
    assert (tmp_path / "channels" / "index.md").is_file()
    assert "[md](" in (tmp_path / "callsites" / "index.md").read_text(
        encoding="utf-8"
    )
    assert "# IPC Channels" in (
        tmp_path / "channels" / "index.md"
    ).read_text(encoding="utf-8")
    assert "affected_channel_ids" in (
        tmp_path / "unresolved_items.md"
    ).read_text(encoding="utf-8")
    callsite_page = next((tmp_path / "callsites").glob("callsite_*.md"))
    callsite_json = callsite_page.with_name(
        callsite_page.stem + "_result.json"
    )
    report = IPCCallsiteReport.model_validate_json(
        callsite_json.read_text(encoding="utf-8")
    )
    assert report.callsite.callsite_id == "callsite:connect"
    assert "## callsite_accounting" in callsite_page.read_text(encoding="utf-8")
    assert "```json" not in callsite_page.read_text(encoding="utf-8")


def test_channel_report_combines_topology_dependency_and_unresolved_items(
    tmp_path: Path,
) -> None:
    result = _site_merged(tmp_path)
    channel_id = result.channels[0].channel_id
    unresolved = UnresolvedItem(
        unresolved_item_id="unresolved:peer-provider",
        subject_kind="peer",
        subject_id="usr/sbin/peer",
        affected_channel_ids=[channel_id],
        reason="candidate provider could not be inspected",
        missing_evidence=["provider code location"],
    )
    result = result.model_copy(update={"unresolved_items": [unresolved]})
    out_dir = tmp_path / "reports"

    persist_result(result, out_dir)

    report_path = next((out_dir / "channels").glob("*_result.json"))
    report = IPCChannelReport.model_validate_json(
        report_path.read_text(encoding="utf-8")
    )
    page = report_path.with_name(
        report_path.name.removesuffix("_result.json") + ".md"
    ).read_text(encoding="utf-8")
    assert report.channel.channel_id == channel_id
    assert len(report.dependency_assessments) == 1
    assert report.unresolved_items == [unresolved]
    assert "## dependency_assessments" in page
    assert "target consumes the opposite endpoint reply" in page
    assert "## unresolved_items" in page
    assert "candidate provider could not be inspected" in page
    assert "```json" not in page


def test_old_ipc_result_schema_is_rejected() -> None:
    data = _result().model_dump(exclude={"covered_api_calls"})
    data["schema_version"] = IPC_ANALYSIS_SCHEMA_VERSION - 1

    with pytest.raises(ValidationError, match="expected schema_version"):
        IPCAnalysisResult.model_validate(data)


def test_human_index_states_verified_data_dependency(tmp_path: Path) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")
    site_result = _site_merged(
        tmp_path,
        peer_requirement=PeerRequirement.DATA,
        local_impact=LocalImpact.PROCESS_BLOCKED,
    )
    result = IPCResultController(tmp_path).merge_peer_verification(
        site_result, site_result.channels[0].channel_id, _output(),
    )

    rendered = render_index(result)

    assert (
        "`/usr/sbin/httpd` depends on `/usr/sbin/peer` through Unix domain "
        "socket `/tmp/demo.sock` for data, shared state, or handles."
    ) in rendered
    assert (
        "Impact if the peer is unavailable: the target cannot start or remain ready."
    ) in rendered
    assert "```json" not in rendered


def test_human_index_does_not_call_topology_only_relation_dependency(
    tmp_path: Path,
) -> None:
    for relative in ("usr/sbin/httpd", "usr/sbin/peer"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF")
    site_result = _site_merged(
        tmp_path,
        peer_requirement=PeerRequirement.NONE,
        local_impact=LocalImpact.NONE,
    )
    result = IPCResultController(tmp_path).merge_peer_verification(
        site_result, site_result.channels[0].channel_id, _output(),
    )

    rendered = render_index(result)

    assert (
        "communicates with `/usr/sbin/peer` through Unix domain socket "
        "`/tmp/demo.sock`, but this call does not depend on the peer's result"
    ) in rendered
    assert "depends on `/usr/sbin/peer`" not in rendered


def test_human_index_summarizes_unresolved_items_and_keeps_every_field() -> None:
    result = _static_result()

    index = render_index(result)
    unresolved = render_unresolved_items(result)

    assert "`1` unresolved items were recorded" in index
    assert "[`unresolved_items.md`](unresolved_items.md)" in index
    assert "site resolution pending" not in index
    assert "all `1` items without truncation" in unresolved
    assert "`unresolved_item_id`: `unresolved:site`" in unresolved
    assert "`subject_kind`: `function`" in unresolved
    assert "`subject_id`: `usr/sbin/httpd::main`" in unresolved
    assert "`affected_channel_ids`: none" in unresolved
    assert "`reason`: site resolution pending" in unresolved
    assert "resource identity" in unresolved
    assert "`runtime_evidence_requests`: none" in unresolved
