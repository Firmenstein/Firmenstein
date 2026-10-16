"""Tests for resource-anchor site resolution."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from dotenv import load_dotenv

load_dotenv()

from _g2_fixtures import unknown_semantics, ipc_topology_findings

from fmst_analyzer.analysis.ipc_analyzer.agent_schema import (  # noqa: E402
    AgentResourceFinding,
    SiteCallsiteFinding,
    SiteDependencyFinding,
    SiteResolutionOutput,
)
from fmst_analyzer.analysis.ipc_analyzer.schema import (  # noqa: E402
    APIBindingKind,
    APISymbolBinding,
    AnalysisPhase,
    CallsiteDisposition,
    CallsiteFact,
    CodeLocation,
    EndpointRole,
    EvidenceCitation,
    IPCMechanism,
    LocalImpact,
    PeerRequirement,
    TargetProcess,
    RawArgument,
    VerificationStatus,
)
from fmst_analyzer.analysis.ipc_analyzer.site_resolution import (  # noqa: E402
    SiteResolutionAgent,
    _clear_auxiliary_citation_ids,
)


def _role() -> TargetProcess:
    return TargetProcess(
        executable_path="usr/sbin/httpd",
        executable_sha256="a" * 64,
        argv0="httpd",
    )


def _fact(identity: str = "cs:1", function_ea: int = 0x1000) -> CallsiteFact:
    return CallsiteFact(
        callsite_id=identity,
        location=CodeLocation(
            binary_path="usr/sbin/httpd",
            binary_sha256="a" * 64,
            function_name="main",
            function_ea=function_ea,
            snapshot_hash="b" * 64,
            ctree_index=1,
            source_ea=0x1010,
            line_number=10,
            column_number=1,
        ),
        api_family="socket_endpoint",
        mechanism_hint=IPCMechanism.UNKNOWN,
        callee_name="connect",
        call_kind="direct",
        expression_text="connect(fd, &addr, 16)",
        arguments=[],
        return_expression="result",
        api_binding=APISymbolBinding(
            kind=APIBindingKind.DYNAMIC_IMPORT,
            symbol="connect",
            binary_path=None,
            binary_sha256=None,
            status=VerificationStatus.VERIFIED_STATIC,
            reason="source ELF declares an undefined dynamic symbol",
        ),
    )


def _socket_fact(
    identity: str,
    callee: str,
    *,
    argument: str,
    return_expression: str | None = None,
    ctree_index: int,
) -> CallsiteFact:
    fact = _fact(identity)
    arguments = [RawArgument(index=1, expression=argument)]
    if callee == "socket":
        arguments.extend([
            RawArgument(index=2, expression="1"),
            RawArgument(index=3, expression="0"),
        ])
    return fact.model_copy(update={
        "location": fact.location.model_copy(update={
            "ctree_index": ctree_index,
            "line_number": 10 + ctree_index,
        }),
        "callee_name": callee,
        "expression_text": f"{callee}(...)",
        "arguments": arguments,
        "return_expression": return_expression,
    })


class _Snapshot:
    snapshot_hash = "b" * 64

    def __init__(self, records):
        self.records = records
        self.variables = {record.varname: [record] for record in records}

    def trace_variable_prop(self, _function_name, identifier):
        if identifier != "fd":
            raise KeyError(identifier)
        return SimpleNamespace(variables=self.records)


class _StaticView:
    def __init__(self, snapshot):
        node = SimpleNamespace(semantic_snapshot=snapshot)
        self.callgraph = SimpleNamespace(get_node_by_ea=lambda _ea: node)

    def _get_callgraph_for_binary(self, _binary_name):
        return self.callgraph


def _record(*, consumers=(), is_global=False, affects_return_value=False):
    return SimpleNamespace(
        varname="fd",
        is_global=is_global,
        is_parameter=False,
        is_return_value=False,
        affects_return_value=affects_return_value,
        declaration_line=1,
        usage_lines=[1, *range(2, 2 + len(consumers))],
        flows_to=[],
        flows_from=[SimpleNamespace(type="CALL", name="socket", line=1)],
        callsite_args=[
            SimpleNamespace(callee=callee, line=2 + index)
            for index, callee in enumerate(consumers)
        ],
    )


class _NeverCalled:
    async def analyze(self, **_kwargs):
        raise AssertionError("static phase invoked the Agent")


class _Returns:
    def __init__(self, result):
        self.result = result

    async def analyze(self, **_kwargs):
        return self.result


def _agent(backend) -> SiteResolutionAgent:
    agent = SiteResolutionAgent.__new__(SiteResolutionAgent)
    agent.global_config = SimpleNamespace(diagnosis_model="test")
    agent._agent = backend
    return agent


def test_static_phase_has_an_internal_zero_llm_gate() -> None:
    result = asyncio.run(_agent(_NeverCalled()).resolve_function(
        phase=AnalysisPhase.STATIC,
        view=SimpleNamespace(),
        target_process=_role(),
        callsites=[_fact()],
        trace_dir=None,
    ))
    assert result is None


def _loopback_resource(kind: str, value: str) -> AgentResourceFinding:
    return AgentResourceFinding(
        kind=kind,
        canonical_value=value,
        expression=value,
        evidence=[],
        missing_evidence=[],
    )


def _loopback_finding(resources) -> SiteCallsiteFinding:
    return SiteCallsiteFinding(
        identity_resource_indices=list(range(len(resources))),
        callsite_id="cs:loopback",
        disposition=CallsiteDisposition.CHANNEL_ENDPOINT,
        mechanism=IPCMechanism.LOOPBACK_SOCKET,
        endpoint_role=EndpointRole.CLIENT,
        resources=resources,
        wrapper_path=[],
        covered_callsite_ids=[],
        dependency=SiteDependencyFinding(
            finding=unknown_semantics(),
            peer_requirement=PeerRequirement.AVAILABILITY,
            local_impact=LocalImpact.OPERATION_AFFECTED,
            summary="operation needs a loopback peer",
            evidence=[EvidenceCitation(
                claim="connect result is checked",
                binary_path="usr/sbin/httpd",
                function_name="main",
                line_number=10,
                callsite_id="cs:loopback",
            )],
            missing_evidence=[],
        ),
        summary="loopback client",
        evidence=[EvidenceCitation(
            claim="target connects to a loopback endpoint",
            binary_path="usr/sbin/httpd", function_name="main",
            line_number=10, callsite_id="cs:loopback",
        )],
        missing_evidence=[],
    )


def test_loopback_retains_typed_resources() -> None:
    finding = _loopback_finding([
        _loopback_resource("socket_family", "AF_INET"),
        _loopback_resource("socket_type", "SOCK_DGRAM"),
        _loopback_resource("socket_protocol", "IPPROTO_UDP"),
        _loopback_resource("loopback_address", "127.0.0.1"),
        _loopback_resource("socket_port", "40500"),
    ])
    assert finding.resources[-1].canonical_value == "40500"


def test_terminal_evidence_is_checked_in_agent_output_before_assembly() -> None:
    finding = _negative_finding(_fact(), IPCMechanism.UNKNOWN, "external endpoint")
    raw = finding.model_dump(mode="json")
    raw["evidence"] = []
    with pytest.raises(ValueError, match="requires non-empty evidence"):
        SiteResolutionOutput.model_validate({"callsite_findings": [raw]})
    raw.update(disposition="unresolved", missing_evidence=["target endpoint unknown"])
    assert SiteResolutionOutput.model_validate({"callsite_findings": [raw]})


def test_child_evidence_does_not_replace_terminal_disposition_evidence() -> None:
    from test_ipc_contract import _site_output

    raw = _site_output([]).model_dump(mode="json")
    finding = raw["callsite_findings"][0]
    assert finding["dependency"]["evidence"]
    finding["evidence"] = []
    with pytest.raises(ValueError, match="callsite_findings.0"):
        SiteResolutionOutput.model_validate(raw)


def test_loopback_missing_kind_feedback_names_exact_fields_and_keeps_unknown_values():
    schema = SiteResolutionOutput.model_json_schema()
    descriptions = (
        schema["$defs"]["AgentResourceFinding"]["properties"]["kind"]["description"],
        schema["$defs"]["SiteCallsiteFinding"]["properties"]["identity_resource_indices"]["description"],
    )
    for description in descriptions:
        for kind in ("socket_family", "socket_type", "socket_protocol", "loopback_address", "socket_port"):
            assert kind in description
    with pytest.raises(ValueError, match="missing=.*socket_protocol"):
        _loopback_finding([
            _loopback_resource("socket_family", "AF_INET"),
            _loopback_resource("socket_type", "SOCK_DGRAM"),
            _loopback_resource("loopback_address", "127.0.0.1"),
            _loopback_resource("socket_port", "40500"),
        ])


def test_loopback_preserves_unusual_socket_type_protocol_combination() -> None:
    resources = [
        _loopback_resource("socket_family", "AF_INET"),
        _loopback_resource("socket_type", "SOCK_STREAM"),
        _loopback_resource("socket_protocol", "IPPROTO_UDP"),
        _loopback_resource("loopback_address", "127.0.0.1"),
        _loopback_resource("socket_port", "40500"),
    ]
    finding = _loopback_finding(resources)
    replayed = SiteCallsiteFinding.model_validate_json(finding.model_dump_json())
    assert replayed.resources == resources


def test_loopback_keeps_runtime_built_typed_resource_unresolved() -> None:
    resources = [
        _loopback_resource("socket_family", "AF_INET"),
        _loopback_resource("socket_type", "SOCK_STREAM"),
        _loopback_resource("socket_protocol", "IPPROTO_TCP"),
        _loopback_resource("loopback_address", "127.0.0.1"),
        AgentResourceFinding(
            kind="socket_port",
            canonical_value=None,
            expression="ntohs(runtime_addr.sin_port)",
            evidence=[],
            missing_evidence=["port is supplied at runtime"],
        ),
    ]

    finding = _loopback_finding(resources)

    assert finding.resources[-1].canonical_value is None


def test_full_phase_rejects_incomplete_agent_accounting() -> None:
    output = SiteResolutionOutput(
        callsite_findings=[],
    )
    with pytest.raises(ValueError, match="accounting mismatch"):
        asyncio.run(_agent(_Returns(output)).resolve_function(
            phase=AnalysisPhase.FULL,
            view=SimpleNamespace(),
            target_process=_role(),
            callsites=[_fact()],
            trace_dir=None,
        ))


def test_full_phase_accepts_controller_owned_auxiliary_coverage(tmp_path) -> None:
    anchor = _fact("cs:anchor")
    auxiliary = _fact("cs:send").model_copy(update={
        "callee_name": "send",
        "api_binding": anchor.api_binding.model_copy(update={"symbol": "send"}),
    })
    target_file = tmp_path / anchor.location.binary_path
    target_file.parent.mkdir(parents=True)
    target_file.write_bytes(b"\x7fELF")
    citation = EvidenceCitation(
        claim="target connects to the local UDS endpoint",
        binary_path=anchor.location.binary_path,
        function_name=anchor.location.function_name,
        line_number=anchor.location.line_number,
        callsite_id=anchor.callsite_id,
    )
    output = SiteResolutionOutput(callsite_findings=[SiteCallsiteFinding(
        identity_resource_indices=[0],
        callsite_id=anchor.callsite_id,
        disposition=CallsiteDisposition.CHANNEL_ENDPOINT,
        mechanism=IPCMechanism.UDS,
        endpoint_role=EndpointRole.CLIENT,
        resources=[AgentResourceFinding(
            kind="uds_path",
            canonical_value="/tmp/demo.sock",
            expression='addr.sun_path = "/tmp/demo.sock"',
            evidence=[citation],
            missing_evidence=[],
        )],
        wrapper_path=[],
        covered_callsite_ids=[auxiliary.callsite_id],
        dependency=SiteDependencyFinding(
            finding=unknown_semantics(),
            peer_requirement=PeerRequirement.DATA,
            local_impact=LocalImpact.OPERATION_AFFECTED,
            summary="target consumes the opposite endpoint reply",
            evidence=[citation],
            missing_evidence=[],
        ),
        summary="target connects to the local UDS endpoint",
        evidence=[citation],
        missing_evidence=[],
    )])
    agent = _agent(_Returns(output))
    agent.global_config.fw_rootfs_path = tmp_path

    result = asyncio.run(agent.resolve_function(
        phase=AnalysisPhase.FULL,
        view=SimpleNamespace(lib_dep_graph=SimpleNamespace(get_node_by_name=lambda _: object()),
                             get_function_ea=lambda *args: anchor.location.function_ea,
                             get_full_code=lambda *args: "\n" * 9 + anchor.expression_text),
        target_process=_role(),
        callsites=[anchor],
        auxiliary_callsites=[auxiliary],
        trace_dir=None,
    ))

    assert result == output


def test_function_batch_cannot_cross_snapshot_identity() -> None:
    with pytest.raises(ValueError, match="cannot span containing functions"):
        asyncio.run(_agent(_NeverCalled()).resolve_function(
            phase=AnalysisPhase.FULL,
            view=SimpleNamespace(),
            target_process=_role(),
            callsites=[_fact("cs:1"), _fact("cs:2", function_ea=0x2000)],
            trace_dir=None,
        ))


def test_auxiliary_citation_keeps_location_without_dangling_callsite_id() -> None:
    anchor = _fact("cs:anchor")
    finding = _negative_finding(
        anchor, IPCMechanism.EXTERNAL_NETWORK, "External endpoint.",
    )
    finding.evidence[0] = finding.evidence[0].model_copy(
        update={"callsite_id": "cs:aux"},
    )

    normalized = _clear_auxiliary_citation_ids(
        SiteResolutionOutput(callsite_findings=[finding]),
        {"cs:aux"},
    )

    citation = normalized.callsite_findings[0].evidence[0]
    assert citation.callsite_id is None
    assert citation.binary_path == anchor.location.binary_path
    assert citation.line_number == anchor.location.line_number


def test_source_correction_reports_all_independent_positions_without_mutation(tmp_path) -> None:
    anchor = _fact("cs:anchor")
    source = tmp_path / anchor.location.binary_path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"fixture")
    finding = _negative_finding(anchor, IPCMechanism.EXTERNAL_NETWORK, "Remote endpoint.")
    finding.evidence = [
        EvidenceCitation(
            claim="Socket endpoint call",
            binary_path=anchor.location.binary_path,
            function_name="main",
            line_number=9,
            callsite_id=anchor.callsite_id,
        ),
        EvidenceCitation(
            claim="Caller branch",
            binary_path=anchor.location.binary_path,
            function_name="main",
            function_ea=0x2000,
            line_number=11,
        ),
    ]
    output = SiteResolutionOutput(callsite_findings=[finding])
    original = output.model_dump_json()
    agent = _agent(_NeverCalled())
    agent.global_config.fw_rootfs_path = tmp_path
    view = SimpleNamespace(lib_dep_graph=SimpleNamespace(get_node_by_name=lambda _: object()),
                           get_function_ea=lambda *args: 0x1000,
                           get_full_code=lambda *args: "\n" * 9 + "connect(fd, addr, len);")

    with pytest.raises(ValueError) as failure:
        agent._validate_echoed_identities([anchor], output, view=view)

    message = str(failure.value)
    assert "cs:anchor" in message
    assert "expected line 10, got 9" in message
    assert "expected function_ea 4096 (0x1000), got 8192 (0x2000)" in message
    assert "line_number=11" in message and "1..10" in message
    assert output.model_dump_json() == original


def test_source_correction_distinguishes_unavailable_function_from_wrong_address(tmp_path) -> None:
    anchor = _fact()
    source = tmp_path / anchor.location.binary_path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"fixture")
    finding = _negative_finding(anchor, IPCMechanism.EXTERNAL_NETWORK, "Remote endpoint.")
    finding.evidence = [EvidenceCitation(claim="Unavailable caller", binary_path=anchor.location.binary_path,
                                         function_name="unknown_caller", line_number=1)]
    output = SiteResolutionOutput(callsite_findings=[finding])
    agent = _agent(_NeverCalled())
    agent.global_config.fw_rootfs_path = tmp_path
    view = SimpleNamespace(get_function_ea=lambda *args: None)

    with pytest.raises(ValueError, match="usr/sbin/httpd::unknown_caller.*unknown source function"):
        agent._validate_echoed_identities([anchor], output, view=view)










def _negative_finding(
    fact: CallsiteFact,
    mechanism: IPCMechanism,
    summary: str,
) -> SiteCallsiteFinding:
    return SiteCallsiteFinding(
        callsite_id=fact.callsite_id,
        disposition=CallsiteDisposition.NOT_FIRMWARE_IPC,
        mechanism=mechanism,
        endpoint_role=EndpointRole.UNKNOWN,
        resources=[],
        wrapper_path=[],
        covered_callsite_ids=[],
        dependency=None,
        summary=summary,
        evidence=[EvidenceCitation(
            claim=summary,
            binary_path=fact.location.binary_path,
            function_name=fact.location.function_name,
            line_number=fact.location.line_number,
            callsite_id=fact.callsite_id,
        )],
        missing_evidence=[],
    )
