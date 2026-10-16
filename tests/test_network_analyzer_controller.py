"""Controller coverage, citation, and normalization validation tests."""
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.base.output_validation import OutputValidationError
from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    IdentityResolution,
    NetworkAPIBinding,
    NetworkAPIEffect,
    NetworkCallsite,
    NetworkCodeLocation,
    NetworkDisposition,
    NetworkEvidence,
    NetworkResourceAgentResult,
    NetworkIdentity,
    NetworkInteractionOutput,
    NetworkInteractionKind,
)
from fmst_analyzer.analysis.network_analyzer.controller import (
    finalize_resource_result,
    normalize_resource_result,
    stable_interaction_id,
    validate_resource_result,
)


def _output(**fields):
    evidence = fields.get("evidence", [])
    context = None
    if fields.get("disposition") != NetworkDisposition.UNRESOLVED:
        cite = evidence[0] if evidence else None
        context = dict(binary_name=cite.binary_name if cite else "httpd",
                       function_name=cite.function_name if cite else "main",
                       line_number=cite.line_number if cite else 1, column_number=0)
    fields.setdefault("context_anchor", context)
    fields.setdefault("applicability", "Synthetic source context for this structural test.")
    return NetworkInteractionOutput(finding=dict(summary="Synthetic fixture; behavior unassessed.",
        claims=[dict(kind="unknown", statement="No semantic analysis in this fixture.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[]), **fields)


def _fact(identity: str, api: str, line: int):
    return NetworkCallsite(
        callsite_id=identity,
        location=NetworkCodeLocation(
            binary_name="httpd",
            binary_path="usr/sbin/httpd",
            binary_sha256="a" * 64,
            function_name="main",
            function_ea=0x1000,
            snapshot_hash="b" * 64,
            ctree_index=line,
            line_number=line,
            column_number=0,
        ),
        api_name=api,
        api_family="endpoint",
        api_binding=NetworkAPIBinding(
            symbol=api, call_kind="direct", verified=True,
        ),
        expression_text=f"{api}(fd)",
        arguments=[],
    )


class _Graph:
    def get_node_by_name(self, name):
        return object() if name == "httpd" else None


class _View:
    lib_dep_graph = _Graph()

    class _ADG:
        def get_callgraph_by_name(self, name):
            return self if name == "httpd" else None

        def get_node_by_name(self, name):
            return name

        def is_reachable(self, node):
            return True

    adg = _ADG()

    def get_function_ea(self, binary, function):
        return 0x1000 if (binary, function) == ("httpd", "main") else None

    def get_full_code(self, binary, function):
        return "int main() {\nsocket(2, 1, 0);\nbind(fd);\nlisten(fd);\n}"


def test_existing_but_target_unreachable_context_cannot_be_a_resolved_interaction():
    class View(_View):
        class _Unreachable(_View._ADG):
            def is_reachable(self, node):
                return False
        adg = _Unreachable()

    output = NetworkResourceAgentResult(analyses=[_listener(["bind"])])
    validate_resource_result(output, "bind", [_fact("bind", "bind", 3)], View())


def _listener(ids):
    return _output(
        callsite_ids=ids,
        disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.LISTENER,
        identity=NetworkIdentity(
            resolution=IdentityResolution.EXACT,
            family="AF_INET",
            local_address="0.0.0.0",
            local_port=80,
        ),

        summary="binds a public listener",
        evidence=[
            NetworkEvidence(
                claim="bind establishes the local endpoint",
                binary_name="httpd",
                function_name="main",
                line_number=3,
                api_name="bind",
                callsite_id="bind",
            )
        ],
    )


def test_related_callsites_can_form_one_interaction():
    facts = [_fact("bind", "bind", 3), _fact("listen", "listen", 4)]
    output = NetworkResourceAgentResult(analyses=[_listener(["bind", "listen"])])
    validate_resource_result(output, "bind", facts, _View())
    finalized = finalize_resource_result("httpd", "bind", output)
    assert len(finalized) == 1
    assert finalized[0].analysis.interaction_id.startswith("network:")


def test_casted_call_uses_static_identity_instead_of_direct_c_spelling():
    class View(_View):
        def get_full_code(self, binary, function):
            return "int main() {\nvoid *target = resolved_symbol;\n((int (*)(int))target)(fd);\n}"

    fact = _fact("bind", "bind", 3)
    fact.api_binding.call_kind = "indirect"
    output = NetworkResourceAgentResult(analyses=[_listener(["bind"])])
    validate_resource_result(output, "bind", [fact], View())
    output.analyses[0].evidence[0].line_number = 2
    with pytest.raises(ValueError, match="disagrees with its catalog location"):
        validate_resource_result(output, "bind", [fact], View())


@pytest.mark.parametrize("kind,family", [
    (NetworkInteractionKind.LISTENER, "AF_INET"),
    (NetworkInteractionKind.OUTBOUND_CONNECTION, "AF_INET"),
    (NetworkInteractionKind.NETLINK, "AF_NETLINK"),
])
def test_inherited_socket_context_does_not_require_creation_calls(kind, family):
    class View(_View):
        def get_full_code(self, binary, function):
            return "int main() {\nint fd = 0;\ngetsockname(fd, &addr, &len);\n}"

    finding = _listener(["inherited"])
    finding.interaction_kind = kind
    finding.identity.family = family
    finding.evidence[0].api_name = "getsockname"
    finding.evidence[0].callsite_id = "inherited"
    finding.evidence[0].claim = "The process inspects an inherited socket."
    output = NetworkResourceAgentResult(analyses=[finding])
    validate_resource_result(output, "inherited", [_fact("inherited", "getsockname", 3)], View())


def test_repeated_callsite_ids_are_normalized_without_agent_correction():
    facts = [_fact("bind", "bind", 3), _fact("listen", "listen", 4)]
    output = NetworkResourceAgentResult(
        analyses=[_listener(["listen", "bind", "listen", "bind"])]
    )
    normalized = normalize_resource_result(output, facts)
    assert normalized.analyses[0].callsite_ids == ["bind", "listen"]
    validate_resource_result(normalized, "bind", facts, _View())


def test_interaction_id_ignores_callsite_order_and_repetition():
    first = _listener(["bind", "listen"])
    second = _listener(["listen", "bind", "listen"])
    assert stable_interaction_id("httpd", "bind", first) == stable_interaction_id(
        "httpd", "bind", second
    )


def test_auxiliary_context_variants_cannot_collide_after_agent_validation():
    facts = [_fact("socket", "socket", 2), _fact("bind", "bind", 3),
             _fact("listen", "listen", 4)]
    seed = _output(
        callsite_ids=["socket"],
        disposition=NetworkDisposition.UNRESOLVED,
        summary="Socket context remains unresolved.",
        missing_evidence=["The socket's address family depends on its caller."],
    )
    ipv4 = _listener(["bind", "listen"])
    ipv6 = _listener(["listen", "bind", "listen"])
    ipv6.identity.family = "AF_INET6"
    ipv6.identity.local_address = "::"
    output = NetworkResourceAgentResult(analyses=[seed, ipv4, ipv6])

    # Different family labels alone do not prove distinct source contexts. This
    # must reach the Agent's correction loop, before final result persistence.
    validate_resource_result(output, "socket", facts, _View())


def test_overlapping_coverage_with_distinct_source_contexts_remains_valid():
    facts = [_fact("socket", "socket", 2), _fact("bind", "bind", 3),
             _fact("listen", "listen", 4)]
    output = NetworkResourceAgentResult(analyses=[
        _output(
            callsite_ids=["socket"],
            disposition=NetworkDisposition.UNRESOLVED,
            summary="Socket context remains unresolved.",
            missing_evidence=["Caller-dependent address family."],
        ),
        _listener(["bind"]),
        _listener(["bind", "listen"]).model_copy(update={"context_anchor":
            _listener(["bind"]).context_anchor.model_copy(update={"line_number": 4})}),
    ])
    validate_resource_result(output, "socket", facts, _View())
    finalized = finalize_resource_result("httpd", "socket", output)
    assert len({item.analysis.interaction_id for item in finalized}) == 3


def test_cross_function_callsites_can_form_one_resource_interaction():
    bind = _fact("bind", "bind", 3)
    listen = _fact("listen", "listen", 2)
    listen.location.function_name = "start_listener"
    listen.location.function_ea = 0x2000

    class _CrossFunctionView(_View):
        def get_function_ea(self, binary, function):
            return {
                ("httpd", "main"): 0x1000,
                ("httpd", "start_listener"): 0x2000,
            }.get((binary, function))

        def get_full_code(self, binary, function):
            if function == "start_listener":
                return "int start_listener(int fd) {\nlisten(fd);\n}"
            return super().get_full_code(binary, function)

    output = NetworkResourceAgentResult(
        analyses=[_listener(["bind", "listen"])]
    )
    validate_resource_result(
        output, "bind", [bind, listen], _CrossFunctionView()
    )


def test_same_function_does_not_force_unrelated_callsites_to_merge():
    facts = [_fact("left", "ioctl", 2), _fact("right", "ioctl", 3)]
    for fact in facts:
        fact.api_family = "ioctl"
    output = NetworkResourceAgentResult(analyses=[
        _output(
            callsite_ids=["left"],
            context_anchor=dict(binary_name="httpd", function_name="main", line_number=2),
            disposition=NetworkDisposition.UNRESOLVED,
            summary="first descriptor",
            missing_evidence=["fd origin unresolved"],
        ),
        _output(
            callsite_ids=["right"],
            context_anchor=dict(binary_name="httpd", function_name="main", line_number=3),
            disposition=NetworkDisposition.UNRESOLVED,
            summary="second descriptor",
            missing_evidence=["fd origin unresolved"],
        ),
    ])
    validate_resource_result(output, "left", facts, _View())


def test_same_handle_with_distinct_remote_contracts_stays_separate():
    facts = [_fact("left", "connect", 2), _fact("right", "connect", 3)]

    class _ConnectView(_View):
        def get_full_code(self, binary, function):
            return "int main() {\nconnect(fd, &left);\nconnect(fd, &right);\n}"

    def outbound(callsite_id: str, remote_address: str):
        return _output(
            callsite_ids=[callsite_id],
            disposition=NetworkDisposition.NETWORK,
            interaction_kind=NetworkInteractionKind.OUTBOUND_CONNECTION,
            identity=NetworkIdentity(
                resolution=IdentityResolution.EXACT,
                family="AF_INET",
                socket_type="SOCK_STREAM",
                remote_address=remote_address,
                remote_port=443,
            ),

            summary=f"connects to {remote_address}",
            evidence=[
                NetworkEvidence(
                    claim="connect establishes this remote endpoint",
                    binary_name="httpd",
                    function_name="main",
                    line_number=2 if callsite_id == "left" else 3,
                    api_name="connect",
                    callsite_id=callsite_id,
                )
            ],
        )

    output = NetworkResourceAgentResult(
        analyses=[outbound("left", "192.0.2.1"), outbound("right", "192.0.2.2")]
    )
    validate_resource_result(output, "left", facts, _ConnectView())
    finalized = finalize_resource_result("httpd", "left", output)
    assert len(finalized) == 2
    assert finalized[0].analysis.interaction_id != finalized[1].analysis.interaction_id


def test_network_ioctl_and_device_ioctl_can_have_distinct_ownership():
    socket_fact = _fact("socket", "socket", 2)
    socket_fact.api_family = "socket"
    network_ioctl = _fact("network-ioctl", "ioctl", 3)
    network_ioctl.api_family = "ioctl"
    device_ioctl = _fact("device-ioctl", "ioctl", 4)
    device_ioctl.api_family = "ioctl"

    class _IoctlView(_View):
        def get_full_code(self, binary, function):
            return (
                "int main() {\n"
                "socket(2, 1, 0);\n"
                "ioctl(sock, SIOCGIFADDR, &ifr);\n"
                "ioctl(device, DEVICE_REQUEST, &state);\n"
                "}"
            )

    output = NetworkResourceAgentResult(analyses=[
        _output(
            callsite_ids=["socket", "network-ioctl"],
            disposition=NetworkDisposition.NETWORK,
            interaction_kind=NetworkInteractionKind.INTERFACE_QUERY,
            identity=NetworkIdentity(
                resolution=IdentityResolution.PARTIAL,
                family="AF_INET",
                operation="SIOCGIFADDR",
            ),

            summary="queries an interface through a network socket",
            evidence=[
                NetworkEvidence(
                    claim="the ioctl uses the socket descriptor",
                    binary_name="httpd",
                    function_name="main",
                    line_number=3,
                    api_name="ioctl",
                    callsite_id="network-ioctl",
                )
            ],
        ),
        _output(
            callsite_ids=["device-ioctl"],
            disposition=NetworkDisposition.FILE_RESOURCE,
            summary="operates on a device descriptor",
            evidence=[
                NetworkEvidence(
                    claim="the ioctl uses a device descriptor",
                    binary_name="httpd",
                    function_name="main",
                    line_number=4,
                    api_name="ioctl",
                    callsite_id="device-ioctl",
                )
            ],
        ),
    ])
    validate_resource_result(
        output,
        "socket",
        [socket_fact, network_ioctl, device_ioctl],
        _IoctlView(),
    )


def test_claims_require_seed_and_known_ids_but_allow_overlapping_coverage():
    facts = [_fact("bind", "bind", 3), _fact("listen", "listen", 4)]
    with pytest.raises(ValueError, match="claim mismatch") as missing:
        validate_resource_result(
            NetworkResourceAgentResult(analyses=[_listener(["listen"])]),
            "bind",
            facts,
            _View(),
        )
    assert "seed_callsite_id='bind'" in str(missing.value)
    assert "legal callsite_ids=['bind', 'listen']" in str(missing.value)
    validate_resource_result(
        NetworkResourceAgentResult(
            analyses=[_listener(["bind"]), _listener(["bind", "listen"])]
        ), "bind",
        facts,
        _View(),
    )
    with pytest.raises(ValueError, match="claim mismatch"):
        validate_resource_result(
            NetworkResourceAgentResult(analyses=[_listener(["bind", "foreign"])]),
            "bind",
            facts,
            _View(),
        )


def test_network_validation_preserves_reported_loopback_address():
    draft = _listener(["bind"])
    draft.identity.local_address = "127.0.0.1"
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "bind", [_fact("bind", "bind", 3)],
        _View(),
    )
    assert draft.identity.local_address == "127.0.0.1"


@pytest.mark.parametrize("address", [None, "0.0.0.0 for IPv4 or :: for IPv6"])
def test_partial_endpoint_identity_does_not_erase_known_socket_behavior(address):
    draft = _listener(["bind"])
    draft.identity.local_address = address
    draft.identity.resolution = IdentityResolution.PARTIAL
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "bind", [_fact("bind", "bind", 3)],
        _View(),
    )


def test_known_loopback_hostname_is_internal_ipc():
    draft = _listener(["bind"])
    draft.identity.hostname = "localhost"
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "bind", [_fact("bind", "bind", 3)], _View(),
    )


def test_same_api_at_another_line_cannot_borrow_callsite_identity():
    fact = _fact("bind", "bind", 3)
    draft = _listener(["bind"])
    draft.evidence = [NetworkEvidence(
        claim="Listener setup", binary_name="httpd", function_name="main",
        line_number=4, api_name="bind", callsite_id="bind",
    )]
    with pytest.raises(ValueError, match="disagrees with its catalog location"):
        validate_resource_result(NetworkResourceAgentResult(analyses=[draft]), "bind", [fact], _View())


def test_passive_null_listener_is_a_proven_nonloopback_endpoint():
    draft = _listener(["bind"])
    draft.identity.local_address = "AI_PASSIVE result for NULL node"
    draft.identity.resolution = IdentityResolution.PARTIAL
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "bind", [_fact("bind", "bind", 3)],
        _View(),
    )


def test_non_endpoint_network_interaction_does_not_require_ip_address():
    fact = _fact("hostname", "gethostname", 2)
    fact.api_family = "host_query"
    draft = _output(
        callsite_ids=["hostname"],
        disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.RESOLVER,
        identity=NetworkIdentity(resolution=IdentityResolution.PARTIAL),

        summary="queries the local hostname",
        evidence=[NetworkEvidence(
            claim="gethostname supplies local identity metadata",
            binary_name="httpd",
            function_name="main",
            line_number=2,
            api_name="gethostname",
            callsite_id="hostname",
        )],
    )
    class _HostView(_View):
        def get_full_code(self, binary, function):
            return "int main() {\ngethostname(name, sizeof(name));\n}"

    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "hostname", [fact], _HostView(),
    )


def test_out_of_range_evidence_fails_validation():
    draft = _listener(["bind"])
    draft.evidence[0].line_number = 99
    draft.evidence[0].callsite_id = None
    with pytest.raises(ValueError, match="outside"):
        validate_resource_result(
            NetworkResourceAgentResult(analyses=[draft]),
            "bind", [_fact("bind", "bind", 3)],
            _View(),
        )


def test_target_infeasible_registered_api_can_be_not_network():
    fact = _fact("resolver", "getaddrinfo", 2)
    fact.api_family = "resolver"
    fact.location.function_name = "usock"
    fact.location.function_ea = 0x2000

    class _CallerView(_View):
        def get_function_ea(self, binary, function):
            return {
                ("httpd", "main"): 0x1000,
                ("httpd", "usock"): 0x2000,
                ("httpd", "ubus_reconnect"): 0x3000,
            }.get((binary, function))

        def get_full_code(self, binary, function):
            if function == "usock":
                return "int usock(int flags) {\ngetaddrinfo(host, service, 0, &ai);\n}"
            if function == "ubus_reconnect":
                return "int ubus_reconnect() {\nusock(0x8000);\n}"
            return super().get_full_code(binary, function)

    draft = _output(
        callsite_ids=["resolver"],
        disposition=NetworkDisposition.NOT_NETWORK,
        summary="the target caller selects the mutually exclusive AF_UNIX branch",
        evidence=[
            NetworkEvidence(
                claim="the only target caller passes the AF_UNIX selector",
                binary_name="httpd",
                function_name="ubus_reconnect",
                line_number=2,
            )
        ],
    )
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "resolver", [fact],
        _CallerView(),
    )


def test_target_infeasible_branch_cannot_publish_network_identity():
    fact = _fact("resolver", "getaddrinfo", 2)
    fact.api_family = "resolver"
    draft = _output(
        callsite_ids=["resolver"],
        disposition=NetworkDisposition.NOT_NETWORK,
        identity=NetworkIdentity(
            resolution=IdentityResolution.PARTIAL,
            family="AF_INET",
        ),
        summary="the target cannot enter this branch",
        evidence=[
            NetworkEvidence(
                claim="caller excludes the branch",
                binary_name="httpd",
                function_name="main",
                line_number=1,
            )
        ],
    )
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "resolver", [fact],
        _View(),
    )


def test_symbolic_loopback_fails_network_validation():
    loopback = _listener(["bind"])
    loopback.identity.local_address = "htonl(INADDR_LOOPBACK)"
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[loopback]),
        "bind", [_fact("bind", "bind", 3)],
        _View(),
    )


@pytest.mark.parametrize("socket_type, protocol, contradiction", [
    ("SOCK_STREAM (SOCK_DGRAM only if Datagrams is set without Address)",
     "IPPROTO_IP(0); resolves to TCP when SOCK_STREAM", False),
    ("SOCK_STREAM", "IPPROTO_TCP", False),
    ("SOCK_DGRAM", "IPPROTO_UDP", False),
    ("SOCK_STREAM", "IPPROTO_UDP", True),
    ("SOCK_DGRAM", "IPPROTO_TCP", True),
])
def test_transport_check_only_compares_single_literal_facts(
    socket_type, protocol, contradiction,
):
    draft = _listener(["bind"])
    draft.identity.socket_type = socket_type
    draft.identity.protocol = protocol

    def validate():
        validate_resource_result(
            NetworkResourceAgentResult(analyses=[draft]),
            "bind", [_fact("bind", "bind", 3)], _View(),
        )

    validate()


def test_external_stub_citation_requests_correction_instead_of_crashing():
    class _ExternalStubView(_View):
        def get_function_ea(self, binary, function):
            if (binary, function) in {("httpd", "main"), ("httpd", "ioctl")}:
                return 0x1000
            return None

        def get_full_code(self, binary, function):
            if function == "ioctl":
                raise FileNotFoundError("external stub has no C artifact")
            return super().get_full_code(binary, function)

        def is_external_function(self, binary, function, resolve_thunk=False):
            return function == "ioctl"

    draft = _listener(["bind"])
    draft.evidence[0].function_name = "ioctl"
    draft.evidence[0].callsite_id = None
    with pytest.raises(OutputValidationError, match="external/import"):
        validate_resource_result(
            NetworkResourceAgentResult(analyses=[draft]),
            "bind", [_fact("bind", "bind", 3)],
            _ExternalStubView(),
        )


def test_connected_udp_is_a_supported_datagram_interaction():
    draft = _output(
        callsite_ids=["connect"],
        disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.DATAGRAM,
        identity=NetworkIdentity(
            resolution=IdentityResolution.PARTIAL,
            family="AF_INET",
            socket_type="SOCK_DGRAM",
            protocol="IPPROTO_UDP",
            remote_address="192.0.2.1",
        ),

        summary="connect establishes a fixed UDP peer",
        evidence=[
            NetworkEvidence(
                claim="the supplied call establishes the peer",
                binary_name="httpd",
                function_name="main",
                line_number=1,
            )
        ],
    )
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[draft]),
        "connect", [_fact("connect", "connect", 2)],
        _View(),
    )

    contradiction = _listener(["bind"])
    contradiction.identity.socket_type = "SOCK_STREAM"
    contradiction.identity.protocol = "IPPROTO_UDP"
    validate_resource_result(
        NetworkResourceAgentResult(analyses=[contradiction]),
        "bind", [_fact("bind", "bind", 3)],
        _View(),
    )


@pytest.mark.parametrize("api", ["socket", "bind", "recvfrom"])
def test_datagram_setup_and_receive_do_not_require_sending_or_connecting(api):
    class DatagramView(_View):
        def get_full_code(self, binary, function):
            return f"int main() {{\n{api}(fd);\n}}"

    draft = _output(
        callsite_ids=[api], disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.DATAGRAM,
        identity=NetworkIdentity(resolution=IdentityResolution.PARTIAL,
                                 family="AF_INET", socket_type="SOCK_DGRAM"),
        summary="Only the current datagram lifecycle operation is observed.",
        evidence=[NetworkEvidence(
            claim="The source observes a datagram operation without sending or connecting.",
            binary_name="httpd", function_name="main", line_number=2,
            api_name=api, callsite_id=api,
        )],
    )
    validate_resource_result(NetworkResourceAgentResult(analyses=[draft]),
                             api, [_fact(api, api, 2)], DatagramView())


def test_correction_reports_all_independent_reference_errors_without_mutation():
    draft = _listener(["bind"])
    draft.context_anchor.column_number = 999
    draft.evidence[0].callsite_id = "bind"
    draft.evidence[0].line_number = 2
    draft.api_effects = [NetworkAPIEffect(binary_name="httpd", function_name="missing_function",
        line_number=1, api_name="bind", role="setup", return_or_output_use="fd used",
        side_effect="binds endpoint", failure_effect="returns error")]
    output = NetworkResourceAgentResult.model_validate({"analyses": [draft.model_dump(mode="json")]})
    before = output.model_dump(mode="json")
    with pytest.raises(ValueError) as failure:
        validate_resource_result(output, "bind", [_fact("bind", "bind", 3)], _View())
    message = str(failure.value)
    assert "context_anchor.column_number" in message
    assert "disagrees with its catalog location" in message
    assert "missing_function" in message
    assert output.model_dump(mode="json") == before
