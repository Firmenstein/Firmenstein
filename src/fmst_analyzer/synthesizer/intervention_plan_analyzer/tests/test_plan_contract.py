"""Concrete anchor and Contract invariants shared by all planning batches."""
import pytest
from pydantic import ValidationError
from fmst_analyzer.synthesizer.intervention_plan_analyzer.normalization import normalize_unit
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionUnitDraft, InterventionUnit, InterventionContract, ResourceAnchor, FunctionAnchorDraft,
    CallsiteAnchorDraft, InterventionPlanResult,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import (
    _catalog, _choice, _pseudo_file_unit, _Resolver, _View, scopes_for_test, contract_for_test,
)


def _normalize(draft):
    return normalize_unit("device", draft, catalog=_catalog(), resolver=_Resolver(), view=_View(), launch_choice=_choice())


@pytest.mark.parametrize("path,source,valid", [
    ("/dev/null", "file:F1", True), ("/proc/vendor/status", "file:F1", True),
    ("/sys/board/value", "launch-test", True), ("/etc/httpd.conf", "file:F1", True),
    ("/var/www/thttpd.conf", "launch-test", True), ("relative/path", "file:F1", False),
    ("/dev/null", "invented-source", False),
])
def test_pseudo_file_requires_absolute_path_and_allowed_source(path, source, valid):
    # Directory names do not determine whether a resource can be virtualized.
    draft = _pseudo_file_unit()
    draft.anchors = [ResourceAnchor(resource_kind="path", value=path, source_ref=source)]
    if valid:
        unit = _normalize(draft)
        assert unit.anchors[0].value == path
        assert unit.contract == draft.contract
    else:
        with pytest.raises(ValueError):
            _normalize(draft)


@pytest.mark.parametrize("entry,valid", [(0x1000, True), (0x1004, False)])
def test_function_requires_entry_address_and_portable_guest_basename(entry, valid):
    draft = InterventionUnitDraft(behavior_scopes=scopes_for_test(["file:F1"]), strategy="function_stub",
        anchors=[FunctionAnchorDraft(binary_name="/lib/libnvram.so", function_ea=entry)],
        contract=contract_for_test(["get and set share one key-value state"]), summary="NVRAM API")
    if valid:
        anchor = _normalize(draft).anchors[0]
        assert anchor.binary_name == "libnvram.so" and anchor.function_name == "nvram_get"
    else:
        with pytest.raises(ValueError, match="exact function entry"):
            _normalize(draft)


@pytest.mark.parametrize("identity,valid", [("ioctl-cs", True), ("exit-cs", True), ("invented", False)])
def test_callsite_resolution_checks_identity_without_rerouting_semantics(identity, valid):
    draft = InterventionUnitDraft(behavior_scopes=scopes_for_test(["file:F1"]), strategy="callsite_hook",
        anchors=[CallsiteAnchorDraft(callsite_id=identity)], contract=contract_for_test(["Caller-visible output"]), summary="Local correction")
    if valid:
        anchor = _normalize(draft).anchors[0]
        assert anchor.callsite_id == identity and anchor.ctree_index == 7
    else:
        with pytest.raises(ValueError, match="unknown callsite"):
            _normalize(draft)


@pytest.mark.parametrize("version", [1, 9, 10, 11, 12])
def test_old_cluster_plan_format_is_explicitly_rejected(version):
    with pytest.raises(ValidationError):
        InterventionPlanResult.model_validate({"schema_version": version, "clusters": {}})


def test_structured_contract_is_canonical_and_legacy_field_is_rejected():
    contract = InterventionContract(
        applicability=["the exact path is opened"],
        owned_resources=["/dev/null"],
        operations=["read returns EOF"],
        state=["descriptor state is per open"],
        native_fallback=["unclaimed paths continue natively"],
        verification=["the harness observes EOF"],
        allowed_refinement_scope=["implementation details only"],
    )
    unit = InterventionUnitDraft(
        behavior_scopes=scopes_for_test(["file:F1"]),
        strategy="pseudo_file",
        anchors=[ResourceAnchor(
            resource_kind="path", value="/dev/null", source_ref="file:F1"
        )],
        contract=contract,
        summary="Provide the exact path behavior",
    )
    assert unit.contract.operations == contract.operations

    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        InterventionUnitDraft(
            behavior_scopes=scopes_for_test(["file:F1"]),
            strategy="pseudo_file",
            anchors=[ResourceAnchor(
                resource_kind="path", value="/dev/null", source_ref="file:F1"
            )],
            mock_contract=["different operation"],
            contract=contract,
            summary="Conflicting duplicate contract",
        )

def test_strategy_anchor_shape_is_enforced_by_schema():
    with pytest.raises(ValidationError, match="requires only function anchors"):
        InterventionUnitDraft(
            behavior_scopes=scopes_for_test(["file:F1"]),
            strategy="function_stub",
            anchors=[ResourceAnchor(
                resource_kind="path",
                value="/dev/null",
                source_ref="file:F1",
            )],
            contract=contract_for_test(["provide path behavior"]),
            summary="invalid shape",
        )

def test_environment_setup_accepts_only_static_filesystem_resources():
    static = InterventionUnitDraft(
        behavior_scopes=scopes_for_test(["file:F1"]),
        strategy="environment_setup",
        anchors=[ResourceAnchor(
            resource_kind="path",
            value="/etc/service.conf",
            source_ref="file:F1",
        )],
        contract=contract_for_test(["create the known service configuration before import"]),
        summary="Prepare a static configuration file",
    )
    assert static.strategy == "environment_setup"

    for resource_kind in (
        "ipc_peer",
        "ipc_channel",
        "network_endpoint",
        "environment_value",
    ):
        with pytest.raises(ValidationError, match="environment_setup requires only"):
            InterventionUnitDraft(
                behavior_scopes=scopes_for_test(["file:F1"]),
                strategy="environment_setup",
                anchors=[ResourceAnchor(
                    resource_kind=resource_kind,
                    value="runtime-resource",
                    source_ref="file:F1",
                )],
                contract=contract_for_test(["runtime behavior"]),
                summary="invalid runtime environment unit",
            )

    with pytest.raises(ValueError, match="environment_setup requires only"):
        InterventionUnit(
            unit_id="unit-runtime-resource",
            behavior_scopes=scopes_for_test(["file:F1"]),
            strategy="environment_setup",
            anchors=[ResourceAnchor(
                resource_kind="ipc_peer",
                value="/usr/sbin/peer",
                source_ref="file:F1",
            )],
            contract=contract_for_test(["start the peer process"]),
            summary="invalid persisted environment unit",
        )
