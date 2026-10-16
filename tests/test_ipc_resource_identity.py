"""Kernel-object identity is independent of related observations and labels."""
import pytest
from pydantic import ValidationError

from fmst_analyzer.analysis.ipc_analyzer.agent_schema import SiteCallsiteFinding, SiteResolutionOutput
from fmst_analyzer.analysis.ipc_analyzer.controller import IPCResultController
from fmst_analyzer.analysis.ipc_analyzer.schema import IPCMechanism, WrapperHop, EndpointRole
from test_ipc_contract import _site_output, _static_result


def _finding():
    finding = _site_output([]).callsite_findings[0]
    resource = finding.resources[0].model_copy(update={"kind": "sysv_key", "canonical_value": "15004"})
    return finding.model_copy(update={"mechanism": IPCMechanism.SYSV_SHM, "resources": [resource]})


def _merge(tmp_path, findings):
    target = tmp_path / "usr/sbin/httpd"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"portable target")
    output = SiteResolutionOutput.model_validate({"callsite_findings": [f.model_dump() for f in findings]})
    return IPCResultController(tmp_path).merge_site_resolutions(_static_result(), [output])


def test_related_objects_and_longer_source_chain_do_not_change_identity(tmp_path):
    original = _finding()
    anchor = WrapperHop(binary_path="usr/sbin/httpd", function_name="main", line_number=1)
    original = original.model_copy(update={"wrapper_path": [anchor], "context_anchor": anchor})
    related = original.resources[0].model_copy(update={"kind": "sysv_sem_key", "canonical_value": "25004"})
    expanded = original.model_copy(update={
        "resources": [related, original.resources[0].model_copy(update={"kind": "sysv_shm_key"})],
        "identity_resource_indices": [1],
        "wrapper_path": [anchor, WrapperHop(binary_path="usr/sbin/httpd", function_name="helper", line_number=8)],
    })
    first = _merge(tmp_path, [original]).channels[0]
    second = _merge(tmp_path, [expanded]).channels[0]
    assert first.channel_id == second.channel_id
    assert first.endpoints[0].endpoint_id == second.endpoints[0].endpoint_id
    assert {r.canonical_value for r in second.resources} == {"15004", "25004"}
    keys = set(second.endpoints[0].identity_resource_keys)
    assert {r.canonical_value for r in second.resources if r.resource_key in keys} == {"15004"}


def test_same_kernel_object_preserves_distinct_source_contexts(tmp_path):
    findings = []
    for name, line in [("lan", 12), ("wan", 35)]:
        anchor = WrapperHop(binary_path="usr/sbin/httpd", function_name=name, line_number=line)
        findings.append(_finding().model_copy(update={"wrapper_path": [anchor], "context_anchor": anchor}))
    channel = _merge(tmp_path, findings).channels[0]
    assert len(channel.endpoints) == 2
    assert len({e.endpoint_id for e in channel.endpoints}) == 2
    assert {e.context_anchor.function_name for e in channel.endpoints} == {"lan", "wan"}
    with pytest.raises(ValidationError, match="duplicate endpoint context"):
        _merge(tmp_path, [findings[0], findings[0].model_copy(update={"endpoint_role": EndpointRole.SENDER})])


def test_related_resource_or_runtime_handle_cannot_be_the_wrong_mechanisms_identity():
    finding = _finding()
    for kind in ("sysv_sem_key", "sysv_shmid"):
        raw = finding.model_dump()
        raw["resources"][0]["kind"] = kind
        with pytest.raises(ValidationError, match="this mechanism's key"):
            SiteCallsiteFinding.model_validate(raw)


def test_unresolved_identity_does_not_depend_on_expression_wording(tmp_path):
    original = _finding()
    unknown = original.resources[0].model_copy(update={"canonical_value": None,
        "missing_evidence": ["Exact runtime key is unknown"], "expression": "config.key"})
    original = original.model_copy(update={"resources": [unknown]})
    expanded = original.model_copy(update={"resources": [unknown.model_copy(update={"expression": "caller -> config.key"})]})
    a, b = _merge(tmp_path, [original]), _merge(tmp_path, [expanded])
    assert a.channels[0].channel_id == b.channels[0].channel_id
    assert a.channels[0].endpoints[0].endpoint_id == b.channels[0].endpoints[0].endpoint_id


def test_numeric_key_spelling_does_not_split_the_same_object(tmp_path):
    original = _finding()
    hexadecimal = original.model_copy(update={"resources": [
        original.resources[0].model_copy(update={"canonical_value": hex(15004)})]})
    first, second = _merge(tmp_path, [original]), _merge(tmp_path, [hexadecimal])
    assert first.channels[0].channel_id == second.channels[0].channel_id
    assert first.channels[0].endpoints[0].endpoint_id == second.channels[0].endpoints[0].endpoint_id


def test_private_key_does_not_join_independent_allocations(tmp_path):
    findings = []
    for name, line in [("lan", 12), ("wan", 35)]:
        finding = _finding()
        anchor = WrapperHop(binary_path="usr/sbin/httpd", function_name=name, line_number=line)
        findings.append(finding.model_copy(update={"wrapper_path": [anchor], "context_anchor": anchor,
            "resources": [finding.resources[0].model_copy(update={"canonical_value": "0"})]}))
    result = _merge(tmp_path, findings)
    assert len(result.channels) == 2


def test_catalog_records_related_kernel_object_overlap_without_choosing_owner():
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.assembler import _anchor_keys
    shared_memory = {"mechanism": "sysv_shm", "resources": [
        {"kind": "sysv_key", "canonical_value": "15004"},
        {"kind": "sysv_sem_key", "canonical_value": "0x61ac"}]}
    semaphore = {"mechanism": "sysv_sem", "resources": [
        {"kind": "sysv_key", "canonical_value": "25004"}]}
    assert _anchor_keys(shared_memory) & _anchor_keys(semaphore) == {"ipc:sysv_sem_key:25004"}
    semaphore["resources"][0]["canonical_value"] = "0"
    assert not _anchor_keys(semaphore)
