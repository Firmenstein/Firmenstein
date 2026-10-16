"""Planner interface regressions: visible constraints, scoped reads and revisions."""
import json

import pytest
from pydantic import ValidationError

from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import InterventionContract
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import contract_for_test


@pytest.mark.parametrize("resolved", [False, True])
def test_anchor_kind_feedback_identifies_only_the_offending_positions(resolved):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import InterventionUnit, InterventionUnitDraft
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import scopes_for_test

    function = {"kind": "function", "binary_name": "httpd", "function_ea": 0x1000}
    if resolved:
        function["function_name"] = "read_config"
    payload = dict(strategy="function_stub", summary="Replace the config accessor",
                   behavior_scopes=scopes_for_test(["file:F1"]),
                   contract=contract_for_test(["Preserve the config API"]),
                   anchors=[function, {"kind": "resource", "resource_kind": "path",
                                       "value": "/var/config", "source_ref": "file:F1"}])
    model = InterventionUnit if resolved else InterventionUnitDraft
    if resolved:
        payload["unit_id"] = "config-reader"
    with pytest.raises(ValidationError) as caught:
        model.model_validate(payload)
    message = caught.value.errors()[0]["msg"]
    assert "function_stub requires only function anchors" in message
    assert "anchors[1].kind='resource'" in message
    assert "anchors[0]" not in message
    payload["anchors"] = [function]
    assert model.model_validate(payload).anchors[0].kind == "function"


@pytest.mark.parametrize("field", ["applicability", "owned_resources", "operations", "verification"])
def test_contract_required_fields_match_model_visible_schema(field):
    payload = contract_for_test(["Preserve the fixture behavior"]).model_dump()
    schema = InterventionContract.model_json_schema()
    assert field in schema["required"]
    assert schema["properties"][field]["minItems"] == 1
    for invalid, error_type in (({k: v for k, v in payload.items() if k != field}, "missing"),
                                ({**payload, field: []}, "too_short")):
        with pytest.raises(ValidationError) as error:
            InterventionContract.model_validate(invalid)
        assert any(e["loc"] == (field,) and e["type"] == error_type for e in error.value.errors())


def test_explicit_empty_refinement_scope_is_valid_but_omission_is_not():
    payload = contract_for_test(["Provide initial generation behavior"]).model_dump()
    payload["allowed_refinement_scope"] = []
    contract = InterventionContract.model_validate(payload)
    assert InterventionContract.model_validate_json(contract.model_dump_json()).allowed_refinement_scope == []
    schema = InterventionContract.model_json_schema()
    assert "allowed_refinement_scope" in schema["required"]
    assert not schema["properties"]["allowed_refinement_scope"].get("minItems")
    del payload["allowed_refinement_scope"]
    with pytest.raises(ValidationError) as error:
        InterventionContract.model_validate(payload)
    assert error.value.errors()[0]["loc"] == ("allowed_refinement_scope",)


def test_removed_auxiliary_output_and_previous_versions_are_not_silently_loaded():
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import InterventionPlanResult, PlanContents
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import PlanDraft, PlanBatch
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import PlanningContext

    context = PlanningContext(evidence_level="implementation", implementation_sources={}, runtime_observations=[], limitations=[])
    common = dict(catalog_digest="a" * 64, planning_context=context, service_goal="Fixture service",
                  launch_choice={"recipe_id": None, "reason": "No launch candidate"})
    plan = InterventionPlanResult(**common, claim_counts={}, draft_revision=0)
    draft = PlanDraft(**common)
    for model, payload, old_version in [(InterventionPlanResult, plan.model_dump(), 12),
                                         (PlanDraft, draft.model_dump(), 1)]:
        payload["schema_version"] = old_version
        with pytest.raises(ValidationError) as error:
            model.model_validate(payload)
        assert any(e["loc"] == ("schema_version",) for e in error.value.errors())
    with pytest.raises(ValidationError, match="overlap_assessments"):
        PlanContents.model_validate({"overlap_assessments": {}})
    with pytest.raises(ValidationError, match="overlap_assessments"):
        PlanBatch.model_validate({"expected_revision": 0, "reason": "Old auxiliary protocol", "overlap_assessments": {}})


def test_batch_finding_reads_equal_individual_reads_and_keep_source_bytes(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _write_sources
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import FindingEvidenceResolver, make_finding_evidence_tool

    _write_sources(tmp_path)
    catalog = PlanningEvidenceAssembler(tmp_path).run()
    resolver = FindingEvidenceResolver(tmp_path, catalog)
    refs = list(catalog.finding_index)
    original = {p: p.read_bytes() for p in tmp_path.rglob("*.json")}
    records = {ref: [catalog.finding_index[ref].evidence_refs[0]] for ref in refs}
    tool = make_finding_evidence_tool(resolver, set(refs))
    batch = json.loads(tool.invoke({"finding_refs": refs, "record_refs": records}))
    assert batch == {ref: resolver.read_finding(ref, records[ref]) for ref in refs}
    assert json.loads(tool.invoke({"finding_refs": [refs[0]]})) == {
        refs[0]: resolver.read_finding(refs[0])}
    assert {p: p.read_bytes() for p in original} == original
    with pytest.raises(ValueError, match="outside.*scope") as caught:
        tool.invoke({"finding_refs": [refs[0], "foreign:finding"]})
    assert "task input" in str(caught.value)
    assert all(ref not in str(caught.value) for ref in refs)
    with pytest.raises(ValueError, match="record_refs.*not requested"):
        tool.invoke({"finding_refs": [refs[0]], "record_refs": {refs[1]: records[refs[1]]}})
    with pytest.raises(ValueError, match="unknown evidence references"):
        tool.invoke({"finding_refs": [refs[0]], "record_refs": {refs[0]: ["/foreign/record"]}})


def test_unknown_catalog_id_feedback_keeps_the_complete_index_accessible(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import PlanDraftStore
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.plan_agent import make_plan_tools
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import build_planning_context
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import _catalog, _Resolver

    refs = [f"file:F{index}" for index in range(180)]
    store = PlanDraftStore(tmp_path / "draft.json", _catalog(*refs), _Resolver(),
                           build_planning_context(), service_goal="Fixture service")
    tools = {t.name: t for t in make_plan_tools(store)}
    with pytest.raises(ValueError, match="unknown finding IDs.*invented") as caught:
        tools["read_catalog"].invoke({"kind": "finding", "ids": ["invented"]})
    assert "read_plan" in str(caught.value)
    assert "remaining_only=False" in str(caught.value)
    assert all(ref not in str(caught.value) for ref in refs)
    first = tools["read_plan"].invoke({"remaining_only": False, "limit": 100})
    second = tools["read_plan"].invoke({"remaining_only": False, "offset": first["next_offset"], "limit": 100})
    assert first["total"] == second["total"] == 180
    assert set(first["findings"]) | set(second["findings"]) == set(refs)
    assert second["next_offset"] is None


@pytest.mark.parametrize("permission", [[], ["Adjust the verified implementation detail"]])
@pytest.mark.parametrize("unit_id", ["unit-a", "u-nvram-defaults"])
def test_runner_preserves_unit_when_runtime_refinement_is_not_authorized(tmp_path, permission, unit_id):
    from fmst_analyzer.runner.runner import _protected_files, _validate_protected_files
    from fmst_analyzer.synthesizer.intervention_generator.shell import unit_module_name

    contract = contract_for_test(["Initial generation remains useful"])
    contract.allowed_refinement_scope = permission
    source = tmp_path / "src" / unit_module_name(unit_id) / "logic.rs"
    source.parent.mkdir(parents=True)
    source.write_text("initial generated implementation")
    before = _protected_files(tmp_path)
    source.write_text("attempted runtime edit")
    editable = {unit_id} if contract.allowed_refinement_scope else set()
    if permission:
        assert _validate_protected_files(tmp_path, before, declared_unit_ids=[unit_id],
                                        editable_unit_ids=editable) == {unit_id}
    else:
        with pytest.raises(RuntimeError, match="non-editable.*logic.rs"):
            _validate_protected_files(tmp_path, before, declared_unit_ids=[unit_id],
                                      editable_unit_ids=editable)
        assert _protected_files(tmp_path) == before
