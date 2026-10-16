"""Conditional ownership, immutable source evidence and Generation readiness."""
import asyncio
import json
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fmst_analyzer.analysis.base.report_io import model_content_sha256
from fmst_analyzer.synthesizer.intervention_plan_analyzer.analyzer import load_persisted_intervention_plan
from fmst_analyzer.synthesizer.intervention_plan_analyzer.behavior_validation import claim_counts, overlap_pairs, validate_plan_behaviors
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler, SourceKind
from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import validate_contents
from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import FindingEvidenceResolver
from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import build_planning_context
from fmst_analyzer.synthesizer.intervention_plan_analyzer.normalization import normalize_unit
from fmst_analyzer.synthesizer.intervention_plan_analyzer.reports import persist_intervention_plan, render_index
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    BehaviorScope, PlanContents, InterventionPlanResult, InterventionUnit, LaunchChoice,
    NoIntervention, RunnerTask, UnresolvedBehavior,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _write_sources
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import _catalog, _choice, _pseudo_file_unit, _Resolver, _View


def _scope(ref="file:F1", indices=(0,), condition="mode A"):
    return BehaviorScope(finding_ref=ref, claim_indices=list(indices), applicability=condition)


def _resolver(count=1):
    return SimpleNamespace(finding_evidence=lambda ref: {"finding": {"claims": [{"statement": f"Conditional behavior {i}"} for i in range(count)]}})


def _unit(key, scope):
    draft = _pseudo_file_unit()
    return InterventionUnit(unit_id=key, behavior_scopes=[scope], strategy=draft.strategy,
        anchors=draft.anchors, contract=draft.contract, summary=draft.summary)


def _validate(contents, catalog=None, resolver=None):
    validate_contents(contents, catalog or _catalog(), resolver or _resolver(), complete=True)


def _publishable(contents, catalog, resolver, choice=None):
    return InterventionPlanResult(**contents.model_dump(), catalog_digest=model_content_sha256(catalog),
        planning_context=build_planning_context(), launch_choice=choice or _choice(),
        claim_counts=claim_counts(resolver, catalog.finding_index), draft_revision=1,
        service_goal="Provide the fixture's documented interaction")


def _source_plan(root):
    _write_sources(root)
    catalog = PlanningEvidenceAssembler(root).run()
    resolver = FindingEvidenceResolver(root, catalog)
    scopes = {ref: _scope(ref, range(count)) for ref, count in claim_counts(resolver, catalog.finding_index).items()}
    contents = PlanContents(no_interventions={f"native-{i}": NoIntervention(**scope.model_dump(), reason="Fixture baseline assumption")
        for i, scope in enumerate(scopes.values())})
    return catalog, resolver, contents, scopes


def test_contract_conditions_state_fallback_and_capabilities_survive_normalization():
    draft = _pseudo_file_unit()
    draft.contract.required_iib_capabilities = ["guest_memory_read_write"]
    draft.contract.applicability = ["request == 7 and caller is in LAN setup"]
    draft.contract.state = ["Output +0x14 is read before the caller returns"]
    unit = normalize_unit("device", draft, catalog=_catalog(), resolver=_Resolver(), view=_View(), launch_choice=_choice())
    assert unit.contract == draft.contract
    assert unit.behavior_scopes == draft.behavior_scopes
    assert InterventionUnit.model_validate_json(unit.model_dump_json()) == unit
    assert "mock_contract" not in unit.model_dump()


@pytest.mark.parametrize("path", ["/vendor/dev/status", "/run/virtual/status", "/device-state"])
def test_pseudo_file_binding_depends_on_exact_path_not_directory_name(path):
    draft = _pseudo_file_unit()
    draft.anchors[0].value = path
    unit = normalize_unit("device", draft, catalog=_catalog(), resolver=_Resolver(),
                          view=_View(), launch_choice=_choice())
    assert unit.anchors[0].value == path
    assert unit.contract == draft.contract


def test_split_claims_preserve_native_branch_and_reject_omission():
    plan = PlanContents(units={"unit": _unit("unit", _scope())}, no_interventions={"native": NoIntervention(
        **_scope(indices=(1,), condition="mode B").model_dump(), reason="The native mode B path remains unchanged")})
    _validate(plan, resolver=_resolver(2))
    with pytest.raises(ValueError, match="unprocessed claims"):
        _validate(plan.model_copy(update={"no_interventions": {}}), resolver=_resolver(2))


def test_duplicate_owner_and_nonexistent_claim_are_rejected():
    with pytest.raises(ValueError, match="already has decision"):
        _validate(PlanContents(units={key: _unit(key, _scope()) for key in ("a", "b")}))
    with pytest.raises(ValueError, match="nonexistent source claims"):
        _validate(PlanContents(units={"invalid": _unit("invalid", _scope(indices=(5,)))}))


def _partial_overlap_plan():
    catalog = _catalog("file:F1", "network:N1")
    for entry in catalog.finding_index.values():
        entry.anchor_keys = ["ctree:shared-lifecycle"]
    unit = _unit("shared-buffer", _scope())
    unit.behavior_scopes.append(_scope("network:N1"))
    contents = PlanContents(units={unit.unit_id: unit}, no_interventions={"optional": NoIntervention(
        **_scope(indices=(1,)).model_dump(), reason="Optional diagnostic has native fallback")},
        unresolved={"peer-effect": UnresolvedBehavior(**_scope("network:N1", indices=(1,)).model_dump(),
            return_to="analyzer", reason="The external peer side effect is unproved")})
    return contents, catalog, _resolver(2)


def test_shared_evidence_preserves_claim_level_decisions_after_replay():
    contents, catalog, resolver = _partial_overlap_plan()
    _validate(contents, catalog, resolver)
    restored = PlanContents.model_validate_json(contents.model_dump_json())
    _validate(restored, catalog, resolver)
    result = _publishable(restored, catalog, resolver)
    rendered = render_index(catalog, result)
    assert "overlap_assessments" not in result.model_dump()
    assert "Optional diagnostic has native fallback" in rendered
    assert "The external peer side effect is unproved" in rendered
    assert len(restored.units["shared-buffer"].behavior_scopes) == 2


def test_runtime_followup_cannot_replace_an_execution_decision():
    contents, catalog, resolver = _partial_overlap_plan()
    contents.runner_tasks = {"observe": RunnerTask(behavior_scopes=[_scope(), _scope("network:N1")],
        objective="Observe the shared buffer response fields and compare with the Contract")}
    _validate(contents, catalog, resolver)
    contents.units = {}
    with pytest.raises(ValueError, match="unprocessed claims"):
        _validate(contents, catalog, resolver)


@pytest.mark.parametrize("outcome", ["native", "unresolved"])
def test_runtime_followup_preserves_current_decision_but_not_duplicate_owner(outcome):
    scope = _scope()
    fields = {"no_interventions": {"native": NoIntervention(**scope.model_dump(), reason="The baseline provides it")}} if outcome == "native" else {
        "unresolved": {"gap": UnresolvedBehavior(**scope.model_dump(), return_to="launch", reason="Required mode unknown")}}
    plan = PlanContents(runner_tasks={"observe": RunnerTask(behavior_scopes=[scope], objective="Observe guard and return value")}, **fields)
    _validate(PlanContents.model_validate_json(plan.model_dump_json()))
    plan.units = {"unit": _unit("unit", scope)}
    with pytest.raises(ValueError, match="already has decision"):
        _validate(plan)


def test_report_names_use_short_ids_and_preserve_long_descriptions(tmp_path):
    contents, catalog, resolver = _partial_overlap_plan()
    summary = "optional-prefix-output-state-" * 40 + "完整诊断内容" * 40
    catalog.finding_index["file:F1"].summary = summary
    result = _publishable(contents, catalog, resolver)
    persist_intervention_plan(tmp_path, catalog, result)
    folder = tmp_path / "intervention_plan_reports"
    paths = set((folder / "units").iterdir())
    assert len(paths) == 2
    assert all(path.name.isascii() and len(path.name) < 100 for path in paths)
    for link in re.findall(r"\]\((units/[^)]+)\)", (folder / "index.md").read_text()):
        assert (folder / link).is_file(), link
    assert summary in next(path for path in paths if path.suffix == ".md").read_text()


def test_failed_unit_publication_does_not_publish_completed_plan(tmp_path, monkeypatch):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer import reports
    contents, catalog, resolver = _partial_overlap_plan()
    write = reports.write_model_json
    def fail_page(path, value):
        if path.parent.name == "units":
            raise OSError("synthetic report write failure")
        return write(path, value)
    monkeypatch.setattr(reports, "write_model_json", fail_page)
    with pytest.raises(OSError, match="report write failure"):
        reports.persist_intervention_plan(tmp_path, catalog, _publishable(contents, catalog, resolver))
    assert not (tmp_path / "intervention_plan_reports/intervention_plan_result.json").exists()


@pytest.mark.parametrize("return_to,reason", [
    (None, "caller.c:24 contradicts the Analyzer exit claim: failure returns to startup; native behavior suffices"),
    (None, "caller.c:24 exits only an optional export helper; the service remains usable"),
    ("analyzer", "caller.c:24 does not establish which process exits; this blocks startup judgment"),
    ("launch", "Selected launch and cited argv disagree on the required startup branch"),
    ("runtime_capability", "Required process behavior has no established runtime capability"),
])
def test_fallible_claim_decisions_replay_and_gate_generation(tmp_path, monkeypatch, return_to, reason):
    from fmst_analyzer.synthesizer.intervention_generator import generator as generation
    catalog, resolver, contents, scopes = _source_plan(tmp_path)
    source_bytes = {path: path.read_bytes() for path in tmp_path.rglob("*.json")}
    ref = next(ref for ref, entry in catalog.finding_index.items() if entry.source_kind is SourceKind.PROCESS)
    key = next(key for key, value in contents.no_interventions.items() if value.finding_ref == ref)
    if return_to:
        del contents.no_interventions[key]
        contents.unresolved["blocker"] = UnresolvedBehavior(**scopes[ref].model_dump(), reason=reason, return_to=return_to)
    else:
        contents.no_interventions[key].reason = reason
    contents.runner_tasks["observe"] = RunnerTask(behavior_scopes=[scopes[ref]], objective="Observe the startup branch once prerequisites are resolved")
    plan = _publishable(contents, catalog, resolver, LaunchChoice(recipe_id="launch-httpd", reason="Fixed fixture decision"))
    persist_intervention_plan(tmp_path, catalog, plan)
    loaded = load_persisted_intervention_plan(tmp_path)
    assert loaded == (catalog, plan)
    assert reason in (tmp_path / "intervention_plan_reports/index.md").read_text()
    assert {path: path.read_bytes() for path in source_bytes} == source_bytes
    monkeypatch.setattr(generation, "load_persisted_intervention_plan", lambda *args, **kwargs: loaded)
    generator = generation.InterventionGenerator(SimpleNamespace(agent_provider="codex", agent_concurrency_limit=1))
    run_impl = AsyncMock(side_effect=RuntimeError("reached generation boundary"))
    monkeypatch.setattr(generator, "_run_impl", run_impl)
    # Generation no longer treats unresolved Plan semantics as a second
    # planning gate; it reaches the Generator boundary and lets later stages
    # use runtime evidence to revise the candidate.
    with pytest.raises(RuntimeError, match="reached generation boundary"):
        asyncio.run(generator.run(view=_View(), image_name="synthetic", arch="arm", diagnostic_reports_root=tmp_path,
            trace_root=tmp_path / "trace", interventions_root=tmp_path / "interventions", test_harnesses_root=tmp_path / "tests",
            env_scripts_root=tmp_path / "env", iib_api_abspath=tmp_path / "iib-api"))
    assert run_impl.await_count == 1
    assert {path: path.read_bytes() for path in source_bytes} == source_bytes


def test_rebuilt_catalog_cannot_refresh_old_plan_with_unchanged_finding_ids(tmp_path):
    catalog, resolver, contents, _ = _source_plan(tmp_path)
    plan = _publishable(contents, catalog, resolver, LaunchChoice(recipe_id=None, reason="Offline source validation only"))
    persist_intervention_plan(tmp_path, catalog, plan)
    assert load_persisted_intervention_plan(tmp_path)[1] == plan
    plan_path = tmp_path / "intervention_plan_reports/intervention_plan_result.json"
    before = plan_path.read_bytes()
    source = tmp_path / "file_reports/file_resolver_result.json"
    from fmst_analyzer.analysis.base.input_provenance import require_receipt, publish_receipt
    from fmst_analyzer.analysis.file_resolver import FileResolverResult
    receipt = require_receipt(source)
    payload = json.loads(source.read_text())
    next(iter(payload["planning_findings"].values()))["claims"][0]["statement"] = "New conditional effect"
    source.write_text(json.dumps(payload))
    publish_receipt(source, FileResolverResult.model_validate(payload), receipt.inputs)
    rebuilt = PlanningEvidenceAssembler(tmp_path).run()
    assert set(rebuilt.finding_index) == set(catalog.finding_index)
    assert plan_path.read_bytes() == before
    with pytest.raises(ValueError, match="Catalog differs"):
        load_persisted_intervention_plan(tmp_path)


def test_shared_source_evidence_does_not_force_quadratic_native_checklist():
    catalog = _catalog(*(f"file:f{i}" for i in range(75)))
    for entry in catalog.finding_index.values():
        entry.anchor_keys = ["ctree:one-common-caller"]
    contents = PlanContents(no_interventions={f"native-{i}": NoIntervention(**_scope(ref).model_dump(),
        reason="This behavior is already supplied by the fixture baseline") for i, ref in enumerate(catalog.finding_index)})
    assert len(overlap_pairs(catalog, catalog.finding_index)) == 2775
    _validate(contents, catalog)
    assert "overlap_assessments" not in contents.model_dump()


def test_duplicate_concrete_owner_is_rejected_without_semantic_keyword_rules():
    catalog = _catalog("file:F1", "file:F2")
    contents = PlanContents(units={"a": _unit("a", _scope()), "b": _unit("b", _scope("file:F2"))})
    with pytest.raises(ValueError, match="concrete anchor.*already belongs"):
        _validate(contents, catalog)
    contents.units["b"].anchors[0].value = "/dev/another"
    _validate(contents, catalog)


def test_finding_tool_returns_all_claims_and_exact_requested_records(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import make_finding_evidence_tool
    catalog, resolver, _, _ = _source_plan(tmp_path)
    ref = next(ref for ref, entry in catalog.finding_index.items() if entry.source_kind is SourceKind.FILE)
    tool = make_finding_evidence_tool(resolver, {ref})
    complete = resolver.finding_evidence(ref)
    result = json.loads(tool.invoke({"finding_refs": [ref]}))[ref]
    assert result["finding"] == complete["finding"] and result["records"] == {}
    pointer = catalog.finding_index[ref].evidence_refs[0]
    selected = json.loads(tool.invoke({"finding_refs": [ref], "record_refs": {ref: [pointer]}}))[ref]
    from fmst_analyzer.analysis.base.analysis_finding import resolve_evidence_ref
    source = json.loads((tmp_path / catalog.source_artifacts[SourceKind.FILE].relative_path).read_text())
    assert selected["records"] == {pointer: resolve_evidence_ref(source, pointer)}
    with pytest.raises(ValueError, match="unknown evidence references"):
        tool.invoke({"finding_refs": [ref], "record_refs": {ref: ["/planning_findings/not-owned"]}})


def test_published_plan_rejects_a_newer_accepted_draft(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import PlanBatch, PlanDraftStore
    catalog, resolver, contents, _ = _source_plan(tmp_path)
    choice = LaunchChoice(recipe_id="launch-httpd", reason="Supported fixture launch")
    plan = _publishable(contents, catalog, resolver, choice)
    store = PlanDraftStore(tmp_path / "intervention_plan_reports/plan_draft.json", catalog, resolver,
        plan.planning_context, service_goal=plan.service_goal)
    store.apply(PlanBatch(expected_revision=0, reason="Initial supported decisions", launch_choice=choice,
        no_interventions=contents.no_interventions))
    persist_intervention_plan(tmp_path, catalog, plan)
    assert load_persisted_intervention_plan(tmp_path)[1] == plan
    key, item = next(iter(contents.no_interventions.items()))
    store.apply(PlanBatch(expected_revision=1, reason="A newly reviewed premise",
        no_interventions={key: item.model_copy(update={"reason": "A revised source-supported decision"})}))
    with pytest.raises(ValueError, match="differs from the current draft"):
        load_persisted_intervention_plan(tmp_path)


def test_plan_goal_change_requires_replanning(tmp_path, monkeypatch):
    catalog, resolver, contents, _ = _source_plan(tmp_path)
    plan = _publishable(contents, catalog, resolver, LaunchChoice(recipe_id="launch-httpd", reason="Supported direct command"))
    persist_intervention_plan(tmp_path, catalog, plan)
    monkeypatch.setattr(PlanningEvidenceAssembler, "assemble", lambda self: catalog)
    with pytest.raises(ValueError, match="service goal changed"):
        load_persisted_intervention_plan(tmp_path, global_config=SimpleNamespace(rehosting_goal="Another required interaction"))


def test_no_launch_does_not_stop_generation_before_agent_or_build(tmp_path, monkeypatch):
    from fmst_analyzer.synthesizer.intervention_generator import generator as generation
    catalog, resolver, contents, _ = _source_plan(tmp_path)
    plan = _publishable(contents, catalog, resolver, LaunchChoice(recipe_id=None, reason="Required argv is unknown"))
    monkeypatch.setattr(generation, "load_persisted_intervention_plan", lambda *a, **kw: (catalog, plan))
    generator = generation.InterventionGenerator(SimpleNamespace(agent_provider="codex", agent_concurrency_limit=1))
    run_impl = AsyncMock(side_effect=RuntimeError("reached generation boundary"))
    monkeypatch.setattr(generator, "_run_impl", run_impl)
    with pytest.raises(RuntimeError, match="reached generation boundary"):
        asyncio.run(generator.run(view=_View(), image_name="synthetic", arch="arm", diagnostic_reports_root=tmp_path,
            trace_root=tmp_path / "trace", interventions_root=tmp_path / "interventions", test_harnesses_root=tmp_path / "tests",
            env_scripts_root=tmp_path / "env", iib_api_abspath=tmp_path / "iib-api"))
    run_impl.assert_awaited_once()
