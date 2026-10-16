"""Offline draft transactions and completion boundaries; no model or binaries."""
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from fmst_analyzer.analysis.base.finding_binding import pointer
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.schema import (
    FindingIndexEntry, PlanningEvidenceCatalog, PlanningTargetIdentity,
    SourceArtifact, SourceKind,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import PlanBatch, PlanDraftStore
from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import PlanningContext
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    BehaviorScope, InterventionPlanResult, InterventionUnit, InterventionUnitDraft, LaunchChoice,
    NoIntervention, ResourceAnchor, RunnerTask, UnresolvedBehavior,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import contract_for_test


def scope(ref="file:a", indices=(0,)):
    return BehaviorScope(finding_ref=ref, claim_indices=list(indices), applicability="The fixture caller consumes these independent fields.")


def native(ref="file:a", indices=(0,)):
    return NoIntervention(**scope(ref, indices).model_dump(), reason="This branch is supplied by the fixture's native baseline.")


def unit(*scopes):
    return InterventionUnitDraft(behavior_scopes=list(scopes), strategy="environment_setup",
        anchors=[ResourceAnchor(resource_kind="path", value="/etc/service.conf", source_ref=scopes[0].finding_ref)],
        summary="Supply the packaged fixture configuration.",
        contract=contract_for_test(["Copy the packaged config to /etc/service.conf before launch."]))


def resolve_unit(key, value, choice):
    # Resource anchors require no binary backend in this state-layer fixture.
    return InterventionUnit(unit_id=key, **value.model_dump(mode="json"))


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({ref: {"finding": {"claims": [{"statement": f"field {i}"} for i in range(2)]}}
                                  for ref in ["file:a", "network:b"]}))
    resolver = SimpleNamespace(finding_evidence=lambda ref: json.loads(source.read_text())[ref])
    catalog = PlanningEvidenceCatalog(
        target_identity=PlanningTargetIdentity(target_basename="service", selected_rootfs_path="bin/service",
            executable_sha256="a" * 64, argv0="service", firmware_sha256="b" * 64),
        source_artifacts={kind: SourceArtifact(source_kind=kind, relative_path=f"{kind}.json",
            schema_version=1, phase="full", content_sha256="c" * 64, provenance_sha256="d" * 64) for kind in SourceKind},
        finding_index={ref: FindingIndexEntry(finding_ref=ref, source_kind=SourceKind.FILE,
            source_id=ref, summary="Independent source fields", boundary_kind="resource", anchor_keys=[],
            evidence_refs=[], source_locator=pointer("planning_findings", ref)) for ref in ["file:a", "network:b"]})
    context = PlanningContext(evidence_level="implementation", implementation_sources={}, runtime_observations=[], limitations=[])
    path = tmp_path / "plan/draft.json"
    store = PlanDraftStore(path, catalog, resolver, context, service_goal="Complete the fixture request", resolve_unit=resolve_unit)
    return store, catalog, resolver, context, source


def apply(store, **kwargs):
    return store.apply(PlanBatch(expected_revision=store.state.revision, reason="Fixture evidence supports this revision.", **kwargs))


def test_partial_split_merge_withdraw_and_reload(setup):
    store, catalog, resolver, context, source = setup
    original = source.read_bytes()
    apply(store, units={"first": unit(scope())})
    assert store.progress()["findings"]["file:a"]["status"] == "partial"
    assert store.progress()["findings"]["file:a"]["remaining_claim_indices"] == [1]
    second = unit(scope(indices=(1,)), scope("network:b", (0, 1)))
    second.anchors[0].value = "/etc/second.conf"
    apply(store, units={"second": second})
    assert store.progress()["decided_claims"] == 4
    assert store.progress()["processed_findings"] == 2
    # Replacing two owners with one is a single transaction.
    merged = unit(scope(indices=(0, 1)), scope("network:b", (0, 1)))
    apply(store, withdraw=["first", "second"], units={"shared": merged})
    assert set(store.state.units) == {"shared"}
    apply(store, launch_choice=LaunchChoice(recipe_id=None, reason="No supported launch candidate in this fixture."), reconfirm=["shared"])
    assert store.validate_complete().units["shared"].contract == merged.contract
    loaded = PlanDraftStore(store.path, catalog, resolver, context, service_goal="Complete the fixture request", resolve_unit=resolve_unit)
    assert loaded.progress() == store.progress()
    apply(loaded, withdraw=["shared"])
    assert loaded.progress()["decided_claims"] == 0
    assert loaded.state.history[2].withdraw == ["first", "second"]
    assert source.read_bytes() == original


def test_tasks_alone_never_complete_claims_but_may_accompany_native_or_unresolved(setup):
    store, *_ = setup
    task = RunnerTask(behavior_scopes=[scope(indices=(0, 1))], objective="Observe actual output fields and compare them with the selected branch.")
    apply(store, runner_tasks={"observe": task})
    assert store.progress()["decided_claims"] == 0
    with pytest.raises(ValueError, match="unprocessed claims"):
        store.validate_complete()
    gap = UnresolvedBehavior(**scope(indices=(1,)).model_dump(), reason="Required output layout conflicts with the code.", return_to="analyzer")
    apply(store, no_interventions={"native": native(), "other": native("network:b", (0, 1))}, unresolved={"layout": gap},
          launch_choice=LaunchChoice(recipe_id=None, reason="Missing applicable command."), reconfirm=["observe"])
    assert store.progress()["processed_findings"] == 2
    complete = store.validate_complete()
    assert complete.unresolved == {"layout": gap}
    assert complete.runner_tasks == {"observe": task}
    # Accounted-for semantic blockers remain explicit, never silently ready.
    assert complete.launch_choice.recipe_id is None


@pytest.mark.parametrize("bad", [
    {"units": {"bad": unit(scope(indices=(9,))) }},
    {"units": {"bad": unit(scope("file:unknown"))}},
    {"units": {"duplicate": unit(scope())}},
    {"no_interventions": {"close": native()}},
    {"withdraw": ["not-present"]},
    {"launch_choice": LaunchChoice(recipe_id="invented", reason="Unsupported identity.")},
])
def test_rejected_batch_preserves_memory_disk_and_history(setup, bad):
    store, *_ = setup
    apply(store, units={"good": unit(scope())})
    before, raw = store.state, store.path.read_bytes()
    with pytest.raises(ValueError):
        apply(store, **bad)
    assert store.state == before
    assert store.path.read_bytes() == raw


def test_failed_atomic_write_and_stale_writer_preserve_committed_draft(setup, monkeypatch):
    store, catalog, resolver, context, _ = setup
    other = PlanDraftStore(store.path, catalog, resolver, context, service_goal="Complete the fixture request")
    apply(store, no_interventions={"first": native()})
    with pytest.raises(ValueError, match="changed on disk"):
        apply(other, no_interventions={"second": native("network:b")})
    raw, before = store.path.read_bytes(), store.state
    def fail(*args):
        raise OSError("fixture storage failure")
    monkeypatch.setattr("fmst_analyzer.synthesizer.intervention_plan_analyzer.draft.write_model_json", fail)
    with pytest.raises(OSError, match="storage failure"):
        apply(store, no_interventions={"second": native("network:b")})
    assert store.path.read_bytes() == raw
    assert store.state == before


def test_cross_input_reuse_is_rejected(setup):
    store, catalog, resolver, context, _ = setup
    with pytest.raises(ValueError, match="service goal changed"):
        PlanDraftStore(store.path, catalog, resolver, context, service_goal="A different required interaction")
    changed = context.model_copy(update={"limitations": ["A changed baseline"]})
    with pytest.raises(ValueError, match="PlanningContext"):
        PlanDraftStore(store.path, catalog, resolver, changed, service_goal=store.state.service_goal)
    changed_catalog = catalog.model_copy(deep=True)
    changed_catalog.finding_index["file:a"].summary = "Changed source input"
    with pytest.raises(ValueError, match="Catalog"):
        PlanDraftStore(store.path, changed_catalog, resolver, context, service_goal=store.state.service_goal)


def test_launch_change_requires_review_and_cannot_hide_completed_work(setup):
    store, *_ = setup
    apply(store, no_interventions={"first": native(indices=(0, 1)), "second": native("network:b", (0, 1))})
    apply(store, launch_choice=LaunchChoice(recipe_id=None, reason="The fixture has no launch candidate."))
    assert store.progress()["review_pending"] == ["first", "second"]
    assert store.progress()["decided_claims"] == 0
    with pytest.raises(ValueError, match="require review"):
        store.validate_complete()
    apply(store, reconfirm=["first"], no_interventions={"second": native("network:b", (0, 1))})
    assert store.validate_complete().review_pending == []
    escaped = store.state
    escaped.no_interventions.clear()
    assert store.progress()["decided_claims"] == 4


def test_shared_source_hints_allow_distinct_owners_but_not_duplicate_anchors(setup):
    store, catalog, resolver, context, _ = setup
    store.path.unlink()
    for entry in catalog.finding_index.values():
        entry.anchor_keys = ["same-resource"]
    store = PlanDraftStore(store.path, catalog, resolver, context, resolve_unit=resolve_unit)
    apply(store, units={"first": unit(scope(indices=(0, 1)))})
    with pytest.raises(ValueError, match="concrete anchor.*already belongs"):
        apply(store, units={"second": unit(scope("network:b", (0, 1)))})
    distinct = unit(scope("network:b", (0, 1)))
    distinct.anchors[0].value = "/etc/second.conf"
    apply(store, units={"second": distinct})
    apply(store, units={"first": unit(scope(indices=(0, 1)), scope("network:b", (0, 1)))},
          withdraw=["second"], launch_choice=LaunchChoice(recipe_id=None, reason="No launch candidate."))
    assert store.validate_complete().revision == 3
    assert set(store.state.units) == {"first"}


def test_empty_catalog_still_requires_launch_assessment(setup):
    store, catalog, resolver, context, _ = setup
    store.path.unlink()
    catalog.finding_index.clear()
    store = PlanDraftStore(store.path, catalog, resolver, context)
    with pytest.raises(ValueError, match="launch selection"):
        store.validate_complete()
    apply(store, launch_choice=LaunchChoice(recipe_id=None, reason="No candidate was supplied."))
    assert store.validate_complete().units == {}


def test_draft_cannot_be_loaded_as_a_published_plan(setup):
    store, *_ = setup
    with pytest.raises(ValueError):
        InterventionPlanResult.model_validate_json(store.path.read_text())


def test_stale_batch_cannot_overwrite_a_later_revision(setup):
    store, *_ = setup
    old_batch = PlanBatch(expected_revision=0, reason="An earlier proposal", no_interventions={"second": native("network:b")})
    apply(store, no_interventions={"first": native()})
    with pytest.raises(ValueError, match="stale expected_revision"):
        store.apply(old_batch)
    assert set(store.state.no_interventions) == {"first"}


def test_logical_ids_preserve_exact_spelling_across_review_withdraw_and_reload(setup):
    store, catalog, resolver, context, _ = setup
    decision = " Native / 初始化: " + "source-observation-" * 8
    other = "Native / 初始化"
    apply(store, no_interventions={decision: native(indices=(0, 1)),
                                  other: native("network:b", (0, 1))})
    apply(store, launch_choice=LaunchChoice(recipe_id=None, reason="No applicable fixture launch."))
    assert set(store.state.review_pending) == {decision, other}
    apply(store, reconfirm=[decision, other])
    assert store.validate_complete().no_interventions[decision] == native(indices=(0, 1))
    loaded = PlanDraftStore(store.path, catalog, resolver, context,
        service_goal=store.state.service_goal, resolve_unit=resolve_unit)
    assert set(loaded.state.no_interventions) == {decision, other}
    apply(loaded, withdraw=[decision])
    assert set(loaded.state.no_interventions) == {other}
    assert loaded.state.history[-1].withdraw == [decision]


@pytest.mark.parametrize("key", ["", " ", "\t\n"])
@pytest.mark.parametrize("field", ["no_interventions", "unresolved", "runner_tasks", "withdraw", "reconfirm"])
def test_blank_logical_ids_are_rejected(key, field):
    from pydantic import ValidationError
    values = {"no_interventions": native(),
              "unresolved": UnresolvedBehavior(**scope().model_dump(), reason="Unobserved material state", return_to="launch"),
              "runner_tasks": RunnerTask(behavior_scopes=[scope()], objective="Observe the missing state producer")}
    payload = [key] if field in {"withdraw", "reconfirm"} else {key: values[field]}
    with pytest.raises(ValidationError):
        PlanBatch(expected_revision=0, reason="Invalid logical handle", **{field: payload})


def test_logical_uniqueness_and_implementation_names_remain_separate(setup):
    store, *_ = setup
    from pydantic import ValidationError
    decision = "Native / 状态"
    apply(store, no_interventions={decision: native()})
    before = store.path.read_bytes()
    with pytest.raises(ValueError, match="unique across outcomes"):
        apply(store, runner_tasks={decision: RunnerTask(behavior_scopes=[scope()], objective="Observe state")})
    assert store.path.read_bytes() == before
    with pytest.raises(ValidationError):
        PlanBatch(expected_revision=store.state.revision, reason="Unit build name stays constrained",
                  units={decision: unit(scope(indices=(1,)))})
    valid = "u-startup_state"
    apply(store, units={valid: unit(scope(indices=(1,)))})
    assert store.state.units[valid].unit_id == valid
