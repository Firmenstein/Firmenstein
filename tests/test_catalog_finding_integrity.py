"""Production Catalog consumes exact findings and pins every source byte set."""
import hashlib
import json

import pytest

from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler
from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import FindingEvidenceResolver
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _write_sources


def test_catalog_indexes_all_source_findings_without_semantic_projection(tmp_path):
    _write_sources(tmp_path)
    catalog = PlanningEvidenceAssembler(tmp_path).run()
    resolver = FindingEvidenceResolver(tmp_path, catalog)
    refs = set()
    for kind, artifact in catalog.source_artifacts.items():
        raw = (tmp_path / artifact.relative_path).read_bytes()
        assert artifact.content_sha256 == hashlib.sha256(raw).hexdigest()
        document = json.loads(raw)
        for ref, finding in document["planning_findings"].items():
            refs.add(ref)
            index = catalog.finding_index[ref]
            assert index.summary == finding["summary"]
            assert index.boundary_kind == finding["boundary"]["kind"]
            assert resolver.finding_evidence(ref)["finding"] == finding
    assert set(catalog.finding_index) == refs
    assert {index.source_kind for index in catalog.finding_index.values()} == set(catalog.source_artifacts)
    assert "evidence_items" not in catalog.model_dump()


def test_catalog_resolves_ipc_callsite_ids_to_same_network_source_object(tmp_path):
    from fmst_analyzer.analysis.ipc_analyzer.schema import CodeLocation, IPCAnalysisResult
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import SourceKind
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _ipc_result, _network_result

    ipc, network = _ipc_result(), _network_result()
    site = next(iter(network.callsites.values()))
    ipc.callsites[0].location = CodeLocation.model_validate(site.location.model_dump(exclude={"binary_name"}))
    ipc.callsites[0].callee_name = site.api_name
    ipc.callsites[0].expression_text = site.expression_text
    ipc.callsites[0].api_binding.symbol = site.api_name
    for citation in ipc.dependency_assessments[0].evidence:
        citation.function_name = site.location.function_name
        citation.function_ea = site.location.function_ea
        citation.line_number = site.location.line_number
    ipc = IPCAnalysisResult.model_validate(ipc.model_dump())
    _write_sources(tmp_path, ipc=ipc, network=network)

    catalog = PlanningEvidenceAssembler(tmp_path).run()
    by_kind = {entry.source_kind: entry for entry in catalog.finding_index.values()}
    shared = set(by_kind[SourceKind.IPC].anchor_keys) & set(by_kind[SourceKind.NETWORK].anchor_keys)
    assert any(key.startswith("ctree:") for key in shared)
    # The index is a hint. Both original conditional source findings remain intact.
    resolver = FindingEvidenceResolver(tmp_path, catalog)
    for source in (ipc, network):
        for ref, finding in source.planning_findings.items():
            assert resolver.finding_evidence(ref)["finding"] == finding.model_dump(mode="json")


def test_ctree_overlap_does_not_conflate_two_paths_with_same_module_basename():
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.assembler import _anchor_keys, source_binary_paths

    identity = dict(binary_name="libservice.so", function_ea=0x1000,
                    snapshot_hash="same-function-content", ctree_index=7)
    left = _anchor_keys({**identity, "binary_path": "lib/libservice.so"})
    right = _anchor_keys({**identity, "binary_path": "opt/libservice.so"})
    assert left and right and not left.intersection(right)
    documents = [{"callsites": [dict(location={**identity, "binary_path": path, "binary_sha256": "1" * 64})]}
                 for path in ("lib/libservice.so", "opt/libservice.so")]
    # Name-only File/Process evidence can join a known path only while unambiguous.
    unique = source_binary_paths(documents[:1])
    assert _anchor_keys(identity, binary_paths=unique) == left
    ambiguous = source_binary_paths(documents)
    assert "libservice.so" not in ambiguous
    assert not _anchor_keys(identity, binary_paths=ambiguous)


def test_changed_content_invalidates_index_even_when_finding_id_is_stable(tmp_path):
    _write_sources(tmp_path)
    catalog = PlanningEvidenceAssembler(tmp_path).assemble()
    source = tmp_path / "file_reports/file_resolver_result.json"
    document = json.loads(source.read_text())
    next(iter(document["planning_findings"].values()))["claims"][0]["statement"] = "Changed conditional behavior."
    source.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="digest"):
        FindingEvidenceResolver(tmp_path, catalog)


def test_source_target_bytes_must_match_even_when_basename_matches(tmp_path):
    _write_sources(tmp_path)
    source = tmp_path / "init_launch_reports/init_launch_analysis_result.json"
    document = json.loads(source.read_text())
    document["finding_target"]["sha256"] = "b" * 64
    # A source's internal finding validation already rejects this mismatch;
    # the assembler must never fall back to a basename match.
    source.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        PlanningEvidenceAssembler(tmp_path).assemble()


def test_failed_standalone_catalog_rebuild_preserves_attempt_and_downstream(tmp_path):
    _write_sources(tmp_path)
    PlanningEvidenceAssembler(tmp_path).run()
    original = (tmp_path / "intervention_planner_inputs/planner_input_catalog.json").read_bytes()
    plan_dir = tmp_path / "intervention_plan_reports"
    plan_dir.mkdir()
    (plan_dir / "plan.json").write_text("preserved downstream evidence")
    source = tmp_path / "file_reports/file_resolver_result.json"
    source.write_text('{"schema_version": 1}')
    with pytest.raises(ValueError):
        PlanningEvidenceAssembler(tmp_path).run()
    attempts = sorted((tmp_path / ".attempts/catalog").iterdir())
    assert len(attempts) == 2
    assert (attempts[0] / "artifacts/reports/planner_input_catalog.json").read_bytes() == original
    assert (attempts[1] / "previous/reports/planner_input_catalog.json").read_bytes() == original
    failed = json.loads((attempts[1] / "attempt.json").read_text())
    assert failed["status"] == "failed"
    assert failed["available_source_digests"]["file_reports/file_resolver_result.json"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert (plan_dir / "plan.json").read_text() == "preserved downstream evidence"


def test_catalog_and_resolver_preserve_three_contexts_for_one_launch(tmp_path):
    from fmst_analyzer.analysis.base.analysis_finding import FindingAnchor, InitLaunchFindingDomain
    from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, bind_finding
    from fmst_analyzer.analysis.init_launch import InitLaunchAnalysisResult, SourceSnippet
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _init_result

    source = _init_result()
    base = next(iter(source.launch_recipes.values()))
    recipes, findings = {}, {}
    for line, name in enumerate(("lan", "bridge", "wan"), start=1):
        context = SourceSnippet(path="etc/init.d/rcS", location=f"line {line}",
                                text=f"if {name}_enabled; then start_httpd; fi")
        recipe_id = f"launch-{name}"
        recipe = base.model_copy(update={
            "recipe_id": recipe_id, "context_anchor": context,
            "applicability": f"Only when {name}_enabled is true.",
            "initialization_chain": [context, base.launch_site],
        })
        prefix = f"/launch_recipes/{recipe_id}"
        finding = bind_finding(
            target=source.finding_target, source="init_launch", source_id=recipe_id,
            semantics=FindingSemantics(summary=recipe.applicability, claims=[dict(
                kind="guarantee", statement=f"Invokes the target if {name}_enabled is true.",
                evidence_refs=["/context_anchor"], unknown_kind=None)],
                reachability_refs=["/context_anchor"], coverage_refs=[]),
            record_ref=prefix, boundary_kind="environment",
            anchors=[FindingAnchor(kind="environment", ref=f"{prefix}/{field}")
                     for field in ("launch_site", "context_anchor")],
            domain=InitLaunchFindingDomain(kind="init_launch", recipe_id=recipe_id, preparation_refs=[]),
        )
        recipes[recipe_id], findings[finding.finding_ref] = recipe, finding
    payload = source.model_dump(mode="json")
    payload.update(launch_recipes=recipes, planning_findings=findings)
    source = InitLaunchAnalysisResult.model_validate(payload)
    _write_sources(tmp_path, init_launch=source)

    catalog = PlanningEvidenceAssembler(tmp_path).run()
    resolver = FindingEvidenceResolver(tmp_path, catalog)
    assert set(catalog.launch_candidates) == set(recipes)
    for recipe_id, recipe in recipes.items():
        assert catalog.launch_candidates[recipe_id].applicability == recipe.applicability
    for ref, finding in findings.items():
        resolved = resolver.finding_evidence(ref)
        assert resolved["finding"] == finding.model_dump(mode="json")
        recipe_id = finding.domain.recipe_id
        assert finding.claims[0].evidence_refs == [f"/launch_recipes/{recipe_id}/context_anchor"]
        assert resolved["records"][f"/launch_recipes/{recipe_id}"] == recipes[recipe_id].model_dump(mode="json")
