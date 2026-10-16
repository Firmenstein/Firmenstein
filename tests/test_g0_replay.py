"""Replay frozen boundary artifacts without firmware, SDKs, or Agents."""

import hashlib
import importlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError


FIXTURES = Path(__file__).parent / "fixtures" / "g0"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
ENTRIES = {item["path"]: item for item in MANIFEST["fixtures"]}
MIGRATED_MODELS = {
    "fmst_analyzer.runner.schema:RehostingResult",
    "fmst_analyzer.analysis.file_resolver.analyzer_schema:FileResourceReport",
    "fmst_analyzer.analysis.ipc_analyzer.schema:IPCAnalysisResult",
    "fmst_analyzer.analysis.ipc_analyzer.schema:IPCCallsiteReport",
    "fmst_analyzer.analysis.ipc_analyzer.schema:IPCChannelReport",
    "fmst_analyzer.analysis.network_analyzer.analyzer_schema:NetworkAnalysisResult",
    "fmst_analyzer.analysis.network_analyzer.analyzer_schema:NetworkInteractionReport",
    "fmst_analyzer.analysis.file_resolver.analyzer_schema:FileResolverResult",
    "fmst_analyzer.analysis.process_lifecycle.analyzer_schema:ProcessLifecycleAnalysisResult",
    "fmst_analyzer.analysis.process_lifecycle.analyzer_schema:ProcessEventAssessmentReport",
    "fmst_analyzer.analysis.init_launch.analyzer_schema:InitLaunchAnalysisResult",
    "fmst_analyzer.analysis.init_launch.analyzer_schema:LaunchRecipe",
    "fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.schema:PlanningEvidenceCatalog",
    "fmst_analyzer.synthesizer.intervention_plan_analyzer.schema:InterventionPlanResult",
    "fmst_analyzer.synthesizer.intervention_generator.schema:InterventionGenerationResult",
    "fmst_analyzer.synthesizer.intervention_generator.schema:UnitGenerationReport",
}


def _symbol(name):
    module, attribute = name.split(":")
    return getattr(importlib.import_module(module), attribute)


def _load(path):
    return _symbol(ENTRIES[path]["model"]).model_validate_json(
        (FIXTURES / path).read_text(encoding="utf-8")
    )


def _write_sources(root):
    for kind, relative in MANIFEST["source_paths"].items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((FIXTURES / f"full/{kind}.json").read_bytes())


@pytest.mark.parametrize("entry", MANIFEST["fixtures"], ids=ENTRIES)
def test_frozen_json_and_markdown(entry):
    payload = (FIXTURES / entry["path"]).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == entry["sha256"]
    raw = json.loads(payload)
    assert raw.get("schema_version") == entry["schema_version"]
    assert raw.get("phase") == entry["phase"]
    model_type = _symbol(entry["model"])
    if entry["model"] in MIGRATED_MODELS:
        # Frozen G0 bytes remain historical evidence. G2 deliberately rejects
        # their old schemas; current-schema replay lives in the G2 fixtures.
        if "markdown" in entry:
            markdown = (FIXTURES / entry["markdown"]).read_bytes()
            assert hashlib.sha256(markdown).hexdigest() == entry["markdown_sha256"]
        with pytest.raises(ValidationError):
            model_type.model_validate_json(payload)
        return
    if "expected_error" in entry:
        with pytest.raises(ValidationError, match=entry["expected_error"]):
            model_type.model_validate_json(payload)
        return

    model = model_type.model_validate_json(payload)
    assert model.model_dump(mode="json") == raw
    assert model_type.model_validate_json(model.model_dump_json()) == model
    if "renderer" in entry:
        expected = (FIXTURES / entry["markdown"]).read_text(encoding="utf-8")
        assert hashlib.sha256(expected.encode()).hexdigest() == entry["markdown_sha256"]
        if entry["renderer"] == "fmst_analyzer.analysis.file_resolver.reports:render_per_resource_report":
            # The domain record is unchanged, but G2 renders exact field labels.
            return
        if any(ENTRIES[path]["model"] in MIGRATED_MODELS for path in entry.get("renderer_inputs", [])):
            # Preserve the old renderer's output; current Catalog/Plan replay is
            # exercised against current source fixtures, not a silent migration.
            return
        inputs = [_load(path) for path in entry.get("renderer_inputs", [entry["path"]])]
        before = [item.model_dump_json() for item in inputs]
        render = _symbol(entry["renderer"])
        assert render(*inputs) == expected
        assert render(*inputs) == expected
        assert [item.model_dump_json() for item in inputs] == before


def test_historical_catalog_and_plan_preserve_overlap_and_source_identities(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
        PlanningEvidenceAssembler,
    )
    _write_sources(tmp_path)
    before = {path: path.read_bytes() for path in tmp_path.rglob("*.json")}
    with pytest.raises(ValueError, match="schema_version|planning_findings"):
        PlanningEvidenceAssembler(tmp_path).assemble()
    catalog = json.loads((FIXTURES / "pipeline/catalog.json").read_text())
    with pytest.raises(ValidationError):
        _load("pipeline/catalog.json")
    assert {path: path.read_bytes() for path in before} == before

    plan = json.loads((FIXTURES / "pipeline/plan.json").read_text())
    with pytest.raises(ValidationError):
        _load("pipeline/plan.json")
    assert plan["launch_choice"]["recipe_id"] in catalog["launch_candidates"]
    overlap = plan["clusters"]["cluster-nvram"]
    assert set(overlap["finding_refs"]) == {"file:file_dev_nvram", "process:process-callsite"}
    assert json.loads((FIXTURES / "full/file.json").read_text())["resources"]["file_dev_nvram"]["path_value"] == "/dev/nvram"
    historical_process = json.loads((FIXTURES / "full/process.json").read_text())
    assert historical_process["assessments"]["process-callsite"]["trigger_inputs"][0]["value"] == "/dev/nvram"
    accounted = {item["finding_ref"] for item in plan["scope_no_interventions"]}
    for cluster in plan["clusters"].values():
        accounted.update(cluster["finding_refs"])
    assert accounted == set(catalog["evidence_items"])
    report = json.loads((FIXTURES / "pipeline/unit.json").read_text())
    assert overlap["units"][report["unit"]["unit_id"]] == report["unit"]


@pytest.mark.parametrize("failure", ["missing", "static", "target", "schema"])
def test_catalog_rejects_incomplete_or_stale_g0_input(tmp_path, failure):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
        PlanningEvidenceAssembler,
    )

    _write_sources(tmp_path)
    path = tmp_path / MANIFEST["source_paths"]["file"]
    error = ValueError
    if failure == "missing":
        path = tmp_path / MANIFEST["source_paths"]["ipc"]
        path.unlink()
        error, message = FileNotFoundError, "required JSON artifact is missing"
    elif failure == "static":
        path.write_bytes((FIXTURES / "static/file.json").read_bytes())
        message = "schema_version|planning_findings"
    elif failure == "schema":
        path.write_bytes((FIXTURES / "legacy/file.json").read_bytes())
        message = "schema_version"
    else:
        path = tmp_path / MANIFEST["source_paths"]["init"]
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["target_identity"]["selected_rootfs_path"] = "usr/libexec/httpd"
        path.write_text(json.dumps(raw), encoding="utf-8")
        message = "schema_version|planning_findings"
    with pytest.raises(error, match=message):
        PlanningEvidenceAssembler(tmp_path).run()
    assert not (tmp_path / "intervention_planner_inputs").exists()


def test_generator_contract_digest_and_review_accounting_survive_replay():
    from fmst_analyzer.synthesizer.intervention_generator.generator import _contract_digest
    from fmst_analyzer.synthesizer.intervention_generator.review_schema import normalize_unit_review

    current = FIXTURES.parent / "g3_publication"
    report = _symbol(ENTRIES["pipeline/unit.json"]["model"]).model_validate_json(
        (current / "unit.json").read_bytes())
    assert report.generation.contract_digest == _contract_digest(report.unit)
    generation = _symbol(ENTRIES["pipeline/generator.json"]["model"]).model_validate_json(
        (current / "generator.json").read_bytes())
    assert generation.units == [report.generation]
    assert report.generation.review_history[-1] == _load("pipeline/reviewer.json")
    for review in report.generation.review_history:
        assert normalize_unit_review(review, len(report.unit.contract.operations))[1] is None
    # Current plans require the complete Contract and reject list-only input.
    old_unit = report.unit.model_dump(mode="json")
    old_unit.pop("contract")
    with pytest.raises(ValidationError):
        type(report.unit).model_validate(old_unit)
    bad_review = _load("pipeline/reviewer.json")
    bad_review.contract_reviews = []
    assert normalize_unit_review(bad_review, len(report.unit.contract.operations))[1]


@pytest.mark.parametrize("kind,analyzer,helper", [
    ("file", "FileResolver", "file_resolver"),
    ("network", "NetworkAnalyzer", "network_analyzer"),
    ("process", "ProcessLifecycleAnalyzer", "process_lifecycle"),
])
def test_analyzer_cache_miss_does_not_run_another_analyzer(tmp_path, monkeypatch, kind, analyzer, helper):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from fmst_analyzer.testing.pipeline_tester import PipelineTester

    module = importlib.import_module(f"fmst_analyzer.analysis.{helper}")
    if kind == "process":
        expected = module.ProcessLifecycleAnalysisResult(execution={"tasks": {}},
            schema_version=5, phase="static", root_binary="httpd",
            finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64},
            planning_findings={},
        )
    elif kind == "file":
        expected = module.FileResolverResult(execution={"tasks": {}},
            schema_version=12, phase="static", root_binary="httpd",
            finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={},
        )
    else:
        expected = module.NetworkAnalysisResult(execution={"tasks": {}},
            schema_version=11, phase="static", root_binary="httpd",
            finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={},
        )
    run = AsyncMock(return_value=expected)
    monkeypatch.setattr(getattr(module, analyzer), "run", run)
    tester = object.__new__(PipelineTester)
    tester.global_config = SimpleNamespace(
        workdir=tmp_path, agent_concurrency_limit=1,
        target_diagnostic_reports_dir=lambda: tmp_path,
    )
    tester.view = object()
    if kind in {"file", "network", "process"}:
        tester.fw_rootfs_path = tmp_path / "rootfs"
        tester.target_binary_path = tester.fw_rootfs_path / "usr/sbin/httpd"
        tester.target_binary_path.parent.mkdir(parents=True)
        tester.target_binary_path.write_bytes(b"test target")
    tester.ensure_analysis_view = AsyncMock()
    setattr(tester, f"_{helper}_result", {})
    for other in ("ipc", "file_resolver", "network_analyzer", "process_lifecycle", "init_launch"):
        if other != helper:
            monkeypatch.setattr(tester, f"ensure_{other}_result", AsyncMock(
                side_effect=AssertionError("implicit cross-analyzer execution")
            ))
    actual = asyncio.run(getattr(tester, f"ensure_{helper}_result")(phase="static"))
    assert actual == expected
    run.assert_awaited_once_with(tester.view, phase="static")


def test_long_failure_and_agent_evidence_are_not_silently_truncated():
    from fmst_analyzer.synthesizer.intervention_generator.reports import render_index
    from fmst_analyzer.runner.reports import render_index as runner_index
    from fmst_analyzer.testing.stages import format_fail_detail

    detail = "完整语义证据 " * 1800 + "END-OF-EVIDENCE"
    generation = _symbol(ENTRIES["pipeline/generator.json"]["model"]).model_validate_json(
        (FIXTURES.parent / "g3_publication/generator.json").read_bytes())
    generation.units[0].failure_reason = detail
    assert detail in render_index(generation)
    runner = _symbol(ENTRIES["pipeline/runner.json"]["model"])(
        target_binary="fixture", guest_arch="arm", selected_recipe_id=None,
        status="error", final_summary=detail)
    assert detail in runner_index(runner)
    assert detail in format_fail_detail("G0", detail)
