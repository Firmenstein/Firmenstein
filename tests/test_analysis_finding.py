"""G1 contract tests. Result integration itself belongs to each G2 Analyzer."""

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Literal, Self

import pytest
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, ValidationError, model_validator

from fmst_analyzer.analysis.base.analysis_finding import (
    AnalysisFinding,
    EvidenceRef,
    PlanningFindings,
    make_finding_ref,
    resolve_evidence_ref,
    validate_finding_references,
)
from fmst_analyzer.analysis.base.finding_reports import render_finding, render_planning_findings
from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json


FIXTURES = Path(__file__).parent / "fixtures" / "g1"


class FindingResultFixture(BaseModel):
    """Test-only embedding: G1 adds no parallel production Result/artifact."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = Field(description="Fixture Result version.")
    phase: Literal["static", "full"] = Field(description="Explicit producing phase.")
    planning_findings: PlanningFindings = Field(description="Required finding map; an explicit empty map is valid.")
    evidence: dict[str, JsonValue] = Field(description="Source facts/citations already persisted by the Analyzer.")

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        validate_finding_references(self.planning_findings, self.model_dump(mode="json"))
        return self


def _raw(case="full"):
    return json.loads((FIXTURES / f"{case}.json").read_text(encoding="utf-8"))


def _first(case="full"):
    return next(iter(_raw(case)["planning_findings"].values()))


@pytest.mark.parametrize("case", ["static", "full", "empty", "gap"])
def test_result_json_and_markdown_replay(case, tmp_path):
    digests = json.loads((FIXTURES / "manifest.json").read_text())["sha256"]
    for suffix in ("json", "md"):
        name = f"{case}.{suffix}"
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == digests[name]
    raw = _raw(case)
    result = FindingResultFixture.model_validate(raw)
    assert result.model_dump(mode="json") == raw
    target = tmp_path / "result.json"
    write_model_json(target, result)
    restored = load_model_json(target, FindingResultFixture)
    assert restored == result
    before = restored.model_dump_json()
    expected = (FIXTURES / f"{case}.md").read_text(encoding="utf-8")
    assert render_planning_findings(restored.planning_findings) == expected
    assert render_planning_findings(dict(reversed(list(restored.planning_findings.items())))) == expected
    assert restored.model_dump_json() == before


def test_identity_is_stable_across_enrichment_and_target_specific():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    static = FindingResultFixture.model_validate(_raw("static"))
    full = FindingResultFixture.model_validate(_raw("full"))
    assert set(static.planning_findings) == set(full.planning_findings)
    for ref, origin in manifest["origins"].items():
        args = dict(origin, **manifest["target"])
        assert make_finding_ref(**args) == ref
        for change in ({"target_path": "usr/libexec/httpd"}, {"target_sha256": "b" * 64}, {"source_id": origin["source_id"] + "-other"}):
            assert make_finding_ref(**(args | change)) != ref
    assert static.planning_findings != full.planning_findings


@pytest.mark.parametrize("changes", [
    {"target_path": "/usr/sbin/httpd"}, {"target_path": "../httpd"},
    {"target_path": "usr/./httpd"}, {"target_path": "usr//httpd"},
    {"target_path": r"C:\firmware\httpd"}, {"target_path": "C:/firmware/httpd"},
    {"target_path": "."}, {"target_sha256": "not-a-digest"},
    {"source_id": " "}, {"source_id": " resource"}, {"source": "invented"},
])
def test_identity_rejects_ambiguous_or_host_paths(changes):
    args = dict(source="file", target_path="usr/sbin/httpd", target_sha256="a" * 64, source_id="resource-nvram")
    with pytest.raises(ValueError):
        make_finding_ref(**(args | changes))


@pytest.mark.parametrize("field", ["schema_version", "phase", "planning_findings"])
def test_current_result_requires_explicit_fields(field):
    raw = _raw("empty")
    raw.pop(field)
    with pytest.raises(ValidationError, match=field):
        FindingResultFixture.model_validate(raw)


def test_old_result_is_rejected_without_compatibility_inference():
    raw = _raw("empty")
    raw["schema_version"] = 0
    with pytest.raises(ValidationError, match="schema_version"):
        FindingResultFixture.model_validate(raw)


def test_map_identity_and_source_discriminator_are_enforced():
    raw = _first()
    with pytest.raises(ValidationError, match="key must equal finding_ref"):
        TypeAdapter(PlanningFindings).validate_python({"arbitrary": raw})
    raw["finding_ref"] = raw["finding_ref"].replace(":file:", ":ipc:")
    with pytest.raises(ValidationError, match="domain kind"):
        AnalysisFinding.model_validate(raw)


def test_source_namespaces_do_not_alias_and_freeform_finding_ids_fail():
    args = dict(target_path="usr/sbin/httpd", target_sha256="a" * 64, source_id="same-source-id")
    assert len({make_finding_ref(source=source, **args) for source in ("file", "network", "ipc", "process", "init_launch")}) == 5
    class Source(str, Enum):
        FILE = "file"

    assert make_finding_ref(source=Source.FILE, **args) == make_finding_ref(source="file", **args)
    raw = _first()
    raw["finding_ref"] = "file:agent-chosen-label"
    with pytest.raises(ValidationError, match="finding_ref"):
        AnalysisFinding.model_validate(raw)


@pytest.mark.parametrize("field", ["anchors", "claims"])
def test_a_finding_requires_a_located_subject_and_semantic_content(field):
    raw = _first()
    if field == "anchors":
        raw["boundary"][field] = []
    else:
        raw[field] = []
    with pytest.raises(ValidationError, match=field):
        AnalysisFinding.model_validate(raw)


@pytest.mark.parametrize("kind", ["guarantee", "state", "fallback"])
def test_known_claim_requires_evidence_and_forbids_unknown_category(kind):
    raw = _first()
    claim = raw["claims"][0]
    claim.update(kind=kind, evidence_refs=[], unknown_kind=None)
    with pytest.raises(ValidationError, match="requires evidence_refs"):
        AnalysisFinding.model_validate(raw)
    claim.update(evidence_refs=["/evidence/code"], unknown_kind="semantics")
    with pytest.raises(ValidationError, match="unknown_kind"):
        AnalysisFinding.model_validate(raw)


@pytest.mark.parametrize("category", ["instance_data", "applicability", "semantics", "external_effects"])
def test_unknown_categories_are_explicit_without_fabricated_evidence(category):
    raw = _first("gap")
    raw["claims"][0]["unknown_kind"] = category
    finding = AnalysisFinding.model_validate(raw)
    assert finding.claims[0].evidence_refs == []
    raw["claims"][0]["unknown_kind"] = None
    with pytest.raises(ValidationError, match="unknown_kind"):
        AnalysisFinding.model_validate(raw)


@pytest.mark.parametrize("ref", ["", "#/evidence/code", "https://example.com/report", "/bad~escape", "/planning_findings", "/planning_findings/other"])
def test_invalid_or_self_referential_citations_are_rejected(ref):
    with pytest.raises(ValidationError):
        TypeAdapter(EvidenceRef).validate_python(ref)


def test_reference_resolution_handles_json_keys_and_arrays_without_io():
    document = {"a/b": {"~": [0, {"": False}, None]}, "01": "object key"}
    assert resolve_evidence_ref(document, "/a~1b/~0/0") == 0
    assert resolve_evidence_ref(document, "/a~1b/~0/1/") is False
    assert resolve_evidence_ref(document, "/a~1b/~0/2") is None
    assert resolve_evidence_ref(document, "/01") == "object key"
    for ref in ["/missing", "/a~1b/~0/01", "/a~1b/~0/-1", "/a~1b/~0/3", "/01/child"]:
        with pytest.raises(ValueError, match="unresolved evidence ref"):
            resolve_evidence_ref(document, ref)


@pytest.mark.parametrize("place", ["anchor", "reachability", "coverage", "claim", "preparation"])
def test_all_reference_surfaces_reject_dangling_evidence(place):
    raw = _raw()
    finding = next(iter(raw["planning_findings"].values()))
    if place == "anchor":
        finding["boundary"]["anchors"][0]["ref"] = "/evidence/missing"
    elif place == "claim":
        finding["claims"][0]["evidence_refs"] = ["/evidence/missing"]
    elif place == "preparation":
        finding = next(f for f in raw["planning_findings"].values() if f["domain"] and f["domain"]["kind"] == "init_launch")
        finding["domain"]["preparation_refs"] = ["/evidence/missing"]
    else:
        finding["boundary"][f"{place}_refs"] = ["/evidence/missing"]
    with pytest.raises(ValidationError, match="unresolved evidence ref"):
        FindingResultFixture.model_validate(raw)


@pytest.mark.parametrize("field", ["summary", "strategy", "domain"])
def test_no_blank_summary_speculative_decision_or_untyped_domain_payload(field):
    raw = _first()
    if field == "summary":
        raw[field] = "\n  "
    elif field == "strategy":
        raw[field] = "function_stub"
    else:
        raw[field]["full_report"] = {"arbitrary": "payload"}
    with pytest.raises(ValidationError):
        AnalysisFinding.model_validate(raw)


def test_every_schema_field_exposes_its_description():
    schema = AnalysisFinding.model_json_schema()
    for model in [schema, *schema.get("$defs", {}).values()]:
        assert model.get("additionalProperties") is False
        for field in model["properties"].values():
            assert field.get("description")


def test_persisted_result_rejects_a_reference_whose_source_was_removed(tmp_path):
    target = tmp_path / "result.json"
    raw = _raw()
    del raw["evidence"]["nvram_code"]
    target.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="unresolved evidence ref.*nvram_code"):
        load_model_json(target, FindingResultFixture)


def test_rendering_contains_every_nested_field_and_scalar():
    def check(value, rendered):
        if isinstance(value, dict):
            for key, item in value.items():
                assert f"- {key}:" in rendered
                check(item, rendered)
        elif isinstance(value, list):
            for item in value:
                check(item, rendered)
        else:
            assert json.dumps(value, ensure_ascii=False) in rendered

    for finding in FindingResultFixture.model_validate(_raw()).planning_findings.values():
        check(finding.model_dump(mode="json"), render_finding(finding))


def test_rendering_preserves_long_text_newlines_and_backticks():
    raw = _first()
    text = "caller state `x` and ``` code\n" * 500 + "完整结尾"
    raw["summary"] = text
    raw["claims"][0]["statement"] = text
    finding = AnalysisFinding.model_validate(raw)
    rendered = render_finding(finding)
    assert rendered.count(json.dumps(text, ensure_ascii=False)) == 2
    assert "````" in rendered
