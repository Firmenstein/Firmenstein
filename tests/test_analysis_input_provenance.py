"""Changes outside the target ELF must invalidate Analyzer/Planner inputs."""
import asyncio
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fmst_analyzer.analysis.base import input_provenance as provenance
from fmst_analyzer.analysis.base.finding_binding import FindingTarget
from fmst_analyzer.analysis.file_resolver import FileResolverResult
from fmst_analyzer.testing.pipeline_tester import PipelineTester


def test_file_digest_does_not_require_python_311_hashlib_helper(tmp_path, monkeypatch):
    import hashlib

    path = tmp_path / "source.bin"
    payload = b"portable input receipt\0" * 1000
    path.write_bytes(payload)
    monkeypatch.delattr(hashlib, "file_digest", raising=False)
    assert provenance.file_digest(path) == hashlib.sha256(payload).hexdigest()


def _published(tmp_path):
    rootfs = tmp_path / "rootfs"
    target = rootfs / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"portable target")
    (rootfs / "startup.sh").write_text("httpd -L\n")
    (rootfs / "dependency").write_bytes(b"library semantics v1")
    reports = tmp_path / "work/reports"
    config = SimpleNamespace(workdir=tmp_path / "work", fw_rootfs_path=rootfs, agent_concurrency_limit=1,
        diagnosis_model="synthetic-model", target_diagnostic_reports_dir=lambda: reports)
    result = FileResolverResult(schema_version=12, phase="static", execution={"tasks": {}},
        finding_target=FindingTarget.from_file(rootfs, target), root_binary="httpd", planning_findings={})
    path = reports / provenance.ANALYZER_FILES["file"]
    path.parent.mkdir(parents=True)
    path.write_text(result.model_dump_json())
    inputs = provenance.capture_inputs(config, "file", "static", target)
    provenance.publish_receipt(path, result, inputs)
    return config, target, result, path


@pytest.mark.parametrize("change", ["startup", "library", "settings", "implementation", "receipt_missing", "result_content"])
def test_cache_rejects_changed_inputs_or_unbound_publication(tmp_path, monkeypatch, change):
    config, target, result, path = _published(tmp_path)
    assert provenance.cache_matches_inputs(config, "file", "static", target, result)
    if change == "startup":
        (config.fw_rootfs_path / "startup.sh").write_text("httpd -W\n")
    elif change == "library":
        (config.fw_rootfs_path / "dependency").write_bytes(b"library semantics v2")
    elif change == "settings":
        config.diagnosis_model = "different-model"
    elif change == "implementation":
        monkeypatch.setattr(provenance, "implementation_digest", lambda _: "f" * 64)
    elif change == "receipt_missing":
        (path.parent / "input_provenance.json").unlink()
    else:
        path.write_text(path.read_text() + "\n")
    assert not provenance.cache_matches_inputs(config, "file", "static", target, result)


def test_inputs_are_portable_across_host_directories(tmp_path):
    config, target, result, path = _published(tmp_path)
    original = provenance.capture_inputs(config, "file", "static", target)
    copied = tmp_path / "relocated"
    shutil.copytree(config.fw_rootfs_path, copied, symlinks=True)
    relocated = provenance.capture_inputs(config, "file", "static", copied / "usr/sbin/httpd", rootfs=copied)
    assert original == relocated
    assert str(tmp_path) not in original.model_dump_json()


def test_memory_cache_does_not_hide_changed_rootfs_or_trigger_other_analyzers(tmp_path, monkeypatch):
    config, target, result, path = _published(tmp_path)
    tester = object.__new__(PipelineTester)
    tester.global_config = config
    tester.fw_rootfs_path = config.fw_rootfs_path
    tester.target_binary_path = target
    tester._file_resolver_result = {"static": result}
    tester.ensure_analysis_view = AsyncMock()
    tester.view = object()
    assert asyncio.run(tester.ensure_file_resolver_result("static")) == result
    tester.ensure_analysis_view.assert_not_awaited()
    (config.fw_rootfs_path / "startup.sh").write_text("different launch\n")
    run = AsyncMock(return_value=result)
    monkeypatch.setattr("fmst_analyzer.analysis.file_resolver.FileResolver.run", run)
    asyncio.run(tester.ensure_file_resolver_result("static"))
    run.assert_awaited_once_with(tester.view, phase="static")
    tester.ensure_analysis_view.assert_awaited_once()


def test_catalog_rejects_publications_from_different_rootfs_versions(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _write_sources
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler
    _write_sources(tmp_path)
    path = tmp_path / "network_reports/input_provenance.json"
    receipt = json.loads(path.read_text())
    receipt["inputs"]["rootfs_sha256"] = "f" * 64
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="different rootfs"):
        PlanningEvidenceAssembler(tmp_path).assemble()


@pytest.mark.parametrize("stage", provenance.ANALYZER_FILES)
def test_catalog_rejects_receipt_for_different_target_path_with_same_bytes(tmp_path, stage):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _write_sources
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler

    _write_sources(tmp_path)
    path = (tmp_path / provenance.ANALYZER_FILES[stage]).parent / "input_provenance.json"
    receipt = json.loads(path.read_text())
    # Identical ELF bytes can be installed at different guest paths. Their
    # launch context is not interchangeable, even though the SHA matches.
    receipt["inputs"]["target_path"] = "usr/libexec/httpd"
    path.write_text(json.dumps(receipt))

    with pytest.raises(ValueError, match="receipt identity disagrees"):
        PlanningEvidenceAssembler(tmp_path).assemble()


def test_catalog_admits_original_producer_but_rejects_changed_firmware(tmp_path, monkeypatch):
    import hashlib
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests import test_catalog as fixtures
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler
    rootfs = tmp_path / "rootfs"
    target = rootfs / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"portable catalog target")
    (rootfs / "startup.sh").write_text("supported direct command")
    monkeypatch.setattr(fixtures, "TARGET_SHA", hashlib.sha256(target.read_bytes()).hexdigest())
    monkeypatch.setattr(fixtures, "FIRMWARE_SHA", provenance.rootfs_digest(rootfs))
    reports = tmp_path / "reports"
    fixtures._write_sources(reports)
    before = {p: p.read_bytes() for p in reports.rglob("*.json")}
    config = SimpleNamespace(fw_rootfs_path=rootfs, diagnosis_model="different-from-producer", planner_model="new-planner")
    catalog = PlanningEvidenceAssembler(reports, global_config=config).assemble()
    assert catalog.target_identity.executable_sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert {p: p.read_bytes() for p in before} == before
    (rootfs / "startup.sh").write_text("changed firmware premise")
    with pytest.raises(ValueError, match="firmware differs"):
        PlanningEvidenceAssembler(reports, global_config=config).assemble()
