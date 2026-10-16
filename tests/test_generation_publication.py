"""Publish/consume content identity, including failed and Environment-only candidates."""
from pathlib import Path

import pytest
from pydantic import ValidationError

from fmst_analyzer.analysis.base.report_io import model_content_sha256
from fmst_analyzer.synthesizer.intervention_generator.baseline import materialize_generation_workspace
from fmst_analyzer.synthesizer.intervention_generator.environment import EnvironmentGenerationResult
from fmst_analyzer.synthesizer.intervention_generator.publication import validate_generation_publication
from fmst_analyzer.synthesizer.intervention_generator.reports import persist_generation, load_persisted_intervention_generation
from fmst_analyzer.synthesizer.intervention_generator.schema import InterventionGenerationResult, UnitGenerationResult
from fmst_analyzer.synthesizer.intervention_generator.tests.test_environment_generator import _plan


def publish(tmp_path, *, failed=False, missing=False):
    plan = _plan()
    script = tmp_path / "env" / "setup_rootfs.py"
    script.parent.mkdir()
    if not missing:
        script.write_text("return\n" if failed else "print('prepare')\n")
    crate = tmp_path / "candidate"
    (crate / "src").mkdir(parents=True)
    for name in ("Cargo.toml", "manifest.json", "src/logic.rs"):
        (crate / name).write_text("candidate content")
    test_root = tmp_path / "tests"
    (test_root / "tests/unit_test").mkdir(parents=True)
    (test_root / "tests/unit_test/main.rs").write_text("test candidate")
    result = InterventionGenerationResult(
        plan_digest=model_content_sha256(plan), target_binary="service", arch="arm",
        total_units=2, ok_count=0 if failed else 2,
        not_ready_count=2 if failed else 0, skipped_count=0,
        units=[UnitGenerationResult(unit_id=key, report_stem=key,
                strategy="environment_setup", status="generation_failed" if failed else "ok",
                generated_files=[str(script)], failure_reason="syntax error" if failed else None)
               for key in plan.units],
        intervention_crate_path=str(crate), test_crate_path=str(test_root),
        cargo_build_status="not_run", cargo_test_status="not_run",
        environment=EnvironmentGenerationResult(status="unable" if failed else "completed",
                     unit_ids=list(plan.units), script_path=str(script), reason="syntax error" if failed else "ready"),
    )
    result = persist_generation(tmp_path / "reports", result, plan)
    return plan, result


@pytest.mark.parametrize("changed", ["env/setup_rootfs.py", "candidate/src/logic.rs",
                                       "candidate/manifest.json", "candidate/Cargo.toml",
                                       "tests/tests/unit_test/main.rs", "candidate/extra.rs"])
def test_published_sources_and_inventory_cannot_change(tmp_path, changed):
    plan, result = publish(tmp_path)
    baseline = validate_generation_publication(result, plan)
    (tmp_path / changed).write_text("modified")
    with pytest.raises(ValueError, match="content or inventory changed"):
        load_persisted_intervention_generation(tmp_path / "reports", plan, require_complete=True)
    assert (baseline.root / "environment/setup_rootfs.py").read_text() == "print('prepare')\n"


def test_metadata_snapshot_and_contract_are_bound(tmp_path):
    plan, result = publish(tmp_path)
    changed = result.model_copy(deep=True)
    changed.units[0].contract_digest = "1" * 64
    with pytest.raises(ValueError, match="metadata differs"):
        validate_generation_publication(changed, plan)
    baseline = validate_generation_publication(result, plan)
    (baseline.root / "intervention/manifest.json").write_text("tampered")
    with pytest.raises(RuntimeError, match="baseline was modified"):
        validate_generation_publication(result, plan)


@pytest.mark.parametrize("missing", [False, True])
def test_failed_candidate_is_preserved_without_becoming_ready(tmp_path, missing):
    plan, result = publish(tmp_path, failed=True, missing=missing)
    loaded = load_persisted_intervention_generation(tmp_path / "reports", plan, require_complete=True)
    assert loaded == result
    assert loaded.not_ready_count == 2
    assert all(unit.status == "generation_failed" for unit in loaded.units)
    baseline = validate_generation_publication(result, plan)
    if missing:
        assert result.publication.missing_files == [str(tmp_path / "env/setup_rootfs.py")]
    else:
        assert (baseline.root / "environment/setup_rootfs.py").read_text() == "return\n"


def test_environment_only_workspaces_are_independent(tmp_path):
    plan, result = publish(tmp_path)
    # Publish a separate Environment-only candidate; old receipt stays immutable.
    result.intervention_crate_path = result.test_crate_path = None
    result = persist_generation(tmp_path / "reports", result, plan)
    baseline = validate_generation_publication(result, plan)
    assert baseline.intervention_sha256 is None
    project_src = tmp_path / "checkout/src"
    project_src.mkdir(parents=True)
    workspaces = [materialize_generation_workspace(baseline, workdir=tmp_path,
                 target_binary="service", project_src=project_src) for _ in range(2)]
    assert workspaces[0].root != workspaces[1].root
    workspaces[0].environment_script.write_text("changed")
    assert workspaces[1].environment_script.read_text() == "print('prepare')\n"
    assert (baseline.root / "environment/setup_rootfs.py").read_text() == "print('prepare')\n"


def test_schema_16_is_not_accepted_as_content_bound(tmp_path):
    _, result = publish(tmp_path)
    payload = result.model_dump()
    payload["schema_version"] = 16
    with pytest.raises(ValidationError):
        InterventionGenerationResult.model_validate(payload)


def test_relocated_published_candidate_loads_without_rewriting_source_identity(tmp_path, monkeypatch):
    import shutil
    import fmst_analyzer.synthesizer.intervention_generator.baseline as baseline_module
    import fmst_analyzer.synthesizer.intervention_generator.publication as publication_module
    import fmst_analyzer.synthesizer.intervention_generator.reports as reports_module
    original = tmp_path / 'before'
    original.mkdir()
    plan, result = publish(original)
    moved = tmp_path / 'after'
    shutil.move(original, moved)
    def resolve(path):
        try: return moved / path.relative_to(original)
        except ValueError: return path
    for module in (baseline_module, publication_module, reports_module):
        monkeypatch.setattr(module, 'resolve_archived_path', resolve)
    loaded = load_persisted_intervention_generation(moved / 'reports', plan, require_complete=True)
    assert loaded == result
    assert loaded.units[0].generated_files[0].startswith(str(original))
    # Resolving paths never excuses changed bytes.
    (moved / 'env/setup_rootfs.py').write_text('changed')
    with pytest.raises(ValueError, match='content or inventory changed'):
        load_persisted_intervention_generation(moved / 'reports', plan, require_complete=True)
