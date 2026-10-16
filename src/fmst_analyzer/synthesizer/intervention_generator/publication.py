"""Bind a candidate's complete authored file set and input to its publication."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fmst_analyzer.analysis.base.report_io import model_content_sha256
from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import build_planning_context
from .baseline import (
    _authored_files,
    create_generation_baseline,
    load_generation_baseline,
    resolve_archived_path,
)
from .schema import GenerationPublication, InterventionGenerationResult, ImplementationContextChange


def contract_digest(unit) -> str:
    payload = unit.contract.model_dump(mode="json") if unit.contract else {}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _file_hash(path: Path) -> str:
    if path.is_symlink():
        raise ValueError(f"published authored file must not be a symlink: {path}")
    return hashlib.sha256(str(path.stat().st_mode & 0o7777).encode() + b"\0" + path.read_bytes()).hexdigest()


def _roots(result):
    return {name: resolve_archived_path(Path(value)) for name, value in (
        ("intervention", result.intervention_crate_path),
        ("test_harness", result.test_crate_path),
    ) if value is not None}


def _files(result, snapshot=None):
    """Map published absolute paths to live files or their immutable copies."""
    files = {}
    for name, source in _roots(result).items():
        source_value = Path(
            result.intervention_crate_path
            if name == "intervention" else result.test_crate_path
        )
        root = source if snapshot is None else snapshot / name
        for path in _authored_files(root):
            # Keep the publication's original path spelling in the identity
            # map while reading a relocated counterpart from disk.
            files[str(source_value / path.relative_to(root))] = path
    if result.environment.script_path:
        original_value = Path(result.environment.script_path)
        original = resolve_archived_path(original_value)
        path = original if snapshot is None else snapshot / "environment" / "setup_rootfs.py"
        if path.is_file():
            files[str(original_value)] = path
    return files


def _input_identity(result, plan, artifact_hashes, missing):
    candidate = result.model_copy(update={"publication": None})
    return {
        "plan_digest": model_content_sha256(plan),
        "candidate_digest": model_content_sha256(candidate),
        "file_index_digest": hashlib.sha256(json.dumps(
            {"files": artifact_hashes, "missing": missing}, sort_keys=True,
            separators=(",", ":"),
        ).encode()).hexdigest(),
        **{f"contract:{key}": contract_digest(unit) for key, unit in plan.units.items()},
    }


def bind_generation_publication(result: InterventionGenerationResult, plan, workdir: Path,
                                *, runtime_workspace: Path | None = None):
    """Snapshot failed as well as successful candidates before publishing JSON."""
    planned = plan.planning_context.implementation_sources
    observed = build_planning_context(runtime_workspace).implementation_sources
    result.implementation_context_changes = {
        key: ImplementationContextChange(
            planned_sha256=planned[key].file_sha256 if key in planned else None,
            observed_sha256=observed[key].file_sha256 if key in observed else None,
        ) for key in sorted(set(planned) | set(observed)) if planned.get(key) != observed.get(key)
    }
    if len(result.units) != len(plan.units) or {u.unit_id for u in result.units} != set(plan.units):
        raise ValueError("Generation must account for every Plan Unit exactly once")
    for unit in result.units:
        expected = contract_digest(plan.units[unit.unit_id])
        if unit.contract_digest and unit.contract_digest != expected:
            raise ValueError(f"Generation Unit contract digest differs: {unit.unit_id}")
        unit.contract_digest = expected
    if (result.total_units != len(result.units)
        or result.ok_count != sum(u.status == "ok" for u in result.units)
        or result.skipped_count != sum(u.status == "skipped" for u in result.units)
        or result.not_ready_count != sum(u.status not in {"ok", "skipped"} for u in result.units)):
        raise ValueError("Generation Unit counters differ from recorded statuses")
    files = _files(result)
    missing = []
    roots = list(_roots(result).values())
    environment_path = (
        resolve_archived_path(Path(result.environment.script_path))
        if result.environment.script_path else None
    )
    for unit in result.units:
        for value in unit.generated_files:
            path = resolve_archived_path(Path(value))
            if path != environment_path and not any(path.is_relative_to(root) for root in roots):
                raise ValueError(f"generated file is outside candidate roots: {value}")
            if str(path) not in files:
                missing.append(str(path))
    missing = sorted(set(missing))
    hashes = {name: _file_hash(path) for name, path in files.items()}
    baseline = create_generation_baseline(
        workdir=workdir, target_binary=result.target_binary,
        intervention_root=Path(result.intervention_crate_path) if result.intervention_crate_path else None,
        test_root=Path(result.test_crate_path) if result.test_crate_path else None,
        environment_script=Path(result.environment.script_path) if result.environment.script_path else None,
        input_identity=_input_identity(result, plan, hashes, missing),
    )
    result.publication = GenerationPublication(
        baseline_id=baseline.baseline_id, baseline_path=str(baseline.root),
        artifact_hashes=hashes, missing_files=missing,
    )
    validate_generation_publication(result, plan)
    return baseline


def validate_generation_publication(result, plan):
    """Reject changed files, metadata or snapshots instead of resnapshotting them."""
    publication = result.publication
    if publication is None:
        raise ValueError("Generation publication receipt is missing")
    baseline = load_generation_baseline(Path(publication.baseline_path))
    if baseline.baseline_id != publication.baseline_id:
        raise ValueError("Generation publication baseline identity differs")
    if baseline.input_identity != _input_identity(result, plan, publication.artifact_hashes, publication.missing_files):
        raise ValueError("Generation publication input or candidate metadata differs")
    for snapshot in (None, baseline.root):
        hashes = {name: _file_hash(path) for name, path in _files(result, snapshot).items()}
        if hashes != publication.artifact_hashes:
            raise ValueError("Generation published authored file content or inventory changed")
    if any(resolve_archived_path(Path(path)).exists() for path in publication.missing_files):
        raise ValueError("Generation previously missing file appeared after publication")
    return baseline
