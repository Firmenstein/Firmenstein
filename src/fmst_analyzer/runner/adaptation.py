"""Validate runtime ownership proposals without rewriting upstream claims."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re

from .adaptation_schema import RuntimeUnitDefinition, RuntimeUnitProposal
from fmst_analyzer.synthesizer.intervention_generator.resolve import resolve_units
from fmst_analyzer.synthesizer.intervention_generator.shell import unit_module_name


def definition(unit) -> RuntimeUnitDefinition:
    return RuntimeUnitDefinition(**{key: getattr(unit, key) for key in RuntimeUnitDefinition.model_fields})


def validate_proposal(proposal: RuntimeUnitProposal, *, units: dict, active_id: str | None,
                      view, readable_roots: list[Path], attempt_path: Path, artifact_root: Path,
                      check_budget, runtime_artifact_roots: list[Path] | None = None) -> RuntimeUnitDefinition | None:
    if proposal.parent_adaptation_id != active_id:
        raise RuntimeError("Unit proposal has a stale parent_adaptation_id")
    if proposal.operation == "rollback" and active_id is None:
        raise RuntimeError("No active runtime adaptation to roll back")
    roots = [p.resolve() for p in readable_roots]
    runtime_roots = [root.resolve() for root in [artifact_root, *(runtime_artifact_roots or [])]]
    runtime_evidence = False
    for item in proposal.evidence:
        check_budget()
        path = Path(item.path)
        if not path.is_absolute():
            raise RuntimeError("Unit evidence requires absolute paths")
        path = path.resolve()
        if not any(path.is_relative_to(root) for root in roots) or not path.is_file():
            raise RuntimeError("Unit evidence is missing or outside Controller read-only roots")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError("Unit evidence exceeds 16 MiB; cite a bounded Controller artifact")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != item.sha256 or item.excerpt.encode() not in content:
            raise RuntimeError("Unit evidence hash/excerpt mismatch: " + str(path))
        runtime_evidence |= path == attempt_path.resolve() or any(
            path.is_relative_to(root) for root in runtime_roots)
    if not runtime_evidence:
        raise RuntimeError("Unit proposal needs current runtime or partial execution evidence")
    if proposal.operation == "rollback":
        return None
    unit = proposal.unit
    assert unit is not None
    previous = units.get(unit.unit_id)
    if previous is not None and (unit.strategy != previous.strategy or unit.anchors != previous.anchors):
        raise RuntimeError("Existing Unit revisions retain their strategy and anchors; propose a distinct owner for a distinct resource")
    if unit.strategy == "environment_setup":
        if previous is None:
            raise RuntimeError("Environment adaptation revises an existing owner; new environment owners require planning")
        if not any(not any(Path(item.path).resolve().is_relative_to(root) for root in runtime_roots)
                   and Path(item.path).resolve() != attempt_path.resolve() for item in proposal.evidence):
            raise RuntimeError("Environment Contract revision needs cited source evidence as well as the failed Controller attempt")
        return definition(previous)
    for other_id, other in units.items():
        if other.strategy != "environment_setup" and other_id != unit.unit_id and unit_module_name(other_id) == unit_module_name(unit.unit_id):
            raise RuntimeError("Unit module name collides with existing owner: " + other_id)
    if previous is None and not unit.contract.allowed_refinement_scope:
        raise RuntimeError("A new runtime owner needs explicit implementation scope before the Agent can implement it")
    for anchor in unit.anchors:
        if anchor.kind == "callsite" and previous is None:
            try:
                candidates = view.collect_api_callsites(anchor.api_name)
                fields = ("binary_name", "caller_ea", "snapshot_hash", "ctree_index", "source_ea", "line_number", "column_number")
                expected = (anchor.binary_name, anchor.function_ea, anchor.snapshot_hash, anchor.ctree_index,
                            anchor.source_ea, anchor.line_number, anchor.column_number)
                if not any(tuple(getattr(site, key) for key in fields) == expected for site in candidates):
                    raise RuntimeError("Runtime callsite identity is absent from the current semantic snapshot")
            except (ValueError, AttributeError) as error:
                raise RuntimeError("Cannot resolve runtime callsite semantic identity") from error
        if anchor.kind == "resource":
            path = PurePosixPath(anchor.value)
            if anchor.resource_kind != "path" or not path.is_absolute() or ".." in path.parts or path.as_posix() != anchor.value or "\x00" in anchor.value:
                raise RuntimeError("Runtime pseudo-file requires a normalized exact absolute guest path")
            if previous is None:
                match = re.fullmatch(r"evidence:(\d+)", anchor.source_ref)
                if not match or int(match[1]) >= len(proposal.evidence):
                    raise RuntimeError("New resource source_ref must bind to proposal evidence:N")
    proposed = resolve_units([unit], view)
    others = resolve_units([other for key, other in units.items()
                            if key != unit.unit_id and other.strategy != "environment_setup"], view)
    def keys(manifest):
        result = []
        for entry in manifest.entries:
            result.extend(("path", p) for p in entry.pseudo_file_paths)
            if entry.binary is not None and entry.offset is not None:
                result.append(("address", entry.binary, entry.offset))
        return result
    slugs = [entry.entry_slug for entry in proposed.entries if entry.entry_slug is not None]
    if len(set(slugs)) != len(slugs):
        raise RuntimeError("Runtime anchors collide in their generated adapter names")
    proposed_keys = keys(proposed)
    if len(set(proposed_keys)) != len(proposed_keys) or set(proposed_keys).intersection(keys(others)):
        raise RuntimeError("Runtime owner overlaps an existing or duplicate anchor")
    # Resolution proves address/path identity, not the proposed semantics.
    return definition(previous) if previous is not None else None


def snapshot_evidence(proposal: RuntimeUnitProposal, root: Path, *, check_budget) -> dict[str, str]:
    """Retain the exact source bytes so later report archival loses no citation."""
    snapshots = {}
    for item in proposal.evidence:
        check_budget()
        with Path(item.path).open("rb") as stream:
            content = stream.read(16 * 1024 * 1024 + 1)
        if len(content) > 16 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != item.sha256 or item.excerpt.encode() not in content:
            raise RuntimeError("Unit evidence changed before snapshot: " + item.path)
        relative = "evidence/" + item.sha256 + ".bin"
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        snapshots[item.path] = relative
    return snapshots
