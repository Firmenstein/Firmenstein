"""Read v2 publications as frozen inputs for explicit *new* validation only.

The seven-validator v2 format used the same tree identity v2 as today's v3.
This fixture does not upgrade files, execute archived code or permit strict
replay of a legacy success. New success must come from the current scenario
executor and gets its own v3 configuration ID.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Literal

from fmst_analyzer.runner.budget import ExecutionBudget
from fmst_analyzer.runner.identity import tree_sha256
from fmst_analyzer.runner.publication import SuccessfulConfiguration


class LegacyInputs(SuccessfulConfiguration):
    schema_version: Literal[2] = 2


LegacyInputs.model_rebuild()


_VALIDATORS = {"probe.py", "schema.py", "docker_sandbox.py", "supervision.py",
    "identity.py", "publication.py", "budget.py"}
_TREES = {"rootfs", "runtime", "evidence", "authored", "baseline", "sources"}


def load_legacy_inputs(path: Path, budget: ExecutionBudget) -> LegacyInputs:
    budget.check()
    raw = json.loads(path.read_text())
    manifest = LegacyInputs.model_validate(raw)
    if set(manifest.input_trees) != _TREES:
        raise ValueError("unexpected legacy frozen input trees")
    for name, expected in manifest.input_trees.items():
        directory = path.parent / name
        if directory.is_symlink() or not directory.is_dir() or tree_sha256(directory, budget) != expected:
            raise ValueError(f"legacy frozen identity mismatch: {name}")
    for relative in manifest.evidence_locations.values():
        candidate = PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts or candidate.parts[0] not in _TREES or not (path.parent / relative).exists():
            raise ValueError(f"invalid legacy evidence location: {relative}")
    if set(manifest.validation_code_sha256) != _VALIDATORS:
        raise ValueError("unexpected v2 validator source set")
    for name, expected in manifest.validation_code_sha256.items():
        budget.check()
        source = path.parent / "sources/validator" / name
        if source.is_symlink() or not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError(f"legacy validator source hash mismatch: {name}")
    attempt = manifest.attempt
    if raw["attempt"] != json.loads((path.parent / "evidence/attempt.json").read_text()):
        raise ValueError("legacy manifest and original attempt differ")
    if attempt.tree_identity_version != 2:
        raise ValueError("legacy attempt must use tree identity v2")
    if (attempt.outcome != "success" or attempt.scenario is None or attempt.scenario_result is None
            or attempt.scenario_result.status != "success"
            or manifest.input_trees["rootfs"] != attempt.rootfs_sha256
            or manifest.input_trees["runtime"] != attempt.harness_sha256):
        raise ValueError("legacy manifest no longer binds the recorded execution")
    if not manifest.executable_path.startswith("/"):
        raise ValueError("legacy guest executable must be absolute")
    target = (path.parent / "rootfs" / manifest.executable_path.lstrip("/")).resolve(strict=True)
    target.relative_to((path.parent / "rootfs").resolve())
    if hashlib.sha256(target.read_bytes()).hexdigest() != attempt.target_binary_sha256:
        raise ValueError("legacy target ELF identity differs")
    return manifest
