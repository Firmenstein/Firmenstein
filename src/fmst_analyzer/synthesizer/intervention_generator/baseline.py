"""Immutable authored-source baselines for Runner refinement.

Cargo outputs are reproducible caches and are intentionally excluded. The
baseline identity binds Intervention/Test trees, Environment, and publication
input identity. Source, manifest, test, permission or input changes produce a
new immutable identity. Incomplete candidates can be snapshotted, not executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fmst_basic.utils.archive_paths import resolve_archived_path


_SCHEMA_VERSION = 4


@dataclass(frozen=True)
class GenerationBaseline:
    baseline_id: str
    intervention_sha256: str | None
    test_harness_sha256: str | None
    root: Path
    environment_sha256: str | None = None
    input_identity: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GenerationWorkspace:
    """Disposable authored-source copy used by one Runner session."""

    root: Path
    intervention_root: Path
    test_harness_root: Path | None
    environment_script: Path | None = None


def _authored_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    files = []
    for path in root.rglob("*"):
        if path.relative_to(root).parts[0] == "target":
            continue
        if path.is_symlink():
            raise RuntimeError(f"authored artifact must not be a symlink: {path}")
        if path.is_file():
            files.append(path)
    return sorted(files)


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in _authored_files(root):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_mode & 0o7777).encode("ascii"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _copy_authored_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for source_path in _authored_files(source):
        relative = source_path.relative_to(source)
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)


def _restore_authored_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for child in list(destination.iterdir()):
        if child.name == "target":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for source_path in _authored_files(source):
        relative = source_path.relative_to(source)
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        # copyfile gives restored inputs a fresh mtime, forcing Cargo to
        # revalidate any retained target/ fingerprint against their content.
        shutil.copyfile(source_path, destination_path)
        shutil.copymode(source_path, destination_path)


def _manifest_path(root: Path) -> Path:
    return root / "baseline_manifest.json"


def _baseline_identity(intervention_hash, test_hash, environment_hash, input_identity) -> str:
    payload = {"schema_version": _SCHEMA_VERSION,
               "intervention": intervention_hash, "test_harness": test_hash,
               "environment": environment_hash, "input_identity": input_identity}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_generation_baseline(root: Path) -> GenerationBaseline:
    """Verify an immutable publication by content, never by the current pointer."""
    root = resolve_archived_path(Path(root))
    payload = json.loads(_manifest_path(root).read_text(encoding="utf-8"))
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise RuntimeError(f"unsupported Generator baseline schema: {root}")
    baseline = GenerationBaseline(
        baseline_id=str(payload["baseline_id"]),
        intervention_sha256=payload["intervention_sha256"],
        test_harness_sha256=(
            str(payload["test_harness_sha256"])
            if payload.get("test_harness_sha256") is not None
            else None
        ),
        root=root.resolve(),
        environment_sha256=payload["environment_sha256"],
        input_identity=payload["input_identity"],
    )
    if baseline.baseline_id != root.name:
        raise RuntimeError(f"Generator baseline directory identity mismatch: {root}")
    actual_intervention_hash = _tree_sha256(root / "intervention") if (root / "intervention").is_dir() else None
    if actual_intervention_hash != baseline.intervention_sha256:
        raise RuntimeError(f"immutable Intervention baseline was modified: {root}")
    test_source = root / "test_harness"
    actual_test_hash = _tree_sha256(test_source) if test_source.is_dir() else None
    if actual_test_hash != baseline.test_harness_sha256:
        raise RuntimeError(f"immutable Test-Harness baseline was modified: {root}")
    environment = root / "environment"
    actual_environment_hash = _tree_sha256(environment) if environment.is_dir() else None
    if actual_environment_hash != baseline.environment_sha256:
        raise RuntimeError(f"immutable Environment baseline was modified: {root}")
    if _baseline_identity(actual_intervention_hash, actual_test_hash, actual_environment_hash,
                          baseline.input_identity) != baseline.baseline_id:
        raise RuntimeError(f"Generator baseline content identity mismatch: {root}")
    return baseline


def create_generation_baseline(
    *,
    workdir: Path,
    target_binary: str,
    intervention_root: Path | None,
    test_root: Path | None,
    environment_script: Path | None = None,
    input_identity: dict[str, str] | None = None,
) -> GenerationBaseline:
    """Snapshot complete or failed candidates; missing crates are not executable.

    Source/test trees include manifest/anchors and exclude only Cargo outputs.
    Environment-only and incomplete candidates retain exact content identity.
    """
    intervention_root = Path(intervention_root).resolve() if intervention_root else None
    test_root = Path(test_root).resolve() if test_root is not None else None
    environment_script = Path(environment_script) if environment_script else None
    input_identity = dict(input_identity or {})
    intervention_hash = _tree_sha256(intervention_root) if intervention_root and intervention_root.is_dir() else None
    test_hash = (
        _tree_sha256(test_root)
        if test_root is not None and test_root.is_dir()
        else None
    )
    target_root = Path(workdir).resolve() / "intervention_baselines" / target_binary
    target_root.mkdir(parents=True, exist_ok=True)
    temporary = target_root / f".tmp-{uuid.uuid4().hex}"
    temporary.mkdir()
    try:
        if intervention_hash is not None:
            _copy_authored_tree(intervention_root, temporary / "intervention")
        if test_hash is not None:
            _copy_authored_tree(test_root, temporary / "test_harness")
        environment_hash = None
        if environment_script and environment_script.is_file():
            if environment_script.is_symlink():
                raise RuntimeError(f"Environment script must not be a symlink: {environment_script}")
            (temporary / "environment").mkdir()
            shutil.copy2(environment_script, temporary / "environment" / "setup_rootfs.py")
            environment_hash = _tree_sha256(temporary / "environment")
        identity = _baseline_identity(intervention_hash, test_hash, environment_hash, input_identity)
        destination = target_root / identity
        if not destination.exists():
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "baseline_id": identity,
                "intervention_sha256": intervention_hash,
                "test_harness_sha256": test_hash,
                "environment_sha256": environment_hash,
                "input_identity": input_identity,
            }
            _manifest_path(temporary).write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
            os.replace(temporary, destination)
        baseline = load_generation_baseline(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)

    pointer = target_root / "current.json"
    temporary_pointer = pointer.with_suffix(".json.tmp")
    temporary_pointer.write_text(
        json.dumps({
            "schema_version": _SCHEMA_VERSION,
            "baseline_id": baseline.baseline_id,
        }, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary_pointer, pointer)
    return baseline


def restore_generation_baseline(
    baseline: GenerationBaseline,
    *,
    intervention_root: Path,
    test_root: Path | None,
) -> None:
    """Restore authored sources while retaining only reproducible Cargo caches."""
    verified = load_generation_baseline(baseline.root)
    if verified != baseline:
        raise RuntimeError(f"Generator baseline identity changed: {baseline.root}")
    _restore_authored_tree(baseline.root / "intervention", intervention_root)
    if baseline.test_harness_sha256 is not None:
        if test_root is None:
            raise RuntimeError("Generator baseline includes tests but no test root was supplied")
        _restore_authored_tree(baseline.root / "test_harness", test_root)


def materialize_generation_workspace(
    baseline: GenerationBaseline,
    *,
    workdir: Path,
    target_binary: str,
    project_src: Path,
) -> GenerationWorkspace:
    """Create a clean Runner workspace without modifying Generator outputs.

    Generated Cargo manifests use repository-relative dependencies.  The
    workspace-level ``src`` symlink preserves those paths while the authored
    Intervention and Test-Harness trees remain isolated from their immutable
    baseline and from the Generator's published crates.
    """
    verified = load_generation_baseline(baseline.root)
    if verified != baseline:
        raise RuntimeError(f"Generator baseline identity changed: {baseline.root}")

    workspace_root = Path(workdir).resolve() / "runner_workspaces"
    source_link = workspace_root / "src"
    project_src = Path(project_src).resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    if source_link.is_symlink():
        if source_link.resolve() != project_src:
            raise RuntimeError(
                f"Runner workspace src link points outside this checkout: {source_link}"
            )
    elif source_link.exists():
        raise RuntimeError(f"Runner workspace src path is not a symlink: {source_link}")
    else:
        source_link.symlink_to(project_src, target_is_directory=True)

    root = workspace_root / target_binary / f"{baseline.baseline_id}-{uuid.uuid4().hex}"
    intervention_root = root / "interventions" / target_binary
    test_root = (
        root / "test_harnesses" / target_binary
        if baseline.test_harness_sha256 is not None
        else None
    )
    restore_generation_baseline(
        baseline,
        intervention_root=intervention_root,
        test_root=test_root,
    )
    environment_script = None
    if baseline.environment_sha256 is not None:
        _copy_authored_tree(baseline.root / "environment", root / "environment")
        environment_script = root / "environment" / "setup_rootfs.py"
    return GenerationWorkspace(
        root=root,
        intervention_root=intervention_root,
        test_harness_root=test_root,
        environment_script=environment_script,
    )


__all__ = [
    "GenerationBaseline",
    "GenerationWorkspace",
    "create_generation_baseline",
    "load_generation_baseline",
    "materialize_generation_workspace",
    "restore_generation_baseline",
]
