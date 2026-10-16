"""Content-bound runtime launch proposals without rewriting upstream sources."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from .schema import RuntimeLaunchRecord


def admit_launch_proposal(decision, *, target_identity, rootfs: Path, readable_roots: list[Path], check_budget) -> RuntimeLaunchRecord:
    proposal = decision.launch_proposal
    if proposal is None:
        raise RuntimeError("No selected launch recipe: submit a source-backed launch_proposal for the selected ELF, and investigate unresolved launch dependencies.")
    expected = "/" + target_identity.selected_rootfs_path.lstrip("/")
    if proposal.executable_path != expected or ".." in PurePosixPath(expected).parts:
        raise RuntimeError("launch_proposal must retain the Controller-selected target path")
    if (proposal.args, proposal.working_directory, proposal.environment) != (
        decision.guest_args, decision.guest_working_directory, decision.guest_environment
    ):
        raise RuntimeError("launch_proposal argv/cwd/env differ from the proposed execution")
    selected = (rootfs / expected.lstrip("/")).resolve()
    if not selected.is_relative_to(rootfs.resolve()) or not selected.is_file():
        raise RuntimeError("selected launch ELF is missing or escapes the firmware rootfs")
    check_budget()
    digest = hashlib.sha256()
    with selected.open("rb") as stream:
        magic = stream.read(4)
        digest.update(magic)
        while data := stream.read(1024 * 1024):
            check_budget()
            digest.update(data)
    digest = digest.hexdigest()
    if magic != b"\x7fELF" or digest != target_identity.executable_sha256:
        raise RuntimeError("selected launch ELF content does not match Catalog identity")
    roots = [p.resolve() for p in readable_roots]
    for item in proposal.evidence:
        check_budget()
        path = Path(item.path)
        if not path.is_absolute():
            raise RuntimeError("launch evidence requires an absolute source path")
        path = path.resolve()
        if not any(path.is_relative_to(root) for root in roots) or not path.is_file():
            raise RuntimeError("launch evidence is outside read-only source roots or missing")
        # Bounded native evidence reads; a larger source can be cited through
        # its existing bounded assembly/report artifact instead.
        if path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError("launch evidence exceeds 16 MiB collection limit; cite a bounded existing source artifact")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != item.sha256:
            raise RuntimeError(f"launch evidence digest mismatch: {path}")
        if item.excerpt.encode("utf-8") not in content:
            raise RuntimeError(f"launch evidence excerpt is absent: {path}")
    check_budget()
    identifier = hashlib.sha256(proposal.model_dump_json().encode("utf-8")).hexdigest()
    return RuntimeLaunchRecord(recipe_id="runtime-launch:" + identifier, executable_path=expected,
        target_sha256=digest, original_recipe_id=None, proposal=proposal)
