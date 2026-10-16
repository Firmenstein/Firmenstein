"""Freeze successful execution inputs; replay them without rebuilding or an Agent.

The rootfs is the staged *input*, not a committed live container. Runtime writes,
old PIDs, sockets and network connections are deliberately not carried forward.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
import uuid
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field

from fmst_analyzer.analysis.base.report_io import load_model_json, model_content_sha256, write_model_json, write_text
from fmst_basic.utils.archive_paths import resolve_archived_path
from .budget import ExecutionBudget
from .docker_sandbox import DockerRootfsSandbox
from .identity import copy_file, tree_sha256
from .runtime_builder import RuntimeBuilder, create_runtime_builder
from .schema import RuntimeAttempt, RunnerRevision, RunnerCompletion, ScenarioResult, StrictModel

# Capture this process's implementation at import, not from files potentially
# edited while a long Runner session is already executing. Replay never silently
# substitutes a newer probe/observer/launch policy for the published one.
_VALIDATOR_FILES = ("probe.py", "schema.py", "adaptation_schema.py", "docker_sandbox.py", "supervision.py", "identity.py", "publication.py", "budget.py", "request_wire.py", "peer_readiness.py", "runtime_builder.py", "container_output.py", "live_client.py", "browser_access.py")
_VALIDATOR_SOURCES = {name: Path(__file__).with_name(name).read_bytes() for name in _VALIDATOR_FILES}
_VALIDATOR_HASHES = {name: hashlib.sha256(content).hexdigest() for name, content in _VALIDATOR_SOURCES.items()}


class SuccessfulConfiguration(StrictModel):
    schema_version: Literal[3] = 3
    tree_identity_version: Literal[2] = 2
    configuration_id: str = Field(description="Unique frozen publication; unrelated runs never inherit success.")
    controller_session_id: str = Field(description="Controller invocation that observed this successful attempt.")
    sandbox_session_id: str = Field(description="Sandbox owning the original execution evidence.")
    created_unix_ns: int = Field(description="Publication time, not guest sample time.")
    target_binary: str = Field(description="Selected firmware service identity.")
    executable_path: str = Field(description="Exact guest POSIX executable path; resolved against frozen rootfs only.")
    guest_arch: Literal["arm", "mipsel", "mipsbe", "x86_64"]
    host_platform: str | None = Field(description="Docker platform of the frozen host harness; no rebuild on replay.")
    validation_code_sha256: dict[str, str] = Field(description="Exact local launch/probe/supervision implementation; mismatch rejects replay rather than replacing acceptance semantics.")
    watchdog_stall_seconds: float = Field(gt=0, description="Same health window for original execution and replay; not a proof of infinite looping.")
    generation_baseline_id: str = Field(description="Original Generator baseline identity, retained without modification.")
    input_trees: dict[str, str] = Field(description="v2 hashes of fixed relative rootfs/runtime/evidence/authored/baseline/sources trees.")
    attempt: RuntimeAttempt = Field(description="Original successful execution and exact argv/cwd/env/peers/IPC/actions/scenario. Historical paths are provenance; portable copies live in evidence/.")
    revision_history: list[RunnerRevision] = Field(description="Authorized changes and their parent/result identities.")
    evidence_locations: dict[str, str] = Field(default_factory=dict, description="Historical absolute path to existing relative frozen artifact. Resolve values against this manifest's directory after relocation; no source record is rewritten.")
    limitations: list[str] = Field(default_factory=lambda: [
        "Replay imports the exact staged input rootfs; it does not rerun Environment scripts or rebuild binaries.",
        "External peers, networks, kernel and Docker versions are not a resumable VM snapshot.",
        "Historical absolute evidence paths remain provenance; copied attempt files are under evidence/.",
        "Frozen artifacts are hash-checked, not signed or protected against coordinated manifest tampering.",
    ])


class SuccessfulConfigurationPointer(StrictModel):
    schema_version: Literal[1] = 1
    configuration_id: str
    manifest_path: str = Field(description="Path relative to this pointer's directory.")
    manifest_sha256: str = Field(description="Canonical Pydantic manifest digest.")
    controller_session_id: str


class ReplayReceipt(StrictModel):
    schema_version: Literal[1] = 1
    configuration_id: str
    manifest_sha256: str
    sandbox_session_id: str
    artifact_root: str
    started_unix_ns: int
    finished_unix_ns: int | None = None
    state: Literal["preparing", "running", "success", "blocked", "error"] = "preparing"
    error: str | None = None
    input_identity_verified: bool = False
    runtime_identity_verified: bool = False
    scenario_result: ScenarioResult | None = None
    cleanup_records: list[dict[str, object]] = Field(default_factory=list)


_TREES = {"rootfs", "runtime", "evidence", "authored", "baseline", "sources"}


def _copy_tree(source: Path, destination: Path, budget: ExecutionBudget, *, authored=False) -> None:
    budget.check()
    shutil.copytree(source, destination, symlinks=True,
        copy_function=partial(copy_file, budget=budget),
        ignore=shutil.ignore_patterns("target", "__pycache__") if authored else None)


def _target_digest(rootfs: Path, guest_path: str) -> str:
    # Do not let guest absolute symlinks read an arbitrary host file. Such a
    # layout needs an explicit guest-path resolver; reject instead of guessing.
    if not guest_path.startswith("/"):
        raise ValueError("guest executable must be absolute")
    target = (rootfs / guest_path.lstrip("/")).resolve(strict=True)
    target.relative_to(rootfs.resolve())
    return hashlib.sha256(target.read_bytes()).hexdigest()


def publish_success(*, root: Path, sandbox: DockerRootfsSandbox, attempt: RuntimeAttempt,
                    attempt_dir: Path, controller_session_id: str, baseline_id: str,
                    baseline_root: Path, authored_root: Path,
                    source_records: dict[str, BaseModel], revisions: list[RunnerRevision],
                    budget: ExecutionBudget, watchdog_stall_seconds: float = 60.0,
                    completion: RunnerCompletion | None = None) -> Path:
    """Publish only a verified success; failed/incomplete copies never move current."""
    native_completion = completion is not None and completion.client_receipt is not None
    if not native_completion and (attempt.outcome != "success" or attempt.scenario is None or attempt.scenario_result is None or attempt.scenario_result.status != "success"):
        raise ValueError("success publication requires an independently satisfied scenario")
    if not all((attempt.rootfs_sha256, attempt.target_binary_sha256, attempt.harness_sha256)):
        raise ValueError("success publication requires complete execution identity")
    if sandbox._active_rootfs is None:
        raise ValueError("cannot publish after staged inputs were removed")
    if attempt.network != sandbox.network:
        raise ValueError("attempt network differs from the executed sandbox configuration")
    if completion is not None:
        _validate_completion_evidence(attempt_dir, attempt, completion)
    budget.check()
    identifier = uuid.uuid4().hex
    root.mkdir(parents=True, exist_ok=True)
    pending = root / (".pending-" + identifier)
    pending.mkdir()
    # On failure retain only this named incomplete directory as diagnostic
    # evidence. It is never loadable through current.json.
    _copy_tree(sandbox._active_rootfs, pending / "rootfs", budget)
    _copy_tree(sandbox.bundle_dir, pending / "runtime", budget)
    _copy_tree(attempt_dir, pending / "evidence", budget)
    revision_locations = {}
    for number, revision in enumerate(attempt.request_revisions, 1):
        if revision.kind not in {"cookie_continuity", "client_request"}:
            continue
        destination = pending / "evidence" / "request-revisions" / str(number)
        destination.mkdir(parents=True)
        originals = [(Path(revision.source_attempt_path), revision.source_attempt_sha256, "source-attempt.json")]
        originals.extend((Path(source.response_path), source.response_sha256, f"step-{source.step_index:02d}-response.bin")
                         for source in revision.cookie_sources)
        if revision.correction is not None:
            originals.extend((Path(source.path), source.sha256, f"source-{i:02d}.bin")
                             for i, source in enumerate(revision.correction.evidence))
        for source, expected, name in originals:
            budget.check()
            if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
                raise ValueError("request correction source changed before publication")
            copy_file(source, destination / name, budget=budget)
            revision_locations[str(source)] = (destination / name).relative_to(pending).as_posix()
    _copy_tree(baseline_root, pending / "baseline", budget)
    (pending / "authored").mkdir()
    # GenerationWorkspace uses interventions/<target> and
    # test_harnesses/<target>, unlike baseline's singular directory names.
    for name in ("environment", "interventions", "test_harnesses", "runtime_adaptations"):
        source = authored_root / name
        if source.is_dir() and not source.is_symlink():
            _copy_tree(source, pending / "authored" / name, budget, authored=True)
    (pending / "sources").mkdir()
    (pending / "sources/validator").mkdir()
    for name, content in _VALIDATOR_SOURCES.items():
        (pending / "sources/validator" / name).write_bytes(content)
    if sandbox._env_script_snapshot is not None:
        copy_file(sandbox._env_script_snapshot, pending / "sources/setup_rootfs.executed.py", budget=budget)
    for name, record in source_records.items():
        if name not in {"catalog", "plan", "generation"}:
            raise ValueError(f"unknown source record: {name}")
        write_model_json(pending / "sources" / (name + ".json"), record)
    # Preserve revision patches alongside source/evidence even after reports
    # are archived. No reliance on the original report's absolute patch path.
    for revision in revisions:
        if revision.diff_path:
            copy_file(
                resolve_archived_path(Path(revision.diff_path)),
                pending / "sources" / f"revision-{revision.revision_number:02d}.patch",
                budget=budget,
            )
    hashes = {name: tree_sha256(pending / name, budget) for name in sorted(_TREES)}
    if hashes["rootfs"] != attempt.rootfs_sha256 or hashes["runtime"] != attempt.harness_sha256:
        raise ValueError("frozen input identity differs from executed attempt (including permissions/owners)")
    if _target_digest(pending / "rootfs", sandbox.executable_path) != attempt.target_binary_sha256:
        raise ValueError("frozen target ELF identity differs from executed attempt")
    if load_model_json(pending / "evidence/attempt.json", RuntimeAttempt) != attempt:
        raise ValueError("copied evidence does not match the successful attempt")
    manifest = SuccessfulConfiguration(configuration_id=identifier, controller_session_id=controller_session_id,
        sandbox_session_id=sandbox.session_id, created_unix_ns=time.time_ns(), target_binary=sandbox.target_binary,
        executable_path=sandbox.executable_path, guest_arch=sandbox.guest_arch,
        host_platform=sandbox.runtime_builder.platform_name, generation_baseline_id=baseline_id,
        validation_code_sha256=_VALIDATOR_HASHES, watchdog_stall_seconds=watchdog_stall_seconds,
        input_trees=hashes, attempt=attempt, revision_history=revisions)
    manifest.evidence_locations = {
        **revision_locations,
        str(sandbox._active_rootfs): "rootfs",
        str(sandbox.bundle_dir): "runtime",
        str(baseline_root): "baseline",
    }
    for source in attempt_dir.rglob("*"):
        if source.is_file():
            manifest.evidence_locations[str(source)] = "evidence/" + source.relative_to(attempt_dir).as_posix()
    if attempt.scenario_result:
        raw_attempt = sandbox.output_root / f"attempt-{attempt.attempt_number:02d}"
        raw_receipt = sandbox.session_root / "attempt_receipts" / f"attempt-{attempt.attempt_number:02d}.json"
        for observation in attempt.scenario_result.observations:
            if observation.evidence_path is None:
                continue
            source = Path(observation.evidence_path)
            if source == raw_receipt:
                relative = "evidence/execution-receipt.json"
            elif source.is_relative_to(raw_attempt):
                relative = "evidence/" + source.relative_to(raw_attempt).as_posix()
            else:
                continue
            if (pending / relative).exists():
                manifest.evidence_locations[str(source)] = relative
    write_model_json(pending / "manifest.json", manifest)
    write_text(pending / "README.md", render_configuration(manifest))
    budget.check()
    destination = root / identifier
    pending.rename(destination)
    write_model_json(root / "current.json", SuccessfulConfigurationPointer(configuration_id=identifier,
        manifest_path=f"{identifier}/manifest.json", manifest_sha256=model_content_sha256(manifest),
        controller_session_id=controller_session_id))
    return destination / "manifest.json"


def _validate_completion_evidence(evidence: Path, attempt: RuntimeAttempt, completion: RunnerCompletion) -> None:
    """Check the claim's execution identity, without judging firmware semantics."""
    saved = load_model_json(evidence / "completion.json", RunnerCompletion)
    if (saved != completion
            or completion.attempt_number != attempt.attempt_number
            or completion.attempt_sha256 != hashlib.sha256((evidence / "attempt.json").read_bytes()).hexdigest()):
        raise ValueError("completion evidence does not bind the current attempt")
    if completion.client_receipt:
        receipt = evidence / "native-client/receipt.json"
        import json
        client = json.loads(receipt.read_text())
        if client["attempt_sha256"] != completion.attempt_sha256 or not client["commands"]:
            raise ValueError("native client evidence does not bind the completed candidate")


def render_configuration(manifest: SuccessfulConfiguration) -> str:
    native = bool(manifest.attempt.browser_origin or
        "evidence/native-client/receipt.json" in manifest.evidence_locations.values())
    return "\n".join([
        "# Frozen successful rehosting configuration", "",
        f"- configuration_id: `{manifest.configuration_id}`",
        f"- generation_baseline_id: `{manifest.generation_baseline_id}`",
        (f"- native interaction: attempt {manifest.attempt.attempt_number}, evidence in `evidence/native-client/`"
         if native else
         f"- scenario: attempt {manifest.attempt.attempt_number}, unchanged on replay"),
        "- network: " + manifest.attempt.network.model_dump_json(),
        "- source of truth: [manifest.json](manifest.json)",
        "- portable evidence: `evidence/`; frozen staged input: `rootfs/`; exact host harness: `runtime/`",
        ("- revalidation: fresh native interaction is required; protocol replay does not repeat browser acceptance"
         if native else
         "- replay: `python -m fmst_analyzer.runner.replay MANIFEST --workdir NEW_OUTPUT_DIRECTORY`"),
        "", *[f"- limitation: {item}" for item in manifest.limitations], "",
    ])


def _validate_frozen_validator_sources(path: Path, manifest: SuccessfulConfiguration, budget: ExecutionBudget) -> None:
    """Bind the recorded implementation hashes to the copied source files.

    A manifest hash is metadata, not evidence by itself.  Publications carry
    the validator sources so a relocated artifact can be inspected without
    the checkout that produced it; the two representations must agree before
    either the current-code check or replay is attempted.
    """
    # Original v3 publications predate runtime-derived owner records. They
    # remain readable as historical inputs; load_success still requires the
    # complete current validator hash map before replay.
    if set(manifest.validation_code_sha256) not in (
        set(_VALIDATOR_FILES), set(_VALIDATOR_FILES) - {"adaptation_schema.py"},
    ):
        raise ValueError("unexpected frozen validator source set")
    validator_root = path.parent / "sources" / "validator"
    if validator_root.is_symlink() or not validator_root.is_dir():
        raise ValueError("missing frozen validator sources")
    for name, expected in manifest.validation_code_sha256.items():
        budget.check()
        if Path(name).name != name:
            raise ValueError(f"invalid frozen validator source name: {name}")
        source = validator_root / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"missing frozen validator source: {name}")
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"frozen validator source hash mismatch: {name}")


def load_frozen_inputs(path: Path, budget: ExecutionBudget) -> SuccessfulConfiguration:
    """Verify historical inputs without claiming success under current code.

    Explicit revalidation may consume these read-only inputs in a new attempt.
    Strict replay additionally requires the original validator implementation;
    it must use ``load_success`` instead.
    """
    budget.check()
    manifest = load_model_json(path, SuccessfulConfiguration)
    if set(manifest.input_trees) != _TREES:
        raise ValueError("unexpected frozen input trees")
    for relative in manifest.evidence_locations.values():
        candidate = PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts or candidate.parts[0] not in _TREES or not (path.parent / relative).exists():
            raise ValueError(f"invalid frozen evidence location: {relative}")
    for name, expected in manifest.input_trees.items():
        directory = path.parent / name
        if directory.is_symlink() or not directory.is_dir() or tree_sha256(directory, budget) != expected:
            raise ValueError(f"frozen identity mismatch: {name}")
    _validate_frozen_validator_sources(path, manifest, budget)
    attempt = manifest.attempt
    completion_path = path.parent / "evidence/completion.json"
    completion = load_model_json(completion_path, RunnerCompletion) if completion_path.exists() else None
    native_completion = completion is not None and completion.client_receipt is not None
    if ((not native_completion and (attempt.outcome != "success" or attempt.scenario is None or attempt.scenario_result is None
            or attempt.scenario_result.status != "success"))
            or manifest.input_trees["rootfs"] != attempt.rootfs_sha256
            or manifest.input_trees["runtime"] != attempt.harness_sha256
            or load_model_json(path.parent / "evidence/attempt.json", RuntimeAttempt) != attempt
            or _target_digest(path.parent / "rootfs", manifest.executable_path) != attempt.target_binary_sha256):
        raise ValueError("manifest no longer binds the successful execution")
    if completion is not None:
        _validate_completion_evidence(completion_path.parent, attempt, completion)
    return manifest


def load_success(path: Path, budget: ExecutionBudget) -> SuccessfulConfiguration:
    manifest = load_frozen_inputs(path, budget)
    if manifest.validation_code_sha256 != _VALIDATOR_HASHES:
        raise ValueError("frozen validation implementation differs; revalidate explicitly, do not silently replace it")
    return manifest


def replay_success(manifest_path: Path, *, workdir: Path, budget: ExecutionBudget) -> ReplayReceipt:
    """Use the production sandbox/probe without Agent, upstream stages or build.

    Each replay owns a new session and receipt, never updates current success.
    """
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = load_success(manifest_path, budget)
    image = os.environ.get("FMST_RUNTIME_BUILDER_IMAGE")
    # Replay never invokes a build. When a Docker builder is configured, it
    # only collects the idle output mount using the same host handoff as run.
    builder = (create_runtime_builder(runtime_workspace=manifest_path.parent,
        workdir=workdir, image=image, platform_name=manifest.host_platform, budget=budget)
        if image else RuntimeBuilder(budget=budget))
    builder.platform_name = manifest.host_platform
    sandbox = DockerRootfsSandbox(rootfs=manifest_path.parent / "rootfs", workdir=workdir,
        target_binary=manifest.target_binary, executable_path=manifest.executable_path,
        guest_arch=manifest.guest_arch, runtime_workspace=manifest_path.parent,
        env_script=None, runtime_builder=builder, budget=budget, network=manifest.attempt.network)
    receipt = ReplayReceipt(configuration_id=manifest.configuration_id,
        manifest_sha256=model_content_sha256(manifest), sandbox_session_id=sandbox.session_id,
        artifact_root=str(sandbox.session_root), started_unix_ns=budget.started_unix_ns)
    receipt_path = sandbox.session_root / "replay.json"
    write_model_json(receipt_path, receipt)
    try:
        sandbox.prepare_frozen(manifest_path.parent / "runtime",
            rootfs_sha256=manifest.input_trees["rootfs"], runtime_sha256=manifest.input_trees["runtime"])
        receipt.input_identity_verified = True
        receipt.state = "running"
        write_model_json(receipt_path, receipt)
        if (manifest_path.parent / "evidence/native-client/receipt.json").is_file():
            raise ValueError("Native browser completion requires fresh Agent interaction; protocol replay alone cannot revalidate its service assessment")
        original = manifest.attempt
        # Reusing the logical attempt number renders the exact same supervisor
        # file; the sandbox/session/container identity is new.
        result = sandbox.run_attempt(attempt_number=original.attempt_number,
            intervention_so=manifest_path.parent / "runtime/intervention.so" if original.intervention_binary_path else None,
            executable_path=manifest.executable_path, guest_args=original.guest_args,
            guest_working_directory=original.guest_working_directory, guest_environment=original.guest_environment,
            companion_processes=original.companion_processes, probe=original.probe,
            scenario=original.scenario, timeout_seconds=budget.remaining(),
            watchdog_stall_seconds=manifest.watchdog_stall_seconds)
        receipt.scenario_result = result.scenario_result
        if receipt.scenario_result:
            for observation in receipt.scenario_result.observations:
                if observation.evidence_path == str(sandbox._active_rootfs):
                    # This was independently verified before import; the frozen
                    # tree survives cleanup and has the same v2 identity.
                    observation.evidence_path = str(manifest_path.parent / "rootfs")
        receipt.runtime_identity_verified = tree_sha256(sandbox.bundle_dir, budget) == manifest.input_trees["runtime"]
        if not receipt.runtime_identity_verified:
            raise ValueError("replay changed frozen runtime identity")
        receipt.state = "success" if result.scenario_result and result.scenario_result.status == "success" else "blocked"
    except BaseException as error:
        receipt.state = "error"
        receipt.error = f"{type(error).__name__}: {error}"
        raise
    finally:
        try:
            sandbox.close()
        finally:
            receipt.cleanup_records = sandbox.cleanup_records
            receipt.finished_unix_ns = time.time_ns()
            write_model_json(receipt_path, receipt)
    return receipt


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--budget-seconds", type=float, default=7200)
    args = parser.parse_args()
    receipt = replay_success(args.manifest, workdir=args.workdir, budget=ExecutionBudget(args.budget_seconds))
    print(receipt.model_dump_json(indent=2))
    raise SystemExit(0 if receipt.state == "success" else 1)
