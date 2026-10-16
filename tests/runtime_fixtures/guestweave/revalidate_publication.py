"""Revalidate frozen inputs using current Core, publish, then replay cleanly.

This integration fixture never edits the source publication or inherits its
success. It verifies all original trees, executes the retained checks with a
newly built harness, and records a separate configuration and provenance.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import shutil
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--budget-seconds", type=float, default=7200)
    parser.add_argument("--runtime-workspace", type=Path,
        help="Explicit framework checkout, including an independent source delivery")
    parser.add_argument("--legacy-v2-input", action="store_true",
        help="Explicitly verify v2 inputs for new execution; never upgrade/replay the old success")
    parser.add_argument("--authored-candidate", type=Path,
        help="Explicit revised authored tree to build/test; never edits the parent publication")
    parser.add_argument("--revision-reason")
    parser.add_argument("--reviewed-scenario", type=Path,
        help="Explicit reviewed scene retaining every original executable check")
    parser.add_argument("--review-reason")
    args = parser.parse_args()
    if args.authored_candidate and not args.revision_reason:
        parser.error("--authored-candidate requires --revision-reason")
    if args.reviewed_scenario and not args.review_reason:
        parser.error("--reviewed-scenario requires --review-reason")
    workspace = Path(__file__).resolve().parents[4]
    project = workspace / "Firmenstein"
    framework = (args.runtime_workspace or workspace / "GuestWeave").resolve(strict=True)
    load_dotenv(project / ".env")

    from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json
    from fmst_analyzer.runner.budget import ExecutionBudget
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    from fmst_analyzer.runner.identity import tree_sha256, copy_file
    from fmst_analyzer.runner.publication import load_frozen_inputs, publish_success, replay_success
    from fmst_analyzer.runner.runtime_builder import create_runtime_builder
    from fmst_analyzer.runner.schema import InteractionScenario, RuntimeAttempt, RunnerRevision
    from fmst_analyzer.synthesizer.intervention_generator.schema import InterventionGenerationResult
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceCatalog
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import InterventionPlanResult

    if args.legacy_v2_input:
        from legacy_publication import load_legacy_inputs
        load_inputs = load_legacy_inputs
    else:
        load_inputs = load_frozen_inputs

    budget = ExecutionBudget(args.budget_seconds, cleanup_seconds=60)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = args.manifest.resolve(strict=True)
    original_bytes = manifest_path.read_bytes()
    (output / "parent-manifest.json").write_bytes(original_bytes)
    # Bind runtime source files, not ignored build outputs or historical runs.
    source_paths = [Path(__file__).resolve(), project / "src/scripts/build_runtime_bundle.py"]
    if args.reviewed_scenario:
        source_paths.append(args.reviewed_scenario.resolve(strict=True))
    if args.legacy_v2_input:
        source_paths.append(Path(__file__).with_name("legacy_publication.py"))
    source_paths.extend((project / "src/fmst_analyzer/runner").glob("*.py"))
    for crate in (framework, *(framework / name for name in (
        "fmst-iib-api", "fmst-iib-runtime", "harness-arm", "harness-mips", "harness-x86"))):
        source_paths.extend((crate / "src").rglob("*.rs"))
        source_paths.extend(p for p in (crate / "Cargo.toml", crate / "build.rs") if p.is_file())
    source_paths.extend([framework / "Cargo.lock", framework / "tools/build_runtime_bundle.py",
        framework / "dependencies/libafl-qemu.json", framework / "patches/libafl-qemu-cli-bytes.patch"])
    source_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    record = {"kind": "current_core_revalidation_and_new_publication_replay", "state": "preparing",
        "parent_manifest": str(manifest_path), "parent_manifest_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "source_hashes": source_hashes, "started_unix_ns": budget.started_unix_ns,
        "budget_seconds": args.budget_seconds, "agent_invoked": False}
    record["runtime_workspace"] = str(framework)
    record["legacy_v2_input"] = args.legacy_v2_input
    sandbox = None
    builder = None

    def save() -> None:
        (output / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")

    save()
    try:
        parent = load_inputs(manifest_path, budget)
        frozen = manifest_path.parent
        original = parent.attempt
        scenario = original.scenario
        if args.reviewed_scenario:
            from fmst_analyzer.runner.runner import _scenario_weakening
            if scenario is None:
                raise ValueError("reviewed scene requires an original scenario to compare")
            reviewed_path = args.reviewed_scenario.resolve(strict=True)
            reviewed = load_model_json(reviewed_path, InteractionScenario)
            weakening = _scenario_weakening(scenario, reviewed)
            if weakening:
                raise ValueError(f"reviewed scene weakened original checks: {weakening}")
            write_model_json(output / "original-scenario.json", scenario)
            write_model_json(output / "reviewed-scenario.json", reviewed)
            record["scenario_review"] = {
                "path": str(reviewed_path), "sha256": source_hashes[str(reviewed_path)],
                "reason": args.review_reason, "original_checks_preserved": True,
                "human_reviewed": True,
            }
            scenario = reviewed
        record.update(parent_configuration_id=parent.configuration_id,
            parent_input_trees=parent.input_trees, parent_inputs_verified=True)
        builder = create_runtime_builder(runtime_workspace=framework, workdir=output,
            image=os.environ.get("FMST_RUNTIME_BUILDER_IMAGE"),
            platform_name=parent.host_platform, budget=budget)
        record["builder_image"] = getattr(builder, "image", None)
        authored = frozen / "authored"
        intervention = frozen / "runtime/intervention.so" if original.intervention_binary_path else None
        revisions = list(parent.revision_history)
        if args.authored_candidate:
            authored = output / "authored"
            shutil.copytree(args.authored_candidate.resolve(strict=True), authored,
                symlinks=True, ignore=shutil.ignore_patterns("target", "__pycache__"),
                copy_function=lambda src, dst: copy_file(Path(src), Path(dst), budget=budget))
            candidate_hash = tree_sha256(authored, budget)
            before_files = {p.relative_to(frozen / "authored").as_posix(): p
                for p in (frozen / "authored").rglob("*") if p.is_file()}
            after_files = {p.relative_to(authored).as_posix(): p for p in authored.rglob("*") if p.is_file()}
            changed = []
            diff = []
            for relative in sorted(before_files.keys() | after_files.keys()):
                budget.check()
                before = before_files[relative].read_bytes() if relative in before_files else b""
                after = after_files[relative].read_bytes() if relative in after_files else b""
                if before != after:
                    changed.append(relative)
                    diff.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                        fromfile="parent/" + relative, tofile="candidate/" + relative))
            patch = output / "candidate.patch"
            patch.write_text("".join(diff))
            revision = RunnerRevision(revision_number=max((r.revision_number for r in revisions), default=0) + 1,
                parent_sha256=parent.input_trees["authored"], result_sha256=candidate_hash,
                changed_paths=changed, action="edit_workspace", reason=args.revision_reason, diff_path=str(patch))
            revisions.append(revision)
            record["candidate_revision"] = revision.model_dump(mode="json")
            crate = authored / "interventions" / parent.target_binary
            tests = authored / "test_harnesses" / parent.target_binary
            for stage, cargo_manifest in (("build", crate / "Cargo.toml"), ("test", tests / "Cargo.toml")):
                result = builder.run_cargo(cargo_manifest, stage, timeout=900)
                (output / f"candidate-{stage}-stdout.log").write_text(result.stdout)
                (output / f"candidate-{stage}-stderr.log").write_text(result.stderr)
                if result.returncode:
                    raise ValueError(f"candidate {stage} failed; see preserved Cargo logs")
            from fmst_analyzer.runner.runner import _locate_cdylib
            intervention = _locate_cdylib(crate, builder)
            revision.verification = "build_test_passed"
            record["candidate_revision"] = revision.model_dump(mode="json")
        sandbox = DockerRootfsSandbox(rootfs=frozen / "rootfs", workdir=output,
            target_binary=parent.target_binary, executable_path=parent.executable_path,
            guest_arch=parent.guest_arch, runtime_workspace=framework,
            env_script=None, runtime_builder=builder, budget=budget, network=original.network)
        record["session_id"] = sandbox.session_id
        print("Preparing current runtime", parent.configuration_id, sandbox.session_id, flush=True)
        save()
        try:
            # The publication already contains the executed staged rootfs.
            # Do not apply the historical script/actions a second time.
            sandbox.prepare([], original.companion_processes)
            staged_hash = tree_sha256(sandbox._active_rootfs, budget)
            if staged_hash != parent.input_trees["rootfs"]:
                raise ValueError("current staging changed frozen rootfs identity")
            record["rootfs_identity_preserved"] = True
            if intervention is not None and not intervention.is_file():
                raise ValueError("missing original intervention binary")
            record["intervention_binary_sha256"] = hashlib.sha256(intervention.read_bytes()).hexdigest() if intervention else None
            result = sandbox.run_attempt(attempt_number=original.attempt_number,
                intervention_so=intervention, executable_path=parent.executable_path,
                guest_args=original.guest_args, guest_working_directory=original.guest_working_directory,
                guest_environment=original.guest_environment, companion_processes=original.companion_processes,
                probe=original.probe, scenario=scenario, timeout_seconds=budget.remaining(),
                watchdog_stall_seconds=parent.watchdog_stall_seconds)
            attempt_dir = result.container_log_path.parent
            intervention_copy = None
            if intervention:
                intervention_copy = attempt_dir / "intervention.so"
                copy_file(intervention, intervention_copy, budget=budget)
            attempt = RuntimeAttempt(tree_identity_version=2, attempt_number=original.attempt_number,
                network=original.network,
                probe=original.probe, scenario=scenario, scenario_result=result.scenario_result,
                guest_args=original.guest_args, guest_working_directory=original.guest_working_directory,
                guest_environment=original.guest_environment, companion_processes=original.companion_processes,
                companion_log_paths=[str(p) for p in result.companion_log_paths],
                ipc=original.ipc, rootfs_actions=[], disabled_unit_ids=original.disabled_unit_ids,
                launch_resolution=original.launch_resolution, request_revisions=original.request_revisions,
                intervention_binary_path=str(intervention_copy) if intervention_copy else None,
                container_exit_code=result.container_exit_code, target_exit_code=result.target_exit_code,
                timed_out=result.timed_out, outcome="success" if result.scenario_result and result.scenario_result.status == "success" else "blocked",
                probe_result=result.probe_result, runtime_trace_path=str(result.runtime_trace_path),
                runtime_trace_paths=[str(p) for p in result.runtime_trace_paths],
                runtime_trace_context_path=str(attempt_dir / "unavailable-context.json"),
                runtime_trace_context_available=False,
                runtime_trace_context_error="This isolated validation does not instantiate an IDA view",
                runtime_trace_available=result.runtime_trace_path.is_file(), container_log_path=str(result.container_log_path),
                runtime_dump_manifest_path=str(result.runtime_dump_manifest_path) if result.runtime_dump_manifest_path else None,
                runtime_dump_capture_kind=result.runtime_dump_capture_kind, runtime_dump_available=result.runtime_dump_available,
                runtime_trace_heartbeat_paths=[str(p) for p in result.heartbeat_paths],
                watchdog_path=str(result.watchdog_path), watchdog_triggered=result.watchdog_triggered,
                termination_reason=result.termination_reason, rootfs_sha256=staged_hash,
                rootfs_adaptations=list(result.rootfs_adaptations),
                target_binary_sha256=hashlib.sha256((sandbox._active_rootfs / parent.executable_path.lstrip("/")).read_bytes()).hexdigest(),
                harness_sha256=tree_sha256(sandbox.bundle_dir, budget),
                agent_summary="Current Core validation of frozen inputs; no new Agent repair")
            write_model_json(attempt_dir / "attempt.json", attempt)
            copy_file(sandbox.session_root / "attempt_receipts" / f"attempt-{attempt.attempt_number:02d}.json",
                attempt_dir / "execution-receipt.json", budget=budget)
            request_source = sandbox.session_root / "attempt_receipts" / f"attempt-{attempt.attempt_number:02d}-requests"
            if request_source.is_dir():
                shutil.copytree(request_source, attempt_dir / "requests", symlinks=True,
                    copy_function=lambda src, dst: copy_file(Path(src), Path(dst), budget=budget))
            copy_file(output / "parent-manifest.json", attempt_dir / "parent-manifest.json", budget=budget)
            record.update(fresh_outcome=attempt.outcome, attempt=str(attempt_dir / "attempt.json"),
                current_runtime_sha256=attempt.harness_sha256)
            if attempt.outcome != "success":
                raise ValueError("selected scenario not satisfied by current runtime; inspect attempt evidence")
            models = {"catalog": PlanningEvidenceCatalog, "plan": InterventionPlanResult,
                "generation": InterventionGenerationResult}
            sources = {name: load_model_json(frozen / "sources" / f"{name}.json", model)
                for name, model in models.items() if (frozen / "sources" / f"{name}.json").is_file()}
            new_path = publish_success(root=output / "successes", sandbox=sandbox, attempt=attempt,
                attempt_dir=attempt_dir, controller_session_id="current-validation-" + sandbox.session_id,
                baseline_id=parent.generation_baseline_id, baseline_root=frozen / "baseline",
                authored_root=authored, source_records=sources, revisions=revisions,
                budget=budget, watchdog_stall_seconds=parent.watchdog_stall_seconds)
            current = load_frozen_inputs(new_path, budget)
            if current.configuration_id == parent.configuration_id or current.attempt.scenario != scenario:
                raise ValueError("new publication identity or selected scenario was lost")
            for name in ("rootfs", "baseline", *([] if args.authored_candidate else ["authored"])):
                if current.input_trees[name] != parent.input_trees[name]:
                    raise ValueError(f"revalidation changed original {name}")
            if args.authored_candidate and current.input_trees["authored"] != candidate_hash:
                raise ValueError("build or publication changed the explicitly provided candidate sources")
            for name in sources:
                if (new_path.parent / "sources" / f"{name}.json").read_bytes() != (frozen / "sources" / f"{name}.json").read_bytes():
                    raise ValueError(f"revalidation changed original {name} source")
            record.update(manifest=str(new_path), configuration_id=current.configuration_id,
                original_scenario_preserved=scenario == original.scenario,
                original_checks_preserved=True, original_sources_preserved=True)
            print("Fresh scenario passed; new publication", current.configuration_id, flush=True)
        finally:
            sandbox.close()
            record["cleanup_records"] = sandbox.cleanup_records
            save()
        # Reuse the same monotonic session budget across preparation, build,
        # guest execution, publication, deletion and clean replay.
        replay = replay_success(new_path, workdir=output / "clean-replay", budget=budget)
        record["replay"] = replay.model_dump(mode="json")
        if replay.state != "success" or not replay.input_identity_verified or not replay.runtime_identity_verified:
            raise ValueError("clean replay did not preserve successful configuration")
        if replay.sandbox_session_id == sandbox.session_id:
            raise ValueError("clean replay reused original sandbox")
        load_inputs(manifest_path, budget)
        if manifest_path.read_bytes() != original_bytes:
            raise ValueError("parent manifest changed")
        record["parent_unchanged"] = True
        if any(hashlib.sha256(Path(p).read_bytes()).hexdigest() != h for p, h in source_hashes.items()):
            raise ValueError("implementation changed during revalidation")
        record.update(state="passed", source_hashes_still_match=True)
    except BaseException as error:
        record.update(state="failed", error=f"{type(error).__name__}: {error}", traceback=traceback.format_exc())
        for stream in ("stdout", "stderr"):
            content = getattr(error, stream, None)
            if content:
                path = output / ("failure-" + stream + ".log")
                path.write_bytes(content if isinstance(content, bytes) else content.encode())
                record["failure_" + stream] = str(path)
        raise
    finally:
        record["builder_cleanup"] = builder.cleanup_records if builder else []
        record["finished_unix_ns"] = time.time_ns()
        record["elapsed_seconds"] = time.monotonic() - budget.started
        save()
    print(json.dumps({"state": record["state"], "receipt": str(output / "receipt.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
