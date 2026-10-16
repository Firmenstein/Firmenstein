"""Run retained demo inputs and original scenarios with the current Core.

This is explicit current-version validation, not a strict replay of archived
validator code, a new publication, or a new Analyzer/Agent run.
"""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import difflib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import time
import traceback

from dotenv import load_dotenv


PROJECT = Path(__file__).resolve().parents[3]


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def run_target(row: dict, output: Path, seconds: float) -> dict:
    from fmst_analyzer.runner.budget import ExecutionBudget
    from fmst_analyzer.runner.delivery import _cleanup_failed, _inventory
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    from fmst_analyzer.runner.publication import load_frozen_inputs
    from fmst_analyzer.runner.runtime_builder import create_runtime_builder

    work = output / row["id"]
    work.mkdir()
    record = {"id": row["id"], "state": "preparing", "started_unix_ns": time.time_ns(),
        "manifest": row["manifest"], "configuration_id": row["configuration_id"],
        "scope": "Current Core execution of verified frozen inputs and unchanged original scenario",
        "agent_invoked": False, "runtime_rebuilt": False, "new_publication": False,
        "strict_archived_replay": False, "budget_seconds": seconds}
    receipt = work / "receipt.json"
    write_json(receipt, record)
    budget = ExecutionBudget(seconds, cleanup_seconds=60)
    sandbox = None
    builder = None
    try:
        manifest = Path(row["manifest"])
        if not manifest.is_absolute():
            manifest = PROJECT / manifest
        manifest = manifest.resolve(strict=True)
        content = manifest.read_bytes()
        if hashlib.sha256(content).hexdigest() != row["manifest_sha256"]:
            raise ValueError("Selected manifest changed")
        (work / "parent-manifest.json").write_bytes(content)
        original = load_frozen_inputs(manifest, budget)
        a = original.attempt
        if (original.configuration_id != row["configuration_id"]
                or original.executable_path != row["guest_path"]
                or a.target_binary_sha256 != row["target_sha256"]
                or a.scenario.model_dump(mode="json") != row["scenario"]):
            raise ValueError("Inventory differs from frozen target/scenario")
        record["original_inputs_verified"] = True
        builder = create_runtime_builder(runtime_workspace=manifest.parent, workdir=work,
            image=os.environ.get("FMST_RUNTIME_BUILDER_IMAGE"),
            platform_name=original.host_platform, budget=budget)
        sandbox = DockerRootfsSandbox(rootfs=manifest.parent / "rootfs", workdir=work,
            target_binary=original.target_binary, executable_path=original.executable_path,
            guest_arch=original.guest_arch, runtime_workspace=manifest.parent,
            env_script=None, runtime_builder=builder, budget=budget, network=a.network)
        record.update(sandbox_session_id=sandbox.session_id, session_root=str(sandbox.session_root))
        write_json(receipt, record)
        sandbox.prepare_frozen(manifest.parent / "runtime",
            rootfs_sha256=original.input_trees["rootfs"], runtime_sha256=original.input_trees["runtime"])
        before = _inventory(sandbox.bundle_dir)
        if before != _inventory(manifest.parent / "runtime"):
            raise ValueError("Frozen runtime copy differs before execution")
        record.update(frozen_runtime_copy_verified=True, state="running")
        write_json(receipt, record)
        result = sandbox.run_attempt(attempt_number=a.attempt_number,
            intervention_so=manifest.parent / "runtime/intervention.so" if a.intervention_binary_path else None,
            executable_path=original.executable_path, guest_args=a.guest_args,
            guest_working_directory=a.guest_working_directory, guest_environment=a.guest_environment,
            companion_processes=a.companion_processes, probe=a.probe, scenario=a.scenario,
            timeout_seconds=budget.remaining(), watchdog_stall_seconds=original.watchdog_stall_seconds)
        after = _inventory(sandbox.bundle_dir)
        differences = {key: {"before": before.get(key), "after": after.get(key)}
            for key in sorted(before.keys() | after.keys()) if before.get(key) != after.get(key)}
        supervisor = f"attempt-{a.attempt_number:02d}.sh"
        record.update(runtime_differences=differences, runtime_identity_verified=not differences,
            scenario_result=result.scenario_result.model_dump(mode="json"),
            container_log=str(result.container_log_path),
            execution_receipt=str(sandbox.session_root / "attempt_receipts" / f"attempt-{a.attempt_number:02d}.json"),
            request_evidence=str(sandbox.session_root / "attempt_receipts" / f"attempt-{a.attempt_number:02d}-requests"),
            original_scenario_preserved=True, original_launch_preserved=True)
        # Current Core generates its own supervisor. Never hide this difference
        # or change an archived manifest/runtime hash to claim strict replay.
        if differences:
            if set(differences) != {supervisor}:
                raise ValueError("Execution changed runtime files beyond the generated supervisor")
            old = (manifest.parent / "runtime" / supervisor).read_text()
            new = (sandbox.bundle_dir / supervisor).read_text()
            (work / "supervisor-before.sh").write_text(old)
            (work / "supervisor-after.sh").write_text(new)
            (work / "supervisor.diff").write_text("".join(difflib.unified_diff(
                old.splitlines(keepends=True), new.splitlines(keepends=True),
                fromfile="frozen/" + supervisor, tofile="current/" + supervisor)))
            record["supervisor_diff"] = str(work / "supervisor.diff")
        if result.scenario_result.status != "success":
            record["state"] = "blocked"
        else:
            load_frozen_inputs(manifest, budget)
            if manifest.read_bytes() != content:
                raise ValueError("Original manifest changed")
            record.update(state="passed", parent_unchanged=True)
    except BaseException as error:
        record.update(state="failed", error=f"{type(error).__name__}: {error}",
            traceback=traceback.format_exc())
    finally:
        try:
            if sandbox is not None:
                sandbox.close()
        except BaseException as error:
            record.update(state="cleanup_failed", cleanup_error=f"{type(error).__name__}: {error}")
        record["cleanup_records"] = sandbox.cleanup_records if sandbox else []
        record["builder_cleanup"] = builder.cleanup_records if builder else []
        if any(_cleanup_failed(item) for item in record["cleanup_records"] + record["builder_cleanup"]):
            record.update(state="cleanup_failed", cleanup_error="Resource cleanup receipt contains errors")
        record.update(finished_unix_ns=time.time_ns(), elapsed_seconds=time.monotonic() - budget.started)
        write_json(receipt, record)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=PROJECT / "docs/workflow/samples/runtime-v2.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--budget-seconds", type=float, default=600)
    parser.add_argument("--concurrency", type=int, choices=range(1, 5), default=4)
    args = parser.parse_args()
    load_dotenv(PROJECT / ".env")
    inventory = json.loads(args.inventory.read_text())
    rows = inventory["targets"]
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate target IDs")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "inventory.json").write_bytes(args.inventory.read_bytes())
    source_files = [Path(__file__), *sorted((PROJECT / "src/fmst_analyzer/runner").glob("*.py"))]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files}
    summary = {"state": "running", "scope": inventory["scope"], "sample_set": inventory["sample_set"],
        "started_unix_ns": time.time_ns(), "concurrency": args.concurrency, "targets": [],
        "source_hashes": hashes, "inventory_sha256": hashlib.sha256(args.inventory.read_bytes()).hexdigest()}
    write_json(output / "receipt.json", summary)
    pending = list(rows)
    active = {}
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        while pending or active:
            for row in list(pending):
                if len(active) >= args.concurrency:
                    break
                subnet = row["network"]["subnet"]
                if subnet and any(other["network"]["subnet"] and
                        ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network(other["network"]["subnet"]))
                        for other in active.values()):
                    continue
                active[pool.submit(run_target, row, output, args.budget_seconds)] = row
                pending.remove(row)
            done, _ = wait(active, return_when=FIRST_COMPLETED)
            for future in done:
                row = active.pop(future)
                result = future.result()
                summary["targets"].append({"id": row["id"], "state": result["state"],
                    "receipt": str(output / row["id"] / "receipt.json"),
                    "scenario_steps": len(result.get("scenario_result", {}).get("steps", [])),
                    "error": result.get("error")})
                write_json(output / "receipt.json", summary)
                print(row["id"], result["state"], flush=True)
    summary["source_hashes_still_match"] = all(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in hashes.items())
    summary["counts"] = {state: sum(row["state"] == state for row in summary["targets"])
        for state in ("passed", "blocked", "failed", "cleanup_failed")}
    summary["state"] = "passed" if summary["counts"]["passed"] == len(rows) and summary["source_hashes_still_match"] else "failed"
    summary["finished_unix_ns"] = time.time_ns()
    write_json(output / "receipt.json", summary)
    print(json.dumps({"state": summary["state"], "counts": summary["counts"]}))
    return int(summary["state"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
