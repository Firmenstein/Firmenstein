"""Run real generic TCP guests through the production sandbox and correlation path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from dotenv import load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    workspace_root = Path(__file__).resolve().parents[4]
    project = workspace_root / "Firmenstein"
    fixture_root = project / "tests/runtime_fixtures/guestweave"
    load_dotenv(project / ".env")
    from fmst_analyzer.runner.budget import ExecutionBudget
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    from fmst_analyzer.runner.runtime_builder import create_runtime_builder
    from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, InteractionStep

    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    workspace = workspace_root / "GuestWeave"
    source = fixture_root / "assets/diagnostic_isolation/tcp_guest.c"
    budget = ExecutionBudget(600, cleanup_seconds=60)
    builder = create_runtime_builder(runtime_workspace=workspace, workdir=out,
        image=os.environ.get("FMST_RUNTIME_BUILDER_IMAGE"),
        platform_name=os.environ.get("FMST_RUNTIME_BUILDER_PLATFORM"), budget=budget)
    source_paths = [source, Path(__file__).resolve(), project / "src/fmst_analyzer/runner/child_failure.py",
        project / "src/fmst_analyzer/runner/docker_sandbox.py",
        project / "src/scripts/build_runtime_bundle.py",
        workspace / "tools/build_runtime_bundle.py",
        workspace / "fmst-iib-runtime/src/diagnostics.rs"]
    source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
    results = []
    status = "incomplete"
    try:
        linker = builder._run(["sh", "-c", "printf '%s' \"$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld\""], timeout=30)
        assert linker.returncode == 0, linker.stderr
        for mode, define in (("normal", None), ("request-crash", "REQUEST_CRASH"),
                             ("unrelated-crash", "UNRELATED_CRASH")):
            rootfs = out / mode / "rootfs-source"
            rootfs.mkdir(parents=True)
            guest = rootfs / "server"
            obj = out / mode / "server.o"
            command = ["clang", "--target=x86_64-linux-gnu", "-O0", "-c", "-nostdlib",
                       "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic",
                       *(["-D" + define] if define else []), builder._container_path(source),
                       "-o", builder._container_path(obj)]
            compiled = builder._run(command, timeout=60)
            assert compiled.returncode == 0, f"{mode}: {compiled.stderr}"
            linked = builder._run([linker.stdout, "-flavor", "gnu", "-m", "elf_x86_64", "-static",
                "--entry=_start", "-o", builder._container_path(guest), builder._container_path(obj)], timeout=60)
            assert linked.returncode == 0, f"{mode}: {linked.stderr}"
            # The Docker builder owns its output files; set the mode there too.
            executable = builder._run(["chmod", "755", builder._container_path(guest)], timeout=30)
            assert executable.returncode == 0, executable.stderr
            sandbox = DockerRootfsSandbox(rootfs=rootfs, workdir=out / mode,
                target_binary="server", executable_path="/server", guest_arch="x86_64",
                runtime_workspace=workspace, env_script=None, runtime_builder=builder, budget=budget)
            record = {"mode": mode, "guest_sha256": hashlib.sha256(guest.read_bytes()).hexdigest(),
                      "session_id": sandbox.session_id}
            try:
                sandbox.prepare()
                marker = "partial page" if mode == "request-crash" else "\r\n\r\nOK"
                probe = InteractionProbe(port=18080, request_text="GET / HTTP/1.0\r\n\r\n",
                                         response_contains=marker)
                scenario = InteractionScenario(protocol="http", port=18080,
                    steps=[InteractionStep(request_text=probe.request_text,
                        expected_status_code=200, response_contains=marker)],
                    evidence_refs=["generic freestanding TCP fixture source: " + str(source)])
                attempt = sandbox.run_attempt(attempt_number=1, intervention_so=None,
                    executable_path="/server", guest_args=[], guest_working_directory="/",
                    guest_environment={"QEMU_STRACE": "1"}, companion_processes=[],
                    probe=probe, scenario=scenario, timeout_seconds=30,
                    watchdog_stall_seconds=10)
                attempt_root = attempt.container_log_path.parent
                association = json.loads((attempt_root / "child-failures.json").read_text())
                record.update(scenario=attempt.scenario_result.model_dump(mode="json"),
                              association=association, attempt_root=str(attempt_root),
                              response=attempt.probe_result.response_text,
                              response_sha256=hashlib.sha256(attempt.probe_result.response_text.encode()).hexdigest())
                expected = "blocked" if mode == "request-crash" else "success"
                assert attempt.scenario_result.status == expected, record
                if mode == "request-crash":
                    assert association["status"] == "related_failure", record
                if mode == "unrelated-crash":
                    assert any(f["relation"] == "unrelated" and f["signal"] == 11
                               for f in association["failures"]), record
            finally:
                sandbox.close()
                record["cleanup"] = sandbox.cleanup_records
                results.append(record)
                (out / "results.json").write_text(json.dumps(results, indent=2))
        assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
                   for path, digest in source_hashes.items()), "source changed during validation"
        status = "passed"
    finally:
        (out / "receipt.json").write_text(json.dumps({
            "status": status, "results": results, "source_hashes": source_hashes,
            "builder_cleanup": builder.cleanup_records,
            "baseline": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "elapsed_seconds": time.monotonic() - budget.started,
        }, indent=2))
    print(json.dumps({"status": status, "receipt": str(out / "receipt.json")}))


if __name__ == "__main__":
    main()
