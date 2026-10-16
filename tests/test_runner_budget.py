"""Deadline boundaries are deterministic; marked tests prove OS cancellation."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from fmst_analyzer.runner import budget as budget_module
from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped, run_process


def test_all_phases_share_one_deadline_and_cleanup_reserve(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(budget_module.time, "monotonic", lambda: clock[0])
    budget = ExecutionBudget(100, cleanup_seconds=10)
    assert budget.limit(1800) == 90
    clock[0] += 35
    assert budget.limit(1800) == 55
    clock[0] += 55
    with pytest.raises(RunnerStopped, match="session_budget_exhausted"):
        budget.check()
    assert budget.limit(30, cleanup=True) == 10
    clock[0] += 10
    with pytest.raises(RunnerStopped, match="session_budget_exhausted"):
        budget.check(cleanup=True)


def test_cancel_stops_new_work_but_permits_bounded_cleanup():
    budget = ExecutionBudget(100)
    budget.cancelled.set()
    with pytest.raises(RunnerStopped, match="user_cancelled"):
        budget.limit(10)
    assert 0 < budget.limit(10, cleanup=True) <= 10


def test_expired_budget_never_starts_a_subprocess(monkeypatch):
    budget = ExecutionBudget(100)
    budget.cancelled.set()
    monkeypatch.setattr(budget_module.subprocess, "Popen", lambda *a, **k: pytest.fail("process started"))
    with pytest.raises(RunnerStopped):
        run_process(["not-executed"], budget=budget, timeout=10)


@pytest.mark.external
def test_real_child_is_killed_and_reaped_on_budget_expiry(tmp_path):
    pid_file = tmp_path / "pid.json"
    budget = ExecutionBudget(1, cleanup_seconds=0.1)
    with pytest.raises(RunnerStopped, match="session_budget_exhausted"):
        run_process([sys.executable, "-c",
            "import os,sys,json,time; "
            "open(sys.argv[1],'w').write(json.dumps({'pid':os.getpid(),'pgrp':os.getpgrp()})); "
            "time.sleep(60)", str(pid_file)], budget=budget, timeout=30, capture_output=True)
    identity = json.loads(pid_file.read_text())
    assert identity["pid"] == identity["pgrp"]
    with pytest.raises(ProcessLookupError):
        os.kill(identity["pid"], 0)


@pytest.mark.external
def test_async_cancel_reaches_a_real_blocking_subprocess(tmp_path):
    async def check():
        budget = ExecutionBudget(10)
        pid_file = tmp_path / "pid"
        worker = asyncio.create_task(budget.run_sync(run_process,
            [sys.executable, "-c", "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)",
             str(pid_file)], budget=budget, timeout=30, capture_output=True))
        deadline = time.monotonic() + 2
        while not pid_file.is_file() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        assert pid_file.is_file()
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        assert budget.cancelled.is_set()
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
    asyncio.run(check())


@pytest.mark.external
def test_operation_timeout_is_not_session_expiry():
    budget = ExecutionBudget(10)
    with pytest.raises(subprocess.TimeoutExpired):
        run_process([sys.executable, "-c", "import time; time.sleep(60)"],
                    budget=budget, timeout=0.1, capture_output=True)
    budget.check()


@pytest.mark.external
def test_stdin_is_not_replayed_after_communicate_poll():
    budget = ExecutionBudget(10)
    result = run_process([sys.executable, "-c",
        "import sys,time; value=sys.stdin.read(); time.sleep(0.3); print(value,end='')"],
        budget=budget, timeout=2, capture_output=True, text=True, input="once")
    assert result.stdout == "once"


@pytest.mark.external
def test_docker_budget_expiry_removes_own_container(tmp_path):
    from fmst_analyzer.runner.runtime_builder import DockerRuntimeBuilder
    image = os.environ.get("FMST_RUNTIME_BUILDER_IMAGE")
    if not image:
        pytest.skip("requires configured local Linux builder image")
    (tmp_path / "src").mkdir()
    builder = DockerRuntimeBuilder(image=image, project_root=tmp_path, workdir=tmp_path,
                                   budget=ExecutionBudget(6, cleanup_seconds=2))
    with pytest.raises(RunnerStopped, match="session_budget_exhausted"):
        builder._run(["python3", "-c", "import time; time.sleep(60)"], timeout=30)
    assert len(builder.cleanup_records) == 1
    record = builder.cleanup_records[0]
    assert record.get("returncode") == 0, record
    remaining = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=^{record['container']}$"],
                               capture_output=True, text=True, check=True, timeout=5)
    assert not remaining.stdout.strip()
