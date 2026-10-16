"""Container PID 1 delegate: owns services independently of Claude's lifetime.

Requests are local task files, not a command allowlist. Agent has sudo anyway.
This process owns the deadline even if the host client disconnects.
"""
import json
import os
import signal
import subprocess
import time
import shutil
from pathlib import Path

from .common import CONTROL, TASK, clean_environment, process_identity, write_json, lifecycle_lock


def stop_reason(state, *, now):
    if state["status"] == "repairing" and now >= state["deadline"]:
        return "budget_exhausted"
    return None


def handoff_expired(state, now):
    return (state.get("status") == "serving" and state.get("agent_phase") == "handoff"
            and now >= state["handoff_deadline"])


def main():
    CONTROL.mkdir(parents=True, exist_ok=True)
    os.chmod(CONTROL, 0o700)
    lock = CONTROL / "lifecycle.lock"
    lock.touch()
    shutil.chown(lock, user="runner", group="runner")
    for name in ("work", "evidence", "delivery", "control", "control/requests", "control/replies"):
        path = TASK / name
        path.mkdir(parents=True, exist_ok=True)
        shutil.chown(path, user="runner", group="runner")
    jobs = {}
    executions = {}
    stopped = False
    last_snapshot = 0

    def terminate(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    while not stopped:
        for request in sorted((TASK / "control/requests").glob("*.json")):
            reply = TASK / "control/replies" / request.name
            if reply.exists():
                continue
            try:
                value = json.loads(request.read_text())
                log_path = TASK / "evidence" / (request.stem + ".log")
                with log_path.open("ab") as log:
                    process = subprocess.Popen(value["argv"], cwd=value.get("cwd", "/task/work"),
                        env={**clean_environment(), **value.get("env", {})},
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        start_new_session=True)
                jobs[process.pid] = process
                result = {"pid": process.pid, "start_ticks": process_identity(process.pid), 'log': str(log_path)}
                if value.get('execution_path'):
                    from .execution import update_execution, process_record
                    path = Path(value['execution_path'])
                    record = json.loads(path.read_text())
                    changes = {'log_paths': record['log_paths'] + [{'path': str(log_path), 'role': value.get('role', 'job')}]}
                    if value.get('role') == 'firmware':
                        changes['process'] = process_record(process.pid)
                        executions[process.pid] = path
                    update_execution(path, **changes)
                    result['execution_path'] = str(path)
                write_json(reply, result)
            except Exception as error:
                write_json(reply, {"error": str(error)})
        for pid, process in list(jobs.items()):
            if process.poll() is not None:
                jobs.pop(pid)
                if pid in executions:
                    from .execution import finish_execution
                    finish_execution(executions.pop(pid), process.returncode)
        lifecycle = CONTROL / "lifecycle.json"
        if lifecycle.exists():
            state = json.loads(lifecycle.read_text())
            mem = {line.split(":")[0]: int(line.split()[1]) * 1024
                   for line in open("/proc/meminfo") if line.startswith("MemAvailable:")}
            available = mem["MemAvailable"]
            disk = shutil.disk_usage(TASK).free
            if time.time() - last_snapshot >= 5:
                write_json(TASK / "delivery/resource.json", {"at": time.time(),
                    "disk_free_bytes": disk, "memory_available_bytes": available,
                    "lifecycle": state["status"], "jobs": len(jobs)})
                last_snapshot = time.time()
            with lifecycle_lock():
                # Completion may have arrived during resource sampling.
                state = json.loads(lifecycle.read_text())
                reason = stop_reason(state, now=time.time())
                if reason:
                    write_json(TASK / "delivery/host-stop.json", {"status": reason, "at": time.time()})
                    stopped = True
                elif handoff_expired(state, time.time()):
                    # Bound the model even after a host disconnect. The service
                    # and its init-owned peers remain running.
                    from .worker_control import main as stop_worker
                    stop_worker()
                    state["agent_phase"] = "exited"
                    write_json(lifecycle, state)
                    status_path = TASK / "delivery/handoff-status.json"
                    status = json.loads(status_path.read_text()) if status_path.exists() else {}
                    if status.get("status") not in {"ready", "invalid", "error"}:
                        write_json(status_path, {**status, "status": "timeout", "finished_at": time.time()})
        time.sleep(1)
    for process in jobs.values():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    # Container exit stops every descendant, including manual Agent processes.


if __name__ == "__main__":
    main()
