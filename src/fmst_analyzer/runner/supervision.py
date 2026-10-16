"""Independent, read-only process supervision for one disposable attempt.

The observer wakes the Controller; it never deletes the execution container.
That leaves one owner responsible for capturing evidence before cleanup.
"""

from __future__ import annotations

from collections import deque
import json
from pathlib import Path
import re
import subprocess
import threading
import time

from .budget import ExecutionBudget, RunnerStopped, run_process


def parse_process_table(output: str) -> list[dict[str, object]]:
    """Parse Docker's host PID table, retaining start time against PID reuse.

    Command text is evidence, never executable input. Unexpected rows make the
    observation fail rather than falsely establishing that all guests exited.
    """
    rows = output.splitlines()
    if not rows or rows[0].split() != ["PID", "PPID", "STAT", "STARTED", "COMMAND"]:
        raise ValueError("unexpected Docker process table header")
    processes: list[dict[str, object]] = []
    for row in rows[1:]:
        if not row.strip():
            continue
        fields = row.split(maxsplit=8)
        if len(fields) != 9:
            raise ValueError("incomplete Docker process table row")
        processes.append({
            "pid": int(fields[0]), "ppid": int(fields[1]),
            "state": fields[2], "started": " ".join(fields[3:8]),
            "command": fields[8],
        })
    return processes


class TargetProgressWatchdog:
    """Observe process identities and probe progress without interpreting success.

    Host PIDs from Docker are not guest PIDs from trace. Roles are identified
    by the Controller-owned trace argument before the guest argv separator,
    then inherited by observed descendants. Unattributed processes prevent a
    claim that a role has completely exited. Terminal checkpoints alone never
    terminate supervision of a surviving daemon child.
    """

    def __init__(self, *, container_name: str, attempt_dir: Path,
                 stall_seconds: float, peer_count: int = 0,
                 poll_seconds: float = 0.5, budget: ExecutionBudget | None = None) -> None:
        self.container_name = container_name
        self.attempt_dir = attempt_dir
        self.stall_seconds = max(0.05, stall_seconds)
        self.poll_seconds = max(0.01, poll_seconds)
        self.path = attempt_dir / "watchdog.json"
        self.process_path = attempt_dir / "processes.json"
        self.final_process_path = attempt_dir / "processes-final.json"
        self.budget = budget
        self.final_observation: dict[str, object] | None = None
        self.triggered = False
        self.termination_reason = "unknown"
        self.last_heartbeat: dict[str, object] | None = None
        self.last_processes: list[dict[str, object]] = []
        self.last_sample_monotonic: float | None = None
        self.observation_error: str | None = None
        self.interrupted = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._requested_reason = "controller_cleanup"
        self._roles = {"/fmst-output/runtime_trace.json": "target"}
        self._roles.update({
            f"/fmst-output/runtime_trace.peer-{index:02d}.json": f"peer-{index:02d}"
            for index in range(1, peer_count + 1)
        })
        self._known: dict[tuple[object, object], str] = {}
        self._seen: set[str] = set()
        self._events: deque[dict[str, object]] = deque(maxlen=128)
        self._event_count = 0
        self._step: int | None = None
        self._step_started: float | None = None
        self._probe_attempts = 0
        self._response_seen = False
        self._step_started_unix_ns: int | None = None
        self._last_probe_unix_ns: int | None = None
        self._last_response_unix_ns: int | None = None
        self._last_response_monotonic: float | None = None
        self._container_exited = False
        self._started_unix_ns: int | None = None

    @property
    def target_alive(self) -> bool:
        """Positive liveness at the last completed process observation only."""
        return self.observation_error is None and any(
            p.get("role") == "target" and not str(p["state"]).startswith(("Z", "X"))
            for p in self.last_processes
        )

    @property
    def target_alive_after_probe(self) -> bool:
        """Positive final sample begun after the most recent response.

        This is a point observation, not proof of continuous service liveness.
        An old monitor sample or failed final read cannot satisfy it.
        """
        sample = self.final_observation
        return bool(sample and sample["status"] == "complete"
                    and sample["after_last_response"] and self.target_alive)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run,
            name=f"fmst-watchdog-{self.container_name}", daemon=True)
        self._thread.start()

    def stop(self, reason: str) -> None:
        self._requested_reason = reason
        self._stop.set()

    def join(self) -> None:
        if self._thread is not None:
            timeout = min(5.0, self.budget.remaining(cleanup=True)) if self.budget else 5.0
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                raise RuntimeError("process observer did not stop within its bounded read timeout")

    def begin_step(self, index: int) -> None:
        with self._lock:
            self._step = index
            self._step_started = time.monotonic()
            self._step_started_unix_ns = time.time_ns()
            self._last_probe_unix_ns = None
            self._last_response_unix_ns = None
            self._last_response_monotonic = None
            self._probe_attempts = 0
            self._response_seen = False

    def probe_attempted(self) -> None:
        with self._lock:
            self._probe_attempts += 1
            self._last_probe_unix_ns = time.time_ns()

    def response_received(self) -> None:
        with self._lock:
            self._response_seen = True
            self._last_response_unix_ns = time.time_ns()
            self._last_response_monotonic = time.monotonic()
            self._step_started = None

    def _event(self, kind: str, **details: object) -> None:
        self._event_count += 1
        self._events.append({"kind": kind, "unix_ns": time.time_ns(), **details})

    def _process(self, command: list[str]) -> subprocess.CompletedProcess:
        if self.budget is not None:
            return run_process(command, budget=self.budget, timeout=2.0,
                               capture_output=True, text=True)
        return subprocess.run(command, capture_output=True, text=True, timeout=2.0)

    def _read_processes(self) -> list[dict[str, object]]:
        result = self._process(
            ["docker", "top", self.container_name, "-eo", "pid,ppid,stat,lstart,args"],
        )
        if result.returncode:
            state = self._process(
                ["docker", "inspect", "--format", "{{.State.Running}}", self.container_name],
            )
            if state.returncode == 0 and state.stdout.strip() == "false":
                self._container_exited = True
                return []
            raise RuntimeError(f"Docker process observation failed: {result.stderr}")
        return parse_process_table(result.stdout)

    def _read_heartbeats(self) -> list[dict[str, object]]:
        values = []
        for path in sorted(self.attempt_dir.glob("runtime_trace*.heartbeat.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue  # A partial checkpoint is not evidence of guest exit.
            if isinstance(value, dict):
                values.append({**value, "path": str(path)})
        return values

    @staticmethod
    def _helper(command: str) -> bool:
        # These are exact Controller-owned executables, not guest name rules.
        prefix = "/fmst-host/ld.so --library-path /fmst-host/lib /fmst-host/"
        if not command.startswith(prefix):
            return False
        executable, _, args = command.removeprefix(prefix).partition(" ")
        return executable in {"sleep", "nc"} or (
            executable == "sh" and re.fullmatch(r"/fmst-host/attempt-\d+\.sh", args) is not None
        )

    def _classify(self, processes: list[dict[str, object]]) -> tuple[set[str], bool]:
        alive = [p for p in processes if not str(p["state"]).startswith(("Z", "X"))]
        assigned: dict[int, str] = {}
        for process in alive:
            command = str(process["command"])
            harness_args = command.partition(" -- ")[0]
            marker = re.search(r"(?:^| )--trace-output (/fmst-output/[^ ]+)(?: |$)", harness_args)
            # Keep the trace-output path as the identity anchor even when a
            # daemonized guest child has been reparented.  The child inherits
            # the harness command line, but no longer has the original
            # harness PID/PPID chain; requiring the harness executable *and*
            # the ancestry would therefore turn a live daemon into an
            # unexplained/unknown process.  The path is Controller-generated,
            # role-specific, and mounted only for this attempt, so it is a
            # stronger identity signal than a binary basename.
            role = self._roles.get(marker.group(1)) if marker else None
            role = role or self._known.get((process["pid"], process["started"]))
            if role:
                assigned[int(process["pid"])] = role
        changed = True
        while changed:
            changed = False
            for process in alive:
                pid, ppid = int(process["pid"]), int(process["ppid"])
                if pid not in assigned and ppid in assigned:
                    assigned[pid] = assigned[ppid]
                    changed = True
        self._known = {
            (p["pid"], p["started"]): assigned[int(p["pid"])]
            for p in alive if int(p["pid"]) in assigned
        }
        for process in processes:
            process["role"] = assigned.get(int(process["pid"]))
        roles = set(assigned.values())
        self._seen.update(roles)
        unknown = any(int(p["pid"]) not in assigned and not self._helper(str(p["command"])) for p in alive)
        return roles, unknown

    def _exited(self, role: str) -> bool:
        path = self.attempt_dir / ("target-exit.json" if role == "target" else f"{role}-exit.json")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return type(payload.get("exit_code")) is int
        except (OSError, ValueError, AttributeError):
            return False

    def _interrupt(self, reason: str, **details: object) -> None:
        if self.triggered:
            return  # Preserve the event that actually woke the probe.
        self.triggered = True
        self.termination_reason = reason
        self._event(reason, **details)
        self.interrupted.set()

    def _check_exits(self, roles: set[str], unknown: bool) -> None:
        if self._container_exited:
            self._interrupt("container_exit")
            return
        for role in self._roles.values():
            if role not in roles and not unknown and (role in self._seen or self._exited(role)):
                self._interrupt("target_exit" if role == "target" else "peer_exit", role=role)
                break

    def sample_after_probe(self) -> None:
        """Join the monitor, then take one bounded final sample before cleanup.

        Preserve the last successful monitor table separately. A failed final
        observation contains no fabricated process table and invalidates a
        final liveness claim. Controller budget/cancellation still propagates.
        """
        self._sample_final('after_probe')

    def sample_for_service(self) -> None:
        """Observe startup liveness without implying any protocol interaction."""
        self._sample_final('service_startup')

    def _sample_final(self, purpose: str) -> None:
        self.join()
        started = time.monotonic()
        self.final_observation = sample = {
            "schema_version": 1, "purpose": purpose,
            "sample_started_unix_ns": time.time_ns(), "sample_finished_unix_ns": None,
            "pid_namespace": "docker_host", "status": "error", "processes": [],
            "last_response_unix_ns": self._last_response_unix_ns,
            "after_last_response": self._last_response_monotonic is not None
                and started >= self._last_response_monotonic,
            "unattributed_live_processes": None, "error": None,
            "last_monitor_sample": self.process_path.name,
        }
        try:
            processes = self._read_processes()
            roles, unknown = self._classify(processes)
            self.last_processes = processes
            self.observation_error = None
            sample.update(status="complete", processes=processes, unattributed_live_processes=unknown)
            self._check_exits(roles, unknown)
        except RunnerStopped as error:
            self.observation_error = str(error)
            sample.update(status="stopped", error=error.reason)
            self._interrupt(error.reason)
            raise
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.observation_error = str(error)
            sample["error"] = str(error)
            self._interrupt("observation_failed", detail=str(error))
        finally:
            sample["sample_finished_unix_ns"] = time.time_ns()
            temporary = self.final_process_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(sample, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.final_process_path)
            self._event("final_process_observation", status=sample["status"],
                        after_last_response=sample["after_last_response"],
                        evidence=self.final_process_path.name)
            self._write_state(self._started_unix_ns or sample["sample_started_unix_ns"])

    def _write_state(self, started: int) -> None:
        with self._lock:
            progress = {
                "step": self._step, "started_unix_ns": self._step_started_unix_ns,
                "probe_attempts": self._probe_attempts, "last_probe_unix_ns": self._last_probe_unix_ns,
                "response_seen": self._response_seen, "last_response_unix_ns": self._last_response_unix_ns,
            }
        payload = {
            "schema_version": 2, "started_unix_ns": started,
            "finished_unix_ns": time.time_ns(), "container": self.container_name,
            "poll_seconds": self.poll_seconds, "stall_seconds": self.stall_seconds,
            "triggered": self.triggered, "termination_reason": self.termination_reason,
            "last_heartbeat": self.last_heartbeat,
            "processes_path": self.process_path.name, "pid_namespace": "docker_host",
            "observation_error": self.observation_error,
            "final_processes_path": self.final_process_path.name if self.final_observation else None,
            "probe_progress": progress,
            "events": list(self._events), "events_total": self._event_count,
            "events_dropped": self._event_count - len(self._events),
        }
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)

    def _run(self) -> None:
        started = time.time_ns()
        self._started_unix_ns = started
        last_observation = time.monotonic()
        last_signature: object = None
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                try:
                    processes = self._read_processes()
                    roles, unknown = self._classify(processes)
                    self.last_processes = processes
                    self.last_sample_monotonic = time.monotonic()
                    self.observation_error = None
                    last_observation = now
                    temporary = self.process_path.with_suffix(".json.tmp")
                    temporary.write_text(json.dumps({
                        "schema_version": 1, "sampled_unix_ns": time.time_ns(),
                        "pid_namespace": "docker_host", "processes": processes,
                        "unattributed_live_processes": unknown,
                    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                    temporary.replace(self.process_path)
                    signature = tuple((p["pid"], p["started"], p["state"], p["role"]) for p in processes)
                    if signature != last_signature:
                        self._event("process_state", roles=sorted(roles), unattributed=unknown,
                            identities=[{k: p[k] for k in ("pid", "ppid", "started", "state", "role")}
                                        for p in processes])
                        last_signature = signature
                    self._check_exits(roles, unknown)
                except RunnerStopped as error:
                    self.observation_error = str(error)
                    self._interrupt(error.reason)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    self.observation_error = str(error)
                    self._event("observation_error", detail=str(error))
                    if now - last_observation >= self.stall_seconds:
                        self._interrupt("observation_failed", detail=str(error))
                heartbeats = self._read_heartbeats()
                if heartbeats:
                    self.last_heartbeat = heartbeats[-1]
                with self._lock:
                    step_started, attempts = self._step_started, self._probe_attempts
                    step, response_seen = self._step, self._response_seen
                if not self.interrupted.is_set() and step_started is not None and attempts and not response_seen:
                    # Two health windows bound an unanswered interaction. A
                    # heartbeat-only signature never triggers this decision.
                    if now - step_started >= 2 * self.stall_seconds:
                        self._interrupt("no_progress_watchdog", step=step, probe_attempts=attempts,
                            basis="interaction window expired without a response; not proof of a spin loop")
                self._write_state(started)
                if self.interrupted.is_set() or self._stop.wait(self.poll_seconds):
                    break
        except Exception as error:
            self.observation_error = str(error)
            self._interrupt("observation_failed", detail=str(error))
        finally:
            if not self.triggered:
                self.termination_reason = self._requested_reason
            self._write_state(started)
