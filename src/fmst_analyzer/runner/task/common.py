"""Small filesystem/process protocol shared by the worker and container init."""
import json
import os
import fcntl
import time
from contextlib import contextmanager
from pathlib import Path

TASK = Path("/task")
CONTROL = Path("/run/fmst")


@contextmanager
def lifecycle_lock():
    """Serialize completion with PID 1's deadline/resource decision."""
    with (CONTROL / "lifecycle.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def retain_service(completion, hashes):
    with lifecycle_lock():
        if (TASK / "delivery/host-stop.json").exists():
            raise RuntimeError("Task already stopped by its host")
        if process_identity(completion.service_pid) != completion.service_start_ticks:
            raise ValueError("Service process identity is no longer live")
        if (TASK / "delivery/completion.json").exists():
            raise RuntimeError("Original completion is frozen; write follow-up findings separately")
        state_path = CONTROL / "lifecycle.json"
        state = json.loads(state_path.read_text())
        now = time.time()
        write_json(TASK / "delivery/evidence.json", hashes)
        write_json(TASK / "delivery/completion.json", completion.model_dump(mode="json"))
        state.update(status="serving", agent_phase="handoff", completed_at=now,
                     handoff_deadline=min(state["deadline"], now + 300))
        write_json(state_path, state)


def finish_agent_phase():
    if not (CONTROL / "lifecycle.json").exists():
        return
    with lifecycle_lock():
        path = CONTROL / "lifecycle.json"
        if path.exists():
            state = json.loads(path.read_text())
            state["agent_phase"] = "exited"
            write_json(path, state)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def process_identity(pid: int) -> int | None:
    try:
        # comm can contain spaces and parentheses; fields after its final ')'.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] == "Z" else int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def evidence_file(value: str) -> Path:
    path = Path(value).resolve(strict=True)
    if not path.is_relative_to(TASK / "evidence") or not path.is_file():
        raise ValueError("Evidence must be a regular file under /task/evidence")
    return path


def clean_environment() -> dict[str, str]:
    """Do not pass model authentication to services and installation commands."""
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("ANTHROPIC_", "FMST_CLAUDE_", "FMST_CODEX_"))
            and key not in {"OPENAI_API_KEY", "OPENAI_BASE_URL"}}
