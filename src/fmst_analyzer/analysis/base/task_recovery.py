"""Durable checkpoints for successful, exactly matched Agent tasks.

Checkpoints are independent of stage publications: incomplete attempts remain
diagnostic evidence. Recovery revalidates each output and never reuses failures.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile

from pydantic import BaseModel

from .input_provenance import active_analysis_inputs

_recovery = ContextVar("analyzer_task_recovery", default=None)


def recovery_available() -> bool:
    state = _recovery.get()
    inputs = active_analysis_inputs()
    return state is not None and inputs is not None and inputs.phase == "full" and getattr(state[0], "workdir", None) is not None


@contextmanager
def task_recovery_scope(config, metadata):
    events = []
    metadata["task_recovery"] = events
    token = _recovery.set((config, metadata, events, {}))
    try:
        yield
    finally:
        _recovery.reset(token)


def _sha(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def checkpoint_path(*, contract: dict) -> Path | None:
    state = _recovery.get()
    inputs = active_analysis_inputs()
    if not recovery_available():
        return None
    config, metadata, _, contracts = state
    identity = inputs.model_dump(mode="json")
    # Scheduling does not change the input/evidence/Agent contract. Stage
    # receipts still bind its actual concurrency; only task recovery ignores it.
    identity["settings"].pop("agent_concurrency_limit", None)
    material = {"version": 1, "inputs": identity, "contract": contract}
    key = _sha(material)
    path = Path(config.target_diagnostic_reports_dir()) / ".task_checkpoints" / inputs.stage / f"{key}.json"
    contracts[path] = material
    return path


def _event(path, disposition, **details):
    state = _recovery.get()
    if state:
        event = {"checkpoint": str(path), "disposition": disposition, **details}
        state[2].append(event)
        attempt = state[1].get("attempt_path")
        if attempt:
            journal = Path(attempt) / "task_recovery.jsonl"
            journal.parent.mkdir(parents=True, exist_ok=True)
            with journal.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())


def load_checkpoint(path: Path | None, output_type: type[BaseModel]):
    state = _recovery.get()
    if path is None or state is None or not getattr(state[0], "resume_analyzer_tasks", False):
        return None
    try:
        envelope = json.loads(path.read_text())
        if (envelope["version"] != 1 or envelope["key"] != path.stem
                or envelope["status"] != "completed"
                or envelope["identity"] != state[3][path]
                or _sha(envelope["identity"]) != path.stem
                or envelope["output_sha256"] != _sha(envelope["output"])):
            raise ValueError("checkpoint identity/status/content mismatch")
        output = output_type.model_validate(envelope["output"])
    except FileNotFoundError:
        _event(path, "missing")
        return None
    except (OSError, ValueError, KeyError, TypeError) as error:
        _event(path, "rejected", reason=f"{type(error).__name__}: invalid checkpoint")
        return None
    _event(path, "loaded", source_attempt=envelope["source_attempt"], output_sha256=envelope["output_sha256"])
    return output


def record_revalidated(path):
    _event(path, "reused_after_validation")


def record_rejected(path, error):
    from .execution import diagnostic_reason
    _event(path, "rejected_after_validation", reason=diagnostic_reason(error))


def store_checkpoint(path: Path | None, output: BaseModel):
    if path is None:
        return
    state = _recovery.get()
    payload = output.model_dump(mode="json")
    envelope = dict(version=1, key=path.stem, status="completed", output=payload,
                    identity=state[3][path],
                    output_sha256=_sha(payload), source_attempt=state[1].get("attempt_path"),
                    analysis_inputs=active_analysis_inputs().model_dump(mode="json"),
                    created_at=datetime.now(timezone.utc).isoformat())
    # The shared lookup may be replaced by a later fresh run. Each producing
    # attempt retains its original envelope, including before abrupt shutdown.
    attempt = state[1].get("attempt_path")
    if attempt:
        retained = Path(attempt) / "task_checkpoints" / path.name
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_text(json.dumps(envelope, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(envelope, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    _event(path, "stored", output_sha256=envelope["output_sha256"])
