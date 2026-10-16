"""Private, persistent native Claude state. Closing never deletes history."""

from __future__ import annotations

import fcntl
import json
import os
import time
import uuid
from pathlib import Path


class ClaudeSession:
    """Own one native session directory and exclude concurrent SDK writers.

    The receipt contains identity, not prompts, credentials or serialized tools.
    Callers must reconstruct tools and authentication when resuming. Native
    transcripts stay in config/projects in the CLI's original format.
    """

    def __init__(self, directory: Path | None, *, resume: bool, identity: dict):
        if resume and directory is None:
            raise ValueError("resume requires an explicit session_dir")
        if directory is None:
            state = Path(os.getenv("XDG_STATE_HOME") or Path.home() / ".local/state")
            directory = state / "firmenstein/claude" / uuid.uuid4().hex
        self.directory = Path(directory).resolve()
        self.receipt_path = self.directory / "session.json"
        self.config_dir = self.directory / "config"
        self.resuming = resume
        self._lock = None
        if resume:
            if not self.receipt_path.is_file():
                raise ValueError("Native session receipt is missing; refusing to start a new session")
        else:
            # Reusing an existing directory must be an explicit resume.
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.directory.chmod(0o700)
        lock = (self.directory / "session.lock").open("a")
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock = lock
            if resume:
                self.data = json.loads(self.receipt_path.read_text())
                if self.data.get("schema_version") != 1 or self.data.get("provider") != "claude":
                    raise ValueError("Unsupported native session receipt")
                if self.data.get("identity") != identity:
                    raise ValueError("Native session identity differs from the requested workdir, tools or Skills")
                expected_cwd = str(self.directory / "shell-cwd") if identity["filesystem_access"] == "read_shell" else identity["workdir"]
                if self.data.get("sdk_cwd", expected_cwd) != expected_cwd:
                    raise ValueError("Restore the original native project cwd before resuming")
                self.data["sdk_cwd"] = expected_cwd
                self.require_transcript()
            else:
                self.config_dir.mkdir(mode=0o700)
                self.data = {"schema_version": 1, "provider": "claude", "identity": identity,
                             "session_id": str(uuid.uuid4()), "turn_count": 0,
                             "sdk_cwd": str(self.directory / "shell-cwd") if identity["filesystem_access"] == "read_shell" else identity["workdir"],
                             "created_at": time.time(), "state": "prepared"}
                self.save()
        except BaseException:
            lock.close()
            self._lock = None
            raise

    @property
    def session_id(self) -> str:
        return self.data["session_id"]

    def require_transcript(self) -> None:
        session_id = self.session_id
        # Only a canonical native ID can be used in a path or SDK resume.
        if str(uuid.UUID(session_id)) != session_id:
            raise ValueError("Invalid native session ID")
        if not any(p.is_file() and p.stat().st_size for p in
                   (self.config_dir / "projects").rglob(session_id + ".jsonl")):
            raise ValueError("Native transcript is missing or empty; refusing to start a new session")

    def bind(self, session_id: str) -> None:
        if self.resuming and session_id != self.session_id:
            raise ValueError("SDK returned a different session while resuming")
        self.data["session_id"] = session_id
        self.data["state"] = "connected"
        self.save()

    def save(self) -> None:
        self.data["updated_at"] = time.time()
        temporary = self.receipt_path.with_suffix(".json.tmp")
        with temporary.open("w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(self.data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.receipt_path)

    def close(self) -> None:
        if self._lock is None:
            return
        try:
            self.data["state"] = "closed"
            self.save()
        finally:
            self._lock.close()
            self._lock = None
