"""Runner follow-ups preserve original delivery and native session backups."""
import asyncio
import gzip
import io
import json
import tarfile
from types import SimpleNamespace

import pytest


def test_worker_resume_sends_only_followup_and_keeps_original_records(monkeypatch, tmp_path):
    import fmst_basic.agent as agents
    from fmst_analyzer.runner.task import worker, analysis_rpc

    monkeypatch.setattr(worker, "TASK", tmp_path)
    (tmp_path / "evidence").mkdir()
    (tmp_path / "delivery").mkdir()
    original_report = tmp_path / "evidence/agent.md"
    original_report.write_text("original business history")
    completion = tmp_path / "delivery/completion.json"
    completion.write_text('{"original":true}')
    (tmp_path / "task.json").write_text(json.dumps({"task_id": "fixture-task", "goal": "original goal",
                                                   "capability_probe": True}))
    calls = []

    class Analysis:
        def __init__(self, *_):
            pass

        async def close(self):
            calls.append("analysis-close")

    class Agent:
        session_receipt = tmp_path / "sessions/runner/session.json"

        async def ainvoke(self, message, trace):
            calls.append(message)
            assert trace.md_path != original_report
            assert trace.md_path.parent == tmp_path / "evidence/resumes"
            return SimpleNamespace(status="completed", text="follow-up result")

        async def aclose(self):
            calls.append("agent-close")

    def create(**kwargs):
        assert kwargs["resume"] is True
        assert kwargs["session_dir"] == tmp_path / "sessions/runner"
        assert kwargs["name"] == "runner-container:fixture-task"
        return Agent()

    monkeypatch.setattr(agents, "create_analysis_agent", create)
    monkeypatch.setattr(analysis_rpc, "AnalysisClient", Analysis)
    asyncio.run(worker.run_session({"FMST_CLAUDE_MODEL": "test", "FMST_CLAUDE_REASONING_EFFORT": "high"},
                                   resume_message="organize retained artifacts"))
    assert calls == ["organize retained artifacts", "agent-close", "analysis-close"]
    assert original_report.read_text() == "original business history"
    assert completion.read_text() == '{"original":true}'
    replies = list((tmp_path / "evidence/resumes").glob("*.json"))
    assert len(replies) == 1
    assert json.loads(replies[0].read_text())["text"] == "follow-up result"


def native_archive_bytes():
    data = b'{"type":"user","message":"original transcript"}\n'
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        item = tarfile.TarInfo("sessions/runner/config/projects/project/session.jsonl")
        item.size = len(data)
        archive.addfile(item, io.BytesIO(data))
    return stream.getvalue(), data


@pytest.mark.parametrize("failed", [False, True])
def test_native_backup_is_private_and_failed_copy_keeps_previous_backup(monkeypatch, tmp_path, failed):
    from fmst_analyzer.runner.task import host
    task = host.ContainerTask(output=tmp_path / "task", target="fixture", image="fixture")
    stream, data = native_archive_bytes()
    private = task.output / "private"
    private.mkdir()
    output = private / "agent-sessions.tar.gz"
    output.write_bytes(b"previous backup")

    class Process:
        def __init__(self, command, **_):
            assert command[-3:] == ["cp", f"{task.name}:/task/sessions", "-"]
            self.stdout = io.BytesIO(stream)
            self.stderr = io.BytesIO(b"copy failed" if failed else b"")

        def wait(self):
            return 1 if failed else 0

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    monkeypatch.setattr(host.subprocess, "Popen", Process)
    if failed:
        with pytest.raises(RuntimeError, match="archive failed"):
            task.archive_session()
        assert output.read_bytes() == b"previous backup"
    else:
        task.archive_session()
        assert output.stat().st_mode & 0o777 == 0o600
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(output.read_bytes()))) as archive:
            assert archive.extractfile(archive.getmembers()[0]).read() == data
        assert (private / "session-retention.json").is_file()
    assert private.stat().st_mode & 0o777 == 0o700
    assert not task.result.container_removed
