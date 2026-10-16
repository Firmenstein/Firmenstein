"""Container permissions and version/identity boundaries, without Docker/model calls."""
import asyncio
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from fmst_basic.agent import create_analysis_agent
from fmst_analyzer.runner.task.schema import TaskResult, ServiceCompletion
from fmst_analyzer.runner.task import common


def test_full_tools_cannot_be_selected_on_host(monkeypatch, tmp_path):
    monkeypatch.delenv("FMST_RUNNER_CONTAINER", raising=False)
    with pytest.raises(ValueError, match="container entrypoint"):
        create_analysis_agent(provider="claude", model="test", developer_instructions="",
                              workdir=tmp_path, filesystem_access="container")


def test_container_full_tools_have_no_path_or_short_watchdog(monkeypatch, tmp_path):
    monkeypatch.setenv("FMST_RUNNER_CONTAINER", "1")
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda self: str(self) == "/.dockerenv" or original(self))
    agent = create_analysis_agent(provider="claude", model="test", developer_instructions="",
                                  workdir=tmp_path, filesystem_access="container")
    try:
        events = []
        monkeypatch.setattr(agent, "_record_container_tool", lambda *args: events.append(args))
        assert agent._options.tools == {"type": "preset", "preset": "claude_code"}
        assert agent._options.permission_mode == "bypassPermissions"
        assert agent.default_tool_timeout_seconds is None
        assert "Bash" not in agent._options.disallowed_tools
        assert "AskUserQuestion" in agent._options.disallowed_tools
        assert asyncio.run(agent._native_tool_started(
            {"tool_name": "Bash", "tool_input": {"command": "sudo apt-get update"}}, "test", None)) == {}
        assert not agent._active_native_tools
        assert events[0][0] == "started"
    finally:
        asyncio.run(agent.aclose())


def test_container_result_does_not_accept_controller_receipts():
    with pytest.raises(ValidationError):
        TaskResult.model_validate({"status": "success", "attempts": []})
    with pytest.raises(ValidationError):
        TaskResult.model_validate({"schema_version": 99, "task_id": "x", "target": "httpd",
                                  "started_at": 0, "status": "serving", "report_dir": "r"})


def test_evidence_symlink_cannot_bind_an_outside_file(monkeypatch, tmp_path):
    monkeypatch.setattr(common, "TASK", tmp_path / "task")
    root = tmp_path / "task/evidence"
    root.mkdir(parents=True)
    outside = tmp_path / "unrelated.json"
    outside.write_text("{}")
    (root / "evidence.json").symlink_to(outside)
    with pytest.raises(ValueError, match="under /task/evidence"):
        common.evidence_file(str(root / "evidence.json"))


def test_completion_releases_deadline_and_external_stop_stays_authoritative(monkeypatch, tmp_path):
    from fmst_analyzer.runner.task.init import stop_reason
    task = tmp_path / "task"
    control = tmp_path / "control"
    control.mkdir()
    monkeypatch.setattr(common, "TASK", task)
    monkeypatch.setattr(common, "CONTROL", control)
    monkeypatch.setattr(common, "process_identity", lambda pid: 123)
    completion = ServiceCompletion(summary="native service", native_url="http://device/",
        service_pid=42, service_start_ticks=123, access="local proxy",
        interactions=[{"operation": "read settings", "observed": "native state", "evidence": ["/task/evidence/read.json"]}])
    common.write_json(control / "lifecycle.json", {"status": "repairing", "deadline": 1})
    common.retain_service(completion, {})
    state = json.loads((control / "lifecycle.json").read_text())
    assert stop_reason(state, now=100) is None
    assert stop_reason({"status":"repairing", "deadline":1}, now=100) == "budget_exhausted"
    common.write_json(task / "delivery/host-stop.json", {"status": "resource_stopped"})
    with pytest.raises(RuntimeError, match="already stopped"):
        common.retain_service(completion, {})


def test_explicit_attempt_limit_is_not_silently_ignored():
    from fmst_analyzer.runner.task.runner import ContainerRehostingRunner
    with pytest.raises(ValueError, match="max_attempts"):
        ContainerRehostingRunner(None, max_attempts=2)


def test_delivery_options_are_read_at_runner_entry(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fmst_analyzer.runner.task import runner
    config = SimpleNamespace(workdir=tmp_path, current_target="httpd",
                             target_diagnostic_reports_dir=lambda: tmp_path / "reports")
    task_runner = runner.ContainerRehostingRunner(config)
    # The upstream process/Runner object already exists when the caller chooses
    # the evaluation scope. Its original Goal and budget must stay unchanged.
    common.write_json(tmp_path / "runner-options.json", {"schema_version":1, "delivery_mode":"rehosting_only"})
    calls = []
    class Task:
        def __init__(self, **kwargs): calls.append(kwargs)
        def create(self): pass
        def configure(self, spec): pass
        async def run(self): return "retained"
    monkeypatch.setattr(runner, "ContainerTask", Task)
    monkeypatch.setattr(runner, "prepare", lambda *args, **kwargs: {})
    assert asyncio.run(task_runner.run(view=None, rootfs=tmp_path, runtime_workspace=tmp_path)) == "retained"
    assert calls[0]["delivery_mode"] == "rehosting_only" and calls[0]["budget_seconds"] == 7200


def test_invalid_delivery_options_fail_before_creating_a_container(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fmst_analyzer.runner.task import runner
    config = SimpleNamespace(workdir=tmp_path)
    common.write_json(tmp_path / "runner-options.json", {"schema_version":1, "delivery_mode":"typo"})
    monkeypatch.setattr(runner, "ContainerTask", lambda **kwargs: pytest.fail("No Docker side effects allowed"))
    with pytest.raises(ValidationError):
        asyncio.run(runner.ContainerRehostingRunner(config).run(view=None, rootfs=tmp_path, runtime_workspace=tmp_path))


def test_rootless_without_per_container_userns_is_rejected(monkeypatch, tmp_path):
    from fmst_analyzer.runner.task import host
    from types import SimpleNamespace
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=json.dumps({"SecurityOptions": ["name=rootless"]}))
    monkeypatch.setattr(host, "docker", docker)
    task = host.ContainerTask(output=tmp_path/'task', target='service', image='fixture')
    with pytest.raises(RuntimeError, match="userns-remap"):
        task._create()
    assert [call[0] for call in calls] == ["info"]


@pytest.mark.parametrize("limited", [False, True])
def test_container_creation_uses_only_caller_limits_without_machine_policy(monkeypatch, tmp_path, limited):
    from types import SimpleNamespace
    from fmst_analyzer.runner.task import host
    from fmst_analyzer.runner.task.options import ContainerResources
    calls = []
    info = {"SecurityOptions":["name=rootless", "name=userns"],
            "MemoryLimit":limited, "SwapLimit":False, "CpuCfsQuota":limited, "PidsLimit":False}
    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == "ps":
            pytest.fail("Firmware concurrency belongs to the caller, not the Docker daemon scan")
        return SimpleNamespace(stdout=json.dumps(info) if args[0] == "info" else "fixture-container")
    monkeypatch.setattr(host, "docker", docker)
    monkeypatch.setattr(host, "copy_tree", lambda *args, **kwargs: None)
    monkeypatch.setattr(host.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    monkeypatch.setattr(host.shutil, "disk_usage", lambda *args: pytest.fail("No fixed host disk reserve belongs here"))
    resources = ContainerResources(memory_bytes=64*1024**2, cpus=.5) if limited else None
    task = host.ContainerTask(output=tmp_path/'task', target='service', image='fixture', resources=resources)
    monkeypatch.setattr(task, "archive_source", lambda *args: None)
    task._create()
    create = next(args for args in calls if args[0] == "create")
    if limited:
        assert create[create.index("--memory")+1] == str(64*1024**2)
        assert create[create.index("--cpus")+1] == "0.5"
    else:
        assert "--memory" not in create and "--cpus" not in create
    assert "--memory-swap" not in create and "--pids-limit" not in create


def test_resource_options_reject_unsupported_or_inconsistent_requested_limits():
    from fmst_analyzer.runner.task.options import ContainerResources
    with pytest.raises(ValidationError, match="requires memory_bytes"):
        ContainerResources(memory_swap_bytes=1024)
    with pytest.raises(RuntimeError, match="requested limit --memory"):
        ContainerResources(memory_bytes=1024).docker_arguments({"MemoryLimit":False})
    assert ContainerResources().docker_arguments({}) == []


def test_ida_runtime_uses_image_without_host_installation_or_injection(monkeypatch):
    from fmst_analyzer.runner.task import inputs
    from types import SimpleNamespace
    monkeypatch.delenv('IDADIR', raising=False)
    monkeypatch.delenv('IDAUSR', raising=False)
    def unexpected(*args, **kwargs):
        pytest.fail('Runtime preparation must not copy or inject host IDA files')
    monkeypatch.setattr(inputs, 'copy_tree', unexpected)
    monkeypatch.setattr(Path, 'read_bytes', unexpected)
    calls = []
    monkeypatch.setattr(inputs, 'docker', lambda *args, **kwargs: calls.append(args))
    task = SimpleNamespace(name='fixture', put_file=unexpected)
    assert inputs.image_analysis_environment(task) == {'IDADIR':'/opt/ida', 'IDAUSR':'/opt/ida-user'}
    assert len(calls) == 1 and calls[0][:6] == ('exec', '--user', 'runner', 'fixture', 'python', '-c')


def test_private_image_context_only_contains_selected_ida_files(tmp_path):
    import importlib.util
    import io
    import tarfile
    script = Path(__file__).resolve().parents[1] / 'docker/runner-agent/build-private-image.py'
    spec = importlib.util.spec_from_file_location('private_image_builder', script)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    ida = tmp_path/'ida';ida.mkdir()
    (ida/'libidalib.so').write_bytes(b'fixture library')
    (ida/'fixture.hexlic').write_bytes(b'fixture license')
    profile = tmp_path/'profile';profile.mkdir()
    (profile/'ida.reg').write_bytes(b'accepted fixture settings')
    extra = tmp_path/'overrides';extra.mkdir()
    (extra/'ida.reg').write_bytes(b'second profile')
    (tmp_path/'.env').write_bytes(b'model fixture must remain outside context')
    files = builder.select_user_files(ida, [profile, extra])
    stream = io.BytesIO()
    builder.stream_context(stream, ida, files)
    stream.seek(0)
    with tarfile.open(fileobj=stream) as archive:
        assert set(archive.getnames()) == {'Dockerfile','ida','ida/libidalib.so','ida-user/fixture.hexlic','ida-user/ida.reg'}
        assert archive.extractfile('ida-user/ida.reg').read() == b'accepted fixture settings'
        assert archive.extractfile('ida-user/fixture.hexlic').read() == b'fixture license'


def test_private_image_build_rejects_missing_license(tmp_path):
    import importlib.util
    script = Path(__file__).resolve().parents[1] / 'docker/runner-agent/build-private-image.py'
    spec = importlib.util.spec_from_file_location('private_image_builder', script)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    with pytest.raises(ValueError, match='No IDA .hexlic'):
        builder.select_user_files(tmp_path, [])
