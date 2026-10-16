"""Guest launch keeps the selected venv even under sudo's reduced PATH."""
import json
from pathlib import Path
from types import SimpleNamespace

from fmst_analyzer.runner.task import guest


def test_guest_and_proxy_keep_active_interpreter_without_python_on_path(monkeypatch, tmp_path):
    selected = str(tmp_path / "venv with spaces/bin/python3.12")
    monkeypatch.setattr(guest.sys, "executable", selected)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(guest.os, "geteuid", lambda: 0)
    task = tmp_path / "task"
    task.mkdir()
    monkeypatch.setattr(guest, "TASK", task)
    # Redirect the one namespace configuration write without creating a real
    # network namespace or touching the host's /etc.
    monkeypatch.setattr(guest, "Path", lambda path: tmp_path / "netns" if path == "/etc/netns" else Path(path))
    execution = task / "evidence/execution.json"
    execution.parent.mkdir()
    monkeypatch.setattr(guest, "create_execution", lambda config: execution)
    monkeypatch.setattr(guest, "update_execution", lambda *args, **kwargs: None)
    monkeypatch.setattr(guest.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""))
    commands = []
    monkeypatch.setattr(guest, "command", lambda *args, **kwargs: commands.append(list(args)))
    jobs = []

    def spawn(argv, **kwargs):
        jobs.append((argv, kwargs))
        return {"pid": 123, "start_ticks": 456}

    monkeypatch.setattr(guest, "spawn", spawn)
    config = task / "config.json"
    config.write_text(json.dumps({"addresses": ["192.0.2.1/32"], "hosts": {"firmware.test": "192.0.2.1"}}))
    guest.start(config)

    namespace_module = "fmst_analyzer.runner.task.netns"
    namespace_commands = [cmd for cmd in commands if namespace_module in cmd]
    assert namespace_commands
    assert all(cmd[0] == selected for cmd in namespace_commands)
    firmware, = [argv for argv, options in jobs if options.get("role") == "firmware"]
    proxy, = [argv for argv, options in jobs if options.get("role") == "proxy"]
    assert firmware[0] == proxy[0] == selected
    assert firmware[firmware.index("--kill-child") + 1] == selected
    assert proxy[proxy.index("--") + 1] == selected
    assert "python" not in firmware + proxy
