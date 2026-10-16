"""Native browser command scope; no real browser or fabricated acceptance."""
import json
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.live_client import RunnerLiveClient
from fmst_analyzer.runner.budget import ExecutionBudget


@pytest.fixture
def client(tmp_path, monkeypatch):
    client = RunnerLiveClient(root=tmp_path, budget=ExecutionBudget(60), runtime_builder=None)
    client.browser = {"debug_port": 123}
    client.current = {"path": str(tmp_path), "commands": []}
    calls = []
    def process(arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout="observed output", stderr="")
    monkeypatch.setattr(client, "_process", process)
    return client, calls


@pytest.mark.parametrize("arguments", [
    ["--help"], ["network", "--help"], ["frame", "--help"], ["screenshot", "--help"],
    ["cookies"], ["cookies", "get"], ["frame", "main"], ["dialog", "status"],
])
def test_native_help_and_observation_retain_exact_commands(client, arguments):
    owned, calls = client
    result = json.loads(owned.command(arguments))
    assert result["returncode"] == 0 and calls == [arguments]
    assert len(owned.current["commands"]) == 1


@pytest.mark.parametrize("arguments", [
    ["cookies", "set", "session", "fabricated"], ["cookies", "clear"],
    ["network", "route", "*", "--body", "success"], ["open", "--session=other", "http://guest/"],
    ["--help", "cookies", "clear"], ["cookies", "get", "--profile", "other"],
])
def test_inspection_does_not_enable_response_or_session_fabrication(client, arguments):
    owned, calls = client
    with pytest.raises(ValueError):
        owned.command(arguments)
    assert calls == [] and owned.current["commands"] == []
