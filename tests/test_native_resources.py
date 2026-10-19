"""Descriptor capacity and cleanup failure precedence, without native SDK processes."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fmst_basic.agent import resources, claude_agent


@pytest.mark.parametrize("before,expected", [((1024,524288),(65536,524288)), ((1024,4096),(4096,4096)),
    ((131072,524288),(131072,524288)), ((-1,-1),(-1,-1)), ((1024,-1),(65536,-1))])
def test_native_soft_limit_respects_hard_and_never_lowers(monkeypatch, before, expected):
    current = [before]
    def setlimit(kind, limits):
        assert kind == resources.resource.RLIMIT_NOFILE
        assert limits[1] == before[1]
        current[0] = limits
    monkeypatch.setattr(resources.resource, "getrlimit", lambda kind: current[0])
    monkeypatch.setattr(resources.resource, "setrlimit", setlimit)
    assert resources.prepare_native_fd_limit() == dict(soft=expected[0], hard=expected[1])
    assert current[0] == expected


def test_connect_cleanup_does_not_mask_primary_and_releases_every_client(monkeypatch):
    primary = OSError(24, "Too many open files")
    clients = []
    def make(**kwargs):
        client = SimpleNamespace(connect=AsyncMock(side_effect=primary),
                                 disconnect=AsyncMock(side_effect=RuntimeError("cleanup failure")))
        clients.append(client)
        return client
    monkeypatch.setattr(claude_agent, "ClaudeSDKClient", make)
    monkeypatch.setattr(resources, "prepare_native_fd_limit", lambda: dict(soft=65536, hard=524288))
    obj = object.__new__(claude_agent.ClaudeAnalysisAgent)
    obj._closed, obj._client, obj._connected_once, obj._options = False, None, False, SimpleNamespace()
    for _ in range(3):
        with pytest.raises(OSError) as caught:
            asyncio.run(obj._ensure_connected())
        assert caught.value is primary
    assert all(client.disconnect.await_count == 1 for client in clients)
    assert obj._client is None
    assert any("SDK disconnect also failed" in note for note in primary.__notes__)
