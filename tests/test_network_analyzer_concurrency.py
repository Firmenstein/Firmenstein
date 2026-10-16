"""Parallel resource-root waves and shared-callsite behavior."""
import asyncio
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    NetworkAPIBinding,
    NetworkCallsite,
    NetworkCodeLocation,
    NetworkDisposition,
    NetworkInteractionOutput,
    NetworkResourceAgentResult,
)
from fmst_analyzer.analysis.network_analyzer.controller import (
    finalize_resource_result,
)
from fmst_analyzer.analysis.network_analyzer.interaction_agent import (
    NetworkInteractionAgent,
)


def _output(**fields):
    evidence = fields.get("evidence", [])
    context = None
    if fields.get("disposition") != NetworkDisposition.UNRESOLVED:
        cite = evidence[0] if evidence else None
        context = dict(binary_name=cite.binary_name if cite else "httpd",
                       function_name=cite.function_name if cite else "main",
                       line_number=cite.line_number if cite else 1, column_number=0)
    fields.setdefault("context_anchor", context)
    fields.setdefault("applicability", "Synthetic source context for this structural test.")
    return NetworkInteractionOutput(finding=dict(summary="Synthetic fixture; behavior unassessed.",
        claims=[dict(kind="unknown", statement="No semantic analysis in this fixture.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[]), **fields)


def _fact(identity: str, function_ea: int, api: str = "ioctl"):
    family = {
        "socket": "socket",
        "socketpair": "socket",
        "accept": "accepted_socket",
        "accept4": "accepted_socket",
        "setsockopt": "socket_option",
        "getaddrinfo": "resolver",
        "bind": "endpoint",
        "connect": "endpoint",
    }.get(api, "ioctl")
    return NetworkCallsite(
        callsite_id=identity,
        location=NetworkCodeLocation(
            binary_name="httpd",
            binary_path="usr/sbin/httpd",
            binary_sha256="a" * 64,
            function_name=f"sub_{function_ea:x}",
            function_ea=function_ea,
            snapshot_hash="b" * 64,
            ctree_index=1,
            line_number=2,
            column_number=0,
        ),
        api_name=api,
        api_family=family,
        api_binding=NetworkAPIBinding(
            symbol=api, call_kind="direct", verified=True,
        ),
        expression_text=f"{api}(fd, req)",
        arguments=[],
    )


def _unresolved(
    root_binary: str,
    anchor_callsite_id: str,
    callsite_ids: list[str],
):
    output = NetworkResourceAgentResult(analyses=[_output(
        callsite_ids=callsite_ids,
        disposition=NetworkDisposition.UNRESOLVED,
        summary="synthetic resource",
        missing_evidence=["synthetic"],
    )])
    return finalize_resource_result(root_binary, anchor_callsite_id, output)


class _Config:
    agent_concurrency_limit = 2
    workdir = None


def test_resource_query_distinguishes_process_root_from_library_anchor(monkeypatch):
    from types import SimpleNamespace
    from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import CodeAnalyzerAgent
    from fmst_analyzer.analysis.base.code_analyzer.analysis_view import EffectiveCallsite

    seed = _fact("socket", 0x1000, "socket")
    seed.location.binary_name = "libtransport.so"
    point = EffectiveCallsite(binary="httpd", function="main", representative_line=7,
                              reached_via="commit → exchange", context_snippet="L7: commit();")
    limits = []

    def collect(binary, function, *, max_sites):
        assert binary == "libtransport.so"
        limits.append(max_sites)
        return ([point] if max_sites else []), 1

    async def analyze(self, **kwargs):
        message = kwargs["user_message"]
        assert '"analyzed_process": "httpd"' in message
        assert '"function": "main"' in message
        assert '"binary_name": "libtransport.so"' in message
        result = NetworkResourceAgentResult(analyses=[_output(callsite_ids=["socket"],
            disposition=NetworkDisposition.UNRESOLVED, summary="Test has no semantic analysis.",
            missing_evidence=["No semantic analysis in this fixture."])])
        kwargs["output_validator"](result)
        return result

    monkeypatch.setattr(CodeAnalyzerAgent, "analyze", analyze)
    config = SimpleNamespace(workdir=None, diagnosis_model="test", agent_provider="codex")
    agent = NetworkInteractionAgent(config, asyncio.Semaphore(1))
    result = asyncio.run(agent._analyze_resource(
        SimpleNamespace(collect_effective_callsites=collect,
                        adg=SimpleNamespace(get_binary_callgraphs=lambda: {})),
        "httpd", seed, [seed], phase="full"))
    assert len(result) == 1
    assert limits == [0, 1]


def test_socket_observation_does_not_suppress_other_seeds(monkeypatch):
    agent = NetworkInteractionAgent(_Config(), asyncio.Semaphore(2))
    seen = []

    async def fake(view, root_binary, seed, catalog, *, phase):
        seen.append((
            seed.callsite_id,
            [fact.callsite_id for fact in catalog],
        ))
        if seed.callsite_id == "socket":
            return _unresolved(root_binary, "socket", ["socket", "option"])
        return _unresolved(root_binary, seed.callsite_id, [seed.callsite_id])

    monkeypatch.setattr(agent, "_analyze_resource", fake)
    output = asyncio.run(agent.analyze(
        object(),
        "httpd",
        [
            _fact("socket", 0x1000, "socket"),
            _fact("option", 0x2000, "setsockopt"),
            _fact("ioctl", 0x3000, "ioctl"),
        ],
    ))
    assert seen == [
        ("socket", ["socket", "option", "ioctl"]),
        ("option", ["socket", "option", "ioctl"]),
        ("ioctl", ["socket", "option", "ioctl"]),
    ]
    assert len(output) == 3
    assert all(
        item.analysis.disposition is NetworkDisposition.UNRESOLVED for item in output
    )
    assert {
        callsite_id
        for item in output
        for callsite_id in item.analysis.callsite_ids
    } == {"socket", "option", "ioctl"}


def test_primary_resource_roots_run_concurrently(monkeypatch):
    agent = NetworkInteractionAgent(_Config(), asyncio.Semaphore(2))
    entered = 0
    peak = 0
    release = asyncio.Event()

    async def fake(view, root_binary, seed, catalog, *, phase):
        nonlocal entered, peak
        if seed.callsite_id == "ioctl":
            return _unresolved(root_binary, seed.callsite_id, [seed.callsite_id])
        entered += 1
        peak = max(peak, entered)
        if entered == 2:
            release.set()
        await release.wait()
        entered -= 1
        return _unresolved(
            root_binary,
            seed.callsite_id,
            [seed.callsite_id],
        )

    monkeypatch.setattr(agent, "_analyze_resource", fake)
    output = asyncio.run(agent.analyze(
        object(),
        "httpd",
        [
            _fact("left", 0x1000, "socket"),
            _fact("right", 0x2000, "socket"),
            _fact("ioctl", 0x3000, "ioctl"),
        ],
    ))
    assert peak == 2
    assert len(output) == 3
    assert {item.analysis.anchor_callsite_id for item in output} == {
        "left", "right", "ioctl",
    }


def test_later_wave_retains_context_when_socket_claims_resolver(monkeypatch):
    agent = NetworkInteractionAgent(_Config(), asyncio.Semaphore(2))
    seen = []

    async def fake(view, root_binary, seed, catalog, *, phase):
        seen.append(seed.callsite_id)
        return _unresolved(
            root_binary,
            seed.callsite_id,
            ["socket", "resolver"],
        )

    monkeypatch.setattr(agent, "_analyze_resource", fake)
    output = asyncio.run(agent.analyze(
        object(),
        "httpd",
        [
            _fact("socket", 0x1000, "socket"),
            _fact("resolver", 0x2000, "getaddrinfo"),
        ],
    ))
    assert seen == ["socket", "resolver"]
    assert len(output) == 2
    assert set(output[0].analysis.callsite_ids) == {"socket", "resolver"}


def test_accept_runs_after_unrelated_socket_wave(monkeypatch):
    agent = NetworkInteractionAgent(_Config(), asyncio.Semaphore(2))
    seen = []

    async def fake(view, root_binary, seed, catalog, *, phase):
        seen.append((seed.callsite_id, [item.callsite_id for item in catalog]))
        return _unresolved(root_binary, seed.callsite_id, [seed.callsite_id])

    monkeypatch.setattr(agent, "_analyze_resource", fake)
    output = asyncio.run(agent.analyze(
        object(),
        "httpd",
        [
            _fact("socket", 0x1000, "socket"),
            _fact("accept", 0x2000, "accept"),
        ],
    ))
    assert seen == [
        ("socket", ["socket", "accept"]),
        ("accept", ["socket", "accept"]),
    ]
    assert len(output) == 2


def test_parallel_shared_claims_are_accepted_without_retry(monkeypatch):
    agent = NetworkInteractionAgent(_Config(), asyncio.Semaphore(2))
    calls = []

    async def fake(view, root_binary, seed, catalog, *, phase):
        ids = [item.callsite_id for item in catalog]
        calls.append((seed.callsite_id, ids))
        return _unresolved(root_binary, seed.callsite_id, ["left", "right"])

    monkeypatch.setattr(agent, "_analyze_resource", fake)
    output = asyncio.run(agent.analyze(
        object(),
        "httpd",
        [
            _fact("left", 0x1000, "socket"),
            _fact("right", 0x2000, "socket"),
        ],
    ))
    assert calls == [
        ("left", ["left", "right"]),
        ("right", ["left", "right"]),
    ]
    assert len(output) == 2
    assert all(
        set(item.analysis.callsite_ids) == {"left", "right"}
        for item in output
    )


def test_fallback_runs_concurrently_and_allows_shared_callsites(monkeypatch):
    agent = NetworkInteractionAgent(_Config(), asyncio.Semaphore(2))
    seen = []
    entered = 0
    peak = 0
    release = asyncio.Event()

    async def fake(view, root_binary, seed, catalog, *, phase):
        nonlocal entered, peak
        ids = [fact.callsite_id for fact in catalog]
        seen.append((seed.callsite_id, ids))
        if seed.callsite_id == "socket":
            return _unresolved(root_binary, "socket", ["socket"])
        entered += 1
        peak = max(peak, entered)
        if entered == 2:
            release.set()
        await release.wait()
        entered -= 1
        return _unresolved(root_binary, seed.callsite_id, ["option", "ioctl"])

    monkeypatch.setattr(agent, "_analyze_resource", fake)
    output = asyncio.run(agent.analyze(
        object(),
        "httpd",
        [
            _fact("socket", 0x1000, "socket"),
            _fact("option", 0x2000, "setsockopt"),
            _fact("ioctl", 0x3000, "ioctl"),
        ],
    ))
    assert seen == [
        ("socket", ["socket", "option", "ioctl"]),
        ("option", ["socket", "option", "ioctl"]),
        ("ioctl", ["socket", "option", "ioctl"]),
    ]
    assert {
        callsite_id
        for item in output
        for callsite_id in item.analysis.callsite_ids
    } == {"socket", "option", "ioctl"}
    assert peak == 2
