"""Deterministic, non-filtering Network resource scheduling."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    NetworkAPIBinding,
    NetworkCallsite,
    NetworkCodeLocation,
)
from fmst_analyzer.analysis.network_analyzer.interaction_agent import (
    resource_anchor_wave,
    resource_seed_sort_key,
)


def _fact(identity: str, api: str, family: str, ctree: int):
    return NetworkCallsite(
        callsite_id=identity,
        location=NetworkCodeLocation(
            binary_name="httpd",
            binary_path="usr/sbin/httpd",
            binary_sha256="a" * 64,
            function_name=f"sub_{ctree:x}",
            function_ea=0x1000 + ctree,
            snapshot_hash="b" * 64,
            ctree_index=ctree,
            line_number=ctree + 1,
            column_number=0,
        ),
        api_name=api,
        api_family=family,
        api_binding=NetworkAPIBinding(
            symbol=api, call_kind="direct", verified=True,
        ),
        expression_text=f"{api}(fd)",
        arguments=[],
    )


def test_resource_roots_precede_handle_operations():
    facts = [
        _fact("ioctl", "ioctl", "ioctl", 1),
        _fact("socket", "socket", "socket", 2),
        _fact("option", "setsockopt", "socket_option", 3),
        _fact("resolver", "getaddrinfo", "resolver", 4),
        _fact("bind", "bind", "endpoint", 5),
    ]
    ordered = sorted(facts, key=resource_seed_sort_key)
    priorities = [resource_seed_sort_key(fact)[0] for fact in ordered]
    assert priorities == [0, 2, 3, 3, 3]
    assert {fact.callsite_id for fact in ordered} == {
        "ioctl", "socket", "option", "resolver", "bind",
    }


def test_resource_seed_order_is_stable():
    facts = [
        _fact("b", "socket", "socket", 2),
        _fact("a", "socket", "socket", 1),
    ]
    first = [fact.callsite_id for fact in sorted(facts, key=resource_seed_sort_key)]
    second = [
        fact.callsite_id
        for fact in sorted(reversed(facts), key=resource_seed_sort_key)
    ]
    assert first == second == ["a", "b"]


def test_resource_anchor_waves_follow_handle_production_order():
    assert resource_anchor_wave(_fact("socket", "socket", "socket", 1)) == 0
    assert resource_anchor_wave(
        _fact("socketpair", "socketpair", "socket", 2)
    ) == 0
    assert resource_anchor_wave(
        _fact("accept", "accept", "accepted_socket", 3)
    ) == 1
    assert resource_anchor_wave(
        _fact("resolver", "getaddrinfo", "resolver", 4)
    ) == 2
    assert resource_anchor_wave(_fact("bind", "bind", "endpoint", 5)) == 3
