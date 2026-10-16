"""Deterministic Network API registry tests."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.network_analyzer.registry import (
    lookup_network_api,
    normalize_api_name,
)


def test_registry_includes_endpoint_query_and_ioctl_anchors():
    expected = {
        "socket", "socketpair", "accept", "accept4",
        "bind", "connect", "listen", "sendto", "sendmsg",
        "setsockopt", "getsockopt", "getsockname", "getpeername",
        "getaddrinfo", "gethostbyname", "getifaddrs", "if_nametoindex",
        "ioctl",
    }
    assert all(lookup_network_api(name) is not None for name in expected)


def test_registry_excludes_handle_only_lifecycle_operations():
    excluded = {"send", "recv", "close", "shutdown", "read", "write"}
    assert all(lookup_network_api(name) is None for name in excluded)


def test_resolver_prefix_and_import_thunk_normalization():
    assert lookup_network_api("res_query").family == "resolver"
    assert lookup_network_api("__res_search").family == "resolver"
    assert normalize_api_name("__imp_connect") == "connect"
