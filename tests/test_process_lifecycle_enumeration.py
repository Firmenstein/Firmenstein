"""Static registry, stable identity, and persisted coverage tests."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.process_lifecycle import (
    PROCESS_EVENT_API_REGISTRY,
    ProcessEventKind,
    ProcessLifecycleAnalyzer,
)
from fmst_analyzer.analysis.process_lifecycle.controller import (
    normalize_api_name,
    stable_ctree_id,
)


def test_registry_is_exactly_the_eleven_planned_apis():
    assert set(PROCESS_EVENT_API_REGISTRY) == {
        "exit", "_exit", "_Exit", "quick_exit", "abort", "__assert_fail",
        "daemon", "fork", "vfork", "clone", "setsid",
    }
    assert {
        api for api, kind in PROCESS_EVENT_API_REGISTRY.items()
        if kind is ProcessEventKind.TERMINATION
    } == {"exit", "_exit", "_Exit", "quick_exit", "abort", "__assert_fail"}
    assert {
        api for api, kind in PROCESS_EVENT_API_REGISTRY.items()
        if kind is ProcessEventKind.PROCESS_TRANSITION
    } == {"daemon", "fork", "vfork", "clone", "setsid"}


def test_api_normalization_only_removes_ida_import_prefix():
    assert normalize_api_name("__imp_exit") == "exit"
    assert normalize_api_name("__imp__Exit") == "_Exit"
    assert normalize_api_name("__imp_quick_exit") == "quick_exit"
    assert normalize_api_name("__imp___assert_fail") == "__assert_fail"
    assert normalize_api_name("my_imp_exit") == "my_imp_exit"


def test_stable_identity_uses_ctree_coordinates_not_rendered_line():
    first = stable_ctree_id("process-event", "httpd", 0x1000, "snap", 7)
    same = stable_ctree_id("process-event", "httpd", 0x1000, "snap", 7)
    second = stable_ctree_id("process-event", "httpd", 0x1000, "snap", 8)
    assert first == same
    assert first != second
