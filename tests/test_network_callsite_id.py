"""Stable immutable NetworkAnalyzer callsite identity."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.network_analyzer.analyzer import (
    _stable_callsite_id,
)


def test_ctree_identity_is_stable_and_coordinate_sensitive():
    args = ("usr/sbin/httpd", "a" * 64, 0x1000, "b" * 64, 7)
    assert _stable_callsite_id(*args) == _stable_callsite_id(*args)
    assert _stable_callsite_id(*args) != _stable_callsite_id(*args[:-1], 8)


def test_ctree_identity_changes_with_binary_and_snapshot():
    baseline = ("usr/sbin/httpd", "a" * 64, 0x1000, "b" * 64, 7)
    assert _stable_callsite_id(*baseline) != _stable_callsite_id(
        "usr/sbin/httpd", "c" * 64, 0x1000, "b" * 64, 7,
    )
    assert _stable_callsite_id(*baseline) != _stable_callsite_id(
        "usr/sbin/httpd", "a" * 64, 0x1000, "d" * 64, 7,
    )
