"""Tests for IPC Agent delta caching."""

from __future__ import annotations

from types import SimpleNamespace
import pytest

from dotenv import load_dotenv

load_dotenv()

from fmst_analyzer.analysis.ipc_analyzer.agent_cache import (  # noqa: E402
    agent_cache_key,
    load_agent_cache,
    store_agent_cache,
)
from fmst_analyzer.analysis.ipc_analyzer.agent_schema import (  # noqa: E402
    SiteResolutionOutput,
)
from fmst_analyzer.analysis.base.input_provenance import AnalysisInputs, analysis_input_scope


@pytest.fixture
def input_scope():
    inputs = AnalysisInputs(stage="ipc", phase="full", target_path="sbin/service",
        target_sha256="a" * 64, rootfs_sha256="b" * 64, implementation_sha256="c" * 64,
        settings={"fixture": "synthetic cache inputs"})
    with analysis_input_scope(inputs):
        yield inputs


def test_agent_delta_cache_is_content_addressed_and_schema_validated(tmp_path, input_scope) -> None:
    config = SimpleNamespace(graph_cache_dir=tmp_path / "graph_cache")
    payload = {"callsite_ids": ["cs:1"]}
    key = agent_cache_key(
        stage="site_resolution",
        model="test-model",
        task_prompt="contract-v1",
        output_type=SiteResolutionOutput,
        payload=payload,
        semantic_identity=[{"snapshot_hash": "a" * 64}],
    )
    changed_key = agent_cache_key(
        stage="site_resolution",
        model="test-model",
        task_prompt="contract-v2",
        output_type=SiteResolutionOutput,
        payload=payload,
        semantic_identity=[{"snapshot_hash": "a" * 64}],
    )
    output = SiteResolutionOutput(callsite_findings=[])

    assert key != changed_key
    assert load_agent_cache(
        config, "site_resolution", key, SiteResolutionOutput,
    ) is None
    store_agent_cache(config, "site_resolution", key, output)
    assert load_agent_cache(
        config, "site_resolution", key, SiteResolutionOutput,
    ) == output
    assert load_agent_cache(
        config, "site_resolution", changed_key, SiteResolutionOutput,
    ) is None


def test_delta_cache_requires_bounded_input_provenance(tmp_path):
    config = SimpleNamespace(graph_cache_dir=tmp_path / "graph_cache")
    output = SiteResolutionOutput(callsite_findings=[])
    store_agent_cache(config, "site_resolution", "no-context", output)
    assert load_agent_cache(config, "site_resolution", "no-context", SiteResolutionOutput) is None
    assert not config.graph_cache_dir.exists()


def test_changed_rootfs_changes_delta_key_without_changing_target_or_payload(input_scope):
    args = dict(stage="site_resolution", model="test", task_prompt="same", output_type=SiteResolutionOutput,
                payload={}, semantic_identity=[])
    original = agent_cache_key(**args)
    with analysis_input_scope(input_scope.model_copy(update={"rootfs_sha256": "d" * 64})):
        assert agent_cache_key(**args) != original
