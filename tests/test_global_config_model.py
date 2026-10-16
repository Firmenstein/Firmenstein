"""Regression tests for repository-defined provider model policy."""

from pathlib import Path

from dotenv import load_dotenv
import pytest

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.global_config import GlobalConfig  # noqa: E402
from fmst_basic.agent import default_model_for_provider  # noqa: E402
from fmst_basic.agent.config import DEFAULT_AGENT_PROVIDER  # noqa: E402


def test_environment_cannot_override_provider_model(monkeypatch):
    monkeypatch.delenv("FMST_CODEX_MODEL", raising=False)
    monkeypatch.setenv("DIAGNOSIS_MODEL", "not-a-real-model")
    monkeypatch.setenv("SYNTHESIZER_MODEL", "not-a-real-model")

    config = GlobalConfig()

    assert config.agent_provider == DEFAULT_AGENT_PROVIDER
    expected = default_model_for_provider(DEFAULT_AGENT_PROVIDER)
    assert config.diagnosis_model == expected
    assert config.synthesizer_model == expected


def test_claude_provider_has_repository_defined_model():
    assert default_model_for_provider("claude") == "deepseek-flash[1m]"


def test_global_config_defaults_to_claude_deepseek(monkeypatch):
    # The developer's local .env may select a private backend; this test
    # verifies the repository defaults in isolation.
    monkeypatch.delenv("FMST_CLAUDE_MODEL", raising=False)
    monkeypatch.delenv("FMST_AGENT_CONCURRENCY_LIMIT", raising=False)
    config = GlobalConfig()

    assert config.agent_provider == "claude"
    assert config.diagnosis_model == "deepseek-flash[1m]"
    assert config.synthesizer_model == "deepseek-flash[1m]"
    assert config.agent_concurrency_limit == 5


def test_development_concurrency_override(monkeypatch):
    monkeypatch.setenv("FMST_AGENT_CONCURRENCY_LIMIT", "100")
    assert GlobalConfig().agent_concurrency_limit == 100


def test_planner_overrides_do_not_change_analyzer_or_generator(monkeypatch):
    monkeypatch.setenv("FMST_CLAUDE_MODEL", "baseline-model")
    monkeypatch.setenv("FMST_PLANNER_MODEL", "planner-model")
    monkeypatch.setenv("FMST_PLANNER_REASONING_EFFORT", "max")
    config = GlobalConfig()
    assert config.planner_model == "planner-model"
    assert config.planner_reasoning_effort == "max"
    assert config.diagnosis_model == config.synthesizer_model == "baseline-model"


@pytest.mark.parametrize("value", ["0", "-1", "invalid", "1.5", ""])
def test_invalid_concurrency_override_is_rejected(monkeypatch, value):
    monkeypatch.setenv("FMST_AGENT_CONCURRENCY_LIMIT", value)
    with pytest.raises(ValueError, match="FMST_AGENT_CONCURRENCY_LIMIT must be a positive integer"):
        GlobalConfig()
