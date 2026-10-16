"""Repository-defined Agent SDK configuration.

Secrets are loaded from the environment through the named variables below;
models, effort levels, endpoints, and runtime limits are defined only here.

The ``FMST_*`` overrides are process-local Firmenstein settings.  Codex state
is always redirected to a Firmenstein-owned directory; the default provider
fails closed unless an explicit separately authenticated state directory is
configured.
"""

import os
from pathlib import Path

DEFAULT_AGENT_PROVIDER = "claude"

DEFAULT_CODEX_MODEL = "gpt-5.6-luna"
DEFAULT_CODEX_REASONING_EFFORT = "xhigh"
DEFAULT_CODEX_MODEL_PROVIDER = "codex"
DEFAULT_CODEX_CONCURRENCY_LIMIT = 30
DEFAULT_EXECUTION_GENERATOR_CODEX_MODEL = "gpt-5.6-luna"
DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS = 120
DEFAULT_RUNNER_CODEX_MODEL = "gpt-5.6-luna"

# Production Agents have no total turn deadline. Bound individual tools, not
# the time spent reasoning, reading evidence or returning a structured result.

DEFAULT_CLAUDE_MODEL = "deepseek-flash[1m]"
DEFAULT_CLAUDE_EFFORT = "high"
DEFAULT_CLAUDE_CONCURRENCY_LIMIT = 5
CLAUDE_BASE_URL_ENV = "FMST_CLAUDE_BASE_URL"
CLAUDE_AUTH_TOKEN_ENV = "FMST_CLAUDE_AUTH_TOKEN"
# Claude Code validates its --model argument against its built-in aliases.
# HighFive's DeepSeek model is injected through Claude's role aliases below.
CLAUDE_MODEL_ALIAS = "sonnet"
CLAUDE_CODE_AUTO_COMPACT_WINDOW = "1000000"
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
# Transport deadline for one HTTP request, independent of total Agent runtime.
CLAUDE_API_TIMEOUT_MS = "3000000"


def configured_codex_model() -> str:
    """Return the process-local Codex model override, if one is configured."""
    return os.getenv("FMST_CODEX_MODEL", DEFAULT_CODEX_MODEL).strip() or DEFAULT_CODEX_MODEL


def configured_claude_model() -> str:
    """Return the process-local Claude model override, if one is configured."""
    return os.getenv("FMST_CLAUDE_MODEL", DEFAULT_CLAUDE_MODEL).strip() or DEFAULT_CLAUDE_MODEL


def configured_claude_reasoning_effort() -> str:
    """Return the process-local Claude reasoning effort."""
    return (
        os.getenv("FMST_CLAUDE_REASONING_EFFORT", DEFAULT_CLAUDE_EFFORT).strip()
        or DEFAULT_CLAUDE_EFFORT
    )


def configured_claude_base_url() -> str:
    """Return the Claude-compatible HighFive endpoint.

    The existing ``FMST_CODEX_*`` names are accepted as a migration fallback
    because the same HighFive credential is used by both wire protocols.
    """
    return (
        os.getenv(CLAUDE_BASE_URL_ENV, "").strip()
        or os.getenv("FMST_CODEX_BASE_URL", "").strip()
    )


def configured_claude_auth_token() -> str:
    """Return the Claude-compatible HighFive token without persisting it."""
    return (
        os.getenv(CLAUDE_AUTH_TOKEN_ENV, "").strip()
        or os.getenv("FMST_CODEX_AUTH_TOKEN", "").strip()
    )


def configured_codex_reasoning_effort() -> str:
    """Return the process-local Codex reasoning effort."""
    return (
        os.getenv("FMST_CODEX_REASONING_EFFORT", DEFAULT_CODEX_REASONING_EFFORT).strip()
        or DEFAULT_CODEX_REASONING_EFFORT
    )


def configured_codex_context_window() -> int | None:
    """Return an explicit model context limit for this process, if supplied."""
    raw = os.getenv("FMST_CODEX_CONTEXT_WINDOW", "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ValueError("FMST_CODEX_CONTEXT_WINDOW must be a positive integer") from None
    if value <= 0:
        raise ValueError("FMST_CODEX_CONTEXT_WINDOW must be a positive integer")
    return value


def configured_codex_model_catalog() -> Path | None:
    """Optional provider metadata, scoped to this application's process."""
    raw = os.getenv("FMST_CODEX_MODEL_CATALOG", "").strip()
    return Path(raw).expanduser().resolve(strict=True) if raw else None


def configured_codex_model_provider() -> str:
    """Return the Codex-compatible backend selected for this process."""
    return (
        os.getenv("FMST_CODEX_MODEL_PROVIDER", DEFAULT_CODEX_MODEL_PROVIDER).strip()
        or DEFAULT_CODEX_MODEL_PROVIDER
    )


def configured_codex_state_dir() -> Path | None:
    """Return the explicit Firmenstein Codex state directory.

    The default Codex provider needs a separately authenticated state
    directory.  Returning ``None`` is intentional: the runtime fails closed
    instead of falling back to the user's ``~/.codex`` directory.
    """
    raw = os.getenv("FMST_CODEX_STATE_DIR", "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser().resolve()
    host_codex_home = (Path.home() / ".codex").resolve()
    if path == host_codex_home or host_codex_home in path.parents:
        raise RuntimeError(
            "FMST_CODEX_STATE_DIR must be a Firmenstein-only directory; "
            "using the user's ~/.codex directory is forbidden"
        )
    return path


__all__ = [
    "CLAUDE_API_TIMEOUT_MS",
    "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "CLAUDE_MODEL_ALIAS",
    "DEFAULT_AGENT_PROVIDER",
    "DEFAULT_CLAUDE_CONCURRENCY_LIMIT",
    "DEFAULT_CLAUDE_EFFORT",
    "DEFAULT_CLAUDE_MODEL",
    "DEFAULT_CODEX_CONCURRENCY_LIMIT",
    "DEFAULT_CODEX_MODEL",
    "DEFAULT_CODEX_MODEL_PROVIDER",
    "DEFAULT_CODEX_REASONING_EFFORT",
    "DEFAULT_EXECUTION_GENERATOR_CODEX_MODEL",
    "DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS",
    "DEFAULT_RUNNER_CODEX_MODEL",
    "CLAUDE_AUTH_TOKEN_ENV",
    "CLAUDE_BASE_URL_ENV",
    "configured_codex_model",
    "configured_claude_auth_token",
    "configured_claude_base_url",
    "configured_claude_model",
    "configured_claude_reasoning_effort",
    "configured_codex_model_provider",
    "configured_codex_reasoning_effort",
    "configured_codex_context_window",
    "configured_codex_model_catalog",
    "configured_codex_state_dir",
]
