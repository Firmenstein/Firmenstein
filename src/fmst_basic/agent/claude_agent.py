"""Claude Agent SDK adapter backed by the HighFive Anthropic endpoint."""

from __future__ import annotations

import asyncio
import json
import os
import hashlib
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeSDKError,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    SystemMessage,
    create_sdk_mcp_server,
    tool as claude_tool,
)
from loguru import logger
from pydantic import BaseModel

from .analysis_agent import (
    AgentProviderError,
    AgentStructuredOutputError,
    AgentResult,
    AgentToolStepLimitError,
    AgentTurnTimeoutError,
    FilesystemAccess,
)
from .config import (
    DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS,
    CLAUDE_API_TIMEOUT_MS,
    CLAUDE_CODE_AUTO_COMPACT_WINDOW,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC,
    CLAUDE_MODEL_ALIAS,
    DEFAULT_CLAUDE_MODEL,
    configured_claude_auth_token,
    configured_claude_base_url,
    configured_claude_model,
    configured_claude_reasoning_effort,
)
from .skill import AgentSkillSpec
from .claude_skills import native_skill_plugins
from .claude_session import ClaudeSession
from .tool import AgentTool


class _ClaudeToolBudget:
    def __init__(self, maximum: int | None, trace: Any | None) -> None:
        self.maximum = maximum
        self.trace = trace
        self.count = 0
        self.last_tool: str | None = None
        self.seen_ids: set[str] = set()
        self.exceeded = False
        self.lock = threading.Lock()

    def reset(self, trace: Any | None) -> None:
        with self.lock:
            self.count = 0
            self.last_tool = None
            self.seen_ids.clear()
            self.exceeded = False
            self.trace = trace

    def register(
        self,
        identity: str | None,
        tool_name: str,
        input_data: dict[str, Any],
    ) -> bool:
        with self.lock:
            if identity and identity in self.seen_ids:
                return self.exceeded
            if identity:
                self.seen_ids.add(identity)
            self.count += 1
            self.last_tool = tool_name
            trace = self.trace
            count = self.count
            if self.maximum is not None and self.count >= self.maximum:
                self.exceeded = True
            exceeded = self.exceeded
        if trace is not None:
            _trace_event(
                trace,
                "tool/started",
                input_data,
                tool_call_id=identity or None,
                tool_name=tool_name,
                tool_call_count=count,
            )
        return exceeded


def _make_tool_budget_hook(budget: _ClaudeToolBudget):
    async def budget_hook(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        del context
        identity = tool_use_id or str(input_data.get("tool_use_id") or "")
        tool_name = str(input_data.get("tool_name", "unknown"))
        if budget.register(identity or None, tool_name, input_data):
            budget.exceeded = True
            return {
                "continue_": False,
                "stopReason": "tool_step_limit",
                "reason": (
                    f"maximum {budget.maximum} tool calls reached; stop this turn"
                ),
            }
        return {}

    return budget_hook

_MCP_SERVER_NAME = "fmst"

_PATH_ARGUMENTS = {
    "Read": "file_path",
    "Write": "file_path",
    "Edit": "file_path",
    "Glob": "path",
    "Grep": "path",
}

_SANDBOX_SECRET_ENV_VARS = [
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "FMST_CLAUDE_AUTH_TOKEN",
    "FMST_CODEX_AUTH_TOKEN",
]

_SANDBOX_PROTECTED_FILES = [
    ".bash_profile",
    ".bashrc",
    ".git/config",
    ".gitconfig",
    ".gitmodules",
    ".mcp.json",
    ".profile",
    ".ripgreprc",
    ".zprofile",
    ".zshrc",
    ".claude/settings.json",
    ".claude/settings.local.json",
]

_SANDBOX_PROTECTED_DIRECTORIES = [
    ".claude/agents",
    ".claude/commands",
    ".git/hooks",
    ".idea",
    ".vscode",
]


def _log_sdk_stderr(line: str) -> None:
    if line:
        logger.trace(f"[Claude Agent SDK] {line}")


def _tool_result_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump_json(indent=2)
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _claude_tool(
    tool: AgentTool,
    *,
    default_timeout_seconds: float | None = None,
    budget: _ClaudeToolBudget | None = None,
):
    @claude_tool(
        tool.name,
        tool.description,
        tool.args_schema.model_json_schema(),
    )
    async def invoke(arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            value = await tool.ainvoke(
                arguments,
                default_timeout_seconds=default_timeout_seconds,
            )
        except TimeoutError as error:
            timeout_seconds = tool.timeout_seconds or default_timeout_seconds
            detail = str(error) or "execution deadline expired"
            limit = f" (tool limit {timeout_seconds:g}s)" if timeout_seconds is not None else ""
            diagnostic = f"TimeoutError: tool {tool.name!r}: {detail}{limit}"
            if tool.error_context is not None:
                diagnostic = tool.error_feedback(arguments, TimeoutError(diagnostic))
            _trace_event(
                budget.trace if budget is not None else None,
                "tool/failed",
                diagnostic,
                tool_name=tool.name,
            )
            return {
                "content": [{"type": "text", "text": diagnostic}],
                "is_error": True,
            }
        except Exception as error:  # noqa: BLE001 - return tool failure to the agent
            _trace_event(
                budget.trace if budget is not None else None,
                "tool/failed",
                str(error),
                tool_name=tool.name,
            )
            return {
                "content": [{"type": "text", "text": tool.error_feedback(arguments, error)}],
                "is_error": True,
            }
        _trace_event(
            budget.trace if budget is not None else None,
            "tool/completed",
            value,
            tool_name=tool.name,
        )
        return {
            "content": [{"type": "text", "text": _tool_result_text(value)}]
        }

    return invoke


def _message_items(message: AssistantMessage) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for block in message.content:
        if is_dataclass(block):
            payload = asdict(block)
        else:
            payload = {"value": str(block)}
        payload["type"] = type(block).__name__
        items.append(payload)
    return items


def _usage(raw: dict[str, Any] | None) -> dict[str, int]:
    values = raw or {}
    return {
        "input_tokens": int(values.get("input_tokens", 0) or 0),
        "output_tokens": int(values.get("output_tokens", 0) or 0),
        "cache_read_input_tokens": int(
            values.get("cache_read_input_tokens", 0) or 0
        ),
        "cache_creation_input_tokens": int(
            values.get("cache_creation_input_tokens", 0) or 0
        ),
    }


def _official_error_message(message: ResultMessage) -> str:
    """Return only diagnostic text supplied by the SDK/provider."""
    parts: list[str] = []
    for error in message.errors or []:
        rendered = str(error).strip()
        if rendered and rendered not in parts:
            parts.append(rendered)
    rendered_result = (message.result or "").strip()
    if rendered_result and rendered_result not in parts:
        parts.append(rendered_result)
    return "\n".join(parts)


def _path_is_within(root: Path, value: str) -> bool:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    return resolved == root or root in resolved.parents


def _make_filesystem_guard(
    workdir: Path,
    read_only_roots: list[Path] | None = None,
    writable_roots: list[Path] | None = None,
):
    """Create a Claude file-tool hook with task read boundaries."""
    root = workdir.resolve()
    extra_roots = [path.resolve() for path in read_only_roots or []]
    extra_writable = [path.resolve() for path in writable_roots or []]

    async def guard(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        del tool_use_id, context
        tool_name = str(input_data.get("tool_name", ""))
        path_argument = _PATH_ARGUMENTS.get(tool_name)
        if path_argument is None:
            return {}

        tool_input = input_data.get("tool_input")
        values = tool_input if isinstance(tool_input, dict) else {}
        raw_path = values.get(path_argument)
        if raw_path is None and tool_name in {"Glob", "Grep"}:
            raw_path = "."

        allowed = isinstance(raw_path, str) and _path_is_within(root, raw_path)
        if not allowed and tool_name in {"Read", "Glob", "Grep"}:
            allowed = isinstance(raw_path, str) and any(
                _path_is_within(extra_root, raw_path)
                for extra_root in [*extra_roots, *extra_writable]
            )
        if not allowed and tool_name in {"Write", "Edit"}:
            allowed = isinstance(raw_path, str) and any(
                _path_is_within(extra_root, raw_path)
                for extra_root in extra_writable
            )
        if allowed and tool_name == "Glob":
            pattern = values.get("pattern")
            if isinstance(pattern, str):
                pattern_path = Path(pattern)
                allowed = (
                    not pattern_path.is_absolute()
                    and ".." not in pattern_path.parts
                    and not pattern.startswith("~")
                )

        if allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"{tool_name} may only access the task workdir or "
                    "an attached root with matching permissions"
                ),
            }
        }

    return guard


def _prepare_native_shell_cwd(root: Path) -> Path:
    """Prepare a session-owned cwd with Claude's protected mount points.

    Claude Code's Linux sandbox currently fails to create missing mandatory
    deny targets after cwd has been made read-only. Keeping those empty mount
    points outside the input avoids touching the firmware rootfs. Keep this
    cwd stable across resume because native history is indexed by project cwd.
    """
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for relative in _SANDBOX_PROTECTED_DIRECTORIES:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative in _SANDBOX_PROTECTED_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
    return root


def _native_read_shell_settings(
    workdir: Path,
    session_cwd: Path,
    read_only_roots: list[Path] | None = None,
    state_dir: Path | None = None,
) -> str:
    """Return strict Claude Bash sandbox settings for one read-only task.

    The native sandbox keeps host runtime paths readable so inspection tools
    can execute, while the task root is the only readable part of the user's
    home. Both cwd and rootfs are read-only; Claude Code supplies a separate
    writable session temporary directory.
    """
    root = workdir.resolve()
    extra_roots = [str(path.resolve()) for path in read_only_roots or []]
    state_path = str(state_dir.resolve()) if state_dir is not None else None
    return json.dumps(
        {
            "sandbox": {
                "enabled": True,
                "failIfUnavailable": True,
                "autoAllowBashIfSandboxed": True,
                "allowUnsandboxedCommands": False,
                "excludedCommands": [],
                "filesystem": {
                    "denyRead": [str(Path.home().resolve())],
                    "allowRead": [
                        str(root),
                        str(session_cwd.resolve()),
                        *extra_roots,
                        *([state_path] if state_path is not None else []),
                    ],
                    "denyWrite": [
                        str(root),
                        str(session_cwd.resolve()),
                        *extra_roots,
                    ],
                    "allowWrite": ([state_path] if state_path is not None else []),
                },
                "network": {
                    "allowedDomains": [],
                    "deniedDomains": ["*"],
                    "allowUnixSockets": [],
                    "allowAllUnixSockets": False,
                },
                "credentials": {
                    "envVars": [
                        {"name": name, "mode": "deny"}
                        for name in _SANDBOX_SECRET_ENV_VARS
                    ],
                },
            },
        },
        sort_keys=True,
    )


class ClaudeAnalysisAgent:
    """Task-scoped Claude Agent SDK session using HighFive DeepSeek Flash."""

    def __init__(
        self,
        *,
        model: str,
        developer_instructions: str,
        tools: list[AgentTool] | None = None,
        output_format: type[BaseModel] | None = None,
        workdir: Path | None = None,
        filesystem_access: FilesystemAccess = "none",
        readable_roots: list[Path] | None = None,
        writable_roots: list[Path] | None = None,
        name: str | None = None,
        skills: list[AgentSkillSpec] | None = None,
        turn_timeout_seconds: float | None = None,
        max_tool_calls_per_turn: int | None = None,
        default_tool_timeout_seconds: float | None = None,
        reasoning_effort: str | None = None,
        session_dir: Path | None = None,
        resume: bool = False,
    ) -> None:
        self.container_task = filesystem_access == "container"
        if self.container_task and not (
            os.getenv("FMST_RUNNER_CONTAINER") == "1" and Path("/.dockerenv").is_file()
        ):
            raise ValueError("Full Agent permissions require the explicit Runner container entrypoint")
        if (
            filesystem_access in {"read", "read_shell", "write", "container"}
            and workdir is None
        ):
            raise ValueError(f"filesystem_access={filesystem_access!r} requires workdir")
        if readable_roots and filesystem_access == "none":
            raise ValueError("readable_roots require filesystem access")
        if writable_roots and filesystem_access not in {"write", "container"}:
            raise ValueError("writable_roots require filesystem_access='write'")
        invalid_writable_roots = [
            Path(path) for path in writable_roots or [] if not Path(path).is_dir()
        ]
        if invalid_writable_roots:
            raise ValueError(
                "writable_roots must be existing directories: "
                + ", ".join(str(path) for path in invalid_writable_roots)
            )
        api_key = configured_claude_auth_token()
        if not api_key:
            raise RuntimeError(
                "Claude provider requires FMST_CLAUDE_AUTH_TOKEN or "
                "FMST_CODEX_AUTH_TOKEN in the local environment"
            )

        self.model = model.strip() or configured_claude_model()
        # Claude Code normalizes this context-window suffix to lowercase, and
        # HighFive receives the model identifier from the role environment.
        if self.model.lower().endswith("[1m]"):
            self.model = self.model[:-4] + "[1m]"
        if self.model == "deepseek-flash":
            self.model = DEFAULT_CLAUDE_MODEL
        sdk_model = (
            CLAUDE_MODEL_ALIAS
            if self.model.startswith("deepseek-flash")
            else self.model
        )
        self.developer_instructions = developer_instructions
        self.output_format = output_format
        self.workdir = Path(workdir).resolve() if workdir else Path.cwd().resolve()
        self.filesystem_access = filesystem_access
        self.readable_roots = [
            Path(path).resolve() for path in readable_roots or []
        ]
        self.writable_roots = [
            Path(path).resolve() for path in writable_roots or []
        ]
        self.name = name or "claude-agent"
        self.tools = list(tools or [])
        self.skills = list(skills or [])
        self.turn_timeout_seconds = (
            None if turn_timeout_seconds is None else float(turn_timeout_seconds)
        )
        if self.turn_timeout_seconds is not None and self.turn_timeout_seconds <= 0:
            raise ValueError("turn_timeout_seconds must be positive")
        if max_tool_calls_per_turn is not None and max_tool_calls_per_turn <= 0:
            raise ValueError("max_tool_calls_per_turn must be positive")
        if default_tool_timeout_seconds is not None and default_tool_timeout_seconds <= 0:
            raise ValueError("default_tool_timeout_seconds must be positive")
        self.max_tool_calls_per_turn = max_tool_calls_per_turn
        self.default_tool_timeout_seconds = (
            (None if self.container_task else DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS)
            if default_tool_timeout_seconds is None else default_tool_timeout_seconds
        )
        for skill in self.skills:
            skill.validate_current()

        names = [item.name for item in self.tools]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"Duplicate dynamic tool names: {duplicates}")
        skill_names = [item.name for item in self.skills]
        duplicate_skills = sorted({
            name for name in skill_names if skill_names.count(name) > 1
        })
        if duplicate_skills:
            raise ValueError(f"Duplicate Agent Skills: {duplicate_skills}")

        identity = {
            "name": self.name, "workdir": str(self.workdir),
            "filesystem_access": filesystem_access,
            "readable_roots": sorted(map(str, self.readable_roots)),
            "writable_roots": sorted(map(str, self.writable_roots)),
            "instructions_sha256": hashlib.sha256(developer_instructions.encode()).hexdigest(),
            "tools": sorted(({"name": item.name, "schema": item.args_schema.model_json_schema()}
                             for item in self.tools), key=lambda item: item["name"]),
            "skills": sorted(({"name": skill.name, "directory": str(skill.skill_dir),
                               "references": sorted(map(str, skill.reference_roots))}
                              for skill in self.skills), key=lambda item: item["name"]),
        }
        self._session = ClaudeSession(session_dir, resume=resume, identity=identity)
        self.session_dir = self._session.directory
        self.session_receipt = self._session.receipt_path
        self._closed = False
        self._connected_once = False
        sdk_cwd = (_prepare_native_shell_cwd(self.session_dir / "shell-cwd")
                   if filesystem_access == "read_shell" else self.workdir)
        skill_wrapper = self._session.config_dir / "skill-plugin"
        try:
            plugins, native_skill_names = native_skill_plugins(self.skills, skill_wrapper)
        except BaseException:
            self._session.close()
            raise
        skill_roots = [root for skill in self.skills
                       for root in (skill.skill_dir, *skill.reference_roots)]
        if skill_wrapper.exists():
            skill_roots.append(skill_wrapper)
        self._tool_budget = _ClaudeToolBudget(max_tool_calls_per_turn, None)
        self._native_tool_scope: asyncio.Timeout | None = None
        self._active_native_tools: dict[str, tuple[float, str]] = {}
        self._filesystem_guard = _make_filesystem_guard(
            self.workdir,
            [*self.readable_roots, *skill_roots],
            self.writable_roots,
        )
        sdk_tools = [
            _claude_tool(
                item,
                default_timeout_seconds=self.default_tool_timeout_seconds,
                budget=self._tool_budget,
            )
            for item in self.tools
        ]
        mcp_servers = (
            {
                _MCP_SERVER_NAME: create_sdk_mcp_server(
                    _MCP_SERVER_NAME,
                    tools=sdk_tools,
                )
            }
            if sdk_tools
            else {}
        )
        builtin_tools = {
            "none": [],
            "read": ["Read", "Glob", "Grep"],
            "read_shell": ["Read", "Glob", "Grep", "Bash"],
            "write": ["Read", "Write", "Edit", "Glob", "Grep"],
            "container": ["Read", "Write", "Edit", "Glob", "Grep", "Bash", "Skill"],
        }[filesystem_access]
        available_tools = list(dict.fromkeys([
            *builtin_tools,
            *(["Skill"] if self.skills else []),
        ]))
        custom_tools = [
            f"mcp__{_MCP_SERVER_NAME}__{item.name}" for item in self.tools
        ]
        native_matcher = ".*" if self.container_task else "^(?:" + "|".join(available_tools) + ")$"
        hooks_matchers = []
        if available_tools:
            hooks_matchers.append(
                HookMatcher(
                    matcher=native_matcher,
                    hooks=[self._native_tool_started],
                )
            )
        if max_tool_calls_per_turn is not None:
            hooks_matchers.append(
                HookMatcher(matcher=None, hooks=[_make_tool_budget_hook(self._tool_budget)])
            )
        hooks = {"PreToolUse": hooks_matchers} if hooks_matchers else {}
        if available_tools:
            for event in ("PostToolUse", "PostToolUseFailure"):
                hooks[event] = [HookMatcher(
                    matcher=native_matcher,
                    hooks=[self._native_tool_finished],
                )]
        output_schema = (
            {
                "type": "json_schema",
                "schema": output_format.model_json_schema(),
            }
            if output_format is not None
            else None
        )
        self._options = ClaudeAgentOptions(
            model=sdk_model,
            effort=reasoning_effort or configured_claude_reasoning_effort(),
            cwd=sdk_cwd,
            session_id=None if resume else self._session.session_id,
            resume=self._session.session_id if resume else None,
            # Keep Claude Code's built-in system prompt (tool guidance,
            # security rules, and workspace context). Callers can explicitly
            # append policy; container Runner sends its task in the user turn.
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                **(
                    {"append": developer_instructions}
                    if developer_instructions.strip()
                    else {}
                ),
            },
            tools={"type": "preset", "preset": "claude_code"} if self.container_task else available_tools,
            allowed_tools=[*builtin_tools, *custom_tools],
            permission_mode="bypassPermissions" if self.container_task else None,
            # Unattended work has no human approval/input channel. All coding,
            # shell and network tools remain available inside the container.
            disallowed_tools=["AskUserQuestion", "EnterPlanMode", "ExitPlanMode"] if self.container_task else [],
            hooks=hooks or None,
            mcp_servers=mcp_servers,
            strict_mcp_config=True,
            setting_sources=[],
            plugins=plugins,
            skills=native_skill_names,
            betas=(
                ["context-1m-2025-08-07"]
                if "[1m]" in self.model.lower()
                else []
            ),
            settings=(
                _native_read_shell_settings(
                    self.workdir,
                    sdk_cwd,
                    [
                        *self.readable_roots,
                        *skill_roots,
                    ],
                    self._session.config_dir,
                )
                if filesystem_access == "read_shell"
                else None
            ),
            add_dirs=(
                [
                    self.workdir,
                    *self.readable_roots,
                    *self.writable_roots,
                    *[root for root in skill_roots if root.is_dir()],
                ]
                if filesystem_access in {"read", "read_shell", "write"}
                else []
            ),
            output_format=output_schema,
            stderr=_log_sdk_stderr,
            env={
                "CLAUDE_CONFIG_DIR": str(self._session.config_dir),
                # Keep native Bash in its session-owned project cwd. Persisting
                # a cd into a read-only input lets the CLI create state there.
                **({"CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR": "1"}
                   if filesystem_access == "read_shell" else {}),
                "ANTHROPIC_AUTH_TOKEN": api_key,
                "ANTHROPIC_BASE_URL": configured_claude_base_url(),
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.model,
                "ANTHROPIC_DEFAULT_SONNET_MODEL": self.model,
                "ANTHROPIC_DEFAULT_OPUS_MODEL": self.model,
                "CLAUDE_CODE_AUTO_COMPACT_WINDOW": (
                    CLAUDE_CODE_AUTO_COMPACT_WINDOW
                ),
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": (
                    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC
                ),
                "API_TIMEOUT_MS": CLAUDE_API_TIMEOUT_MS,
            },
        )
        self._client: ClaudeSDKClient | None = None
        self._session_id: str | None = self._session.session_id
        self._turn_count = self._session.data["turn_count"]

    def _reschedule_native_tools(self) -> None:
        scope = self._native_tool_scope
        if scope is not None and not scope.expired():
            deadline = min(
                (deadline for deadline, _name in self._active_native_tools.values()),
                default=None,
            )
            scope.reschedule(deadline)

    async def _native_tool_started(self, input_data, tool_use_id, context):
        if self.container_task:
            # The task container owns filesystem/process/network isolation and
            # the host owns the overall deadline. Do not reapply host path gates
            # or interrupt a long build with the read-only tool watchdog.
            self._record_container_tool("started", input_data, tool_use_id)
            return {}
        # Do not arm a watchdog for a tool rejected by the filesystem guard.
        decision = await self._filesystem_guard(input_data, tool_use_id, context)
        if decision:
            return decision
        identity = tool_use_id or input_data["tool_use_id"]
        self._active_native_tools.setdefault(identity, (
            asyncio.get_running_loop().time() + self.default_tool_timeout_seconds,
            input_data["tool_name"],
        ))
        self._reschedule_native_tools()
        return {}

    async def _native_tool_finished(self, input_data, tool_use_id, context):
        if self.container_task:
            self._record_container_tool("finished", input_data, tool_use_id)
            return {}
        if self._native_tool_scope is not None and self._native_tool_scope.expired():
            # Retain the expired tool identity while disconnect delivers its
            # final failure hooks, so the timeout keeps the correct cause.
            return {}
        identity = tool_use_id or input_data["tool_use_id"]
        self._active_native_tools.pop(identity, None)
        self._reschedule_native_tools()
        return {}

    def _record_container_tool(self, phase, data, tool_use_id):
        # Preserve actual native-tool outcomes as files. They are evidence,
        # never injected into a subsequent prompt by this adapter.
        import hashlib
        root = Path("/task/evidence/native-tools")
        root.mkdir(parents=True, exist_ok=True)
        identity = tool_use_id or data.get("tool_use_id", "unknown")
        filename = hashlib.sha256(identity.encode()).hexdigest() + "." + phase + ".json"
        path = root / filename
        path.write_text(json.dumps(data, default=str, ensure_ascii=False) + "\n")
        with (root.parent / "tool-events.jsonl").open("a") as stream:
            stream.write(json.dumps({"at": time.time(), "phase": phase,
                "tool": data.get("tool_name"), "id": identity, "evidence": str(path)}) + "\n")

    async def _ensure_connected(self) -> ClaudeSDKClient:
        if self._closed:
            raise RuntimeError("Agent is closed; create an agent with session_dir and resume=True")
        if self._client is not None:
            return self._client
        if self._connected_once:
            self._session.require_transcript()
            self._session.resuming = True
            self._options.session_id = None
            self._options.resume = self._session_id
        client = ClaudeSDKClient(options=self._options)
        try:
            await client.connect()
        except BaseException:
            await client.disconnect()
            raise
        self._client = client
        self._connected_once = True
        return client

    async def ainvoke(
        self,
        prompt: str,
        *,
        trace: Any | None = None,
    ) -> AgentResult:
        started = time.monotonic()
        for skill in self.skills:
            if not self.container_task:
                skill.validate_current()
        client: ClaudeSDKClient | None = None
        self._tool_budget.reset(trace)
        if trace is not None:
            _trace_start(
                trace,
                prompt,
                provider="claude",
                max_tool_calls=self.max_tool_calls_per_turn,
                default_tool_timeout_seconds=self.default_tool_timeout_seconds,
                turn_timeout_seconds=self.turn_timeout_seconds,
            )
            _trace_event(trace, "instruction_context", {
                "system_prompt": self._options.system_prompt,
                "skills": [skill.trace_identity() for skill in self.skills],
                "native_skill_names": self._options.skills,
            })
        try:
            async with (
                asyncio.timeout(self.turn_timeout_seconds) as turn_deadline,
                asyncio.timeout(None) as native_tool_deadline,
            ):
                self._native_tool_scope = native_tool_deadline
                client = await self._ensure_connected()
                await client.query(prompt)

                result_message: ResultMessage | None = None
                items: list[dict[str, Any]] = []
                text_parts: list[str] = []
                async for message in client.receive_response():
                    if (
                        isinstance(message, SystemMessage)
                        and message.subtype == "init"
                    ):
                        session_id = message.data.get("session_id")
                        if isinstance(session_id, str):
                            self._session.bind(session_id)
                            self._session_id = session_id
                            if trace is not None:
                                _trace_bind(trace, session_id=session_id)
                    elif isinstance(message, AssistantMessage):
                        assistant_items = _message_items(message)
                        items.extend(assistant_items)
                        # Persist assistant content while the stream is still
                        # active.  If a later tool or provider timeout occurs,
                        # the terminal trace must retain the messages observed
                        # before the failure instead of only the hook events.
                        _trace_event(
                            trace,
                            "assistant/message",
                            assistant_items,
                        )
                        for block in message.content:
                            text = getattr(block, "text", None)
                            if isinstance(text, str):
                                text_parts.append(text)
                    elif isinstance(message, ResultMessage):
                        result_message = message
                        self._session.bind(message.session_id)
                        self._session_id = message.session_id
        except TimeoutError as error:
            # A timed-out SDK stream cannot be safely reused for a correction
            # turn. Disconnect it before surfacing a per-task failure.
            self._client = None
            if client is not None:
                await client.disconnect()
            if native_tool_deadline.expired():
                _deadline, tool_name = min(self._active_native_tools.values())
                timeout_error = AgentTurnTimeoutError(
                    provider="claude", model=self.model,
                    timeout_seconds=self.default_tool_timeout_seconds,
                    code="tool_timeout", last_tool=tool_name,
                    tool_calls_seen=self._tool_budget.count,
                    limit=self.default_tool_timeout_seconds,
                )
            elif turn_deadline.expired():
                timeout_error = AgentTurnTimeoutError(
                    provider="claude",
                    model=self.model,
                    timeout_seconds=self.turn_timeout_seconds,
                    code="turn_timeout",
                    tool_calls_seen=self._tool_budget.count,
                    last_tool=self._tool_budget.last_tool,
                )
            else:
                if trace is not None:
                    _trace_fail(trace, error, "provider_error", prompt=prompt)
                raise AgentProviderError(str(error), provider="claude", model=self.model) from error
            if trace is not None:
                _trace_fail(trace, timeout_error, timeout_error.code, prompt=prompt)
            raise timeout_error
        except asyncio.CancelledError as error:
            # Cancellation is a terminal per-turn outcome.  Keep the round
            # trajectory auditable before propagating cancellation to the
            # Unit task and its checkpoint handler.
            if trace is not None:
                _trace_fail(trace, error, "cancelled", prompt=prompt)
            self._client = None
            if client is not None:
                await client.disconnect()
            raise
        except ClaudeSDKError as error:
            if trace is not None:
                _trace_fail(trace, error, "provider_error", prompt=prompt)
            raise AgentProviderError(
                str(error),
                provider="claude",
                model=self.model,
            ) from error
        except Exception as error:  # noqa: BLE001 - normalize SDK boundary
            # The SDK normally exposes provider failures as ClaudeSDKError,
            # but transport/runtime exceptions can escape with their native
            # type. Close the same trace boundary and retain the original
            # diagnostic rather than leaving a round in ``started`` state.
            if trace is not None:
                _trace_fail(trace, error, "provider_error", prompt=prompt)
            raise AgentProviderError(
                str(error),
                provider="claude",
                model=self.model,
            ) from error

        finally:
            self._native_tool_scope = None
            self._active_native_tools.clear()

        if result_message is None:
            error = AgentProviderError(
                "Claude Agent SDK returned no ResultMessage",
                provider="claude",
                model=self.model,
            )
            if trace is not None:
                _trace_fail(trace, error, "provider_error", prompt=prompt)
            raise error

        self._turn_count += 1
        self._session.data["turn_count"] = self._turn_count
        self._session.save()
        text = result_message.result or "\n".join(text_parts)
        turn_id = result_message.uuid or f"turn-{self._turn_count}"
        elapsed_seconds = (
            result_message.duration_ms / 1000
            if result_message.duration_ms
            else time.monotonic() - started
        )
        # A budget stop is a local deterministic limit even when the SDK wraps
        # it in an error ResultMessage. Report the stable budget code first.
        if self._tool_budget.exceeded:
            error = AgentToolStepLimitError(
                provider="claude",
                model=self.model,
                limit=int(self.max_tool_calls_per_turn or self._tool_budget.count),
                tool_calls_seen=self._tool_budget.count,
                turn_id=result_message.uuid,
                last_tool=self._tool_budget.last_tool,
            )
            if trace is not None:
                _trace_fail(trace, error, "tool_step_limit", prompt=prompt)
            raise error

        if result_message.is_error:
            official_message = _official_error_message(result_message)
            failed_result = AgentResult(
                text=official_message,
                structured_response=None,
                provider="claude",
                session_id=self._session_id or "unknown",
                turn_id=turn_id,
                status="failed",
                items=items,
                usage=_usage(result_message.usage),
                elapsed_seconds=elapsed_seconds,
                skills=[skill.trace_identity() for skill in self.skills],
                tool_calls_seen=self._tool_budget.count,
                last_tool=self._tool_budget.last_tool,
            )
            if (
                self.output_format is not None
                and result_message.subtype == "error_max_structured_output_retries"
                and result_message.api_error_status is None
            ):
                # The CLI's output-validation budget ended, but its session is
                # still usable. Preserve the failed turn and let the existing
                # author-context correction loop request a complete result.
                error = AgentStructuredOutputError(
                    failed_result, ValueError(official_message)
                )
                if trace is not None:
                    _trace_fail(
                        trace, error, "structured_output_error",
                        result=failed_result, prompt=prompt,
                    )
                raise error
            if trace is not None:
                _trace_fail(
                    trace,
                    AgentProviderError(
                        official_message,
                        provider="claude",
                        model=self.model,
                        http_status=result_message.api_error_status,
                        subtype=result_message.subtype,
                        stop_reason=result_message.stop_reason,
                        terminal_reason=result_message.terminal_reason,
                    ),
                    "provider_error",
                    result=failed_result,
                    prompt=prompt,
                )
            raise AgentProviderError(
                official_message,
                provider="claude",
                model=self.model,
                http_status=result_message.api_error_status,
                subtype=result_message.subtype,
                stop_reason=result_message.stop_reason,
                terminal_reason=result_message.terminal_reason,
                code="provider_error",
            )

        structured_response = None
        if (
            self.output_format is not None
            and result_message.structured_output is not None
        ):
            try:
                structured_response = self.output_format.model_validate(
                    result_message.structured_output
                )
            except Exception as error:  # noqa: BLE001 - schema boundary
                raw_result = AgentResult(
                    text=text,
                    # Keep the provider payload visible in the terminal trace
                    # even though it did not satisfy the local schema.
                    structured_response=result_message.structured_output,  # type: ignore[arg-type]
                    provider="claude",
                    session_id=self._session_id or "unknown",
                    turn_id=turn_id,
                    status="completed",
                    items=items,
                    usage=_usage(result_message.usage),
                    elapsed_seconds=elapsed_seconds,
                    skills=[skill.trace_identity() for skill in self.skills],
                    tool_calls_seen=self._tool_budget.count,
                    last_tool=self._tool_budget.last_tool,
                )
                if trace is not None:
                    _trace_fail(
                        trace,
                        error,
                        "structured_output_error",
                        result=raw_result,
                        prompt=prompt,
                    )
                raise AgentStructuredOutputError(raw_result, error) from error
        result = AgentResult(
            text=text,
            structured_response=structured_response,
            provider="claude",
            session_id=self._session_id or "unknown",
            turn_id=turn_id,
            status="completed",
            items=items,
            usage=_usage(result_message.usage),
            elapsed_seconds=elapsed_seconds,
            skills=[skill.trace_identity() for skill in self.skills],
            tool_calls_seen=self._tool_budget.count,
            last_tool=self._tool_budget.last_tool,
        )
        if self.output_format is not None and structured_response is None:
            error = AgentStructuredOutputError(result, ValueError("Completed turn returned no structured output: " + text))
            if trace is not None:
                _trace_fail(trace, error, "structured_output_error", prompt=prompt)
            raise error
        for skill in self.skills:
            skill.validate_current()
        if trace is not None:
            _trace_finish(trace, result, prompt)
        return result

    async def aclose(self) -> None:
        """Release SDK resources, retaining native history and its resume receipt."""
        self._closed = True
        client = self._client
        self._client = None
        try:
            if client is not None:
                await client.disconnect()
        finally:
            self._session.close()


__all__ = [
    "ClaudeAnalysisAgent",
]


def _trace_start(trace: Any, prompt: str, **kwargs: Any) -> None:
    method = getattr(trace, "start_turn", None)
    if method is not None:
        method(prompt, **kwargs)


def _trace_finish(trace: Any, result: AgentResult, prompt: str) -> None:
    method = getattr(trace, "finish_turn", None)
    if method is not None:
        method(result)
    else:
        trace.record(result, prompt=prompt)


def _trace_bind(trace: Any, **kwargs: Any) -> None:
    method = getattr(trace, "bind_turn", None)
    if method is not None:
        method(**kwargs)


def _trace_event(
    trace: Any | None,
    event_type: str,
    payload: Any,
    **kwargs: Any,
) -> None:
    if trace is None:
        return
    method = getattr(trace, "record_event", None)
    if method is not None:
        method(event_type, payload, **kwargs)


def _trace_fail(
    trace: Any,
    error: BaseException,
    code: str,
    *,
    result: AgentResult | None = None,
    prompt: str = "",
) -> None:
    method = getattr(trace, "fail_turn", None)
    if method is not None:
        method(error, reason_code=code, result=result)
    elif result is not None:
        trace.record(result, prompt=prompt)
