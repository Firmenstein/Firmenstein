"""Codex App Server runtime with in-process dynamic tool dispatch."""

from __future__ import annotations

import asyncio
import atexit
import copy
from concurrent.futures import TimeoutError as FutureTimeoutError
import json
import os
import queue
import re
import tempfile
import threading
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger
from openai_codex.client import CodexClient, CodexConfig
from pydantic import BaseModel

from .analysis_agent import (
    AgentProviderError,
    AgentResult,
    AgentToolStepLimitError,
    AgentTurnTimeoutError,
    FilesystemAccess,
)
from .config import (
    DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS,
    configured_codex_model_provider,
    configured_codex_context_window,
    configured_codex_model_catalog,
    configured_codex_reasoning_effort,
    configured_codex_state_dir,
)
from .skill import AgentSkillSpec
from .tool import AgentTool

DYNAMIC_TOOL_TIMEOUT_SECONDS = DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS

_TOOL_ITEM_TYPES = {
    "commandExecution",
    "fileChange",
    "mcpToolCall",
    "dynamicToolCall",
    "imageView",
    "webSearch",
    "imageGeneration",
    "sleep",
    "subAgentActivity",
}


@dataclass
class _TurnBudgetState:
    max_tool_calls: int | None
    default_tool_timeout_seconds: float | None
    provider: str
    model: str | None
    turn_id: str
    trace: Any | None = None
    count: int = 0
    last_tool: str | None = None
    seen_ids: set[str] = field(default_factory=set)
    exceeded: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def register(
        self,
        identity: str | None,
        tool_name: str,
        payload: Any,
        *,
        event_type: str,
    ) -> bool:
        with self.lock:
            if identity and identity in self.seen_ids:
                return self.exceeded
            if identity:
                self.seen_ids.add(identity)
            self.count += 1
            self.last_tool = tool_name or "unknown"
            if self.trace is not None:
                _trace_event(
                    self.trace,
                    event_type,
                    payload,
                    tool_call_id=identity,
                    tool_name=tool_name,
                    tool_call_count=self.count,
                )
            if self.max_tool_calls is not None and self.count >= self.max_tool_calls:
                self.exceeded = True
            return self.exceeded


@dataclass
class _ThreadContext:
    tools: dict[str, AgentTool]
    loop: asyncio.AbstractEventLoop
    max_tool_calls_per_turn: int | None = None
    default_tool_timeout_seconds: float | None = None
    active_turn: _TurnBudgetState | None = None
    active_lock: threading.Lock = field(default_factory=threading.Lock)


class _CodexStructuredOutputError(ValueError):
    """Keep a completed provider turn available when local validation fails."""

    def __init__(self, result: AgentResult, cause: ValueError) -> None:
        super().__init__(str(cause))
        self.result = result
        self.cause = cause
        self.code = "structured_output_error"


def _permission_profile_config(
    filesystem_access: FilesystemAccess,
    skills: list[AgentSkillSpec] | None = None,
    readable_roots: list[Path] | None = None,
    writable_roots: list[Path] | None = None,
) -> dict[str, Any]:
    """Build a least-privilege Codex permission profile for one task."""
    from codex_cli_bin import bundled_codex_path, bundled_path_dir

    profile_name = f"fmst-{filesystem_access}"
    filesystem: dict[str, Any] = {
        ":minimal": "read",
        str(bundled_codex_path().parent): "read",
        str(bundled_path_dir()): "read",
    }
    workspace_access = (
        "read" if filesystem_access == "read_shell" else filesystem_access
    )
    if workspace_access in {"read", "write"}:
        filesystem[":workspace_roots"] = {".": workspace_access}
    for skill in skills or []:
        filesystem[str(skill.skill_dir)] = "read"
        for root in skill.reference_roots:
            filesystem[str(root)] = "read" if root.is_file() else {".": "read"}
    for root in readable_roots or []:
        filesystem[str(root.resolve())] = {".": "read"}
    for root in writable_roots or []:
        filesystem[str(root.resolve())] = {".": "write"}
    return {
        "default_permissions": profile_name,
        "permissions": {
            profile_name: {
                "description": "Firmenstein task-scoped filesystem access.",
                "filesystem": filesystem,
                "network": {"enabled": False},
            }
        },
    }


def codex_dynamic_tool_spec(item: AgentTool) -> dict[str, Any]:
    """Expose nested argument types in the App Server's model-facing tools.

    Some tool renderers treat a $ref-only parameter as opaque even when its
    definition is present. Inline local definitions so field descriptions and
    constraints reach the model; Python still validates the original model.
    """
    schema = item.args_schema.model_json_schema()
    definitions = schema.get("$defs", {})
    recursive = False

    def expand(node: Any, stack: tuple[str, ...] = ()) -> Any:
        nonlocal recursive
        if isinstance(node, list):
            return [expand(value, stack) for value in node]
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if isinstance(ref, str):
            prefix = "#/$defs/"
            if not ref.startswith(prefix) or ref.removeprefix(prefix) not in definitions:
                raise ValueError(f"Unsupported dynamic-tool schema reference: {ref}")
            name = ref.removeprefix(prefix)
            if name in stack:
                recursive = True
                return copy.deepcopy(node)
            expanded = {**definitions[name], **{key: value for key, value in node.items() if key != "$ref"}}
            return expand(expanded, (*stack, name))
        expanded = {key: expand(value, stack) for key, value in node.items() if key != "$defs"}
        patterns = expanded.get("patternProperties", {})
        if (expanded.get("type") == "object" and len(patterns) == 1
                and "properties" not in expanded and "additionalProperties" not in expanded):
            # Pydantic emits regex-constrained dict keys as patternProperties.
            # The model-facing renderer otherwise exposes their values as
            # unknown. Preserve the key constraint separately from its type.
            pattern, value_schema = next(iter(patterns.items()))
            expanded.pop("patternProperties")
            expanded["propertyNames"] = {**expanded.get("propertyNames", {}), "pattern": pattern}
            expanded["additionalProperties"] = value_schema
        return expanded

    expanded_schema = expand(schema)
    if recursive:
        expanded_schema["$defs"] = definitions
    return {
        "type": "function",
        "name": item.name,
        "description": item.description,
        "inputSchema": expanded_schema,
    }


def codex_turn_input(
    prompt: str,
    skills: list[AgentSkillSpec],
) -> list[dict[str, str]]:
    """Build the App Server's canonical explicit-Skill turn input."""
    skill_invocation = " ".join(f"${skill.name}" for skill in skills)
    text = f"{skill_invocation}\n\n{prompt}" if skill_invocation else prompt
    return [
        {"type": "text", "text": text},
        *[
            {
                "type": "skill",
                "name": skill.name,
                "path": str(skill.skill_file),
            }
            for skill in skills
        ],
    ]


def _serialize_tool_result(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump_json()
    return json.dumps(value, ensure_ascii=False, default=str)


def _strict_output_schema(output_model: type[BaseModel]) -> dict[str, Any]:
    """Convert Pydantic JSON Schema to Codex strict-output form.

    Strict Structured Outputs cannot represent arbitrary-key objects. Such
    mappings are encoded as ordered ``[{key, value}]`` entries for the model
    and decoded before Pydantic validation.
    """
    schema = output_model.model_json_schema()
    definitions = schema.get("$defs", {})

    def visit(node: Any, ref_stack: tuple[str, ...] = ()) -> Any:
        if isinstance(node, list):
            return [visit(item, ref_stack) for item in node]
        if not isinstance(node, dict):
            return node

        ref = node.get("$ref")
        siblings = {key: value for key, value in node.items() if key != "$ref"}
        if isinstance(ref, str):
            prefix = "#/$defs/"
            if not ref.startswith(prefix):
                raise ValueError(f"Unsupported structured-output schema reference: {ref}")
            name = ref.removeprefix(prefix)
            target = definitions.get(name)
            if not isinstance(target, dict):
                raise ValueError(f"Missing structured-output schema definition: {ref}")
            if name in ref_stack:
                # Codex forbids siblings on $ref. Recursive Pydantic schemas
                # retain the reference and necessarily lose only the
                # occurrence-specific decoration at this cycle boundary.
                return {"type": "object"}
            expanded = copy.deepcopy(target)
            expanded.update(siblings)
            return visit(expanded, (*ref_stack, name))

        additional = node.get("additionalProperties")
        if (
            node.get("type") == "object"
            and "properties" not in node
            and isinstance(additional, dict)
        ):
            description = node.get("description", "")
            encoded = {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "value": visit(additional, ref_stack),
                    },
                    "required": ["key", "value"],
                    "additionalProperties": False,
                },
                "description": (
                    f"{description} Encode this mapping as a list of unique "
                    "key/value entries."
                ).strip(),
            }
            if "title" in node:
                encoded["title"] = node["title"]
            return encoded
        properties = node.get("properties")
        if isinstance(properties, dict):
            node["properties"] = {
                key: visit(value, ref_stack) for key, value in properties.items()
            }
            node["additionalProperties"] = False
            node["required"] = list(properties)
        for key, value in list(node.items()):
            if key != "properties":
                node[key] = visit(value, ref_stack)
        return node

    return visit(schema)


def _decode_output_maps(value: Any, schema: dict[str, Any]) -> Any:
    definitions = schema.get("$defs", {})

    def resolve(node: dict[str, Any]) -> dict[str, Any]:
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            return definitions[ref.rsplit("/", 1)[-1]]
        return node

    def decode(current: Any, node: dict[str, Any]) -> Any:
        node = resolve(node)
        additional = node.get("additionalProperties")
        if (
            node.get("type") == "object"
            and "properties" not in node
            and isinstance(additional, dict)
            and isinstance(current, list)
        ):
            result: dict[str, Any] = {}
            for entry in current:
                if not isinstance(entry, dict) or set(entry) != {"key", "value"}:
                    raise ValueError("Invalid key/value entry in encoded mapping")
                key = entry["key"]
                if not isinstance(key, str) or key in result:
                    raise ValueError(f"Invalid or duplicate mapping key: {key!r}")
                result[key] = decode(entry["value"], additional)
            return result
        if isinstance(current, dict):
            properties = node.get("properties", {})
            return {
                key: decode(item, properties.get(key, {}))
                for key, item in current.items()
            }
        if isinstance(current, list) and isinstance(node.get("items"), dict):
            return [decode(item, node["items"]) for item in current]
        return current

    return decode(value, schema)


def _codex_provider_overrides(provider: str) -> tuple[str, ...]:
    """Build CLI ``--config`` overrides for a process-local backend.

    The token is read from the environment and passed to Codex's existing
    command-based auth hook.  Nothing is written to the host Codex config.
    """
    if provider == "codex":
        return ()
    import os

    base_url = os.getenv("FMST_CODEX_BASE_URL", "").strip()
    token = os.getenv("FMST_CODEX_AUTH_TOKEN", "")
    if not base_url or not token:
        raise RuntimeError(
            "A non-default FMST_CODEX_MODEL_PROVIDER requires "
            "FMST_CODEX_BASE_URL and FMST_CODEX_AUTH_TOKEN"
        )
    # The auth hook reads the token from the child environment.  Keeping the
    # value out of argv prevents it from appearing in process listings and
    # SDK diagnostics.
    auth_args = json.dumps(["-c", 'printf "%s" "$FMST_CODEX_AUTH_TOKEN"'])
    return (
        f'model_providers.{provider}.name={json.dumps(provider)}',
        f'model_providers.{provider}.base_url={json.dumps(base_url)}',
        f'model_providers.{provider}.auth.command="sh"',
        f'model_providers.{provider}.auth.args={auth_args}',
    )


def _reject_project_codex_config(cwd: Path) -> None:
    """Prevent a task from inheriting a user-created project Codex config."""
    resolved = cwd.resolve()
    user_home = Path.home().resolve()
    for directory in (resolved, *resolved.parents):
        # ~/.codex/config.toml is the host user's global state, not a project
        # layer. It must never be treated as a project config while walking
        # ancestors of a task under the user's home directory.
        if directory == user_home:
            break
        candidate = directory / ".codex" / "config.toml"
        if candidate.is_file():
            raise RuntimeError(
                "Firmenstein refuses to launch Codex with a project config: "
                f"{candidate}. Move the project config out of the task path "
                "or use the Firmenstein provider configuration."
            )
        if (directory / ".git").exists():
            break


class _CodexRuntime:
    """One App Server process shared by all concurrent analyzer turns."""

    def __init__(self) -> None:
        self.model_provider = configured_codex_model_provider()
        self._provider_overrides = _codex_provider_overrides(self.model_provider)
        catalog = configured_codex_model_catalog()
        if catalog is not None:
            self._provider_overrides += (f"model_catalog_json={json.dumps(str(catalog))}",)
        context_window = configured_codex_context_window()
        if context_window is not None:
            # App Server resolves model metadata at startup; a thread/start
            # config alone does not replace its effective context window.
            self._provider_overrides += (
                f"model_context_window={context_window}",
                f"model_auto_compact_token_limit={context_window * 95 // 100}",
            )
        self._configured_codex_state_dir = (
            configured_codex_state_dir()
            if self.model_provider == "codex"
            else None
        )
        self._isolated_codex_home = (
            tempfile.TemporaryDirectory(prefix="fmst-codex-home-")
            if self._configured_codex_state_dir is None
            else None
        )
        self._codex_home = (
            self._configured_codex_state_dir
            if self._configured_codex_state_dir is not None
            else Path(self._isolated_codex_home.name)
        )
        if self._configured_codex_state_dir is not None:
            self._configured_codex_state_dir.mkdir(parents=True, exist_ok=True)
        codex_env = {"CODEX_HOME": str(self._codex_home)}
        if self.model_provider != "codex":
            codex_env["FMST_CODEX_AUTH_TOKEN"] = os.getenv(
                "FMST_CODEX_AUTH_TOKEN", ""
            )
        self._client = CodexClient(
            CodexConfig(
                experimental_api=True,
                config_overrides=self._provider_overrides,
                env=codex_env,
            ),
            approval_handler=self._handle_server_request,
        )
        self._start_lock = threading.Lock()
        self._started = False
        self._contexts: dict[str, _ThreadContext] = {}
        self._contexts_lock = threading.Lock()
        self._available_models: set[str] | None = None
        self._empty_cwd = tempfile.TemporaryDirectory(prefix="fmst-codex-")
        atexit.register(self.close)

    @property
    def empty_cwd(self) -> Path:
        return Path(self._empty_cwd.name)

    def _ensure_started(self) -> None:
        with self._start_lock:
            if self._started:
                return
            if (
                self.model_provider == "codex"
                and self._configured_codex_state_dir is None
            ):
                raise RuntimeError(
                    "The default Codex provider requires FMST_CODEX_STATE_DIR "
                    "pointing to a separately authenticated Firmenstein directory; "
                    "falling back to ~/.codex is forbidden"
                )
            self._client.start()
            self._client.initialize()
            self._available_models = {
                model.id for model in self._client.model_list(include_hidden=True).data
            }
            self._started = True

    async def validate_model(self, model: str | None) -> None:
        # A private Codex-compatible provider has its own model catalogue;
        # asking the local ChatGPT account for that catalogue is both wrong
        # and can reject an otherwise valid internal model name.
        if self.model_provider != "codex":
            await asyncio.to_thread(self._ensure_started)
            return
        await asyncio.to_thread(self._ensure_started)
        if model is None:
            return
        assert self._available_models is not None
        if model not in self._available_models:
            available = ", ".join(sorted(self._available_models))
            raise ValueError(
                f"Codex model {model!r} is unavailable for the current ChatGPT "
                f"account. Available models: {available}"
            )

    def _handle_server_request(
        self, method: str, params: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if method in {
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
        }:
            return {"decision": "decline"}
        if method != "item/tool/call" or params is None:
            return {}

        thread_id = str(params.get("threadId", ""))
        tool_name = str(params.get("tool", ""))
        with self._contexts_lock:
            context = self._contexts.get(thread_id)
        if context is None:
            return {
                "contentItems": [{
                    "type": "inputText",
                    "text": f"Dynamic tool context for thread {thread_id!r} is unavailable.",
                }],
                "success": False,
            }
        selected = context.tools.get(tool_name)
        if selected is None:
            return {
                "contentItems": [{
                    "type": "inputText",
                    "text": f"Unknown dynamic tool: {tool_name}",
                }],
                "success": False,
            }

        request_id = _request_identity(params)
        try:
            arguments = _normalize_dynamic_tool_arguments(
                params.get("arguments"), selected
            )
        except Exception as exc:  # noqa: BLE001 - return a provider-visible tool error
            return {
                "contentItems": [{
                    "type": "inputText",
                    "text": selected.error_feedback(params.get("arguments"), exc),
                }],
                "success": False,
            }
        with context.active_lock:
            budget = context.active_turn
        if budget is not None:
            exceeded = budget.register(
                request_id,
                tool_name,
                {"arguments": arguments},
                event_type="tool/started",
            )
            if exceeded:
                self._interrupt_turn_async(thread_id, budget.turn_id)
                return {
                    "contentItems": [{
                        "type": "inputText",
                        "text": (
                            f"tool_step_limit: maximum {budget.max_tool_calls} "
                            "tool calls reached"
                        ),
                    }],
                    "success": False,
                }
        timeout_seconds = (
            selected.timeout_seconds
            or (budget.default_tool_timeout_seconds if budget else None)
            or DYNAMIC_TOOL_TIMEOUT_SECONDS
        )
        try:
            future = asyncio.run_coroutine_threadsafe(
                selected.ainvoke(
                    arguments,
                    default_timeout_seconds=timeout_seconds,
                ), context.loop,
            )
            try:
                output = future.result(timeout=timeout_seconds)
            except FutureTimeoutError as exc:
                future.cancel()
                raise TimeoutError(
                    f"Dynamic tool {tool_name!r} exceeded "
                    f"{timeout_seconds:g}s"
                ) from exc
            if budget is not None:
                _trace_event(
                    budget.trace,
                    "tool/completed", output,
                    tool_call_id=request_id,
                    tool_name=tool_name,
                    tool_call_count=budget.count,
                )
            return {
                "contentItems": [{
                    "type": "inputText",
                    "text": _serialize_tool_result(output),
                }],
                "success": True,
            }
        except TimeoutError as exc:
            if budget is not None:
                _trace_event(
                    budget.trace,
                    "tool/failed",
                    str(exc),
                    tool_call_id=request_id,
                    tool_name=tool_name,
                    tool_call_count=budget.count,
                )
            return {
                "contentItems": [{
                    "type": "inputText",
                    "text": selected.error_feedback(params.get("arguments"), exc),
                }],
                "success": False,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(f"Codex dynamic tool {tool_name!r} failed")
            if budget is not None:
                _trace_event(
                    budget.trace,
                    "tool/failed", str(exc),
                    tool_call_id=request_id,
                    tool_name=tool_name,
                    tool_call_count=budget.count,
                )
            return {
                "contentItems": [{
                    "type": "inputText",
                    "text": selected.error_feedback(params.get("arguments"), exc),
                }],
                "success": False,
            }

    def _interrupt_turn_async(self, thread_id: str, turn_id: str) -> None:
        def interrupt() -> None:
            try:
                self._client.turn_interrupt(thread_id, turn_id)
            except Exception:  # noqa: BLE001 - best effort wake-up
                logger.exception(f"Failed to interrupt Codex turn {turn_id}")

        threading.Thread(
            target=interrupt,
            name=f"codex-turn-budget-interrupt-{turn_id}",
            daemon=True,
        ).start()

    async def start_thread(
        self,
        *,
        model: str | None,
        developer_instructions: str,
        tools: list[AgentTool],
        cwd: Path,
        filesystem_access: FilesystemAccess,
        skills: list[AgentSkillSpec] | None = None,
        readable_roots: list[Path] | None = None,
        writable_roots: list[Path] | None = None,
        max_tool_calls_per_turn: int | None = None,
        default_tool_timeout_seconds: float | None = None,
        reasoning_effort: str | None = None,
    ) -> str:
        _reject_project_codex_config(cwd)
        await self.validate_model(model)
        shell_enabled = filesystem_access in {"read", "read_shell", "write"}
        permission_config = _permission_profile_config(
            filesystem_access,
            skills,
            readable_roots,
            writable_roots,
        )
        params: dict[str, Any] = {
            "cwd": str(cwd),
            "ephemeral": True,
            "approvalPolicy": "never",
            "dynamicTools": [codex_dynamic_tool_spec(item) for item in tools],
            "config": {
                # Repository AGENTS.md governs development of Firmenstein, not
                # the task-scoped analysis agents launched by this runtime.
                "project_doc_max_bytes": 0,
                "model_reasoning_effort": reasoning_effort or configured_codex_reasoning_effort(),
                "features": {
                    "shell_tool": shell_enabled,
                    "unified_exec": shell_enabled,
                },
                "web_search": "disabled",
                "tools": {"view_image": False, "web_search": False},
                **permission_config,
            },
        }
        context_window = configured_codex_context_window()
        if context_window is not None:
            params["config"]["model_context_window"] = context_window
            params["config"]["model_auto_compact_token_limit"] = context_window * 95 // 100
        if developer_instructions.strip():
            params["developerInstructions"] = developer_instructions
        if self.model_provider != "codex":
            # thread/start is a raw JSON-RPC payload here.  The App Server
            # field is camel-cased; using the Python model field name leaves
            # the override as an unknown key and silently falls back to the
            # account's default provider.
            params["modelProvider"] = self.model_provider
        if model is not None:
            params["model"] = model
        started = await asyncio.to_thread(self._client.thread_start, params)
        if started.instruction_sources:
            raise RuntimeError(
                "Codex loaded unexpected project instruction sources despite "
                "project_doc_max_bytes=0: "
                f"{started.instruction_sources}"
            )
        thread_id = started.thread.id
        with self._contexts_lock:
            self._contexts[thread_id] = _ThreadContext(
                tools={item.name: item for item in tools},
                loop=asyncio.get_running_loop(),
                max_tool_calls_per_turn=max_tool_calls_per_turn,
                default_tool_timeout_seconds=default_tool_timeout_seconds,
            )
        return thread_id

    async def run_turn(
        self,
        *,
        thread_id: str,
        model: str | None = None,
        prompt: str,
        output_model: type[BaseModel] | None,
        cwd: Path,
        skills: list[AgentSkillSpec],
        timeout_seconds: float | None = None,
        trace: Any | None = None,
        max_tool_calls_per_turn: int | None = None,
        default_tool_timeout_seconds: float | None = None,
    ) -> AgentResult:
        with self._contexts_lock:
            context = self._contexts.get(thread_id)
            if context is not None:
                context.loop = asyncio.get_running_loop()

        output_schema = _strict_output_schema(output_model) if output_model else None
        started_at = time.monotonic()
        notifications: queue.Queue[Any | BaseException] = queue.Queue()
        try:
            return await asyncio.to_thread(
                self._run_turn_sync,
                thread_id,
                prompt,
                output_schema,
                output_model,
                cwd,
                skills,
                started_at,
                timeout_seconds,
                trace,
                max_tool_calls_per_turn,
                default_tool_timeout_seconds,
                model,
                notification_queue=notifications,
            )
        except asyncio.CancelledError:
            # Wake an otherwise unbounded queue wait. Cancelling to_thread
            # alone does not stop its worker or the provider's active turn.
            notifications.put(asyncio.CancelledError())
            raise

    def release_thread(self, thread_id: str) -> None:
        """Release Python-side dynamic-tool state for an ephemeral thread."""
        with self._contexts_lock:
            self._contexts.pop(thread_id, None)

    def _run_turn_sync(
        self,
        thread_id: str,
        prompt: str,
        output_schema: dict[str, Any] | None,
        output_model: type[BaseModel] | None,
        cwd: Path,
        skills: list[AgentSkillSpec],
        started_at: float,
        timeout_seconds: float | None = None,
        trace: Any | None = None,
        max_tool_calls_per_turn: int | None = None,
        default_tool_timeout_seconds: float | None = None,
        model: str | None = None,
        *,
        notification_queue: queue.Queue[Any | BaseException] | None = None,
    ) -> AgentResult:
        turn_params: dict[str, Any] = {
            "cwd": str(cwd),
        }
        if output_schema is not None:
            turn_params["outputSchema"] = output_schema
            # Some compatible providers expose the schema to the model but
            # do not enforce JSON mode. Keep the same typed contract and
            # parser; explicitly request its serialization, without repairing
            # or extracting values from a prose response.
            prompt += "\n\nReturn only JSON matching the requested response schema as the final response."
        turn_input = codex_turn_input(prompt, skills)
        started = self._client.turn_start(
            thread_id,
            turn_input,
            params=turn_params,
        )
        turn_id = started.turn.id
        with self._contexts_lock:
            context = self._contexts.get(thread_id)
        if context is None:
            # A few low-level runtime tests exercise turn parsing without a
            # registered dynamic-tool context. Treat that as a tools-less
            # thread rather than making the parser depend on registration.
            context = _ThreadContext(tools={}, loop=asyncio.new_event_loop())
        if max_tool_calls_per_turn is None:
            max_tool_calls_per_turn = context.max_tool_calls_per_turn
        if default_tool_timeout_seconds is None:
            default_tool_timeout_seconds = (
                context.default_tool_timeout_seconds or DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS
            )
        budget = _TurnBudgetState(
            max_tool_calls=max_tool_calls_per_turn,
            default_tool_timeout_seconds=default_tool_timeout_seconds,
            provider="codex",
            model=model,
            turn_id=turn_id,
            trace=trace,
        )
        with context.active_lock:
            context.active_turn = budget
        if trace is not None:
            binder = getattr(trace, "bind_turn", None)
            if binder is not None:
                binder(session_id=thread_id, turn_id=turn_id)
        items: list[dict[str, Any]] = []
        final_text = ""
        usage: dict[str, int] = {}
        status = "failed"
        if notification_queue is None:
            notification_queue = queue.Queue()

        def pump_notifications() -> None:
            """Forward the SDK's unbounded blocking iterator to a timed queue."""
            try:
                while True:
                    note = self._client.next_turn_notification(turn_id)
                    notification_queue.put(note)
                    if note.method == "turn/completed":
                        return
            except BaseException as exc:  # noqa: BLE001 - cross-thread handoff
                notification_queue.put(exc)

        def interrupt_expired_turn() -> None:
            try:
                self._client.turn_interrupt(thread_id, turn_id)
            except Exception:  # noqa: BLE001 - wake-up is best effort
                logger.exception(
                    f"Failed to interrupt expired Codex turn {turn_id}"
                )

        notification_thread = threading.Thread(
            target=pump_notifications,
            name=f"codex-turn-notifications-{turn_id}",
            daemon=True,
        )
        notification_thread.start()
        deadline = (
            time.monotonic() + timeout_seconds if timeout_seconds is not None else None
        )
        active_native_tools: dict[str, tuple[float, str]] = {}

        def expired_native_tool() -> tuple[str, float] | None:
            """Return the oldest native tool that exceeded its watchdog."""
            if not default_tool_timeout_seconds or not active_native_tools:
                return None
            now = time.monotonic()
            expired = [
                (started_time, tool_name)
                for started_time, tool_name in active_native_tools.values()
                if now - started_time >= default_tool_timeout_seconds
            ]
            if not expired:
                return None
            _started_time, tool_name = min(expired)
            return tool_name, default_tool_timeout_seconds

        try:
            while True:
                remaining = deadline - time.monotonic() if deadline is not None else None
                if budget.exceeded:
                    self._interrupt_turn_async(thread_id, turn_id)
                    raise AgentToolStepLimitError(
                        provider="codex",
                        model=model,
                        limit=int(max_tool_calls_per_turn or budget.count),
                        tool_calls_seen=budget.count,
                        turn_id=turn_id,
                        last_tool=budget.last_tool,
                    )
                if remaining is not None and remaining <= 0:
                    threading.Thread(
                        target=interrupt_expired_turn,
                        name=f"codex-turn-interrupt-{turn_id}",
                        daemon=True,
                    ).start()
                    raise AgentTurnTimeoutError(
                        provider="codex",
                        model=model,
                        timeout_seconds=timeout_seconds,
                        turn_id=turn_id,
                        code="turn_timeout",
                        tool_calls_seen=budget.count,
                        last_tool=budget.last_tool,
                    )
                expired = expired_native_tool()
                if expired is not None:
                    self._interrupt_turn_async(thread_id, turn_id)
                    raise AgentTurnTimeoutError(
                        provider="codex",
                        model=model,
                        timeout_seconds=expired[1],
                        turn_id=turn_id,
                        code="tool_timeout",
                        tool_calls_seen=budget.count,
                        last_tool=expired[0],
                        limit=expired[1],
                    )
                try:
                    wait_for = remaining
                    if default_tool_timeout_seconds and active_native_tools:
                        native_deadline = min(
                            started_time + default_tool_timeout_seconds
                            for started_time, _name in active_native_tools.values()
                        )
                        native_remaining = max(0.0, native_deadline - time.monotonic())
                        wait_for = (
                            native_remaining if remaining is None
                            else min(remaining, native_remaining)
                        )
                    note = notification_queue.get(timeout=wait_for)
                except queue.Empty:
                    expired = expired_native_tool()
                    if expired is not None:
                        self._interrupt_turn_async(thread_id, turn_id)
                        raise AgentTurnTimeoutError(
                            provider="codex",
                            model=model,
                            timeout_seconds=expired[1],
                            turn_id=turn_id,
                            code="tool_timeout",
                            tool_calls_seen=budget.count,
                            last_tool=expired[0],
                            limit=expired[1],
                        )
                    continue
                if isinstance(note, BaseException):
                    if isinstance(note, asyncio.CancelledError):
                        self._interrupt_turn_async(thread_id, turn_id)
                    raise note
                # A busy notification stream must not defeat the native tool
                # watchdog. Check again after dequeueing each event.
                expired = expired_native_tool()
                if expired is not None:
                    self._interrupt_turn_async(thread_id, turn_id)
                    raise AgentTurnTimeoutError(
                        provider="codex",
                        model=model,
                        timeout_seconds=expired[1],
                        turn_id=turn_id,
                        code="tool_timeout",
                        tool_calls_seen=budget.count,
                        last_tool=expired[0],
                        limit=expired[1],
                    )
                if note.method == "item/started":
                    payload = getattr(note, "payload", None)
                    item = getattr(payload, "item", None)
                    if item is None:
                        _trace_event(trace, "item/started", payload)
                        continue
                    dumped = item.model_dump(by_alias=True, exclude_none=True, mode="json")
                    item_id = str(getattr(item, "id", "")) or None
                    item_type = str(getattr(item, "type", ""))
                    tool_name = _item_tool_name(item)
                    if item_type in _TOOL_ITEM_TYPES:
                        budget.register(
                            item_id,
                            tool_name,
                            dumped,
                            event_type="item/started",
                        )
                        # Dynamic tools have their own dispatch deadline. A
                        # second item watchdog would override per-tool values.
                        if default_tool_timeout_seconds and item_type != "dynamicToolCall":
                            native_key = item_id or f"anonymous-{budget.count}"
                            active_native_tools[native_key] = (
                                time.monotonic(),
                                tool_name,
                            )
                    else:
                        _trace_event(trace, "item/started", dumped)
                    if budget.exceeded:
                        self._interrupt_turn_async(thread_id, turn_id)
                elif note.method == "item/completed":
                    payload = getattr(note, "payload", None)
                    wrapped_item = getattr(payload, "item", None)
                    item = getattr(wrapped_item, "root", wrapped_item)
                    if item is None:
                        _trace_event(trace, "item/completed", payload)
                        continue
                    dumped = item.model_dump(by_alias=True, exclude_none=True, mode="json")
                    items.append(dumped)
                    item_id = str(getattr(item, "id", "")) or None
                    if item_id:
                        active_native_tools.pop(item_id, None)
                    elif active_native_tools:
                        # A few provider notifications omit an item id. Match
                        # the oldest same-named native tool instead of
                        # allowing an anonymous watchdog entry to linger.
                        completed_name = _item_tool_name(item)
                        for key, (_started, active_name) in sorted(
                            active_native_tools.items(),
                            key=lambda entry: entry[1][0],
                        ):
                            if active_name == completed_name:
                                active_native_tools.pop(key, None)
                                break
                    _trace_event(trace, "item/completed", dumped)
                    if item.type == "agentMessage":
                        final_text = item.text
                elif note.method == "thread/tokenUsage/updated":
                    payload = getattr(note, "payload", None)
                    token_usage = getattr(payload, "token_usage", None)
                    window = getattr(token_usage, "model_context_window", None)
                    if window is not None:
                        _trace_event(trace, "model_context_window", {"tokens": window})
                    last = getattr(token_usage, "last", None)
                    if last is None:
                        _trace_event(trace, "token_usage", payload)
                        continue
                    usage = {
                        "input_tokens": last.input_tokens,
                        "cache_read_input_tokens": last.cached_input_tokens,
                        "cache_creation_input_tokens": 0,
                        "output_tokens": last.output_tokens,
                        "reasoning_output_tokens": last.reasoning_output_tokens,
                        "total_tokens": last.total_tokens,
                    }
                    _trace_event(trace, "token_usage", usage)
                elif note.method == "turn/completed":
                    payload = getattr(note, "payload", None)
                    turn = getattr(payload, "turn", None)
                    if turn is None:
                        _trace_event(trace, "turn/completed", payload)
                        raise RuntimeError("Codex turn completed without turn payload")
                    _trace_event(trace, "turn/completed", turn.model_dump(mode="json"))
                    status = turn.status.value
                    if status != "completed":
                        error = turn.error
                        raise AgentProviderError(
                            f"Codex turn {status}: {error}",
                            provider="codex", terminal_reason=status,
                        )
                    break
        finally:
            with context.active_lock:
                context.active_turn = None
            self._client.unregister_turn_notifications(turn_id)

        result = AgentResult(
            text=final_text,
            structured_response=None,
            provider="codex",
            session_id=thread_id,
            turn_id=turn_id,
            status=status,
            items=items,
            usage=usage,
            elapsed_seconds=time.monotonic() - started_at,
            skills=[skill.trace_identity() for skill in skills],
            tool_calls_seen=budget.count,
            last_tool=budget.last_tool,
        )
        if output_model is not None:
            try:
                if not final_text:
                    raise ValueError("Codex returned no final structured output")
                raw_value = _parse_structured_output_text(final_text)
                decoded = _decode_output_maps(
                    raw_value, output_model.model_json_schema(),
                )
                result.structured_response = decoded  # type: ignore[assignment] -- retain rejected response for audit
                result.structured_response = output_model.model_validate(decoded)
            except (json.JSONDecodeError, ValueError) as error:
                raise _CodexStructuredOutputError(result, error) from error
        return result

    def close(self) -> None:
        with self._contexts_lock:
            self._contexts.clear()
        with self._start_lock:
            if self._started:
                self._client.close()
                self._started = False
        try:
            self._empty_cwd.cleanup()
        except Exception:  # noqa: BLE001
            pass
        if self._isolated_codex_home is not None:
            try:
                self._isolated_codex_home.cleanup()
            except Exception:  # noqa: BLE001
                pass


_RUNTIME = _CodexRuntime()


def _normalize_model(model: str | None) -> str | None:
    if model is None or model in {"", "default", "codex:default"}:
        return None
    if ":" not in model:
        return model
    provider, name = model.split(":", 1)
    if provider not in {"openai", "codex"}:
        raise ValueError(
            f"Codex App Server cannot use provider {provider!r}; configure a "
            "model available through the current ChatGPT account."
        )
    return None if name == "default" else name


def _request_identity(params: dict[str, Any]) -> str | None:
    for key in ("callId", "toolCallId", "id"):
        value = params.get(key)
        if value is not None:
            return str(value)
    return None


def _parse_structured_output_text(text: str) -> Any:
    """Decode one complete JSON response, accepting one fenced JSON block.

    Providers sometimes put an otherwise complete structured response inside
    Markdown commentary. The raw response remains in ``AgentResult.text`` and
    traces; this helper only accepts an unambiguous single fenced block and
    never guesses at or repairs arbitrary prose.
    """
    if not text or not text.strip():
        raise ValueError("Codex returned no final structured output")
    try:
        return json.loads(text)
    except json.JSONDecodeError as direct_error:
        # A few compatible providers prepend a short natural-language
        # conclusion even when the final payload is otherwise a single JSON
        # object. Accept exactly one object that starts on its own line; this
        # is deterministic extraction, not repair of arbitrary prose. Any
        # ambiguity remains a structured-output failure and the raw response
        # is retained in the Agent trace.
        candidates: list[Any] = []
        decoder = json.JSONDecoder()
        offset = 0
        for line in text.splitlines(keepends=True):
            if not line.lstrip().startswith("{"):
                offset += len(line)
                continue
            start = offset + len(line) - len(line.lstrip())
            try:
                value, _ = decoder.raw_decode(text[start:])
            except json.JSONDecodeError:
                offset += len(line)
                continue
            if isinstance(value, dict):
                candidates.append(value)
            offset += len(line)
        if len(candidates) == 1:
            return candidates[0]
        opening_lines = list(re.finditer(
            r"(?m)^[ \t]*```(?P<language>[A-Za-z0-9_-]*)[ \t]*\r?\n(?![ \t]*```)",
            text,
        ))
        opening = [
            (match, re.search(r"(?m)^[ \t]*```[ \t]*\r?$", text[match.end():]))
            for match in opening_lines
        ]
        opening = [(match, close) for match, close in opening if close is not None]
        if len(opening) != 1:
            raise ValueError(
                "structured output must be JSON or contain exactly one fenced JSON block; "
                f"JSON decode error: {direct_error}"
            ) from direct_error
        match, closing = opening[0]
        language = match.group("language").lower()
        if language not in {"", "json"}:
            raise ValueError(
                f"structured output fence uses unsupported language {language!r}"
            ) from direct_error
        inner_end = match.end() + closing.start()
        trailing = text[match.end() + closing.end():]
        if re.search(r"(?m)^[ \t]*```", trailing):
            raise ValueError("structured output contains multiple fenced blocks") from direct_error
        try:
            return json.loads(text[match.end():inner_end].strip())
        except json.JSONDecodeError as fenced_error:
            raise ValueError(
                f"fenced structured output is not valid JSON; error within JSON block: {fenced_error}"
            ) from fenced_error


def _normalize_dynamic_tool_arguments(
    raw: Any,
    selected: AgentTool,
) -> dict[str, Any]:
    """Normalize proxy-provider envelopes before strict tool validation.

    The native App Server sends an argument object directly.  Some
    Codex-compatible providers wrap it as ``{"arguments": "{...}"}`` or
    send the JSON object as a string.  Only these wire-level envelopes are
    decoded; the selected tool still applies strict Pydantic validation.
    """
    value = raw
    fields = selected.args_schema.model_fields
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError(f"dynamic tool arguments string is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("dynamic tool arguments must be a JSON object")
    # Only unwrap the proxy envelope when `arguments` cannot be a legitimate
    # declared parameter of this tool. This preserves strict validation for a
    # real tool whose input schema intentionally contains that field.
    if set(value) == {"arguments"} and "arguments" not in fields:
        nested = value["arguments"]
        if isinstance(nested, str):
            try:
                nested = json.loads(nested)
            except json.JSONDecodeError as error:
                raise ValueError(f"dynamic tool argument envelope is not valid JSON: {error}") from error
        if not isinstance(nested, dict):
            raise ValueError("dynamic tool argument envelope must contain a JSON object")
        return nested
    return value


def _item_tool_name(item: Any) -> str:
    item_type = str(getattr(item, "type", "unknown"))
    for field_name in ("tool", "command", "path", "server"):
        value = getattr(item, field_name, None)
        if value:
            return str(value)
    return item_type


class CodexAnalysisAgent:
    """Task-scoped Codex agent backed by App Server dynamic tools."""

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
    ) -> None:
        if (
            filesystem_access in {"read", "read_shell", "write"}
            and workdir is None
        ):
            raise ValueError(f"filesystem_access={filesystem_access!r} requires workdir")
        if readable_roots and filesystem_access == "none":
            raise ValueError("readable_roots require filesystem access")
        if writable_roots and filesystem_access != "write":
            raise ValueError("writable_roots require filesystem_access='write'")
        invalid_writable_roots = [
            Path(path) for path in writable_roots or [] if not Path(path).is_dir()
        ]
        if invalid_writable_roots:
            raise ValueError(
                "writable_roots must be existing directories: "
                + ", ".join(str(path) for path in invalid_writable_roots)
            )
        self.model = _normalize_model(model)
        self.reasoning_effort = reasoning_effort or configured_codex_reasoning_effort()
        self.developer_instructions = developer_instructions
        self.output_format = output_format
        self.workdir = Path(workdir).resolve() if workdir else _RUNTIME.empty_cwd
        self.filesystem_access = filesystem_access
        self.readable_roots = [
            Path(path).resolve() for path in readable_roots or []
        ]
        self.writable_roots = [
            Path(path).resolve() for path in writable_roots or []
        ]
        self.name = name or "codex-agent"
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
            DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS
            if default_tool_timeout_seconds is None else default_tool_timeout_seconds
        )
        for skill in self.skills:
            skill.validate_current()
        duplicate_names = sorted({
            item.name for item in self.tools
            if sum(other.name == item.name for other in self.tools) > 1
        })
        if duplicate_names:
            raise ValueError(f"Duplicate dynamic tool names: {duplicate_names}")
        duplicate_skills = sorted({
            skill.name for skill in self.skills
            if sum(other.name == skill.name for other in self.skills) > 1
        })
        if duplicate_skills:
            raise ValueError(f"Duplicate Agent Skills: {duplicate_skills}")
        self.thread_id: str | None = None
        self._thread_finalizer: weakref.finalize | None = None

    async def ainvoke(
        self,
        prompt: str,
        *,
        trace: Any | None = None,
    ) -> AgentResult:
        if trace is not None:
            _trace_start(
                trace,
                prompt,
                provider="codex",
                session_id=self.thread_id,
                max_tool_calls=self.max_tool_calls_per_turn,
                default_tool_timeout_seconds=self.default_tool_timeout_seconds,
                turn_timeout_seconds=self.turn_timeout_seconds,
            )
        try:
            # None leaves the whole turn unbounded. An explicit caller limit
            # also covers thread creation; production callers do not set one.
            async with asyncio.timeout(self.turn_timeout_seconds) as turn_deadline:
                for skill in self.skills:
                    skill.validate_current()
                _trace_event(trace, "instruction_context", {
                    "developer_instructions": self.developer_instructions,
                    "skills": [skill.trace_identity() for skill in self.skills],
                    "reasoning_effort": self.reasoning_effort,
                    "model_context_window": configured_codex_context_window(),
                })
                if self.thread_id is None:
                    self.thread_id = await _RUNTIME.start_thread(
                        model=self.model,
                        developer_instructions=self.developer_instructions,
                        tools=self.tools,
                        cwd=self.workdir,
                        filesystem_access=self.filesystem_access,
                        skills=self.skills,
                        readable_roots=self.readable_roots,
                        writable_roots=self.writable_roots,
                        max_tool_calls_per_turn=self.max_tool_calls_per_turn,
                        default_tool_timeout_seconds=self.default_tool_timeout_seconds,
                        reasoning_effort=self.reasoning_effort,
                    )
                    self._thread_finalizer = weakref.finalize(
                        self,
                        _RUNTIME.release_thread,
                        self.thread_id,
                    )
                if trace is not None:
                    _trace_bind(trace, session_id=self.thread_id)
                result = await _RUNTIME.run_turn(
                    thread_id=self.thread_id,
                    prompt=prompt,
                    output_model=self.output_format,
                    cwd=self.workdir,
                    skills=self.skills,
                    timeout_seconds=self.turn_timeout_seconds,
                    trace=trace,
                    max_tool_calls_per_turn=self.max_tool_calls_per_turn,
                    default_tool_timeout_seconds=self.default_tool_timeout_seconds,
                )
                for skill in self.skills:
                    skill.validate_current()
        except _CodexStructuredOutputError as error:
            if trace is not None:
                _trace_fail(
                    trace,
                    error.cause,
                    "structured_output_error",
                    result=error.result,
                    prompt=prompt,
                )
            try:
                setattr(error.cause, "code", "structured_output_error")
                setattr(error.cause, "agent_result", error.result)
            except Exception:
                pass
            raise error.cause from error
        except AgentTurnTimeoutError as error:
            if trace is not None:
                _trace_fail(trace, error, _error_code(error), prompt=prompt)
            raise
        except asyncio.CancelledError as error:
            if trace is not None:
                _trace_fail(trace, error, "cancelled", prompt=prompt)
            raise
        except TimeoutError as error:
            if not turn_deadline.expired():
                if trace is not None:
                    _trace_fail(trace, error, "provider_error", prompt=prompt)
                raise AgentProviderError(str(error), provider="codex", model=self.model) from error
            timeout_error = AgentTurnTimeoutError(
                provider="codex",
                model=self.model,
                timeout_seconds=self.turn_timeout_seconds,
                turn_id=None,
                code="turn_timeout",
            )
            if trace is not None:
                _trace_fail(trace, timeout_error, "turn_timeout", prompt=prompt)
            raise timeout_error from error
        except BaseException as error:
            if trace is not None:
                _trace_fail(trace, error, _error_code(error), prompt=prompt)
            raise
        if trace is not None:
            _trace_finish(trace, result, prompt)
        return result

    async def aclose(self) -> None:
        """Release this agent's local dynamic-tool context."""
        if self._thread_finalizer is not None and self._thread_finalizer.alive:
            self._thread_finalizer()
        self._thread_finalizer = None
        self.thread_id = None

__all__ = [
    "CodexAnalysisAgent",
    "codex_dynamic_tool_spec",
    "codex_turn_input",
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
        # Compatibility for lightweight traces used by non-production tests
        # and older analyzers; production round traces use fail_turn above.
        trace.record(result, prompt=prompt)


def _error_code(error: BaseException) -> str:
    if isinstance(error, AgentToolStepLimitError):
        return "tool_step_limit"
    if isinstance(error, AgentTurnTimeoutError):
        return getattr(error, "code", "turn_timeout")
    if isinstance(error, asyncio.CancelledError):
        return "cancelled"
    if isinstance(error, _CodexStructuredOutputError):
        return "structured_output_error"
    return "provider_error"


def _trace_event(trace: Any | None, event_type: str, payload: Any, **kwargs: Any) -> None:
    if trace is None:
        return
    method = getattr(trace, "record_event", None)
    if method is not None:
        method(event_type, payload, **kwargs)
