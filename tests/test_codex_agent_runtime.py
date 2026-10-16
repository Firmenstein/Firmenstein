"""Unit tests for the framework-neutral Codex dynamic-tool boundary."""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
import unittest
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated
from unittest.mock import AsyncMock, patch

from dotenv import load_dotenv
from pydantic import BaseModel, Field, StringConstraints, ValidationError

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_basic.agent.codex_agent import (  # noqa: E402
    CodexAnalysisAgent,
    _CodexStructuredOutputError,
    _CodexRuntime,
    _codex_provider_overrides,
    _ThreadContext,
    _decode_output_maps,
    _normalize_dynamic_tool_arguments,
    _parse_structured_output_text,
    _permission_profile_config,
    _strict_output_schema,
    codex_dynamic_tool_spec,
)
from fmst_basic.agent.analysis_agent import (  # noqa: E402
    AgentResult,
    AgentTurnTimeoutError,
)
from fmst_basic.agent.config import (  # noqa: E402
    DEFAULT_CODEX_MODEL,
    configured_codex_reasoning_effort,
)
from fmst_basic.agent.tool import tool  # noqa: E402


class _NestedResult(BaseModel):
    label: str


class _StructuredResult(BaseModel):
    name: str
    optional_note: str | None = None
    values: dict[str, _NestedResult]


class _FindingKind(str, Enum):
    VERIFIED = "verified"
    UNRESOLVED = "unresolved"


class _DescribedEnumResult(BaseModel):
    kind: _FindingKind = Field(description="Evidence status visible to the Agent.")


class _NestedToolBatch(BaseModel):
    entries: dict[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]*$")], _DescribedEnumResult]


class _RecursiveToolNode(BaseModel):
    label: str
    children: list[_RecursiveToolNode] = Field(default_factory=list)


class TestAgentTool(unittest.IsolatedAsyncioTestCase):
    def test_malformed_tool_json_reports_position_in_each_wire_envelope(self):
        @tool
        def submit(value: int) -> int:
            """Return the submitted value."""
            return value

        malformed = '{\n  "value": 1,\n}'
        for raw in (malformed, {"arguments": malformed}):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError) as caught:
                    _normalize_dynamic_tool_arguments(raw, submit)
                self.assertIsInstance(caught.exception.__cause__, json.JSONDecodeError)
                self.assertIn(str(caught.exception.__cause__), str(caught.exception))
                self.assertIn("line 3 column 1", str(caught.exception))

    def test_tool_parameter_named_arguments_is_not_a_proxy_envelope(self):
        @tool
        def submit(arguments: str) -> str:
            """Return literal text, which need not be JSON."""
            return arguments

        literal = {"arguments": '{not JSON'}
        self.assertEqual(_normalize_dynamic_tool_arguments(literal, submit), literal)

    def test_nested_dynamic_tool_fields_are_visible_without_resolving_refs(self):
        @tool
        def submit(batch: _NestedToolBatch) -> dict:
            """Submit an evidence batch.

            Args:
                batch: Entries with their evidence status.
            """
            return batch

        original = submit.args_schema.model_json_schema()
        schema = codex_dynamic_tool_spec(submit)["inputSchema"]
        batch = schema["properties"]["batch"]
        entries = batch["properties"]["entries"]
        entry = entries["additionalProperties"]
        kind = entry["properties"]["kind"]
        self.assertEqual(entries["propertyNames"]["pattern"], r"^[a-z][a-z0-9_-]*$")
        self.assertNotIn("patternProperties", entries)
        self.assertEqual(batch["description"], "Entries with their evidence status.")
        self.assertEqual(kind["enum"], ["verified", "unresolved"])
        self.assertEqual(kind["description"], "Evidence status visible to the Agent.")
        self.assertEqual(entry["required"], ["kind"])
        self.assertNotIn("$defs", schema)
        self.assertEqual(submit.args_schema.model_json_schema(), original)
        self.assertEqual(submit.invoke({"batch": {"entries": {"a": {"kind": "verified"}}}}),
                         {"entries": {"a": {"kind": _FindingKind.VERIFIED}}})
        with self.assertRaises(ValidationError):
            submit.invoke({"batch": {"entries": {"a": {"kind": "unknown"}}}})
        with self.assertRaises(ValidationError):
            submit.invoke({"batch": {"entries": {"INVALID": {"kind": "verified"}}}})

    def test_recursive_dynamic_tool_retains_resolvable_cycle(self):
        @tool
        def submit_tree(node: _RecursiveToolNode) -> dict:
            """Submit a tree."""
            return node

        schema = codex_dynamic_tool_spec(submit_tree)["inputSchema"]
        node = schema["properties"]["node"]
        self.assertEqual(node["properties"]["label"]["type"], "string")
        ref = node["properties"]["children"]["items"]["$ref"]
        self.assertIn(ref.removeprefix("#/$defs/"), schema["$defs"])

    async def test_parameterless_tool_accepts_codex_empty_args_wrapper(self) -> None:
        @tool
        def ping() -> str:
            return "pong"

        self.assertEqual(await ping.ainvoke({"args": {}}), "pong")

    async def test_args_wrapper_is_not_accepted_for_parameterized_tool(self) -> None:
        @tool
        def echo(value: str) -> str:
            return value

        with self.assertRaises(ValidationError):
            await echo.ainvoke({"args": {}})

    async def test_sync_and_async_tools_validate_inputs(self):
        @tool
        def add(left: int, right: int = 1) -> int:
            """Add two numbers.

            Args:
                left: First number.
                right: Second number.
            """
            return left + right

        @tool("double")
        async def multiply(value: int) -> int:
            """Double a number.

            Args:
                value: Number to double.
            """
            return value * 2

        self.assertEqual(add.invoke({"left": 2}), 3)
        self.assertEqual(await add.ainvoke({"left": 2, "right": 3}), 5)
        self.assertEqual(await multiply.ainvoke({"value": 4}), 8)
        self.assertEqual(multiply.name, "double")
        self.assertEqual(
            codex_dynamic_tool_spec(add)["inputSchema"]
            ["properties"]["left"]["description"],
            "First number.",
        )
        with self.assertRaises(Exception):
            add.invoke({"left": 1, "unknown": 2})

    async def test_sync_tool_stays_on_owning_event_loop_thread(self):
        owner = threading.get_ident()

        @tool
        def thread_identity() -> int:
            """Return the current thread identity."""
            return threading.get_ident()

        self.assertEqual(await thread_identity.ainvoke({}), owner)

    async def test_async_tool_timeout_can_be_set_per_tool(self):
        cancelled = asyncio.Event()

        @tool(timeout_seconds=0.01)
        async def hang() -> str:
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        with self.assertRaises(asyncio.TimeoutError):
            await hang.ainvoke({})
        await asyncio.wait_for(cancelled.wait(), timeout=1)


class TestStructuredOutputAdapter(unittest.TestCase):
    def test_structured_output_accepts_one_json_fence_with_surrounding_prose(self):
        text = "The result is complete.\n```json\n{\"value\": \"a `quoted` value\"}\n```\n"
        self.assertEqual(
            _parse_structured_output_text(text),
            {"value": "a `quoted` value"},
        )

    def test_structured_output_rejects_multiple_fences(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            _parse_structured_output_text(
                "```json\n{}\n```\n```json\n{}\n```"
            )

    def test_structured_output_rejects_malformed_fence(self):
        with self.assertRaisesRegex(ValueError, "valid JSON"):
            _parse_structured_output_text("```json\n{broken}\n```")

    def test_structured_output_error_reports_json_location(self):
        for text in ['{"a": [1,}', '```json\n{"a": [1,}\n```']:
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, r"line 1 column 10 \(char 9\)"):
                    _parse_structured_output_text(text)

    def test_strict_schema_and_mapping_round_trip(self):
        schema = _strict_output_schema(_StructuredResult)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["required"],
            ["name", "optional_note", "values"],
        )
        self.assertEqual(schema["properties"]["values"]["type"], "array")

        encoded = {
            "name": "sample",
            "optional_note": None,
            "values": [
                {"key": "first", "value": {"label": "one"}},
                {"key": "second", "value": {"label": "two"}},
            ],
        }
        decoded = _decode_output_maps(
            encoded,
            _StructuredResult.model_json_schema(),
        )
        result = _StructuredResult.model_validate(decoded)
        self.assertEqual(result.values["second"].label, "two")

    def test_duplicate_encoded_mapping_key_is_rejected(self):
        encoded = {
            "name": "sample",
            "optional_note": None,
            "values": [
                {"key": "same", "value": {"label": "one"}},
                {"key": "same", "value": {"label": "two"}},
            ],
        }
        with self.assertRaisesRegex(ValueError, "duplicate mapping key"):
            _decode_output_maps(encoded, _StructuredResult.model_json_schema())

    def test_described_enum_ref_is_inlined_for_codex(self):
        schema = _strict_output_schema(_DescribedEnumResult)
        kind = schema["properties"]["kind"]

        self.assertNotIn("$ref", kind)
        self.assertEqual(kind["type"], "string")
        self.assertEqual(kind["enum"], ["verified", "unresolved"])
        self.assertEqual(
            kind["description"],
            "Evidence status visible to the Agent.",
        )


class TestInvalidStructuredOutputTrace(unittest.IsolatedAsyncioTestCase):
    async def test_completed_turn_is_traced_before_validation_error_escapes(self):
        invalid = _StructuredResult.model_validate
        with self.assertRaises(ValidationError) as captured:
            invalid({"name": "sample", "values": {"bad": {}}})
        raw_result = AgentResult(
            text='{"name":"sample","values":{"bad":{}}}',
            structured_response=None,
            provider="codex",
            session_id="thread-1",
            turn_id="turn-1",
            status="completed",
        )
        agent = CodexAnalysisAgent(
            model=DEFAULT_CODEX_MODEL,
            developer_instructions="test",
            output_format=_StructuredResult,
        )
        trace = SimpleNamespace(record=unittest.mock.Mock())
        with (
            patch.object(
                agent,
                "thread_id",
                "thread-1",
            ),
            patch(
                "fmst_basic.agent.codex_agent._RUNTIME.run_turn",
                AsyncMock(
                    side_effect=_CodexStructuredOutputError(
                        raw_result,
                        captured.exception,
                    )
                ),
            ),
        ):
            with self.assertRaises(ValidationError):
                await agent.ainvoke("prompt", trace=trace)
        trace.record.assert_called_once_with(raw_result, prompt="prompt")


class TestThreadInstructions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runtime = _CodexRuntime()
        self.runtime.validate_model = AsyncMock()

    async def asyncTearDown(self):
        self.runtime.close()

    async def test_explicit_context_window_is_sent_to_app_server(self):
        started = SimpleNamespace(thread=SimpleNamespace(id="context-thread"), instruction_sources=[])
        with patch.dict("os.environ", {"FMST_CODEX_CONTEXT_WINDOW": "1000000"}):
            with patch.object(self.runtime._client, "thread_start", return_value=started) as start:
                await self.runtime.start_thread(model="deepseek-flash", developer_instructions="task",
                    tools=[], cwd=self.runtime.empty_cwd, filesystem_access="none", reasoning_effort="high")
        self.assertEqual(start.call_args.args[0]["config"]["model_context_window"], 1000000)
        self.assertEqual(start.call_args.args[0]["config"]["model_auto_compact_token_limit"], 950000)
        self.assertEqual(start.call_args.args[0]["config"]["model_reasoning_effort"], "high")

    async def test_explicit_effort_is_local_to_one_agent(self):
        started = SimpleNamespace(thread=SimpleNamespace(id="effort-thread"), instruction_sources=[])
        with patch.dict("os.environ", {"FMST_CODEX_REASONING_EFFORT": "high"}):
            with patch.object(self.runtime._client, "thread_start", return_value=started) as start:
                await self.runtime.start_thread(model=None, developer_instructions="Planner contract",
                    tools=[], cwd=self.runtime.empty_cwd, filesystem_access="none", reasoning_effort="max")
            self.assertEqual(start.call_args.args[0]["config"]["model_reasoning_effort"], "max")
            self.assertEqual(configured_codex_reasoning_effort(), "high")

    async def test_thread_uses_codex_base_and_only_explicit_developer_contract(self):
        started = SimpleNamespace(
            thread=SimpleNamespace(id="thread-1"),
            instruction_sources=[],
        )
        with patch.object(
            self.runtime._client,
            "thread_start",
            return_value=started,
        ) as thread_start:
            thread_id = await self.runtime.start_thread(
                model=None,
                developer_instructions="firmware analysis contract",
                tools=[],
                cwd=self.runtime.empty_cwd,
                filesystem_access="none",
            )

        self.assertEqual(thread_id, "thread-1")
        params = thread_start.call_args.args[0]
        self.assertNotIn("baseInstructions", params)
        self.assertEqual(
            params["developerInstructions"],
            "firmware analysis contract",
        )
        self.assertEqual(params["config"]["project_doc_max_bytes"], 0)
        self.assertEqual(
            params["config"]["model_reasoning_effort"],
            configured_codex_reasoning_effort(),
        )
        self.assertFalse(params["config"]["features"]["shell_tool"])
        self.assertFalse(params["config"]["features"]["unified_exec"])
        self.assertIn("thread-1", self.runtime._contexts)

    async def test_thread_omits_empty_developer_contract(self):
        started = SimpleNamespace(thread=SimpleNamespace(id="thread-empty"), instruction_sources=[])
        with patch.object(self.runtime._client, "thread_start", return_value=started) as thread_start:
            await self.runtime.start_thread(model=None, developer_instructions="", tools=[],
                cwd=self.runtime.empty_cwd, filesystem_access="none")
        self.assertNotIn("developerInstructions", thread_start.call_args.args[0])

    def test_firmenstein_provider_overrides_are_process_local(self):
        with patch.dict(
            "os.environ",
            {
                "FMST_CODEX_BASE_URL": "https://proxy.example.test",
                "FMST_CODEX_AUTH_TOKEN": "secret-for-test",
            },
            clear=False,
        ):
            overrides = _codex_provider_overrides("high-five")

        self.assertIn(
            'model_providers.high-five.base_url="https://proxy.example.test"',
            overrides,
        )
        self.assertIn(
            'model_providers.high-five.auth.command="sh"',
            overrides,
        )
        self.assertIn(
            'model_providers.high-five.auth.args=["-c", "printf \\\"%s\\\" \\\"$FMST_CODEX_AUTH_TOKEN\\\""]',
            overrides,
        )
        self.assertNotIn("secret-for-test", " ".join(overrides))
        self.assertIn(
            'model_providers.high-five.name="high-five"',
            overrides,
        )

    async def test_non_default_provider_uses_app_server_model_provider_field(self):
        started = SimpleNamespace(
            thread=SimpleNamespace(id="thread-provider"),
            instruction_sources=[],
        )
        self.runtime.model_provider = "high-five"
        with patch.object(
            self.runtime._client,
            "thread_start",
            return_value=started,
        ) as thread_start:
            await self.runtime.start_thread(
                model="deepseek/deepseek-v4-flash",
                developer_instructions="test",
                tools=[],
                cwd=self.runtime.empty_cwd,
                filesystem_access="none",
            )

        params = thread_start.call_args.args[0]
        self.assertEqual(params["modelProvider"], "high-five")
        self.assertNotIn("model_provider", params)
        self.assertEqual(params["model"], "deepseek/deepseek-v4-flash")

    def test_non_default_provider_requires_firmenstein_credentials(self):
        with patch.dict(
            "os.environ",
            {
                "FMST_CODEX_BASE_URL": "",
                "FMST_CODEX_AUTH_TOKEN": "",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "FMST_CODEX_BASE_URL"):
                _codex_provider_overrides("high-five")

    def test_default_provider_requires_a_firmenstein_state_directory(self):
        with patch.dict(
            "os.environ",
            {
                "FMST_CODEX_MODEL_PROVIDER": "codex",
                "FMST_CODEX_STATE_DIR": "",
            },
            clear=False,
        ):
            runtime = _CodexRuntime()
            try:
                with self.assertRaisesRegex(RuntimeError, "FMST_CODEX_STATE_DIR"):
                    runtime._ensure_started()
            finally:
                runtime.close()

    def test_default_provider_rejects_the_user_codex_directory(self):
        with patch.dict(
            "os.environ",
            {
                "FMST_CODEX_MODEL_PROVIDER": "codex",
                "FMST_CODEX_STATE_DIR": str(Path.home() / ".codex"),
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "user's ~/.codex"):
                _CodexRuntime()

    def test_default_provider_uses_only_the_explicit_firmenstein_state_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "codex-state"
            with patch.dict(
                "os.environ",
                {
                    "FMST_CODEX_MODEL_PROVIDER": "codex",
                    "FMST_CODEX_STATE_DIR": str(state_dir),
                    "CODEX_HOME": str(Path.home() / ".codex"),
                },
                clear=False,
            ):
                runtime = _CodexRuntime()
                try:
                    self.assertIsNone(runtime._isolated_codex_home)
                    self.assertEqual(
                        runtime._client.config.env["CODEX_HOME"],
                        str(state_dir.resolve()),
                    )
                    self.assertTrue(state_dir.is_dir())
                finally:
                    runtime.close()

    def test_project_codex_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".codex").mkdir()
            (root / ".codex/config.toml").write_text("model = 'external'\n")
            with self.assertRaisesRegex(RuntimeError, "project config"):
                asyncio.run(
                    self.runtime.start_thread(
                        model=None,
                        developer_instructions="",
                        tools=[],
                        cwd=root,
                        filesystem_access="none",
                    )
                )

    def test_user_global_codex_config_is_not_treated_as_project_config(self):
        # The real repository lives below the user's home, which contains the
        # global ~/.codex/config.toml under audit. The project-layer guard must
        # stop before treating that global file as a project override.
        from fmst_basic.agent.codex_agent import _reject_project_codex_config

        _reject_project_codex_config(Path.cwd())

    async def test_read_mode_enables_native_shell_in_read_only_sandbox(self):
        started = SimpleNamespace(
            thread=SimpleNamespace(id="thread-read"),
            instruction_sources=[],
        )
        with patch.object(
            self.runtime._client,
            "thread_start",
            return_value=started,
        ) as thread_start:
            await self.runtime.start_thread(
                model=None,
                developer_instructions="test",
                tools=[],
                cwd=self.runtime.empty_cwd,
                filesystem_access="read",
            )

        params = thread_start.call_args.args[0]
        self.assertNotIn("sandbox", params)
        self.assertTrue(params["config"]["features"]["shell_tool"])
        self.assertTrue(params["config"]["features"]["unified_exec"])
        self.assertEqual(params["config"]["default_permissions"], "fmst-read")

    async def test_unexpected_project_instructions_fail_before_context_registration(self):
        started = SimpleNamespace(
            thread=SimpleNamespace(id="thread-2"),
            instruction_sources=["/repo/AGENTS.md"],
        )
        with patch.object(
            self.runtime._client,
            "thread_start",
            return_value=started,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "unexpected project instruction sources",
            ):
                await self.runtime.start_thread(
                    model=None,
                    developer_instructions="firmware analysis contract",
                    tools=[],
                    cwd=self.runtime.empty_cwd,
                    filesystem_access="none",
                )

        self.assertNotIn("thread-2", self.runtime._contexts)


class TestFilesystemSandbox(unittest.TestCase):
    def test_read_mode_uses_only_native_codex_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = CodexAnalysisAgent(
                model=DEFAULT_CODEX_MODEL,
                developer_instructions="test",
                workdir=Path(tmp),
                filesystem_access="read",
            )
        self.assertEqual(agent.tools, [])

    def test_read_and_none_profiles_use_minimal_runtime_access(self):
        read = _permission_profile_config("read")
        read_shell = _permission_profile_config("read_shell")
        none = _permission_profile_config("none")
        read_filesystem = read["permissions"]["fmst-read"]["filesystem"]
        read_shell_filesystem = read_shell["permissions"][
            "fmst-read_shell"
        ]["filesystem"]
        none_filesystem = none["permissions"]["fmst-none"]["filesystem"]

        self.assertEqual(read["default_permissions"], "fmst-read")
        self.assertEqual(read_filesystem[":minimal"], "read")
        self.assertEqual(read_filesystem[":workspace_roots"], {".": "read"})
        self.assertEqual(
            read_shell_filesystem[":workspace_roots"], {".": "read"}
        )
        self.assertEqual(none_filesystem[":minimal"], "read")
        self.assertNotIn(":workspace_roots", none_filesystem)
        self.assertTrue(all(value == "read" for value in none_filesystem.values()))
        self.assertFalse(read["permissions"]["fmst-read"]["network"]["enabled"])

    def test_write_profile_only_adds_workspace_write_access(self):
        profile = _permission_profile_config("write")
        filesystem = profile["permissions"]["fmst-write"]["filesystem"]
        self.assertEqual(filesystem[":minimal"], "read")
        self.assertEqual(filesystem[":workspace_roots"], {".": "write"})
        self.assertNotIn(":tmpdir", filesystem)
        self.assertNotIn(":slash_tmp", filesystem)


class TestDynamicToolDispatch(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runtime = _CodexRuntime()

    async def asyncTearDown(self):
        self.runtime.close()

    async def test_concurrent_requests_share_no_arguments_or_results(self):
        entered = 0
        both_entered = asyncio.Event()

        @tool
        async def echo(value: str) -> str:
            nonlocal entered
            entered += 1
            if entered == 2:
                both_entered.set()
            await asyncio.wait_for(both_entered.wait(), timeout=1)
            return value

        self.runtime._contexts["thread"] = _ThreadContext(
            tools={"echo": echo},
            loop=asyncio.get_running_loop(),
        )

        async def call(value: str):
            return await asyncio.to_thread(
                self.runtime._handle_server_request,
                "item/tool/call",
                {
                    "threadId": "thread",
                    "tool": "echo",
                    "arguments": {"value": value},
                },
            )

        first, second = await asyncio.gather(call("first"), call("second"))
        self.assertTrue(first["success"])
        self.assertTrue(second["success"])
        self.assertEqual(first["contentItems"][0]["text"], "first")
        self.assertEqual(second["contentItems"][0]["text"], "second")

    async def test_timeout_cancels_async_tool_and_returns_failed_call(self):
        cancelled = asyncio.Event()

        @tool
        async def hang() -> str:
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        self.runtime._contexts["thread"] = _ThreadContext(
            tools={"hang": hang},
            loop=asyncio.get_running_loop(),
        )
        with patch(
            "fmst_basic.agent.codex_agent.DYNAMIC_TOOL_TIMEOUT_SECONDS",
            0.01,
        ):
            result = await asyncio.to_thread(
                self.runtime._handle_server_request,
                "item/tool/call",
                {"threadId": "thread", "tool": "hang", "arguments": {}},
            )

        await asyncio.wait_for(cancelled.wait(), timeout=1)
        self.assertFalse(result["success"])
        self.assertIn("TimeoutError", result["contentItems"][0]["text"])

    async def test_tool_exception_returns_failed_call(self):
        @tool
        def explode() -> str:
            raise RuntimeError("expected failure")

        self.runtime._contexts["thread"] = _ThreadContext(
            tools={"explode": explode},
            loop=asyncio.get_running_loop(),
        )
        result = await asyncio.to_thread(
            self.runtime._handle_server_request,
            "item/tool/call",
            {"threadId": "thread", "tool": "explode", "arguments": {}},
        )
        self.assertFalse(result["success"])
        self.assertEqual(
            result["contentItems"][0]["text"],
            "RuntimeError: expected failure",
        )

    async def test_proxy_tool_argument_envelope_is_unwrapped(self):
        @tool
        def echo(value: str) -> str:
            return value

        self.runtime._contexts["thread"] = _ThreadContext(
            tools={"echo": echo},
            loop=asyncio.get_running_loop(),
        )
        result = await asyncio.to_thread(
            self.runtime._handle_server_request,
            "item/tool/call",
            {
                "threadId": "thread",
                "tool": "echo",
                "arguments": {"arguments": '{"value": "wrapped"}'},
            },
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["contentItems"][0]["text"], "wrapped")

    async def test_malformed_proxy_arguments_fail_without_invoking_tool(self):
        called = []

        @tool
        def echo(value: str) -> str:
            called.append(value)
            return value

        self.runtime._contexts["thread"] = _ThreadContext(
            tools={"echo": echo},
            loop=asyncio.get_running_loop(),
        )
        result = await asyncio.to_thread(
            self.runtime._handle_server_request,
            "item/tool/call",
            {
                "threadId": "thread",
                "tool": "echo",
                "arguments": {"arguments": "not-json"},
            },
        )
        self.assertFalse(result["success"])
        self.assertIn("not valid JSON", result["contentItems"][0]["text"])
        self.assertEqual(called, [])

    async def test_arguments_field_is_not_mistaken_for_proxy_envelope(self):
        @tool
        def echo(arguments: str) -> str:
            return arguments

        self.runtime._contexts["thread"] = _ThreadContext(
            tools={"echo": echo},
            loop=asyncio.get_running_loop(),
        )
        result = await asyncio.to_thread(
            self.runtime._handle_server_request,
            "item/tool/call",
            {
                "threadId": "thread",
                "tool": "echo",
                "arguments": {"arguments": "legitimate"},
            },
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["contentItems"][0]["text"], "legitimate")


class TestTurnTimeout(unittest.TestCase):
    def test_expired_codex_turn_is_interrupted(self) -> None:
        interrupted = threading.Event()

        class _FakeClient:
            def turn_start(self, thread_id, turn_input, *, params):
                del thread_id, turn_input, params
                return SimpleNamespace(turn=SimpleNamespace(id="turn-timeout"))

            def turn_interrupt(self, thread_id, turn_id):
                self.interrupt_args = (thread_id, turn_id)
                interrupted.set()

            def next_turn_notification(self, turn_id):
                assert turn_id == "turn-timeout"
                assert interrupted.wait(timeout=1)
                return SimpleNamespace(
                    method="turn/completed",
                    payload=SimpleNamespace(
                        turn=SimpleNamespace(
                            status=SimpleNamespace(value="interrupted"),
                            error=None,
                        )
                    ),
                )

            def unregister_turn_notifications(self, turn_id):
                self.unregistered = turn_id

        runtime = _CodexRuntime()
        runtime._client = _FakeClient()
        try:
            with self.assertRaises(AgentTurnTimeoutError) as caught:
                runtime._run_turn_sync(
                    "thread-timeout",
                    "inspect",
                    None,
                    None,
                    runtime.empty_cwd,
                    [],
                    0.0,
                    timeout_seconds=0.01,
                )
            self.assertEqual(
                runtime._client.interrupt_args,
                ("thread-timeout", "turn-timeout"),
            )
            self.assertEqual(runtime._client.unregistered, "turn-timeout")
            self.assertEqual(caught.exception.turn_id, "turn-timeout")
        finally:
            runtime._started = False
            runtime._empty_cwd.cleanup()

    def test_expired_turn_does_not_wait_for_completion_notification(self) -> None:
        interrupted = threading.Event()
        release_notification = threading.Event()

        class _FakeClient:
            def turn_start(self, thread_id, turn_input, *, params):
                del thread_id, turn_input, params
                return SimpleNamespace(turn=SimpleNamespace(id="turn-stuck"))

            def turn_interrupt(self, thread_id, turn_id):
                self.interrupt_args = (thread_id, turn_id)
                interrupted.set()

            def next_turn_notification(self, turn_id):
                assert turn_id == "turn-stuck"
                release_notification.wait(timeout=1)
                return SimpleNamespace(
                    method="turn/completed",
                    payload=SimpleNamespace(
                        turn=SimpleNamespace(
                            status=SimpleNamespace(value="interrupted"),
                            error=None,
                        )
                    ),
                )

            def unregister_turn_notifications(self, turn_id):
                self.unregistered = turn_id

        runtime = _CodexRuntime()
        runtime._client = _FakeClient()
        started_at = time.monotonic()
        try:
            with self.assertRaises(AgentTurnTimeoutError):
                runtime._run_turn_sync(
                    "thread-stuck",
                    "inspect",
                    None,
                    None,
                    runtime.empty_cwd,
                    [],
                    started_at,
                    timeout_seconds=0.01,
                )
            self.assertLess(time.monotonic() - started_at, 0.5)
            self.assertTrue(interrupted.wait(timeout=0.5))
            self.assertEqual(runtime._client.unregistered, "turn-stuck")
        finally:
            release_notification.set()
            runtime._started = False
            runtime._empty_cwd.cleanup()


if __name__ == "__main__":
    unittest.main()
