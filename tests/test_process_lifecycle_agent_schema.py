"""Structured output and controller input for ProcessLifecycleAgent."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.process_lifecycle import (
    ProcessLifecycleAgentResult,
)
from fmst_analyzer.analysis.process_lifecycle.process_lifecycle_prompt import (
    PROCESS_LIFECYCLE_USER_PROMPT,
)


def test_agent_schema_is_the_small_semantic_draft():
    properties = ProcessLifecycleAgentResult.model_json_schema()["properties"]
    assert set(properties) == {
        "disposition",
        "trigger_callsites",
        "trigger_inputs",
        "summary",
        "evidence",
        "missing_evidence",
        "finding",
    }
    assert all(item.get("description") for item in properties.values())


def test_user_prompt_carries_full_controller_identity():
    rendered = PROCESS_LIFECYCLE_USER_PROMPT.format(
        callsite_id="process-event:abc",
        event_kind="termination",
        api_name="exit",
        binary_name="httpd",
        function_name="main",
        function_ea=0x1000,
        snapshot_hash="snap",
        ctree_index=7,
        source_ea="0x1040",
        line_number=10,
        column_number=6,
    )
    fields = dict(
        line.removeprefix("- ").split(": ", 1)
        for line in rendered.splitlines() if line.startswith("- ")
    )
    assert fields == {
        "callsite_id": "process-event:abc",
        "event_kind": "termination",
        "api_name": "exit",
        "binary_name": "httpd",
        "function_name": "main",
        "function_ea": "0x1000",
        "snapshot_hash": "snap",
        "ctree_index": "7",
        "source_ea": "0x1040",
        "line_number": "10",
        "column_number": "6",
    }
