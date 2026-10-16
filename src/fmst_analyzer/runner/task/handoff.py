"""Post-completion delivery description, collected on the existing Agent client.

The models describe engineering facts and executable recipes. They never decide
whether firmware behavior passes; that decision stays in ServiceCompletion.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import write_json


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Reference(Record):
    path: str = Field(min_length=1, description="Absolute container file or directory path; must exist.")
    purpose: str = Field(min_length=1, description="What this retained artifact or evidence establishes.")


class EngineeringFinding(Record):
    issue: str = Field(min_length=1, description="Observed failure or environment dependency addressed.")
    assessment: Literal["confirmed", "inferred", "unknown"] = Field(description="Certainty of the cause, distinguished from directly observed behavior.")
    explanation: str = Field(min_length=1, description="Concise engineering rationale supported by evidence; not a transcript of private reasoning.")
    changes: list[str] = Field(description="Intervention, configuration, peer, source or system changes actually made.")
    outcome: str = Field(min_length=1, description="Observed effect and any unresolved uncertainty.")
    evidence: list[Reference] = Field(description="Supporting files; empty if the relevant evidence was not retained.")


class Command(Record):
    argv: list[str] = Field(min_length=1, description="Literal executable and arguments. Use an existing script for compound startup; no implicit shell parsing.")
    cwd: str = Field(description="Absolute existing container working directory.")
    env: dict[str, str] = Field(default_factory=dict, description="Necessary service environment only; no model credentials.")
    timeout_seconds: int = Field(default=120, ge=1, le=300, description="Bound for starting the service and writing its fresh receipt, not its lifetime.")

    @model_validator(mode="after")
    def valid_command(self):
        if not self.argv[0] or any("\x00" in part for part in self.argv):
            raise ValueError("argv must contain a nonempty executable and no NUL")
        absolute_path(self.cwd)
        for key, value in self.env.items():
            if not key or "=" in key or "\x00" in key + value:
                raise ValueError("Invalid environment entry")
            if key.startswith(("ANTHROPIC_", "FMST_CLAUDE_", "FMST_CODEX_")) or key in {"OPENAI_API_KEY", "OPENAI_BASE_URL"}:
                raise ValueError("Model configuration does not belong in a service recipe")
        return self


class Startup(Record):
    availability: Literal["available", "unavailable"] = Field(description="Whether an executable recipe is supplied; availability does not claim it was replayed.")
    command: Command | None = Field(default=None, description="Idempotent startup entrypoint that preserves current user configuration and uses init-owned jobs.")
    receipt_path: str | None = Field(default=None, description="Absolute /task/delivery/... JSON written afresh on every startup, with service_pid, service_start_ticks, log_paths and execution_path. Never reuse the completion PID.")
    prerequisites: list[str] = Field(default_factory=list, description="Conditions needed to recreate local dependencies, namespaces and access transport.")
    unavailable_reason: str | None = Field(default=None, description="Concrete missing information when no safe startup recipe can be supplied.")

    @model_validator(mode="after")
    def consistent(self):
        if self.availability == "available":
            if self.command is None or self.receipt_path is None:
                raise ValueError("An available recipe needs command and receipt_path")
            path = absolute_path(self.receipt_path)
            if not path.is_relative_to("/task/delivery") or path == PurePosixPath("/task/delivery"):
                raise ValueError("Startup receipt belongs under /task/delivery")
            if path.name in {"completion.json", "handoff.json", "handoff-status.json", "handoff-schema.json",
                             "evidence.json", "resource.json", "host-stop.json", "instance.json"}:
                raise ValueError("Startup must not overwrite completion or handoff records")
        elif not self.unavailable_reason or self.command is not None or self.receipt_path is not None:
            raise ValueError("Unavailable startup needs a reason and no executable recipe")
        return self


class Access(Record):
    native_url: str = Field(min_length=1, description="Exact native service URL, preserving its hostname and port.")
    transport: Literal["socks5", "container", "direct"] = Field(description="socks5 uses the task's port 1080; container requires the documented container command; direct is already reachable locally.")
    instructions: str = Field(min_length=1, description="User access and login instructions, including any browser requirements. Do not include model credentials.")


class State(Record):
    path: str = Field(description="Absolute container path containing state or a runtime resource.")
    role: str = Field(min_length=1, description="What service behavior consumes this state.")
    persistence: Literal["filesystem", "external_mount", "recreate", "volatile"] = Field(description="Filesystem is captured in image; external_mount needs a separate archive; recreate is rebuilt by startup; volatile is not saved.")
    initialization: str = Field(min_length=1, description="How startup preserves delivered/user configuration or recreates a resource; distinguish defaults from live configuration.")


class RestartVerification(Record):
    status: Literal["not_tested", "tested", "failed"] = Field(description="Actual restart evidence only. Do not restart the retained service merely to fill this field.")
    details: str = Field(min_length=1, description="What was tested or why restart remains unverified.")
    evidence: list[Reference] = Field(default_factory=list, description="Evidence from any real restart already performed.")


class HandoffDraftV1(Record):
    schema_version: Literal[1] = Field(default=1, description="Delivery draft format version.")
    summary: str = Field(min_length=1, description="Purpose and usable scope of the delivered local test environment.")
    analysis: list[EngineeringFinding] = Field(description="Concise explanation of material repairs and remaining causes, with evidence and certainty.")
    startup: Startup = Field(description="Machine-executable startup recipe or explicit unavailability.")
    access: Access = Field(description="How the user reaches the native service.")
    state: list[State] = Field(description="Persistent configuration and runtime dependencies that matter to restart.")
    key_artifacts: list[Reference] = Field(description="Actual entrypoint, intervention, backend changes and loaded binaries; full filesystem is captured separately.")
    evidence: list[Reference] = Field(description="Key execution/trace/browser evidence already retained.")
    limitations: list[str] = Field(description="Known limitations and untested functionality, without hiding native defects.")
    restart_verification: RestartVerification = Field(description="Existing restart evidence, separate from original business completion.")


def absolute_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise ValueError("Expected an absolute container path without traversal")
    if path.is_relative_to("/task/sessions"):
        raise ValueError("Native session history is private recovery material, not a delivery artifact")
    return path


def references(draft: HandoffDraftV1) -> list[Reference]:
    return (draft.key_artifacts + draft.evidence + draft.restart_verification.evidence
            + [ref for finding in draft.analysis for ref in finding.evidence])


def validate_references(draft: HandoffDraftV1) -> None:
    """Container-local existence checks only; no inferred business acceptance."""
    for ref in references(draft):
        absolute_path(ref.path)
        path = Path(ref.path).resolve(strict=True)
        absolute_path(str(path))
        if not (path.is_file() or path.is_dir()):
            raise ValueError(f"Artifact must be a file or directory: {ref.path}")
    for state in draft.state:
        absolute_path(state.path)
        if state.persistence in {"filesystem", "external_mount"} and not Path(state.path).exists():
            raise ValueError(f"Persistent state does not exist: {state.path}")
    if draft.startup.command:
        command = draft.startup.command
        if not Path(command.cwd).is_dir():
            raise ValueError("Startup cwd does not exist")
        import shutil
        executable = command.argv[0]
        if "/" in executable:
            executable = str(Path(command.cwd) / executable)
        if not shutil.which(executable):
            raise ValueError("Startup executable does not exist or is not executable")
        artifacts = {ref.path for ref in draft.key_artifacts if Path(ref.path).is_file()}
        if not any(arg in artifacts for arg in command.argv):
            raise ValueError("Startup must reference its actual executable/script in key_artifacts")


HANDOFF_MESSAGE = """The original service goal is complete and its completion record is frozen.
Now organize delivery for the user in this same session. Read the JSON Schema at
{schema}; atomically write the corresponding JSON object to {output}.
Describe the observed problems, evidence, repairs, usable scope and limitations
concisely. Provide actual startup/access/state/artifact fields for automated use.
Use existing files and evidence. You may add a thin startup wrapper that rebuilds
runtime namespaces and peers, uses init-owned jobs, preserves current user state,
and writes a fresh receipt as described by the schema. The receipt must identify
the new service and its logs/execution; never copy a historical PID as a new one.
Do not restart or stop the retained service, redo business testing, make further
firmware repairs, or change the original completion. Mark missing information
and untested restart honestly. Keep native histories under /task/sessions intact;
they are private recovery material. The framework will capture the filesystem,
record exact images and render the user README from your structured output.
This delivery-only turn has a short remaining budget; finish after writing JSON.
"""


async def collect_handoff(agent, trace, *, task_root: Path, deadline: float) -> dict:
    """One initial request plus at most two format/reference corrections."""
    root = task_root / "delivery"
    schema = root / "handoff-schema.json"
    output = root / "handoff.json"
    write_json(schema, HandoffDraftV1.model_json_schema())
    attempts = root / "handoff-attempts"
    attempts.mkdir(exist_ok=True)
    status = {"status": "collecting", "started_at": time.time(), "deadline": deadline}
    write_json(root / "handoff-status.json", status)
    message = HANDOFF_MESSAGE.format(schema=schema, output=output)
    try:
        for attempt in range(3):
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("Delivery handoff deadline reached")
            await asyncio.wait_for(agent.ainvoke(message, trace=trace), remaining)
            raw = output.read_bytes() if output.exists() else b""
            (attempts / f"{attempt + 1}.json").write_bytes(raw)
            try:
                draft = HandoffDraftV1.model_validate_json(raw)
                validate_references(draft)
            except (ValueError, OSError) as error:
                # Pydantic error text can contain submitted values. Keep it in
                # task-local artifacts; never stream it into the outer report.
                write_json(attempts / f"{attempt + 1}-error.json", {"error": str(error)})
                message = ("Correct only the delivery format or missing references in " + str(output)
                           + ". Validation details are in " + str(attempts / f"{attempt + 1}-error.json")
                           + ". Preserve the service, original completion and session history.")
                status.update(status="invalid", attempts=attempt + 1)
            else:
                write_json(output, draft.model_dump(mode="json"))
                status.update(status="ready", attempts=attempt + 1)
                break
    except TimeoutError:
        status.update(status="timeout")
    except asyncio.CancelledError:
        status.update(status="interrupted")
        raise
    except Exception as error:
        status.update(status="error", error_type=type(error).__name__)
    finally:
        status["finished_at"] = time.time()
        write_json(root / "handoff-status.json", status)
    return status
