"""Deterministic feedback and durable request/response/execution receipts.

An invocation starting is not proof of delivery. A returned decision proves a
response to that invocation, not that the model understood every artifact.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from typing import Literal

from pydantic import Field

from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json
from .schema import RunnerDecision, RuntimeAttempt, RuntimeEventContext, RuntimeTraceContext, RuntimeNetwork, StrictModel
from .identity import copy_file
from .attempt_facts import AttemptFacts, build_attempt_facts, read_request_records
from .owner_context import read_runtime_owners


class FeedbackPreview(StrictModel):
    path: str = Field(description="Full original artifact; the preview never replaces it.")
    text: str = Field(default="", description="UTF-8-decoded tail, with replacement of invalid bytes.")
    total_bytes: int = Field(default=0, description="Original file size at collection.")
    captured_bytes: int = Field(default=0, description="Bytes read from the end of the original file.")
    error: str | None = Field(default=None, description="Read failure, not a guest failure.")


def file_preview(path: Path, limit: int = 2048) -> FeedbackPreview:
    """Read a bounded tail; no unbounded read followed by hidden string slicing."""
    preview = FeedbackPreview(path=str(path))
    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            preview.total_bytes = stream.tell()
            stream.seek(max(0, preview.total_bytes - limit))
            raw = stream.read(limit)
        preview.text = raw.decode("utf-8", errors="replace")
        preview.captured_bytes = len(raw)
    except OSError as error:
        preview.error = str(error)
    return preview


def render_preview(preview: FeedbackPreview) -> str:
    if preview.error:
        return f"{preview.path}: unavailable: {preview.error}"
    extent = (f"truncated, tail {preview.captured_bytes} of {preview.total_bytes} bytes"
              if preview.captured_bytes < preview.total_bytes else f"{preview.total_bytes} bytes")
    return f"{preview.path} ({extent}; log time is not snapshot time):\n{preview.text}"


class PartialExecutionFeedback(StrictModel):
    kind: Literal["partial_execution"] = Field(default="partial_execution", description="Incomplete execution, never a completed RuntimeAttempt or service result.")
    session_id: str = Field(description="Owning Controller session.")
    attempt_number: int = Field(description="Failed execution number within that session.")
    error: str = Field(description="Unabridged execution exception; not an inferred guest root cause.")
    artifacts: dict[str, str] = Field(default_factory=dict, description="Copied evidence under the Agent's read-only report root; absent entries were not collected.")
    collection_errors: list[str] = Field(default_factory=list, description="Missing evidence or copy errors; successful artifacts remain available.")
    previews: list[FeedbackPreview] = Field(default_factory=list, description="Bounded log and receipt excerpts, retaining full source paths and byte extents.")


def collect_partial_feedback(*, source: Path, receipt: Path, destination: Path,
                             session_id: str, attempt_number: int, error: str,
                             budget) -> PartialExecutionFeedback:
    """Publish interrupted execution evidence without inventing a RuntimeAttempt.

    Only named regular artifacts are copied, with the same session budget.
    Originals and copy failures remain attributable; guest symlinks are rejected.
    """
    destination.mkdir(parents=True, exist_ok=True)
    result = PartialExecutionFeedback(session_id=session_id, attempt_number=attempt_number, error=error)
    candidates = [(receipt, "execution-receipt.json")]
    for pattern in ("container.log", "companion-*.log", "peer-readiness.json", "processes*.json",
                    "watchdog.json", "*-exit.json", "runtime_trace*.json", "cleanup.json",
                    "diagnostics-*.json", "diagnostics-*.log", "child-failures.json", "core-collection.json",
                    "*.core", "collected-cores/*.core", "runtime-dump/*", "runtime-dump/cores/*"):
        candidates.extend((path, path.relative_to(source).as_posix()) for path in sorted(source.glob(pattern)))
    for path, name in candidates:
        try:
            if path.is_symlink():
                raise OSError("symlink evidence is not copied")
            if not path.is_file():
                raise OSError("evidence file is missing")
            output = destination / name
            output.parent.mkdir(parents=True, exist_ok=True)
            copy_file(path, output, budget=budget)
            result.artifacts[name] = str(output)
            if name.endswith(".log") or name in {"execution-receipt.json", "peer-readiness.json"}:
                result.previews.append(file_preview(output))
        except OSError as failure:
            result.collection_errors.append(f"{path}: {failure}")
    if (destination / "runtime-owners.json").is_file():
        result.artifacts["runtime_owners"] = str(destination / "runtime-owners.json")
    result.artifacts["partial_feedback"] = str(destination / "partial-feedback.json")
    write_model_json(destination / "partial-feedback.json", result)
    return result


def render_partial_feedback(feedback: PartialExecutionFeedback) -> str:
    """Send the outcome and evidence routes; retained files hold all details."""
    path = feedback.artifacts.get("partial_feedback")
    root = Path(path).parent if path else None
    return "\n".join([
        f"Partial execution: session={feedback.session_id} attempt={feedback.attempt_number}",
        feedback.error,
        "This partial execution is available for diagnosis and intervention repair.",
        f"partial_feedback_path={feedback.artifacts.get('partial_feedback', root / 'partial-feedback.json' if root else 'not collected')}",
        f"evidence_root={root}",
        f"retained_artifacts={len(feedback.artifacts)}; collection_errors={len(feedback.collection_errors)}",
        "Read the feedback file and selected trace/log files as needed; missing capture is unknown.",
    ])


class RuntimeFeedback(StrictModel):
    network: RuntimeNetwork = Field(default_factory=RuntimeNetwork, description="Recorded network configuration, including probe destination policy; see probe_connections for actual attempted addresses.")
    schema_version: Literal[5] = 5
    facts: AttemptFacts = Field(description="Deterministic expected/actual, verified request continuity and previous-attempt comparison; unknown is not a negative observation.")
    tree_identity_version: Literal[2] = Field(description="The attempt uses metadata-aware v2 tree identities; do not compare to legacy content-only hashes.")
    session_id: str = Field(description="Controller session identity.")
    attempt_number: int = Field(description="Completed attempt producing this feedback.")
    created_unix_ns: int = Field(description="Feedback collection wall-clock time, not guest sampling time.")
    attempt_path: str = Field(description="Complete structured attempt with configuration and probe timeline.")
    termination_reason: str = Field(description="Observed stop category, not a model diagnosis.")
    target_exit_code: int | None = Field(description="Observed initial target process exit status; descendants may differ.")
    scenario_status: str = Field(description="Controller scenario status; absent is unknown.")
    scenario_error: str | None = Field(description="Full Controller failure or gap explanation.")
    failed_step: int | None = Field(description="One-based failed step when the structured scenario identifies it.")
    execution_hashes: dict[str, str | None] = Field(description="Exact recorded artifact hashes, with missing identities left null.")
    process_observation: dict[str, object] | None = Field(default=None, description="Timestamped Docker-host PID observation, separate from guest trace identity.")
    probe_progress: dict[str, object] | None = Field(default=None, description="Last observer-recorded step/request/response times, not an inference from heartbeat or PC.")
    log: FeedbackPreview = Field(description="Bounded log preview with a pointer to the original.")
    diagnostic_logs: list[FeedbackPreview] = Field(default_factory=list, description="Bounded host diagnostic previews, separate from guest stdio; all full files remain in artifacts.")
    diagnostic_log_count: int = Field(default=0, description="Number of separate host diagnostic streams discovered, including streams outside the default preview.")
    diagnostic_identities: list[dict[str, object]] = Field(default_factory=list, description="Selected per-image diagnostic identity/checkpoint records corresponding to the previews. Original JSON is retained in artifacts; capture completion is not inferred.")
    child_failure_assessment: dict[str, object] | None = Field(default=None, description="Controller evidence join between a guest image failure and an exact probe connection; related/unknown/unrelated are distinct. Full assessment and connection receipts remain available.")
    trace_identity: dict[str, object] | None = Field(default=None, description="Identity and timing of a historical trace checkpoint; not a crash dump.")
    historical_event: RuntimeEventContext | None = Field(default=None, description="One complete trace event; registers and memory are from this event only.")
    runtime_owners: dict[str, object] | None = Field(default=None, description="Attempt-local configured owners and full definitions pointer, including runtime revisions. Configuration is not an observed invocation or root cause.")
    runtime_dump: dict[str, object] | None = Field(default=None, description="Persisted guest ELF-core manifest; complete/partial status and missing evidence are authoritative.")
    artifacts: dict[str, str] = Field(default_factory=dict, description="Full evidence paths available for native command queries.")
    limitations: list[str] = Field(default_factory=list, description="Missing evidence, mapping failures, truncation, and temporal boundaries.")


def collect_runtime_feedback(attempt: RuntimeAttempt, attempt_path: Path, *, session_id: str,
                             previous_attempt: RuntimeAttempt | None = None) -> RuntimeFeedback:
    scenario = attempt.scenario_result
    requests, request_errors = read_request_records(attempt_path.parent / "requests",
        list(range(1, len(attempt.scenario.steps) + 1)) if attempt.scenario else [])
    feedback = RuntimeFeedback(
        network=attempt.network,
        facts=build_attempt_facts(attempt, previous=previous_attempt, requests=requests, request_errors=request_errors),
        tree_identity_version=attempt.tree_identity_version,
        session_id=session_id, attempt_number=attempt.attempt_number, created_unix_ns=time.time_ns(),
        attempt_path=str(attempt_path), termination_reason=attempt.termination_reason,
        target_exit_code=attempt.target_exit_code,
        scenario_status=scenario.status if scenario else "unknown",
        scenario_error=scenario.error if scenario else attempt.probe_result.error,
        failed_step=next((step.index for step in scenario.steps if not step.passed), None) if scenario else None,
        execution_hashes={name: getattr(attempt, name) for name in (
            "intervention_sha256", "rootfs_sha256", "target_binary_sha256", "harness_sha256")},
        log=file_preview(Path(attempt.container_log_path)),
        artifacts={"attempt": str(attempt_path), "container_log": attempt.container_log_path},
        limitations=[
            "Historical trace is not a crash-time snapshot; use the runtime dump manifest when it is complete.",
            "Scenario status covers executable step checks and exact observation predicates. rejection_conditions are literal response substrings, not interpreted prose or log/state rules; success does not establish every natural-language service requirement.",
        ],
    )
    for name in ("runtime_trace_path", "runtime_trace_context_path", "watchdog_path", "target_lifecycle_path", "probe_timeline_path"):
        value = getattr(attempt, name)
        if value:
            feedback.artifacts[name] = value
    evidence_root = Path(attempt.container_log_path).parent
    feedback.runtime_owners = read_runtime_owners(attempt_path.parent / "runtime-owners.json")
    if "error" not in feedback.runtime_owners:
        feedback.artifacts["runtime_owners"] = feedback.runtime_owners["path"]
    for index, path in enumerate(attempt.runtime_trace_paths):
        feedback.artifacts[f"per_image_trace_{index}"] = path
    assessment_path = evidence_root / "child-failures.json"
    feedback.artifacts["child_failures"] = str(assessment_path)
    connection_path = attempt_path.parent / "requests" / "probe-connections.jsonl"
    if connection_path.is_file():
        feedback.artifacts["probe_connections"] = str(connection_path)
    try:
        preview = file_preview(assessment_path, limit=262144)
        if preview.error or preview.captured_bytes != preview.total_bytes:
            raise ValueError(preview.error or "assessment exceeds 262144 bytes; full original retained")
        assessment = json.loads(preview.text)
        if not isinstance(assessment, dict) or assessment.get("schema_version") != 1:
            raise ValueError("unsupported child failure assessment schema")
        feedback.child_failure_assessment = assessment
        if assessment.get("status") == "unknown":
            feedback.limitations.append("Child failure association is unknown; see collection_errors and the full receipts.")
    except (ValueError, TypeError) as error:
        feedback.limitations.append(f"Child failure assessment unavailable: {assessment_path}: {error}")
    diagnostics = sorted(evidence_root.glob("diagnostics-*.log"))
    feedback.diagnostic_log_count = len(diagnostics)
    for path in (*diagnostics, *sorted(evidence_root.glob("diagnostics-*.json"))):
        feedback.artifacts[path.name] = str(path)
    # The newest images are normally closest to the last interaction. This is
    # a preview order, never attribution of a child failure to that interaction.
    feedback.diagnostic_logs = [file_preview(path) for path in diagnostics[-4:]]
    for path in sorted(evidence_root.glob("diagnostics-*.json")):
        try:
            preview = file_preview(path, limit=65536)
            if preview.error or preview.captured_bytes != preview.total_bytes:
                raise ValueError(preview.error or "identity record exceeds 65536 bytes; full original retained")
            record = json.loads(preview.text)
            if not isinstance(record, dict) or record.get("schema_version") != 2 or record.get("kind") != "host_diagnostics":
                raise ValueError("unsupported diagnostic identity schema/kind")
            if not path.with_suffix(".log").is_file():
                feedback.limitations.append(f"Host diagnostic log missing: {path.with_suffix('.log')}")
            if record.get("write_failures_including_fork_prefix"):
                feedback.limitations.append(f"Host diagnostic writes failed: {path}; failures={record.get('write_failures_including_fork_prefix')}; errno={record.get('last_write_errno')}; counters may include a pre-fork prefix.")
            if path.with_suffix(".log") in diagnostics[-4:]:
                feedback.diagnostic_identities.append({
                    "artifact":str(path), **{key:record.get(key) for key in (
                        "pid_namespace", "pid", "parent_pid", "process_start_ticks", "origin_pid",
                        "image_started_unix_ns", "checkpoint_unix_ns", "binary", "exec_transition",
                        "process_identity_error", "collection_complete", "truncated", "limitations",
                        "stdio_at_checkpoint")},
                })
        except (ValueError, TypeError) as error:
            feedback.limitations.append(f"Host diagnostic identity unavailable: {path}: {error}")
    for path in diagnostics:
        if not path.with_suffix(".json").is_file():
            feedback.limitations.append(f"Host diagnostic identity/checkpoint missing: {path}")
    if diagnostics:
        feedback.limitations.append("Host diagnostics are separate from guest stdio; their signal text is evidence, not a captured PC or proof that the failed child served this request. Per-image JSON records collection identity/errors; missing terminal checkpoints do not prove complete capture.")
    else:
        feedback.limitations.append("Separate host diagnostics unavailable; no claim that container.log contains child diagnostics.")
    if attempt.runtime_dump_manifest_path:
        dump_manifest_path = Path(attempt.runtime_dump_manifest_path)
        feedback.artifacts["runtime_dump_manifest"] = str(dump_manifest_path)
        try:
            dump = json.loads(dump_manifest_path.read_text(encoding="utf-8"))
            if not isinstance(dump, dict):
                raise ValueError("runtime dump manifest must be an object")
            feedback.runtime_dump = dump
            for key in ("core_path", "load_map_path"):
                value = dump.get(key)
                if isinstance(value, str):
                    path = dump_manifest_path.parent.parent / value
                    feedback.artifacts[key] = str(path)
            for relative in (dump.get("files") or {}):
                if isinstance(relative, str):
                    feedback.artifacts.setdefault(relative, str(dump_manifest_path.parent.parent / relative))
            status = dump.get("status")
            if status != "complete":
                feedback.limitations.append(f"Runtime dump status={status}; missing/partial evidence is listed in the manifest.")
            if dump.get("errors"):
                feedback.limitations.extend(f"Runtime dump: {item}" for item in dump["errors"])
            if dump.get("missing"):
                feedback.limitations.extend(f"Runtime dump missing: {item}" for item in dump["missing"])
        except (OSError, ValueError, json.JSONDecodeError) as error:
            feedback.limitations.append(f"Runtime dump manifest unavailable: {error}")
    else:
        feedback.limitations.append("No persisted guest snapshot or guest dump manifest is attached; historical trace is not a crash-time snapshot.")
    process_path = attempt_path.parent / "processes-final.json"
    if not process_path.is_file():
        process_path = attempt_path.parent / "processes.json"
        feedback.limitations.append("No final process sample is attached; the monitor table does not prove liveness after the response.")
    else:
        monitor_path = attempt_path.parent / "processes.json"
        if monitor_path.is_file():
            feedback.artifacts["monitor_processes"] = str(monitor_path)
    feedback.artifacts["processes"] = str(process_path)
    try:
        observation = json.loads(process_path.read_text(encoding="utf-8"))
        if not isinstance(observation, dict):
            raise ValueError("process observation must be an object")
        feedback.process_observation = observation
        if observation.get("purpose") == "after_probe":
            if observation.get("status") != "complete":
                feedback.limitations.append(f"Final process observation unavailable: {observation.get('error')}; the earlier monitor table is historical only.")
            elif not observation.get("after_last_response"):
                feedback.limitations.append("Final process sample has no preceding observed response; it cannot establish liveness after a response.")
    except (OSError, ValueError) as error:
        feedback.limitations.append(f"Process observation unavailable: {error}")
    if attempt.watchdog_path:
        try:
            watchdog = json.loads(Path(attempt.watchdog_path).read_text(encoding="utf-8"))
            if not isinstance(watchdog, dict):
                raise ValueError("watchdog state must be an object")
            progress = watchdog.get("probe_progress")
            if isinstance(progress, dict):
                feedback.probe_progress = progress
            else:
                feedback.limitations.append("Watchdog has no explicit probe progress record.")
            if watchdog.get("observation_error"):
                feedback.limitations.append(f"Observer error: {watchdog['observation_error']}")
        except (OSError, ValueError) as error:
            feedback.limitations.append(f"Watchdog state unavailable: {error}")
    if attempt.runtime_trace_context_available:
        try:
            context = load_model_json(Path(attempt.runtime_trace_context_path), RuntimeTraceContext)
            feedback.trace_identity = {name: getattr(context, name) for name in (
                "guest_arch", "byte_order", "word_bits", "host_pid", "origin_pid", "started_unix_ns",
                "checkpoint_elapsed_ns", "integrity_status", "raw_trace_sha256", "dropped_events",
                "dropped_image_loads", "dropped_tail_entries", "dropped_focus_tail_entries", "dropped_unique_blocks")}
            feedback.limitations.extend(f"Image {item.binary_name}: {item.mapping_error or item.mapping_basis}" for item in context.images)
            feedback.historical_event = context.events[-1] if context.events else None
            if feedback.historical_event is None:
                feedback.limitations.append("Trace has no event with an attributable sampling point.")
            elif feedback.historical_event.location is None:
                feedback.limitations.append("Historical event PC has no assembly mapping; retain the raw address.")
        except (OSError, ValueError) as error:
            feedback.limitations.append(f"Trace context unavailable: {error}")
    else:
        feedback.limitations.append(f"Trace context unavailable: {attempt.runtime_trace_context_error or 'not collected'}")
    return feedback


def render_runtime_feedback(feedback: RuntimeFeedback) -> str:
    """Send concise facts and file routes, keeping traces and log bodies on disk."""
    lines = [
        f"Runtime feedback: session={feedback.session_id}, attempt={feedback.attempt_number}",
        f"termination_reason={feedback.termination_reason}; target_exit_code={feedback.target_exit_code}",
        f"scenario_status={feedback.scenario_status}; failed_step={feedback.failed_step}",
        f"feedback_path={Path(feedback.attempt_path).parent / 'feedback.json'}",
        f"attempt_path={feedback.attempt_path}",
        f"evidence_root={Path(feedback.attempt_path).parent}",
        f"container_log_path={feedback.log.path}",
        "network=" + feedback.network.model_dump_json(),
    ]
    if feedback.scenario_error:
        lines.append("scenario_error=" + feedback.scenario_error)
    if feedback.runtime_owners:
        lines.append("Configured runtime owners=" + str(feedback.runtime_owners.get("path")))
    lines.append(f"retained_artifacts={len(feedback.artifacts)}; diagnostic_streams={feedback.diagnostic_log_count}; capture_limitations={len(feedback.limitations)}")
    lines.append("Trace/log contents, event values, source mappings and collection errors remain in the feedback file and evidence_root. Read selected files as needed. Startup evidence does not cover later native browser actions; use the current client receipt's runtime roots.")
    return "\n".join(lines) + "\n"


class RunnerExchange(StrictModel):
    schema_version: Literal[2] = 2
    exchange_id: int = Field(description="One-based invocation within the Controller session, including rejected decisions.")
    session_id: str = Field(description="Controller session, distinct from provider session identity.")
    kind: Literal["bootstrap", "feedback", "correction"] = Field(description="Why this invocation was prepared.")
    previous_exchange_id: int | None = Field(description="Previous exchange, including a rejected decision being corrected.")
    source_attempt_path: str | None = Field(description="Completed runtime attempt behind feedback, if any; stage failures may have none.")
    message_path: str = Field(description="Exact full invocation text, including artifact pointers.")
    message_sha256: str = Field(description="SHA-256 of message UTF-8 bytes.")
    parent_workspace_sha256: str = Field(description="Workspace identity before this invocation's edits.")
    created_unix_ns: int = Field(description="Prepared time; does not establish delivery.")
    started_unix_ns: int | None = Field(default=None, description="Adapter invocation began; transport delivery still unknown.")
    response_unix_ns: int | None = Field(default=None, description="Structured response actually returned from the same invocation.")
    finished_unix_ns: int | None = Field(default=None, description="Invocation/admission terminal time.")
    remaining_seconds: float = Field(description="Shared work budget left when the message was prepared.")
    delivery: Literal["prepared", "invocation_started", "response_received", "not_delivered", "interrupted_delivery_unknown"] = "prepared"
    admission: Literal["pending", "accepted", "rejected", "not_received"] = "pending"
    response: RunnerDecision | None = Field(default=None, description="Original returned decision before Controller normalization; not a semantic correctness claim.")
    response_metadata: dict[str, object] = Field(default_factory=dict, description="Actual provider/session/turn/status metadata; no invented IDs.")
    response_text_path: str | None = Field(default=None, description="Complete normalized Agent text; raw tool events remain in Agent trace.")
    error: str | None = Field(default=None, description="Rejection, budget, cancellation, or provider error.")
    decision_index: int | None = Field(default=None, description="One-based accepted decision_history index.")
    revision_number: int | None = Field(default=None, description="Accepted file revision, if any; launch-only decisions may have no revision.")
    executions: list[dict[str, object]] = Field(default_factory=list, description="Controller phase/attempt events caused by this accepted decision; starting is not completion.")


class FeedbackJournal:
    def __init__(self, root: Path, session_id: str):
        self.root, self.session_id = root, session_id
        root.mkdir(parents=True, exist_ok=True)
        self.records: list[RunnerExchange] = []

    def save(self, record: RunnerExchange) -> None:
        path = self.root / f"exchange-{record.exchange_id:04d}.json"
        write_model_json(path, record)

    def prepare(self, message: str, *, kind: str, source_attempt_path: Path | None,
                parent_workspace_sha256: str, remaining_seconds: float) -> RunnerExchange:
        index = len(self.records) + 1
        message_path = self.root / f"exchange-{index:04d}.message.txt"
        message_path.write_text(message, encoding="utf-8")
        record = RunnerExchange(exchange_id=index, session_id=self.session_id, kind=kind,
            previous_exchange_id=index - 1 if index > 1 else None,
            source_attempt_path=str(source_attempt_path) if source_attempt_path else None,
            message_path=str(message_path), message_sha256=hashlib.sha256(message.encode()).hexdigest(),
            parent_workspace_sha256=parent_workspace_sha256, created_unix_ns=time.time_ns(),
            remaining_seconds=remaining_seconds)
        self.records.append(record)
        self.save(record)
        return record

    def started(self, record: RunnerExchange) -> None:
        record.started_unix_ns = time.time_ns()
        record.delivery = "invocation_started"
        self.save(record)

    def responded(self, record: RunnerExchange, decision: RunnerDecision, result: object) -> None:
        record.response_unix_ns = time.time_ns()
        record.delivery = "response_received"
        record.response = decision.model_copy(deep=True)
        record.response_metadata = {name: getattr(result, name) for name in
            ("provider", "session_id", "turn_id", "status", "elapsed_seconds", "tool_calls_seen")
            if hasattr(result, name)}
        text = getattr(result, "text", None)
        if text is not None:
            path = self.root / f"exchange-{record.exchange_id:04d}.response.txt"
            path.write_text(text, encoding="utf-8")
            record.response_text_path = str(path)
        self.save(record)

    def failed(self, record: RunnerExchange, error: BaseException) -> None:
        record.error = f"{type(error).__name__}: {error}"
        record.finished_unix_ns = time.time_ns()
        if record.delivery == "response_received":
            record.admission = "rejected"
        else:
            record.admission = "not_received"
            record.delivery = "not_delivered" if record.started_unix_ns is None else "interrupted_delivery_unknown"
        self.save(record)

    def accepted(self, record: RunnerExchange, *, decision_index: int | None, revision_number: int | None) -> None:
        record.admission = "accepted"
        record.decision_index, record.revision_number = decision_index, revision_number
        record.finished_unix_ns = time.time_ns()
        self.save(record)

    def execution(self, phase: str, **details: object) -> None:
        record = next((r for r in reversed(self.records) if r.admission == "accepted"), None)
        if record is not None:
            record.executions.append({"phase": phase, "unix_ns": time.time_ns(), **details})
            self.save(record)
