"""Persistent RunnerAgent with bounded evidence tools."""

from __future__ import annotations

import json
import hashlib
import copy
from pathlib import Path
from typing import Literal

from fmst_basic.agent import AgentResult, AnalysisAgent, create_analysis_agent, tool
from fmst_basic.agent.config import (
    DEFAULT_AGENT_PROVIDER,
    configured_claude_model,
    configured_codex_model,
)
from fmst_basic.agent.trace import AgentTraceHandler
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    ASSEMBLY_EVIDENCE_GUIDANCE,
)
from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import (
    make_analyzer_tools,
)
from fmst_analyzer.synthesizer.intervention_skill import (
    APPLICATION_READ_ROOTS, application_guidance,
)

from .trace_compaction import compact_trace_context
from .owner_context import read_runtime_owners
from .evidence_views import api_view, execution_view, failure_overview
from .report_views import view_report
from .schema import RunnerDecision, RuntimeTraceContext
from .runtime_builder import HostRuntimeBuilder, RuntimeBuilder
from .budget import ExecutionBudget
from .core_inspection import inspect_core, render_inspection
from .elf_inspection import inspect_elf, render_static_inspection
from .emulator_inspection import inspect_emulator
from .trace_files import read_trace, trace_inventory
from fmst_analyzer.framework import guestweave_skill, runtime_workspace as selected_runtime_workspace


RUNNER_SYSTEM_PROMPT = """
You own this rehosting goal through working delivery. Starting from the supplied
Generator candidate, make the selected firmware service support the user's
representative operations through its native interface, according to the supplied
Service Interact contract.

Keep the goal active while you investigate, modify the candidate, run it and
interact with it. A failed attempt, a diagnosis, an unfinished operation or a
summary of next steps is work in progress. Carry out the next useful action
yourself instead of handing an executable next step back as a final result.

Work backward from an observed user-visible failure to the state or behavior
its native consumer needs. When the cause is uncertain, choose an observation
or reversible experiment that distinguishes plausible explanations. Follow the
result: revise your hypothesis or repair and try again. Extend analysis to the
relevant code when existing evidence is insufficient; use the available tool
documentation and alternative evidence when a tool fails. Read trace and log
files selectively through their supplied paths.

Repair the smallest coherent dependency that lets the native service do its job.
You may revise generated code, initialization, configuration and supported peers,
or add an intervention at an appropriate API boundary in the disposable workspace.
An emulated logical resource needs consistent behavior across its consumers; it
does not need a complete physical device behind it. Make assumptions explicit,
preserve native validation and state changes, and keep the original inputs intact.
Observe the resulting behavior rather than treating your explanation as proof.

Verify as a user through the original interface. Follow the supplied contract for
representative operations, authentication where applicable, and independent
readback of changes. Treat interaction mistakes as problems you can investigate
and correct. Confirm the final candidate in a fresh instance and retain evidence
that the delivered configuration reproduces the observed behavior.

Request completion only when those observations support the goal. If progress
requires a specific external input or capability you cannot obtain through the
available environment, identify it, retain the current candidate and evidence,
and request that input while leaving the goal unfinished. Missing evidence or
an unresolved firmware dependency alone is a reason to investigate further.
""".strip() + "\n\n" + ASSEMBLY_EVIDENCE_GUIDANCE


class RuntimeEvidenceState:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Do not expose a previous attempt as the latest failed execution."""
        self.attempt_json: Path | None = None
        self.trace_json: Path | None = None
        self.trace_context_json: Path | None = None
        self.trace_context_error: str | None = None
        self.container_log: Path | None = None
        self.companion_logs: list[Path] = []
        self.watchdog_json: Path | None = None
        self.runtime_dump_manifest: Path | None = None
        self.emulator_harness: Path | None = None
        self.emulator_harness_sha256: str | None = None
        self.executed_binary_hashes: dict[str, str] | None = None


def _inside(root: Path, firmware_path: str) -> Path:
    candidate = root / firmware_path.lstrip("/")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root.resolve())
    return resolved


def _find_rootfs_paths(root: Path, name_or_suffix: str) -> list[str]:
    """Return every in-rootfs path with one exact basename or path suffix."""
    query = name_or_suffix.strip()
    if not query or "\x00" in query:
        raise ValueError("name_or_suffix must be non-empty")
    suffix = "/" + query.lstrip("/")
    matches: list[str] = []
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        guest_path = "/" + relative
        if ("/" in query and guest_path.endswith(suffix)) or (
            "/" not in query and candidate.name == query
        ):
            matches.append(guest_path)
    return sorted(matches)


def make_runner_tools(
    *,
    view: AnalysisView,
    rootfs: Path,
    diagnostic_reports_root: Path,
    intervention_manifest: Path,
    evidence_state: RuntimeEvidenceState,
    runtime_builder: RuntimeBuilder | None = None,
    budget: ExecutionBudget | None = None,
    live_client=None,
):
    report_files = {
        "ipc": diagnostic_reports_root / "ipc_reports" / "ipc_analysis_result.json",
        "file": diagnostic_reports_root / "file_reports" / "file_resolver_result.json",
        "network": diagnostic_reports_root / "network_reports" / "network_analysis_result.json",
        "process": diagnostic_reports_root / "process_lifecycle_reports" / "process_lifecycle_analysis_result.json",
        "launch": diagnostic_reports_root / "init_launch_reports" / "init_launch_analysis_result.json",
        "plan": diagnostic_reports_root / "intervention_plan_reports" / "intervention_plan_result.json",
        "generation": diagnostic_reports_root / "intervention_generation_reports" / "intervention_generation_result.json",
    }

    def current_client():
        current = live_client.current if live_client is not None else None
        if current and evidence_state.attempt_json is not None:
            digest = hashlib.sha256(evidence_state.attempt_json.read_bytes()).hexdigest()
            if current.get("attempt_sha256") == digest:
                return current
        return None

    def runtime_roots() -> list[Path]:
        current = current_client()
        if current:
            # Use the actual browser instance, never its frozen startup copy.
            final = Path(current["path"]) / "runtime"
            if final.is_dir():
                return [final]
            source = current.get("runtime_source_root")
            return [Path(source)] if source else []
        return [evidence_state.attempt_json.parent] if evidence_state.attempt_json else []

    def trace_views_root() -> Path:
        # Derived queries belong to the originating execution too, so they are
        # readable and usable repair evidence rather than orphan reports.
        root = evidence_state.attempt_json.parent if evidence_state.attempt_json else diagnostic_reports_root
        return root / "runtime-trace-views"

    def selected_evidence(trace_path: str | None, source_sha256: str | None = None):
        if trace_path is None:
            if current_client():
                state = copy.copy(evidence_state)
                state.trace_json = state.trace_context_json = None
                state.trace_context_error = "Select a process trace from view_runtime_trace_files; the startup trace does not cover this browser interaction."
                return state
            return evidence_state
        path, digest, _, raw = read_trace(Path(trace_path), runtime_roots(), source_sha256)
        from .trace_context import persist_runtime_trace_context
        output = trace_views_root() / digest
        output.mkdir(parents=True, exist_ok=True)
        snapshot = output / path.name
        if not snapshot.is_file():
            snapshot.write_bytes(raw)
        if budget:
            budget.check()
        # Re-evaluate mappings after on-demand binary onboarding. Raw events
        # remain available even when no semantic source can map their PCs.
        context, _ = persist_runtime_trace_context(snapshot, output, view,
            executed_binary_hashes=evidence_state.executed_binary_hashes)
        state = copy.copy(evidence_state)
        state.trace_json, state.trace_context_json = snapshot, context
        state.trace_context_error = None
        return state

    @tool
    def view_runtime_trace_files(start: int = 0, limit: int = 16, image: str | None = None) -> str:
        """Locate per-process traces from the current native interaction or attempt.

        Writes the full inventory to disk. Select a trace by its image/PID and
        read that file, query its events, or request a mapped view. Live files are
        checkpoints; stop_native_client retains final artifacts before repair.
        Args:
            start: Zero-based inventory offset after filtering.
            limit: At most 32 process records.
            image: Optional exact image basename, such as a CGI or interpreter.
        """
        if start < 0 or not 1 <= limit <= 32:
            raise ValueError("start must be nonnegative; limit must be 1-32")
        roots = runtime_roots()
        inventories = [trace_inventory(root, check=budget.check if budget else lambda: None) for root in roots]
        records = [record for inventory in inventories for record in inventory["traces"]]
        destination = trace_views_root() / "inventory.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(inventories, ensure_ascii=False, indent=2) + "\n")
        selected = [r for r in records if image is None or any(i.rsplit("@0x", 1)[0] == image for i in r["images"])]
        return json.dumps({"inventory_path": str(destination), "runtime_roots": [str(p) for p in roots],
            "showing": f"{len(selected[start:start + limit])} of {len(selected)} matching process traces",
            "next_start": start + limit if start + limit < len(selected) else None,
            "traces": selected[start:start + limit],
            "notice": "Syscall event kind is syscall_result; use syscall_name to filter. Empty/missing capture is not absence of guest execution. Full errors and process inventories are in inventory_path."}, ensure_ascii=False)

    @tool
    async def start_native_client(origin: str) -> str:
        """Start a fresh firmware instance and private browser for the latest candidate.

        Use the native http(s) URL and service port found in firmware evidence.
        Each call discards the previous client and service state, which supports
        clean-instance acceptance. Cookies, JS and redirects run natively. The
        origin proxy preserves the selected hostname and port and does not rewrite
        responses. Run the candidate once before using this tool. A startup error
        is feedback to investigate, not an automatic stop.
        """
        if live_client is None:
            raise ValueError("native client execution is unavailable in this session")
        return await budget.run_sync(live_client.start, origin)

    @tool
    async def native_browser(arguments: list[str], stdin: str | None = None) -> str:
        """Interact with the owned live browser using agent-browser page commands.

        Use snapshot -i to discover refs, then click/fill/select; take a fresh
        snapshot after navigation. get text/value/url, console, errors, network
        requests, cookies get, screenshot and eval --stdin provide actual observations.
        Use ["--help"] or ["frame", "--help"] for installed command syntax.
        frame selects an iframe (frame main returns); dialog status/accept/dismiss
        handles browser dialogs. Custom page modals use ordinary DOM interactions.
        Help lists the CLI's full capabilities; this tool owns only this browser
        and allows cookie inspection, not cookie fabrication or response mocking. Native
        page JavaScript can perform client authentication and encode requests.
        Do not replace server responses, insert fake session state or manufacture
        displayed success. Output and command receipts are retained in full.
        The browser and firmware stay alive across calls until a fresh start or
        the next runtime revision. Review major operations and independent state
        readback in a fresh instance before requesting completion.
        """
        if live_client is None:
            raise ValueError("native client execution is unavailable in this session")
        return await budget.run_sync(live_client.command, arguments, stdin)

    @tool
    async def stop_native_client() -> str:
        """Stop this browser/service and retain its network and runtime evidence.

        Use after a failed native interaction to inspect final container logs,
        per-process traces and the HAR in the instance directory before repair.
        The receipt and paths remain readable; a new start uses fresh state.
        This does not terminate your RunnerAgent session.
        """
        if live_client is None:
            raise ValueError("native client execution is unavailable in this session")
        await budget.run_sync(live_client.stop)
        return json.dumps(live_client.current)

    @tool
    def view_analyzer_result(
        analyzer: Literal[
            "ipc", "file", "network", "process", "launch", "plan", "generation"
        ],
        mode: Literal["overview", "page"] = "overview",
        json_pointer: str = "",
        start: int = 0,
        limit: int = 32,
        source_sha256: str | None = None,
    ) -> str:
        """Read one authoritative Analyzer, Plan, or Generation JSON result.

        The default overview is bounded and identifies the exact source artifact.
        Use ``mode='page'`` with an RFC 6901 ``json_pointer`` to read an exact
        object field, array, or scalar. Pages are stable only while the returned
        ``source_sha256`` is unchanged; pass that hash on every continuation.
        Values are never string-sliced. An oversized single value is reported with
        its exact pointer and complete-artifact route.

        Args:
            analyzer: Result family to inspect.
            mode: ``overview`` for metadata, or ``page`` for selected values.
            json_pointer: RFC 6901 pointer; empty selects the report root.
            start: Zero-based offset within the selected object fields or array.
            limit: Maximum number of complete entries in one page, from 1 to 128.
            source_sha256: Hash returned by the prior page when continuing.
        """
        path = report_files[analyzer]
        return json.dumps(view_report(
            path,
            mode=mode,
            json_pointer=json_pointer,
            start=start,
            limit=limit,
            source_sha256=source_sha256,
        ), ensure_ascii=False, indent=2)

    @tool
    def find_rootfs_paths(name_or_suffix: str) -> str:
        """Find every firmware path with an exact basename or path suffix.

        This is a discovery tool for launch/config evidence, not a fuzzy
        content search. It returns the complete sorted match set.

        Args:
            name_or_suffix: Exact basename such as thttpd.conf, or exact path
                suffix such as var/www/thttpd.conf.
        """
        matches = _find_rootfs_paths(rootfs, name_or_suffix)
        if not matches:
            return f"No rootfs path matches {name_or_suffix!r}."
        return "\n".join([
            f"matches={len(matches)}",
            *matches,
        ])

    @tool
    def read_rootfs_text(
        path: str,
        start_line: int = 1,
        end_line: int = 200,
    ) -> str:
        """Read an exact line range from a text file in the firmware rootfs.

        Args:
            path: Firmware-absolute path such as /etc/init.d/service.
            start_line: First one-based line to return.
            end_line: Last one-based line to return, at most 400 lines after start.
        """
        if start_line < 1 or end_line < start_line or end_line - start_line >= 400:
            raise ValueError("request a valid range of at most 400 lines")
        try:
            resolved = _inside(rootfs, path)
        except FileNotFoundError:
            return (
                f"Rootfs path does not exist: {path}. Use find_rootfs_paths "
                "to locate an exact firmware source path."
            )
        if not resolved.is_file():
            return (
                f"Rootfs path is not a regular text file: {path}. Use "
                "find_rootfs_paths to locate a concrete file."
            )
        data = resolved.read_bytes()
        if b"\x00" in data:
            if data.startswith(b"\x7fELF"):
                return (
                    f"Rootfs path is an ELF binary, not text: {path}. Use "
                    "inspect_static_elf for headers/bytes/disassembly, or onboard_binary for semantic decompilation."
                )
            return f"Rootfs path is not a text file: {path}."
        lines = data.decode("utf-8", errors="replace").splitlines()
        selected = lines[start_line - 1:end_line]
        heading = (
            f"{path}: showing lines {start_line}-{start_line + len(selected) - 1} "
            f"of {len(lines)}"
        )
        return "\n".join([heading, f"source_path={resolved}\nsource_sha256={hashlib.sha256(data).hexdigest()}", *(
            f"L{number}: {line}"
            for number, line in enumerate(selected, start=start_line)
        )])

    @tool
    def view_runtime_evidence(
        section: Literal["overview", "execution", "api", "events", "recent_blocks", "recent_focus_blocks", "functions"] = "overview",
        start: int = 0,
        limit: int = 32,
        stream: Literal["focus", "all"] = "focus",
        trace_path: str | None = None,
        source_sha256: str | None = None,
    ) -> str:
        """Read the latest attempt (or partial execution) and available trace view.

        Overview prioritizes the reported failed step and evidence gaps. Execution
        shows named ASM nodes and repeated paths; api shows ordered event details,
        sampling phase, ownership and available snapshot ranges. These selective
        views omit raw state values and provide original record queries. Missing
        associations stay unknown; no view infers causes or paired calls/returns.
        Original trace pages use lossless dictionaries: expand runs.pattern repeat times
        in order and resolve record/location references. Collection drop counters
        remain explicit; compression cannot recover uncaptured execution.

        Args:
            section: Failure overview, execution/API view, or an original sequence.
            start: Zero-based retained record offset, not event sequence number.
            limit: Maximum retained records, from 1 to 512. A page may be smaller
                to fit transport; next_start gives the exact continuation.
                Oversized single records remain accessible in the named JSON.
            stream: Execution view only: focus projects out other images and does
                not establish direct CFG edges; all reads the captured all-image tail.
            trace_path: Selected current process trace from view_runtime_trace_files.
            source_sha256: Optional inventory hash; a changed checkpoint is explicit.
        """
        if start < 0 or not 1 <= limit <= 512:
            raise ValueError("start must be nonnegative and limit must be between 1 and 512")
        selected = selected_evidence(trace_path, source_sha256)
        evidence = selected
        if evidence.attempt_json is None:
            return "No runtime attempt has been executed yet."
        attempt = json.loads(
            evidence.attempt_json.read_text(encoding="utf-8")
        )
        result = {
            "attempt_path": str(evidence.attempt_json),
            "attempt": {key: attempt.get(key) for key in (
                "attempt_number", "outcome", "termination_reason", "target_exit_code",
                "runtime_trace_context_error", "error") if key in attempt},
            "runtime_owners": read_runtime_owners(evidence.attempt_json.parent / "runtime-owners.json"),
            "complete_context_path": str(evidence.trace_context_json) if evidence.trace_context_json else None,
            "raw_trace_path": str(evidence.trace_json) if evidence.trace_json else None,
        }
        result["runtime_evidence_roots"] = [str(p) for p in runtime_roots()]
        if current_client():
            result["native_client_receipt"] = str(Path(current_client()["path"]) / "receipt.json")
            result["startup_evidence_notice"] = "Attempt/failure/watchdog/dump fields below describe startup, not later browser interaction. Current process traces are selected independently from runtime_evidence_roots."
        for name, path in (("watchdog", evidence.watchdog_json),
                           ("runtime_dump", evidence.runtime_dump_manifest)):
            result[name + "_path"] = str(path) if path else None
        feedback_path = evidence.attempt_json.parent / "feedback.json"
        result["feedback_path"] = str(feedback_path)
        if feedback_path.is_file():
            try:
                feedback = json.loads(feedback_path.read_text())
                result["failure"] = failure_overview(feedback)
            except (OSError, ValueError, TypeError, AttributeError) as error:
                result["feedback_error"] = str(error)
        result["reading_routes"] = {
            "execution": {"section": "execution", "stream": "focus"},
            "api": {"section": "api"},
            "raw_state": "Use each API event's original_event query; register/memory values are historical samples, not assumed crash or output state.",
            "resource_state": "Use runtime_owners.path for frozen Unit definitions/manifest, feedback_path for observed changes and original wire/child/dump artifacts. No resource lifetime is inferred from a snapshot.",
            "partial_execution": str(evidence.attempt_json.parent / "partial-feedback.json") if not feedback_path.is_file() else None,
        }
        if evidence.trace_context_json:
            try:
                context = RuntimeTraceContext.model_validate_json(
                    evidence.trace_context_json.read_text(encoding="utf-8"))
                payload = context.model_dump(mode="json")
                sequences = ("events", "recent_blocks", "recent_focus_blocks", "functions")
                metadata = {key: value for key, value in payload.items() if key not in sequences}
                result["trace_context"] = {
                    "metadata": metadata,
                    "retained_counts": {key: len(payload[key]) for key in sequences},
                    "notice": "Metadata only; execution/api are selective navigation views, other sections are ordered lossless pages. Full original context remains at complete_context_path. Last PC and hot functions are navigation candidates, not root causes.",
                }
                compact_path = evidence.trace_context_json.with_suffix(".compact.json")
                if compact_path.is_file():
                    result["complete_compact_context_path"] = str(compact_path)
                if section in {"execution", "api"}:
                    # Focused views retain checkpoint identity/mapping metadata,
                    # but do not repeat the full failure overview on every page.
                    if "failure" in result:
                        result["failure"] = {key: result["failure"][key] for key in (
                            "scenario_status", "failed_step")}
                    result.pop("reading_routes", None)
                    result["overview_notice"] = "Selective page; full failure facts, capture gaps and artifact routes are available via section='overview' and feedback_path."
                if section != "overview":
                    field = ("recent_focus_blocks" if stream == "focus" else "recent_blocks") if section == "execution" else "events" if section == "api" else section
                    items = payload[field]
                    count = min(limit, max(0, len(items) - start))
                    owners = None
                    if section == "api":
                        try:
                            owners = json.loads((evidence.attempt_json.parent / "runtime-owners.json").read_text())
                        except (OSError, ValueError):
                            pass  # The overview carries the exact snapshot error and path.
                    while True:
                        result["page"] = {
                            "section": section, "start": start, "count": count,
                            "total": len(items),
                            "next_start": start + count if start + count < len(items) else None,
                        }
                        if section == "execution":
                            result["page"]["view"] = execution_view(context, stream=stream, start=start, count=count)
                        elif section == "api":
                            result["page"]["view"] = api_view(context, start=start, count=count, owners=owners)
                        else:
                            page = {key: ([] if key in sequences else value) for key, value in payload.items()}
                            page[section] = items[start:start + count]
                            result["page"]["lossless_context"] = compact_trace_context(page)
                        if section in {"execution", "api"} and trace_path is not None:
                            # Continuation must stay on this process checkpoint,
                            # including original event/state navigation.
                            route = result["page"]["view"]
                            selector = {"trace_path": trace_path, "source_sha256": context.raw_trace_sha256}
                            if section == "execution":
                                route["original_records"].update(selector)
                            else:
                                for event in route["events"]:
                                    event["original_event"].update(selector)
                        if len(json.dumps(result, ensure_ascii=False)) <= 24000 or count <= 1:
                            break
                        count = max(1, count // 2)
            except (OSError, ValueError) as error:
                result["trace_context_error"] = str(error)
        else:
            result["trace_context_error"] = evidence.trace_context_error or "Trace context is absent."
        rendered = json.dumps(result, ensure_ascii=False)
        if len(rendered) > 24000:
            return json.dumps({
                "notice": "Requested evidence exceeds the 24000-character transport budget; no record was truncated. Read the named original JSON for this section/offset.",
                "requested_section": section, "requested_start": start,
                "requested_stream": stream,
                "original_chars": len(rendered), "attempt_path": str(evidence.attempt_json),
                "complete_context_path": result["complete_context_path"],
                "raw_trace_path": result["raw_trace_path"], "feedback_path": str(feedback_path),
            }, ensure_ascii=False)
        return rendered

    @tool
    def view_watchdog_evidence() -> str:
        """Read the complete bounded target-progress watchdog timeline."""
        if evidence_state.watchdog_json and evidence_state.watchdog_json.is_file():
            return evidence_state.watchdog_json.read_text(encoding="utf-8")
        return "No target-progress watchdog evidence is available for the latest attempt."

    @tool
    def view_raw_runtime_trace() -> str:
        """Return raw trace file routes without injecting trace contents into context.

        Native instances contain separate CGI/interpreter/peer traces. Use
        view_runtime_trace_files to select them, then read the file as needed.
        """
        return json.dumps({"runtime_roots": [str(p) for p in runtime_roots()],
            "startup_trace_path": str(evidence_state.trace_json) if evidence_state.trace_json else None,
            "notice": "Startup trace is historical. Select actual native process files with view_runtime_trace_files; full trace content remains on disk."})

    @tool
    def query_runtime_events(
        kind: str | None = None,
        runtime_pc: int | None = None,
        static_ea: int | None = None,
        unit_id: str | None = None,
        hook_id: str | None = None,
        sequence_start: int | None = None,
        sequence_end: int | None = None,
        time_start_ns: int | None = None,
        time_end_ns: int | None = None,
        limit: int = 32,
        trace_path: str | None = None,
        source_sha256: str | None = None,
        syscall_name: str | None = None,
        start: int = 0,
    ) -> str:
        """Save selected events to a file for on-demand reading by the Agent.

        Args:
            kind: Exact event kind, e.g. syscall_result, image_load or process_exit.
            runtime_pc: Optional exact event PC.
            static_ea: Optional exact mapped assembly EA.
            unit_id: Optional exact intervention Unit owner when the trace records one.
            hook_id: Optional exact hook owner when the trace records one.
            sequence_start: Optional inclusive event sequence lower bound.
            sequence_end: Optional inclusive event sequence upper bound.
            time_start_ns: Inclusive lower bound; selects any overlapping repeated-event interval.
            time_end_ns: Inclusive upper bound. Inner timestamps of runtime-coalesced events are unavailable.
            limit: Maximum events saved per query page, at most 64.
            trace_path: Process trace from the current native instance inventory.
            source_sha256: Optional inventory hash to detect a changed checkpoint.
            syscall_name: Exact syscall name within syscall_result.detail, e.g. openat.
            start: Zero-based offset within matching retained events; next_start continues.
        """
        if limit < 1 or limit > 64:
            raise ValueError("limit must be between 1 and 64")
        if start < 0:
            raise ValueError("start must be nonnegative")
        if sequence_start is not None and sequence_start < 1:
            raise ValueError("sequence_start must be positive")
        if sequence_end is not None and sequence_end < 1:
            raise ValueError("sequence_end must be positive")
        if time_start_ns is not None and time_start_ns < 0:
            raise ValueError("time_start_ns must be non-negative")
        if time_end_ns is not None and time_end_ns < 0:
            raise ValueError("time_end_ns must be non-negative")
        if sequence_start is not None and sequence_end is not None and sequence_start > sequence_end:
            raise ValueError("sequence_start must not exceed sequence_end")
        selected = selected_evidence(trace_path, source_sha256)
        if not selected.trace_context_json or not selected.trace_context_json.is_file():
            return json.dumps({"status": "trace_selection_required", "runtime_roots": [str(p) for p in runtime_roots()],
                "notice": selected.trace_context_error or "Use view_runtime_trace_files to select captured process evidence."})
        context = RuntimeTraceContext.model_validate_json(
            selected.trace_context_json.read_text(encoding="utf-8")
        )
        matched = []
        for event in context.events:
            if kind is not None and event.kind != kind:
                continue
            if syscall_name is not None and (event.kind != "syscall_result" or not event.detail.startswith(syscall_name + "(")):
                continue
            if runtime_pc is not None and event.runtime_pc != runtime_pc:
                continue
            if static_ea is not None and (
                event.location is None or event.location.static_ea != static_ea
            ):
                continue
            if unit_id is not None and event.unit_id != unit_id:
                continue
            if hook_id is not None and event.hook_id != hook_id:
                continue
            if sequence_start is not None and event.last_sequence < sequence_start:
                continue
            if sequence_end is not None and event.sequence > sequence_end:
                continue
            if time_start_ns is not None and event.last_elapsed_ns < time_start_ns:
                continue
            if time_end_ns is not None and event.elapsed_ns > time_end_ns:
                continue
            matched.append(event.model_dump(mode="json"))
        payload = dict(
            {
                "showing": f"{len(matched[start:start + limit])} of {len(matched)} matching events",
                "next_start": start + limit if start + limit < len(matched) else None,
                "event_kinds": sorted({e.kind for e in context.events}),
                "filters": {
                    "kind": kind,
                    "runtime_pc": runtime_pc,
                    "static_ea": static_ea,
                    "unit_id": unit_id,
                    "hook_id": hook_id,
                    "sequence_start": sequence_start,
                    "sequence_end": sequence_end,
                    "time_start_ns": time_start_ns,
                    "time_end_ns": time_end_ns,
                    "syscall_name": syscall_name,
                },
                "events": matched[start:start + limit],
                "complete_context_path": str(selected.trace_context_json),
                "raw_trace_path": str(selected.trace_json) if selected.trace_json else None,
            },
        )
        output = trace_views_root() / "queries"
        output.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, ensure_ascii=False, indent=2)
        path = output / (hashlib.sha256(encoded.encode()).hexdigest() + ".json")
        path.write_text(encoded + "\n")
        return json.dumps({key: value for key, value in payload.items() if key != "events"} | {
            "query_path": str(path), "notice": "Read query_path for captured event values; full trace contents are not injected into context."})

    @tool
    def view_container_log(start_line: int = 1, end_line: int = 200) -> str:
        """Read an exact line range from the latest container log.

        Args:
            start_line: First one-based line to return.
            end_line: Last one-based line to return, at most 400 lines after start.
        """
        if start_line < 1 or end_line < start_line or end_line - start_line >= 400:
            raise ValueError("request a valid range of at most 400 lines")
        roots = runtime_roots()
        path = roots[0] / "container.log" if current_client() and roots else evidence_state.container_log
        if path is None:
            return "No runtime attempt has been executed yet."
        if not path.is_file():
            return f"Live container log has not been retained: {path}. stop_native_client collects it; startup log is historical."
        lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        selected = lines[start_line - 1:end_line]
        return "\n".join([
            f"source_path={path}",
            f"showing lines {start_line}-{start_line + len(selected) - 1} of {len(lines)}",
            *(
                f"L{number}: {line}"
                for number, line in enumerate(selected, start=start_line)
            ),
        ])

    @tool
    def view_companion_log(
        process_index: int,
        start_line: int = 1,
        end_line: int = 200,
    ) -> str:
        """Read one support process log from the latest attempt.

        Args:
            process_index: One-based index in companion_processes.
            start_line: First one-based line to return.
            end_line: Last one-based line to return, at most 400 lines after start.
        """
        if start_line < 1 or end_line < start_line or end_line - start_line >= 400:
            raise ValueError("request a valid range of at most 400 lines")
        if process_index < 1 or process_index > len(evidence_state.companion_logs):
            return f"No companion log exists for process index {process_index}."
        path = evidence_state.companion_logs[process_index - 1]
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = lines[start_line - 1:end_line]
        return "\n".join([
            f"{path}: showing lines {start_line}-{start_line + len(selected) - 1} "
            f"of {len(lines)}",
            *(
                f"L{number}: {line}"
                for number, line in enumerate(selected, start=start_line)
            ),
        ])

    @tool
    async def inspect_runtime_core(
        operation: Literal["threads", "registers", "memory", "disassemble", "backtrace"] = "registers",
        thread_id: int = 0, address: str = "", count: int = 32,
        manifest_sha256: str | None = None,
    ) -> str:
        """Read captured guest core registers, memory or code through GNU GDB.

        Uses only the latest Controller-selected, hash-verified core, with no
        staged ELF byte fallback, shell or live inferior. Each query retains
        its input snapshot, actual command and full output in receipt_path.
        Start with threads/registers when a crash needs localization. Combine
        measured addresses with source/assembly tools; a corrupt backtrace or
        GDB's current-thread choice is not a root-cause/faulting-thread verdict.

        Args:
            operation: threads, registers, memory bytes, disassemble, or backtrace.
            thread_id: GDB thread index, not Linux TID. 0 selects all threads for
                registers/backtrace; memory/disassemble needs a positive index.
            address: Numeric guest virtual address or register with one numeric
                offset, e.g. 0x4000, $sp, $sp-64. Used for memory/disassemble.
            count: Memory bytes (1-256), instructions (1-64), or frames (1-32).
            manifest_sha256: Prior source hash to bind a follow-up query; a changed
                latest attempt returns source_changed. Missing bytes stay unknown.
        """
        if budget is not None:
            receipt = await budget.run_sync(inspect_core, evidence_state.runtime_dump_manifest,
                operation=operation, thread_id=thread_id, address=address, count=count,
                manifest_sha256=manifest_sha256, budget=budget)
        else:
            import asyncio
            receipt = await asyncio.to_thread(inspect_core, evidence_state.runtime_dump_manifest,
                operation=operation, thread_id=thread_id, address=address, count=count,
                manifest_sha256=manifest_sha256)
        return render_inspection(receipt)

    @tool
    async def inspect_static_elf(
        path: str, operation: Literal['metadata', 'bytes', 'disassemble'] = 'metadata',
        address: str = '', address_space: Literal['virtual', 'file'] = 'virtual',
        byte_count: int = 64, decoder_mode: str = 'auto', source_sha256: str | None = None,
    ) -> str:
        """Read an exact rootfs ELF without onboarding, IDA, or executing it.

        Returns file identity/hash, ELF header, PT_LOAD mappings, interpreter and
        available ABI metadata. bytes/disassemble queries contain only bounded
        file-backed bytes, decoder version/mode and decoded instruction groups.
        Each query saves a complete immutable file snapshot and receipt.
        Static VA is not runtime VA: establish the image/load bias separately.
        Missing core pages remain unknown. Instruction groups are decoder facts,
        not proof of execution or sufficient CPU support.

        Args:
            path: Guest absolute ELF path; guest absolute symlinks are supported.
            operation: metadata, bytes, or disassemble.
            address: Unsigned numeric static ELF VA or file offset, e.g. 0x4000.
            address_space: virtual for static PT_LOAD VA; file for byte offset.
            byte_count: Exact file interval, 1-256 bytes; undecoded bytes reported.
            decoder_mode: auto from ELF; explicit mips32, mips64, mips32r6,
                micromips, arm, thumb, aarch64, x86, x86_64 with mode evidence.
                Auto ARM uses ARM mode; mixed code/data and Thumb state unknown.
            source_sha256: Prior ELF hash to bind follow-up queries.
        """
        import asyncio
        kwargs = dict(path=path, operation=operation, address=address, address_space=address_space,
            byte_count=byte_count, decoder_mode=decoder_mode, source_sha256=source_sha256, budget=budget)
        if budget is not None:
            receipt = await budget.run_sync(inspect_elf, rootfs, diagnostic_reports_root, **kwargs)
        else:
            receipt = await asyncio.to_thread(inspect_elf, rootfs, diagnostic_reports_root, **kwargs)
        return render_static_inspection(receipt)

    @tool
    async def inspect_emulator_cpu(
        operation: Literal['models', 'find_source', 'read_source'] = 'models',
        name: str = '', source_path: str = '', start: int = 0, limit: int = 80,
        harness_sha256: str | None = None, source_sha256: str | None = None,
    ) -> str:
        """Query the actual latest-attempt harness CPU list or retained QEMU source.

        models runs only the fixed QEMU_CPU=help query, no guest program or
        arbitrary command. Its exit status/stdout/stderr are evidence (QEMU help
        may exit nonzero). find_source locates exact basenames in that build's
        QEMU export; read_source returns bounded complete lines and file hash.
        Combine model feature definitions and instruction ISA groups to propose
        a CPU hypothesis through launch guest_environment['QEMU_CPU']; only the
        original scenario can validate that hypothesis. No CPU is auto-selected.

        Args:
            operation: models, find_source, or read_source.
            name: Exact source basename for find_source, e.g. cpu-defs.c.inc.
            source_path: Returned relative QEMU build source path for read_source.
            start: Zero-based result or line offset.
            limit: Complete entries/lines, 1-200; complete snapshot retained.
            harness_sha256: Prior harness hash to bind all continuation queries.
            source_sha256: Prior source file hash for read_source continuation.
        """
        import asyncio
        kwargs = dict(builder=runtime_builder or HostRuntimeBuilder(budget=budget), operation=operation,
            name=name, source_path=source_path, start=start, limit=limit,
            harness_sha256=harness_sha256, source_sha256=source_sha256,
            execution_harness_sha256=evidence_state.emulator_harness_sha256, budget=budget)
        if budget is not None:
            receipt = await budget.run_sync(inspect_emulator, evidence_state.emulator_harness,
                diagnostic_reports_root, **kwargs)
        else:
            receipt = await asyncio.to_thread(inspect_emulator, evidence_state.emulator_harness,
                diagnostic_reports_root, **kwargs)
        return render_static_inspection(receipt)

    @tool
    def cargo_check() -> str:
        """Check the intervention using the Runner's Linux runtime toolchain.

        Preserve Cargo.lock with --locked. A missing or stale lock returns a
        build error; this check does not create or update dependency source files.
        """
        result = (runtime_builder or HostRuntimeBuilder()).run_cargo(
            intervention_manifest,
            "check",
            timeout=600,
            extra_args=("--locked",),
        )
        return (
            f"exit_code={result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )

    @tool
    async def onboard_binary(path: str) -> str:
        """Onboard and decompile one exact ELF from the firmware rootfs.

        Use only when runtime or Analyzer evidence names a relevant binary
        whose code is missing or insufficient in the code-navigation tools. Existing
        structural-only artifacts can also be upgraded. New analysis uses this
        session's configured analysis cache. This is
        substantially more expensive than reading an existing result.

        Args:
            path: Firmware-absolute path to the ELF binary or custom library.
        """
        resolved = _inside(rootfs, path)
        with resolved.open("rb") as stream:
            magic = stream.read(4)
        if magic != b"\x7fELF":
            raise ValueError(f"not an ELF file: {path}")
        try:
            binary = view.lib_dep_graph.add_binary(resolved)
        except RuntimeError as error:
            return (f"Binary onboarding unavailable: {error}. This does not establish an "
                    "irreparable firmware defect. inspect_static_elf can still read exact "
                    "ELF bytes/disassembly without IDA; runtime process traces remain available.")
        try:
            await view.lib_dep_graph.decompile_analysis(binary)
        except RuntimeError as error:
            return (
                f"Onboarded structural artifacts for {binary.name}, but semantic "
                f"decompilation is unavailable: {error}"
            )
        if not binary.semantic_ready:
            return (f"Structural artifacts for {binary.name} are available, but this backend "
                    "did not produce semantic code. Use static disassembly and runtime evidence.")
        return (
            f"Onboarded semantic code for {binary.name} at {resolved}. "
            "Use the ordinary code-navigation tools with this binary name."
        )

    return [
        start_native_client,
        native_browser,
        stop_native_client,
        view_analyzer_result,
        find_rootfs_paths,
        read_rootfs_text,
        view_runtime_evidence,
        view_runtime_trace_files,
        view_raw_runtime_trace,
        query_runtime_events,
        view_container_log,
        view_companion_log,
        cargo_check,
        inspect_runtime_core,
        inspect_static_elf,
        inspect_emulator_cpu,
        onboard_binary,
    ]


class RunnerAgentSession:
    def __init__(
        self,
        *,
        view: AnalysisView,
        rootfs: Path,
        diagnostic_reports_root: Path,
        intervention_root: Path,
        trace_path: Path,
        evidence_state: RuntimeEvidenceState,
        readable_roots: list[Path] | None = None,
        writable_roots: list[Path] | None = None,
        runtime_builder: RuntimeBuilder | None = None,
        runtime_workspace: Path | None = None,
        budget: ExecutionBudget | None = None,
        live_client=None,
    ) -> None:
        framework = runtime_workspace or selected_runtime_workspace()
        framework_skill = guestweave_skill(framework)
        tools = make_analyzer_tools(view) + make_runner_tools(
            view=view,
            rootfs=rootfs,
            diagnostic_reports_root=diagnostic_reports_root,
            intervention_manifest=intervention_root / "Cargo.toml",
            evidence_state=evidence_state,
            runtime_builder=runtime_builder,
            budget=budget,
            live_client=live_client,
        )
        runner_provider = DEFAULT_AGENT_PROVIDER
        runner_model = (
            configured_claude_model()
            if runner_provider == "claude"
            else configured_codex_model()
        )
        self.agent: AnalysisAgent = create_analysis_agent(
            provider=runner_provider,
            model=runner_model,
            developer_instructions=RUNNER_SYSTEM_PROMPT + "\n\n" + application_guidance("runtime-refinement"),
            tools=tools,
            output_format=RunnerDecision,
            workdir=intervention_root,
            filesystem_access="write",
            readable_roots=[*(readable_roots or []), *APPLICATION_READ_ROOTS],
            writable_roots=(
                writable_roots
                if writable_roots is not None
                else [intervention_root]
            ),
            name="rehosting-runner",
            skills=[framework_skill],
        )
        self.trace = AgentTraceHandler(
            agent_name="rehosting-runner",
            md_path=trace_path,
            title="RunnerAgent runtime refinement",
            model=runner_model,
        )

    async def invoke(self, message: str) -> tuple[RunnerDecision, AgentResult]:
        # Format errors are correctable in the same session. The adapter has
        # already persisted the complete original response and failed trace;
        # transport/provider/cancellation failures must still propagate.
        while True:
            try:
                result = await self.agent.ainvoke(message, trace=self.trace)
            except ValueError as error:
                if getattr(error, "code", None) != "structured_output_error":
                    raise
                message = (
                    "Your previous decision could not be decoded under RunnerDecision. "
                    "Correct its representation in this same session; retain the actual "
                    "workspace edits and declare all changed_paths since the request "
                    "began. Do not repeat completed tools just to fix formatting. "
                    "The goal remains active; unfinished progress can use action=continue. "
                    "The original response is preserved. Full validation error:\n" + str(error)
                )
                continue
            if not isinstance(result.structured_response, RunnerDecision):
                message = (
                    "The goal remains active. Continue with the next useful investigation, repair or "
                    "native interaction in this same session. Your reply is retained in the trace. "
                    "Return a RunnerDecision for execution, progress (continue), evidence-bound "
                    "completion, or a specific unavailable external input. Retain and declare "
                    "any workspace edits made since the current request began."
                )
                continue
            return result.structured_response, result

    async def aclose(self) -> None:
        await self.agent.aclose()


__all__ = [
    "RUNNER_SYSTEM_PROMPT",
    "RunnerAgentSession",
    "RuntimeEvidenceState",
    "_find_rootfs_paths",
    "make_runner_tools",
]
