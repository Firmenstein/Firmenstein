"""Full Claude Code session inside the task's private container."""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from .common import TASK, CONTROL, evidence_file, process_identity, write_json, retain_service, finish_agent_phase
from .schema import ServiceCompletion
from .options import RunnerOptions

TASK_INSTRUCTIONS = """# Firmware rehosting task

## Objective

You own this task from start to completion.
Use the supplied firmware and the original Generator candidate.
Make the selected service usable for local testing, analysis, and bug reproduction.
Run the firmware through GuestWeave.
Keep runtime traces for the native operations that you test.
Use native fallback for operations that do not need an intervention.
Keep runtime instrumentation available during repairs.

## Input paths

These paths are inside your container.

| Material | Path |
|---|---|
| Generator code: editable working copy | /task/work/candidate |
| Generator code: original input | /task/input/candidate |
| Firmware rootfs: working copy | /task/work/rootfs |
| GuestWeave and backend: working copy | /task/work/framework/GuestWeave |
| Material index and path mappings | /task/input/materials.json |
| Selected target reports | /task/input/reports |
| Other analyzed targets in this firmware | /task/input/firmware-reports/<target>/ |
| Existing C, assembly, graphs, and IDB files | /task/analysis |
| Task identity, input paths, and launch hints | /task/task.json |

The material index records supplied files, their source paths, and missing inputs.
Use its source-to-container mappings to locate files referenced by historical reports.
Preserve /task/input as the original evidence.

## Use the existing work

Use the Generator code as the primary starting point for investigation and repair.
At the start, review the material index and available Analyzer, Plan, and Generator report overviews.
Use them to understand existing findings, dependencies, launch options, and the candidate implementation.
You may use each Analyzer's review reports as supporting evidence.
Reports are reference material only.
They can contain false positives and false negatives.
Do not use a report alone to confirm that a problem exists.
Do not treat an omitted issue as proof that no problem exists.
Read detailed reports, evidence, and related code when the current problem needs them.
Check earlier findings against the current code and native execution.
Reuse findings that current evidence supports.
Investigate gaps and conflicting findings.

The following report directories are under /task/input/reports:

| Report | Directory |
|---|---|
| IPC Analyzer | ipc_reports/ |
| File Analyzer | file_reports/ |
| Network Analyzer | network_reports/ |
| Process lifecycle Analyzer | process_lifecycle_reports/ |
| Init/launch Analyzer | init_launch_reports/ |
| Plan | intervention_plan_reports/ |
| Generator | intervention_generation_reports/ |

Start with each available index.md overview.
Use the material index and task.json.report_paths to locate reports for other supplied targets.

## Check native behavior

Choose meaningful native operations that match the service goal.
Usually, select 3–5 different operation types.
Test the main local workflow and relevant state changes.
Include reads.
Where applicable, make a reversible change.
Confirm the change with an independent readback, then restore the previous state.
Use the original browser UI for web management.
Extend native checks when a finding blocks this scope or makes the current results unreliable.
Once the environment is usable for this scope, state which functions remain unverified and finish.

## Repair the environment

Follow a failing native operation to the API or resource behavior that it uses.
Keep ordinary Linux and native paths that already work.
A failed call does not, by itself, prove that an intervention is needed.
Choose a stable API or resource boundary for the repair.
Supply the required return values, outputs, lifetimes, and side effects.
Trace required state from its producer to the operations that consume it.
Keep cooperating operations consistent.
Use packaged defaults, native initializers, or caller inputs where suitable.
State any emulation assumptions and keep them reversible.
A success return is insufficient if later operations do not receive the required state.

Revise or add interventions and bindings as needed.
Rebuild and load the changed implementation.
Retry the affected native operation.
Check whether the repair changed its behavior as intended.
You may prepare the environment, start native peers, or repair the private backend.
Choose these options when they address the cause more directly.

## Environment limits and firmware bugs

Judge behavior against this emulated environment and the intended local use.
Missing physical or external dependencies can be expected limits.
Adapt missing local dependencies when they block the service goal.
Preserve native business logic and firmware defects.
A reproducible firmware bug can be a useful test result.
Use evidence to distinguish a firmware bug from an emulation failure.
Keep the bug reproducible.
If the cause is unresolved, state that it is unknown.

## Tools and engineering Skill

Work autonomously in this private container.
You have full shell, editing, sudo, Internet, compiler, debugger, and browser access.
Install tools and change your approach as needed.
Past stage permissions do not restrict changes to this working copy.
Investigate missing evidence and failed attempts with reversible experiments.
This task runs without user attendance.
Use ordinary messages to report progress.
Continue the task without waiting for a user reply.
Keep working on gaps that prevent the service goal.

Consult the native Skill `fmst-task:guestweave-intervention-engineering` when you implement or revise an intervention.
Also consult it for API, ABI, shared state, binding, build, loading, or execution questions.
Read relevant references when needed.
Apply them to the current problem.

## Evidence and completion

Keep runtime traces, build output, and browser evidence in /task/evidence.
Inspect the current execution as needed for the problem.
Do not disclose model credentials in logs, files, or responses.

Complete the task when native interactions show a usable local environment for the service goal.
A successful build, open port, static page, or requested action alone is insufficient.
Diagnosis alone is insufficient.
Use complete_service with the observed results, evidence, access instructions, and limits.
Keep this same instance and service running.
Use init-owned jobs for processes that must remain after your session ends.
The task guide explains these jobs.
Full physical device equivalence, exhaustive feature tests, and a replay in a new instance are not required.
"""


def initial_message(task: dict) -> str:
    """Send task requirements and Goal as user input; keep evidence in files."""
    paths = task.get("paths", {})
    message = (TASK_INSTRUCTIONS + "\n## Task references\n\nRead the task guide at "
               "/opt/fmst/src/fmst_analyzer/runner/task/README.md.\n")
    if task.get("input_mode") == "upstream_repair":
        message += ("\n## Upstream repair input\n\n"
                    "Upstream analysis/planning/generation stopped before Runner. "
                    "Read task.json.upstream_repair and the available reports, including failed-stage reports under .attempts. "
                    "Failed or missing analysis is not a firmware conclusion and does not prove intervention unnecessary. "
                    "Use the supplied candidate code as the starting point. ")
        if task.get("candidate_origin") == "diagnostic_scaffold":
            message += ("This candidate is a GuestWeave diagnostic scaffold, not a completed Generator intervention. "
                        "If upstream-generator code is supplied, review it as the primary repair reference, "
                        "but verify its target, ABI and bindings before reuse. "
                        "Investigate native loading/launch behavior and implement the necessary interventions. ")
        message += "Preserve the original input and failure records; complete only from actual native interaction.\n"
    if engineering := paths.get("candidate_engineering"):
        message += "Candidate layout and build reference, when needed: " + engineering + "\n"
    if task.get("delivery_mode") == "rehosting_only":
        message += ("\n## Run mode\n\nThis task only verifies native rehosting.\n"
                    "After complete_service, finish your response.\n"
                    "Keep the same instance running.\n"
                    "No post-Goal delivery document or image is required.\n")
    message += "\n## Service goal\n\n"
    if source := task.get("goal_source"):
        message += "Goal source: " + source + "\n"
    return message + "Goal:\n" + task["goal"]


def event(kind: str, **data):
    with (TASK / "evidence/worker-events.jsonl").open("a") as out:
        out.write(json.dumps({"at": time.time(), "kind": kind, **data}) + "\n")


async def run(*, resume_message: str | None = None):
    # docker exec owns this worker independently of init's service jobs.
    write_json(CONTROL / "worker.json", {"pid": os.getpid(), "start_ticks": process_identity(os.getpid())})
    settings = json.loads((CONTROL / "model.json").read_text())
    from .model_route import ModelRoute, PROXY_KEYS
    model_route = ModelRoute(settings)
    try:
        for key in list(os.environ):
            if key.lower() in PROXY_KEYS:
                os.environ.pop(key)
        os.environ.update(model_route.environment(settings))
        await run_session(settings, resume_message=resume_message)
    finally:
        model_route.close()
        (CONTROL / "model.json").unlink(missing_ok=True)
        for key in settings:
            os.environ.pop(key, None)


async def run_session(settings, *, resume_message: str | None = None):
    task = json.loads((TASK / "task.json").read_text())
    delivery_mode = RunnerOptions(delivery_mode=task.get("delivery_mode", "full")).delivery_mode
    os.environ.update(task.get("analysis_environment", {}))
    os.environ.update(task.get("build_environment", {}))
    from fmst_basic.agent import create_analysis_agent, AgentTraceHandler, tool
    from fmst_analyzer.framework import guestweave_skill
    completed = None

    @tool
    def complete_service(completion: ServiceCompletion) -> str:
        """Declare achieved native service goals and retain this exact running instance.

        Supply actual operation results, their evidence files, native URL/access
        instructions and the live container PID with /proc/PID/stat start ticks.
        Format/path/identity errors are repairable and returned to this session.
        This does not create a clean instance or perform a separate business test.
        """
        nonlocal completed
        if (TASK / "delivery/completion.json").exists():
            return "The original completion is retained. Put follow-up findings in separate artifacts."
        completion = ServiceCompletion.model_validate(completion)
        if process_identity(completion.service_pid) != completion.service_start_ticks:
            raise ValueError("Service process identity is no longer live")
        hashes = {}
        for operation in completion.interactions:
            for value in operation.evidence:
                path = evidence_file(value)
                with path.open("rb") as stream:
                    hashes[str(path)] = hashlib.file_digest(stream, "sha256").hexdigest()
        retain_service(completion, hashes)
        completed = completion
        event("completion_declared", service_pid=completion.service_pid,
              operations=len(completion.interactions))
        reply = "Completion recorded and frozen. Leave the same service running; finish this response now."
        if delivery_mode == "full":
            reply += " A delivery-only message will follow in this session."
        return reply

    tools = [complete_service]
    skills = []
    from .analysis_rpc import AnalysisClient, semantic_tools
    from .tools import make_evidence_tools
    analysis = AnalysisClient(TASK)
    if not task.get("capability_probe") or task.get("evidence_probe"):
        framework = TASK / "work/framework/GuestWeave"
        if framework.is_dir():
            skills = [guestweave_skill(framework)]
        tools += make_evidence_tools(task, analysis)
        tools += semantic_tools(analysis)
        catalog = {item.name: item for item in tools}

        @tool
        async def analysis_tool(name: str = "", arguments: dict | None = None) -> str:
            """List or call available tools without initializing IDA.

            Each operation loads only its own dependencies. Native analysis runs
            in a separate process and can be retried after an environment repair.
            Args:
                name: Empty writes the tool catalog; otherwise an exact tool name.
                arguments: Parameters from that tool's schema.
            """
            if not name:
                path = TASK / "evidence/analysis-tools.json"
                write_json(path, {key: {"description": value.description,
                    "schema": value.args_schema.model_json_schema()} for key, value in catalog.items()})
                return json.dumps({"tools": list(catalog), "catalog": str(path)})
            if name not in catalog:
                raise ValueError("Unknown tool; request the catalog with an empty name")
            return await catalog[name].ainvoke(arguments)

        tools.append(analysis_tool)
        event("tools_attached", tools=[item.name for item in tools], analysis="lazy subprocess")
    agent = None
    primary_error = None
    try:
        agent = create_analysis_agent(provider="claude", model=settings["FMST_CLAUDE_MODEL"],
            reasoning_effort=settings["FMST_CLAUDE_REASONING_EFFORT"], developer_instructions="",
            workdir=TASK / "work", filesystem_access="container", tools=tools, skills=skills,
            name="runner-container:" + task["task_id"],
            session_dir=TASK / "sessions/runner", resume=resume_message is not None)
        trace_path = TASK / "evidence/agent.md"
        if resume_message is not None:
            trace_path = TASK / "evidence/resumes" / (uuid.uuid4().hex + ".md")
        trace = AgentTraceHandler(agent_name="runner-container", md_path=trace_path,
                                  title="Autonomous container Runner", model=settings["FMST_CLAUDE_MODEL"])
        event("agent_resumed" if resume_message is not None else "agent_started",
              model=settings["FMST_CLAUDE_MODEL"], tools=[t.name for t in tools],
              session_receipt=str(agent.session_receipt))
        if resume_message is not None:
            # An explicit follow-up is one native turn, not a restart of Goal.
            result = await agent.ainvoke(resume_message, trace=trace)
            write_json(trace_path.with_suffix(".json"), {"status": result.status,
                       "text": result.text, "session_receipt": str(agent.session_receipt)})
            event("resume_turn_finished", status=result.status)
            return
        message = initial_message(task)
        while completed is None:
            await agent.ainvoke(message, trace=trace)
            event("turn_finished", completed=completed is not None)
            message = ("The goal remains active. Your previous response is progress, not a stop request. "
                       "Use the available shell, source, browser and evidence to resolve the next blocker, "
                       "then continue actual native interaction. Submit complete_service when achieved.")
        if delivery_mode == "full":
            from .handoff import collect_handoff
            state = json.loads((CONTROL / "lifecycle.json").read_text())
            event("handoff_started")
            handoff = await collect_handoff(agent, trace, task_root=TASK, deadline=state["handoff_deadline"])
            event("handoff_finished", status=handoff["status"])
        else:
            write_json(TASK / "delivery/handoff-status.json", {
                "status": "not_started", "delivery_mode": delivery_mode,
                "reason": "Post-Goal delivery and image capture were not requested.",
                "finished_at": time.time()})
            event("delivery_skipped", delivery_mode=delivery_mode)
    except BaseException as error:
        primary_error = error
        from fmst_analyzer.runner.repair_intake import persist_pipeline_failure
        try:
            persist_pipeline_failure(TASK / "evidence", error, "runner")
        except Exception as recording_error:
            error.add_note("Runner failure record could not be saved: " + type(recording_error).__name__)
        raise
    finally:
        if completed is not None and not (TASK / "delivery/handoff-status.json").exists():
            write_json(TASK / "delivery/handoff-status.json", {
                "status": "interrupted" if delivery_mode == "full" else "not_started",
                "delivery_mode": delivery_mode, "finished_at": time.time()})
        try:
            if agent is not None:
                await agent.aclose()
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            primary_error.add_note("Runner Agent close also failed: " + type(cleanup_error).__name__)
        finally:
            try:
                await analysis.close()
            except BaseException as cleanup_error:
                if primary_error is None:
                    raise
                primary_error.add_note("Runner analysis close also failed: " + type(cleanup_error).__name__)
            finish_agent_phase()
            event("agent_exited", completed=completed is not None)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume-message", type=Path,
                        help="Explicit follow-up file; resume the retained native session for one turn")
    args = parser.parse_args()
    asyncio.run(run(resume_message=args.resume_message.read_text() if args.resume_message else None))
