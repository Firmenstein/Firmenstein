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

TASK_INSTRUCTIONS = """You own this firmware rehosting task end to end. Starting from the supplied
firmware and original Generator candidate, deliver a running local environment
the user can continue using for testing, analysis and bug reproduction.
The delivered firmware runs through GuestWeave, with runtime trace for the
native operations you exercise. Use its native fallback for behavior that needs
no intervention; keep its instrumentation available while repairing the environment.

Establish usability through a small, varied set of meaningful native operations,
usually 3–5 operation types chosen for the service goal. Exercise the main local
workflow and relevant state transitions, including reads and a reversible change
with independent readback and restoration where applicable. Use the original
browser UI for web management. Extend coverage when a finding blocks this scope
or makes its results unreliable; once it is usable, identify the remaining
unverified functionality and finish.

Use the Generator intervention code as the primary starting point for repairing
missing or inconsistent environment behavior. Follow a failing native operation
to the API or resource behavior it consumes. Preserve ordinary Linux/native paths
that already work; a failed call alone does not establish a need for intervention.
Choose a stable boundary that supplies the required returns, outputs, lifetimes
and side effects. Trace required state from its producer to subsequent consumers,
and keep cooperating operations consistent. Use packaged defaults, native
initializers, caller inputs or explicit, reversible emulation assumptions;
returning success without the state consumed downstream is insufficient.
Revise or add interventions and bindings, rebuild and load the implementation,
then retry the affected native operation and observe whether the repair took
effect. Environment preparation, native peers and private backend repair remain
available when they address the cause more directly.

Judge behavior against the emulated environment and intended local use.
Unavailable physical or external dependencies may be expected limitations;
missing local dependencies that block the service goal still need adaptation.
Preserve native business logic and defects. A reproducible firmware bug can be
a useful test result: distinguish it from an emulation failure using evidence,
keep it reproducible, and state uncertainty when the cause is unresolved.

Consult the native Skill `fmst-task:guestweave-intervention-engineering` when
implementing or revising an intervention, resolving API/ABI, shared-state or
binding questions, or diagnosing its build, loading or execution. Read relevant
references on demand and apply them to the current problem.

Work autonomously with full shell, editing, sudo, Internet, compilation, debugger
and browser access in this private container. Install tools and revise your
approach as needed. Reports and plans are fallible evidence; historical stage
permissions do not restrict this working copy. Missing evidence or failed attempts
call for investigation and reversible experiments. Keep traces, build output and
browser evidence in /task/evidence and inspect the current execution selectively.
This is unattended work: ordinary messages are progress, not requests for user
intervention. Keep working on gaps that prevent the service goal; diagnosis alone
is not delivery.

Complete when actual native interactions establish a usable local environment
for this scope. Use complete_service with the observed results, evidence, access
instructions and limitations, and leave this same instance and service running.
A successful build, open port, static page or requested action alone is insufficient.
Use init-owned jobs for processes that must survive your session; the task guide
describes them. Full physical-device equivalence, exhaustive feature testing and
fresh-instance replay are not completion prerequisites. Never disclose model
credentials in logs, artifacts or your final response.
"""


def initial_message(task: dict) -> str:
    """Send task requirements and Goal as user input; keep evidence in files."""
    paths = task.get("paths", {})
    message = (TASK_INSTRUCTIONS + "\nTask and input paths are in /task/task.json. Read the task guide at "
               "/opt/fmst/src/fmst_analyzer/runner/task/README.md.\n")
    if engineering := paths.get("candidate_engineering"):
        message += "Candidate layout/build reference, when needed: " + engineering + "\n"
    if source := task.get("goal_source"):
        message += "Goal source: " + source + "\n"
    if task.get("delivery_mode") == "rehosting_only":
        message += ("This run evaluates native rehosting. After complete_service, finish the response "
                    "and retain this instance; no post-Goal delivery document or image is requested.\n")
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
    finally:
        if completed is not None and not (TASK / "delivery/handoff-status.json").exists():
            write_json(TASK / "delivery/handoff-status.json", {
                "status": "interrupted" if delivery_mode == "full" else "not_started",
                "delivery_mode": delivery_mode, "finished_at": time.time()})
        try:
            if agent is not None:
                await agent.aclose()
        finally:
            await analysis.close()
            finish_agent_phase()
            event("agent_exited", completed=completed is not None)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume-message", type=Path,
                        help="Explicit follow-up file; resume the retained native session for one turn")
    args = parser.parse_args()
    asyncio.run(run(resume_message=args.resume_message.read_text() if args.resume_message else None))
