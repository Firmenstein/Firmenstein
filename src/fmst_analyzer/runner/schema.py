"""Persisted Runner evidence and per-turn Agent contract."""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .rootfs_actions import RootfsAction
from .adaptation_schema import RuntimeUnitProposal, RuntimeAdaptation, AdaptationEvidence


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuntimeNetwork(StrictModel):
    """Disposable internal network and in-container probe destination."""

    subnet: str | None = Field(default=None, description="Optional strict IPv4 CIDR for the isolated Docker network. Supply subnet, gateway and target_address together; omission keeps Docker allocation.")
    gateway: str | None = Field(default=None, description="Usable IPv4 gateway in subnet, distinct from target_address. No host port or external network is exposed.")
    target_address: str | None = Field(default=None, description="Usable static IPv4 address of the target container in subnet, justified by firmware/network evidence.")
    probe_destination: Literal["auto", "loopback", "interface"] = Field(default="auto", description="Probe runs inside the target namespace. auto tries loopback then the container address; loopback uses only 127.0.0.1; interface uses only the container address and never falls back to loopback. This does not create a separate external client.")

    @model_validator(mode="after")
    def validate_addresses(self) -> Self:
        values = (self.subnet, self.gateway, self.target_address)
        if all(value is None for value in values):
            return self
        if any(value is None for value in values):
            raise ValueError("subnet, gateway and target_address must be supplied together")
        network = IPv4Network(self.subnet, strict=True)
        gateway, target = IPv4Address(self.gateway), IPv4Address(self.target_address)
        for address in (gateway, target):
            if (address not in network or address in (network.network_address, network.broadcast_address)
                    or address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local):
                raise ValueError("gateway and target_address must be usable unicast hosts in subnet")
        if gateway == target:
            raise ValueError("gateway and target_address must differ")
        return self


class InteractionProbe(StrictModel):
    port: int = Field(
        ge=1,
        le=65535,
        description="TCP port exposed by the target service inside the sandbox.",
    )
    request_text: str = Field(
        min_length=1,
        description=(
            "Small protocol-valid request sent after connecting. Escapes such as "
            "\\r\\n represent their actual characters."
        ),
    )
    response_contains: str | None = Field(
        default=None,
        description=(
            "Optional text required in the response. Null means any non-empty "
            "response satisfies this diagnostic probe, not final service Interact acceptance."
        ),
    )


class ResponseValueCapture(StrictModel):
    """One bounded literal-delimiter value from a final HTTP response body."""

    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$", description="Scenario-local name used by later {{response:name}} URL placeholders. A later capture of the same name replaces its value.")
    prefix: str = Field(min_length=1, max_length=1024, description="Exact text immediately before the value in the decoded final HTTP body. Must occur exactly once; headers and trailers are excluded.")
    suffix: str = Field(min_length=1, max_length=1024, description="Exact text immediately after the value. The first occurrence after prefix ends the capture.")
    max_chars: int = Field(default=4096, ge=1, le=4096, description="Maximum nonempty captured value length. Control characters and undecodable UTF-8 are rejected; URL substitutions percent-encode the value.")


class InteractionStep(StrictModel):
    """One ordered caller-visible request in a service scenario."""

    request_text: str = Field(min_length=1, description="Exact protocol request bytes represented as UTF-8 text.")
    expected_status_code: int | None = Field(default=None, ge=100, le=599, description="Required HTTP status when the protocol exposes one; null for raw TCP.")
    response_contains: str | None = Field(default=None, description="Required response text for this step.")
    response_not_contains: list[str] = Field(default_factory=list, description="Strings which reject this step, such as a generic error page.")
    save_cookies: bool = Field(default=False, description="Extract Set-Cookie values for later {{cookie:name}} substitutions.")
    response_captures: list[ResponseValueCapture] = Field(default_factory=list, description="Required values extracted from this step's final HTTP body. Later request targets may use {{response:name}}; missing or ambiguous captures fail this step. They do not prove authentication by themselves.")


class ObservationAssertion(StrictModel):
    """Bind one scenario claim to a narrow Controller-owned machine fact."""

    target: Literal["precondition", "state_change"] = Field(
        description="Which scenario claim this assertion proves."
    )
    target_index: int = Field(
        ge=1,
        description="One-based index into preconditions or required_state_changes.",
    )
    predicate: Literal[
        "staged_rootfs_ready",
        "target_process_alive_at_probe",
        "ordered_response_sequence_complete",
        "same_target_process_identity",
    ] = Field(
        description=(
            "Controller-owned machine fact. These predicates do not prove an "
            "arbitrary semantic state change; they only prove their exact fact."
        )
    )


class InteractionScenario(StrictModel):
    """Fixed, decidable service scenario; success proves its declared scope only."""

    protocol: Literal["http", "tcp"]
    port: int = Field(ge=1, le=65535)
    preconditions: list[str] = Field(default_factory=list, description="Required staged state before the first request.")
    steps: list[InteractionStep] = Field(min_length=1, description="Ordered requests covering representative major operations for the service goal, including their business results and state continuity. Select from native evidence and explain coverage in decision summary; 3–5 distinct operations is a guideline, not a request-count gate. Later steps may use captured cookies or response values. Supplied narrow regressions retain their original scope.")
    required_state_changes: list[str] = Field(default_factory=list, description="Caller-visible state changes that must be evidenced after the sequence.")
    observation_requirements: list[Literal[
        "staged_rootfs", "target_process_alive", "ordered_response_sequence",
        "same_target_process",
    ]] = Field(
        default_factory=list,
        description=(
            "Machine-checkable observation channels required for the natural-"
            "language state-change claims. The Controller, not the Agent, verifies them."
        ),
    )
    observation_assertions: list[ObservationAssertion] = Field(
        default_factory=list,
        description=(
            "Explicit binding from each precondition/state-change claim to a "
            "Controller-owned machine predicate. A channel name without this "
            "binding can never produce success."
        ),
    )
    rejection_conditions: list[str] = Field(default_factory=list, description="Literal substrings rejected in any step's response_text. Natural-language sentences are matched verbatim, not interpreted as rules or log/state observations. Use step status/content fields and typed observation_assertions for executable checks.")
    evidence_refs: list[str] = Field(default_factory=list, description="Plan/Analyzer/rootfs evidence supporting the selected operations and their expected results; static evidence alone does not prove runtime behavior.")
    specification_gap: bool = Field(default=False, description="True when evidence or executor support cannot define a required, decidable service interaction or observation; this scenario can never produce success. Do not hide a required operation by replacing it with an easy request.")
    gap_reason: str | None = Field(default=None, description="Required explanation when specification_gap is true.")

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        captured_names: set[str] = set()
        for step in self.steps:
            markers = re.findall(r"\{\{response:([A-Za-z][A-Za-z0-9_]{0,63})\}\}", step.request_text)
            if step.response_captures or "{{response:" in step.request_text:
                if self.protocol != "http":
                    raise ValueError("response captures require an HTTP scenario")
                line, _, rest = step.request_text.partition("\r\n")
                pieces = line.split(" ")
                if len(pieces) != 3 or not pieces[2].startswith("HTTP/1."):
                    raise ValueError("response captures require a complete HTTP request line")
                target = pieces[1]
                if "{{response:" in rest or "{{response:" in pieces[0]:
                    raise ValueError("response placeholders are supported only in the request target")
                if "{{response:" in re.sub(r"\{\{response:([A-Za-z][A-Za-z0-9_]{0,63})\}\}", "", target):
                    raise ValueError("invalid response placeholder")
                if not set(markers).issubset(captured_names):
                    raise ValueError("response placeholder requires a capture in an earlier step")
            names = [capture.name for capture in step.response_captures]
            if len(set(names)) != len(names):
                raise ValueError("duplicate response capture name in one step")
            captured_names.update(names)
        if self.specification_gap and not (self.gap_reason or "").strip():
            raise ValueError("specification_gap requires gap_reason")
        if not self.specification_gap and not self.evidence_refs:
            raise ValueError("a decidable scenario requires evidence_refs")
        self.evidence_refs = list(dict.fromkeys(ref.strip() for ref in self.evidence_refs if ref.strip()))
        if not self.specification_gap and not any(
            step.expected_status_code is not None or step.response_contains is not None
            for step in self.steps
        ) and not self.required_state_changes:
            self.specification_gap = True
            self.gap_reason = (
                "Scenario has no positive caller-visible assertion: add an expected "
                "status, required response content, or independently observed state change."
            )
        claims = {
            "precondition": self.preconditions,
            "state_change": self.required_state_changes,
        }
        channels = set(self.observation_requirements)
        predicate_channels = {
            "staged_rootfs_ready": "staged_rootfs",
            "target_process_alive_at_probe": "target_process_alive",
            "ordered_response_sequence_complete": "ordered_response_sequence",
            "same_target_process_identity": "same_target_process",
        }
        for assertion in self.observation_assertions:
            if assertion.target_index > len(claims[assertion.target]):
                raise ValueError(
                    f"{assertion.target} observation assertion index is out of range"
                )
            if predicate_channels[assertion.predicate] not in channels:
                raise ValueError(
                    "observation assertion predicate requires its matching "
                    "observation_requirements channel"
                )
        for target, target_claims in claims.items():
            indexes = {
                item.target_index
                for item in self.observation_assertions
                if item.target == target
            }
            if indexes and not set(range(1, len(target_claims) + 1)).issubset(indexes):
                raise ValueError(
                    f"every {target} claim must have an observation assertion binding"
                )
            if not target_claims and indexes:
                raise ValueError(
                    f"{target} observation assertions require corresponding claims"
                )
        return self


class HttpResponseEvidence(StrictModel):
    source: Literal["wire", "saved_text"] = Field(description="Wire means parsing original captured bytes; saved_text is a legacy/test reconstruction, not a wire-identity claim.")
    framing: Literal["content_length", "chunked", "no_body", "close_delimited", "invalid"] = Field(description="HTTP framing observed in the capture; close-delimited framing alone cannot prove application-level completeness.")
    wire_bytes: int = Field(ge=0, description="Byte count of the parsed capture before text decoding.")
    wire_sha256: str = Field(description="SHA-256 of the parsed bytes; source identifies whether these are original wire bytes.")
    status_code: int | None = Field(default=None, description="Final HTTP response status, after any informational responses.")
    headers_text: str = Field(default="", description="Final status and headers decoded as Latin-1, without chunk framing.")
    body_text: str = Field(default="", description="Dechunked body decoded as UTF-8 with replacement, used for text assertions.")
    body_bytes: int | None = Field(default=None, description="Exact body byte count before text decoding.")
    body_sha256: str | None = Field(default=None, description="SHA-256 of the exact dechunked body bytes.")
    error: str | None = Field(default=None, description="Malformed or incomplete framing; an error prevents HTTP scenario success.")


class ScenarioStepResult(StrictModel):
    index: int = Field(ge=1)
    connected: bool
    response_text: str = ""
    status_code: int | None = None
    passed: bool
    error: str | None = None
    http_response: HttpResponseEvidence | None = Field(default=None, description="Controller-derived HTTP framing and byte identity; absent in historical evidence or non-HTTP scenarios.")
    captured_response_values: dict[str, str] = Field(default_factory=dict, description="Values independently extracted under this step's capture rules, bound to http_response.wire_sha256. These are transport observations, not authentication claims.")


class ScenarioObservation(StrictModel):
    """One fact observed by a concrete runtime channel.

    The fact is deliberately not interpreted as a semantic state change.  A
    later report can connect it to a precondition or state-change requirement
    only when the evidence and owner support that interpretation.
    """

    source: Literal["probe", "lifecycle", "container", "trace"]
    kind: Literal[
        "probe_step", "staged_rootfs", "target_process_alive",
        "ordered_response_sequence", "same_target_process", "target_lifecycle",
        "trace_presence",
    ] = "probe_step"
    fact: str = Field(min_length=1)
    evidence_path: str | None = None


class ScenarioResult(StrictModel):
    status: Literal["success", "blocked", "specification_gap", "unsupported"]
    steps: list[ScenarioStepResult] = Field(default_factory=list)
    observations: list[ScenarioObservation] = Field(default_factory=list)
    state_changes_observed: list[str] = Field(default_factory=list)
    observation_assertions_satisfied: list[str] = Field(default_factory=list)
    rejection: str | None = None
    error: str | None = None


class PeerReadiness(StrictModel):
    unix_socket: str = Field(description="Absolute guest UNIX stream socket that must exist and be listening before the target starts. This proves endpoint availability, not protocol initialization or ownership by a particular PID.")
    timeout_seconds: float = Field(default=30, gt=0, le=300,
        description="Maximum peer initialization wait, further limited by this attempt/session's remaining budget.")

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        path = PurePosixPath(self.unix_socket)
        if not path.is_absolute() or ".." in path.parts or str(path) != self.unix_socket or any(c in self.unix_socket for c in "\x00\r\n"):
            raise ValueError("readiness unix_socket must be a normalized absolute guest path without NUL/CR/LF")
        return self


class CompanionProcess(StrictModel):
    readiness: PeerReadiness | None = Field(default=None,
        description="Optional explicit prerequisite for target startup. Null preserves concurrent launch; process startup alone does not establish readiness.")
    executable_path: str = Field(
        description=(
            "Firmware-absolute ELF path for a directly started support process, "
            "normally a verified IPC peer."
        )
    )
    args: list[str] = Field(
        default_factory=list,
        description="Concrete arguments after the support executable's argv0.",
    )
    working_directory: str = Field(
        default="/",
        description="Normalized firmware-absolute working directory.",
    )
    environment: dict[str, str] = Field(
        default_factory=dict,
        description="Concrete environment entries inherited by this process.",
    )
    evidence_ref: str = Field(
        min_length=1,
        description=(
            "Analyzer or runtime evidence that identifies this process as a "
            "required peer; this is explanatory and does not replace ELF validation."
        ),
    )

    @model_validator(mode="after")
    def validate_process(self) -> Self:
        path = PurePosixPath(self.executable_path)
        cwd = PurePosixPath(self.working_directory)
        if not path.is_absolute() or ".." in path.parts or path.as_posix() != self.executable_path:
            raise ValueError("companion executable_path must be normalized and absolute")
        if not cwd.is_absolute() or ".." in cwd.parts or cwd.as_posix() != self.working_directory:
            raise ValueError("companion working_directory must be normalized and absolute")
        if any("\x00" in item for item in self.args):
            raise ValueError("companion args must not contain NUL")
        for name, value in self.environment.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError(f"invalid companion environment name: {name!r}")
            if "\x00" in value:
                raise ValueError(
                    f"companion environment value must not contain NUL: {name!r}"
                )
        self.evidence_ref = self.evidence_ref.strip()
        return self


class IpcDecision(StrictModel):
    """Evidence-backed choice for one IPC dependency in an attempt."""

    strategy: Literal["none", "mock", "peer", "compare", "gap"] = Field(
        default="none",
        description=(
            "Use mock only for a narrow stateless contract, peer for a concrete "
            "companion ELF, compare for a bounded mock/peer experiment, or gap "
            "when evidence cannot safely select either path."
        ),
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Analyzer, Plan, source/assembly, or runtime evidence supporting the choice.",
    )
    rationale: str = Field(
        default="No IPC dependency was selected for this attempt.",
        min_length=1,
        description="Why this IPC strategy is safe for the current attempt.",
    )

    @model_validator(mode="after")
    def normalize(self) -> Self:
        self.evidence_refs = list(dict.fromkeys(ref.strip() for ref in self.evidence_refs if ref.strip()))
        self.rationale = self.rationale.strip()
        if self.strategy != "none" and not self.evidence_refs:
            raise ValueError("an IPC strategy requires evidence_refs")
        return self


class LaunchEvidence(StrictModel):
    path: str = Field(description="Absolute path of a read-only rootfs, assembly or diagnostic source already available to this session.")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the exact source file, calculated with native commands.")
    excerpt: str = Field(min_length=1, description="Exact UTF-8 source excerpt supporting the launch fact. Controller verifies content and identity, not semantic correctness.")


class RuntimeLaunchProposal(StrictModel):
    executable_path: str = Field(description="Absolute guest path of the Controller-selected target, not a replacement executable.")
    args: list[str] = Field(description="Literal arguments after argv0, matching this decision's guest_args.")
    working_directory: str = Field(description="Concrete guest cwd, matching this decision's guest_working_directory.")
    environment: dict[str, str] = Field(description="Explicit environment, matching this decision's guest_environment.")
    evidence: list[LaunchEvidence] = Field(min_length=1, description="Verified source snippets supporting this proposed invocation and its assumptions.")
    rationale: str = Field(min_length=1, description="Why this invocation can test the original service goal, retaining relevant source conditions.")
    limitations: list[str] = Field(description="Unproved launch assumptions and dependencies. Admission does not prove boot-chain or service correctness.")


class RuntimeLaunchRecord(StrictModel):
    recipe_id: str = Field(description="Controller-generated runtime launch content identity, never an invented Catalog ID.")
    executable_path: str = Field(description="Exact selected guest executable.")
    target_sha256: str = Field(description="Verified selected target content digest.")
    original_recipe_id: str | None = Field(description="Original Plan choice; remains null when a runtime proposal fills a missing launch.")
    proposal: RuntimeLaunchProposal = Field(description="Source-bound runtime derivation, separate from immutable Plan/Generation.")


class RuntimeExperiment(StrictModel):
    hypothesis: str = Field(min_length=1, description="Evidence-backed explanation being tested, explicitly a hypothesis.")
    evidence_refs: list[str] = Field(min_length=1, description="Existing attempt/source paths or record references supporting the hypothesis; never invented observations.")
    changed_variable: str = Field(min_length=1, description="The input or implementation change being compared, or the additional observation sought by an unchanged run.")
    expected_observations: list[str] = Field(min_length=1, description="What the next run should show if the hypothesis is supported; predictions are not Controller observations or replacement acceptance criteria.")
    preserved_behavior: str = Field(min_length=1, description="Target processing and acceptance conditions retained by this experiment.")
    state_carrier: str | None = Field(default=None, description="Evidence-backed state carrier relevant to the hypothesis, such as a guest file, process memory, OFD or protocol token. Leave null when unknown.")


class RunnerCompletion(StrictModel):
    """Agent's service assessment, bound to an independently executed attempt."""

    attempt_number: int = Field(ge=1, description="Latest executed candidate supporting completion through native interaction or an optional protocol scenario; an older or external run cannot complete this session.")
    attempt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the complete Controller-written attempt.json, read from the current feedback artifacts.")
    client_receipt: str | None = Field(default=None, description="Receipt path of the fresh native browser instance whose actual operations support this completion. The executor binds it to the current candidate; you assess business coverage. Required for a UI service goal.")
    coverage: str = Field(min_length=1, description="Evidence-based assessment of how the executed operations cover the selected service goal, major handlers and required state continuity. Controller checks evidence identity, not business semantics.")
    limitations: list[str] = Field(default_factory=list, description="Explicit exclusions and residual limitations outside the required service goal; these do not claim unexecuted behavior. Missing state, resources or executor support does not turn required behavior into a scope exclusion; put that in unverified_requirements.")
    unverified_requirements: list[str] = Field(default_factory=list, description="Required service behaviors still failed, missing or unverified. A nonempty list prevents completion; continue investigating, interacting and repairing. Request external input only when it cannot be obtained through the available environment.")


class ScenarioRequestCorrection(StrictModel):
    parent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", description="Optional SHA-256 of the current Controller scenario. Controller binds the proposal to its latest failed attempt and records this digest; supply it when available to reject stale proposals.")
    step_indices: list[int] = Field(min_length=1, description="One-based indices of erroneous client requests to correct. Keep their business assertions and every other existing step unchanged; add checks separately.")
    evidence: list[AdaptationEvidence] = Field(min_length=2, description="Exact read-only sources with hashes/excerpts: include the latest failed Controller attempt or its artifacts, and independent native source/UI supporting the corrected client request. Identity is checked; interpretation remains Agent-owned.")
    reason: str = Field(min_length=1, description="Why these request bytes were wrong and how the new native client requests test the same required operations without weakening their assertions.")


class RunnerInputRequest(StrictModel):
    required_input: str = Field(min_length=1, description="Specific external input or capability needed from the caller, and the action it would enable. An unresolved firmware dependency is ordinarily a repair task.")
    evidence_refs: list[str] = Field(min_length=1, description="Existing evidence paths supporting why this input is required.")
    unavailable_reason: str = Field(min_length=1, description="What was investigated or attempted and why the required input cannot be obtained through the available environment. Keep the goal unfinished.")


class RunnerDecision(StrictModel):
    input_request: RunnerInputRequest | None = Field(default=None, description="Required only for request_input. Retains the candidate and evidence as unfinished work awaiting caller input; it is not a general failure or gap exit.")
    browser_origin: str | None = Field(default=None, description="Native http(s) service URL for direct browser interaction. This is the primary path for a web UI: provide launch configuration and this URL, without a probe or InteractionScenario. The executor starts the candidate and returns a live browser; you inspect and repair until completion.")
    scenario_revision_reason: str | None = Field(default=None, min_length=1, description="Why requests, assertions or operation selection changed after feedback. Tests are revisable, including incorrect assertions. Retain failed business requirements and prior evidence; explain the correction rather than replacing failed work with easy pages.")
    request_correction: ScenarioRequestCorrection | None = Field(default=None, description="Legacy request-correction metadata retained for history. For current tests use scenario_revision_reason; no separate request admission is required.")
    completion: RunnerCompletion | None = Field(default=None, description="Required only for action=complete, after actual interaction confirms the service goal. Does not execute a new attempt or change the candidate.")
    scenario_resolution_reason: str | None = Field(default=None, min_length=1, description="Evidence-based reason why a previously recorded scenario specification gap can now be represented and checked. Retain previous requests/assertions and evidence; new assertions require a fresh execution.")
    network: RuntimeNetwork = Field(default_factory=RuntimeNetwork, description="Complete network configuration for the next attempt, grounded in source/runtime evidence. Keep service requests and acceptance assertions unchanged when repairing network conditions.")
    cookie_continuity_reason: str | None = Field(default=None, min_length=1, description="Explicit reason to enable save_cookies on a proven issuing step and add one Cookie header containing only name={{cookie:name}} pairs to later HTTP requests. Requires captured server Set-Cookie evidence from the last failed attempt; retain every other request byte and scenario assertion. Cannot combine with request_representation_reason, replace an existing Cookie header, or supply literal cookie values.")
    unit_proposal: RuntimeUnitProposal | None = Field(default=None, description="Explicit Controller admission request, only with action=propose_unit after failed runtime evidence. Do not edit files in this turn. Admission scaffolds the owner; implement and test it in the same session afterward.")
    experiment: RuntimeExperiment | None = Field(default=None, description="A bounded diagnostic experiment for the next attempt; retain uncertainty and the original scenario. Optional for bootstrap or an ordinary verification run.")
    launch_proposal: RuntimeLaunchProposal | None = Field(default=None,
        description="Explicit source-backed direct launch proposal when the Controller reports that no selected Catalog recipe exists. Otherwise omit. Uses existing launch configuration authority, never creates an Intervention Unit.")
    request_representation_reason: str | None = Field(default=None, min_length=1,
        description="Reason for an explicit correction of literal CRLF separators in a previously frozen HTTP header. Does not authorize changing request content or acceptance assertions. Omit when no representation repair is proposed.")
    action: Literal["run", "edit_unit", "edit_workspace", "propose_unit", "complete", "continue", "request_input"] = Field(
        description=(
            "Run without changes, edit existing generated Unit Rust, edit another "
            "declared file in the disposable intervention/test/environment workspace, "
            "propose a source-bound runtime owner/Contract for Controller admission before edits, "
            "complete after reviewing independently successful runtime evidence and service coverage, "
            "continue the active goal after reporting progress, or request a specific unavailable external input while leaving the goal unfinished. Ordinary replies, diagnoses and next steps do not end the goal."
        )
    )
    probe: InteractionProbe | None = Field(
        default=None,
        description=(
            "Optional protocol diagnostic/regression. Omit for direct browser interaction."
        ),
    )
    scenario: InteractionScenario | None = Field(
        default=None,
        description="Revisable protocol checks authored from native evidence. Correct mistaken requests and assertions using scenario_revision_reason and run again. Native browser tools provide actual UI/client interaction; this scenario can remain a narrower diagnostic or regression. Omit for complete/continue/request_input.",
    )
    guest_args: list[str] = Field(
        default_factory=list,
        description=(
            "Literal exec arguments after the selected executable's argv0. "
            "No shell expansion is performed; empty strings and $ are preserved. "
            "Use actual values when launch evidence requires expansion."
        ),
    )
    guest_working_directory: str = Field(
        default="/",
        description=(
            "Concrete firmware-absolute working directory inherited by the "
            "guest process. Use / when the launch evidence requires no other cwd."
        ),
    )
    guest_environment: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Literal environment entries required by the selected launch. "
            "Values are not shell-expanded."
        ),
    )
    companion_processes: list[CompanionProcess] = Field(
        default_factory=list,
        description=(
            "Complete cumulative support-process set for the next attempt. "
            "Each process runs in the same disposable rootfs, network, and "
            "filesystem namespace as the target."
        ),
    )
    ipc: IpcDecision = Field(
        default_factory=IpcDecision,
        description=(
            "Evidence-backed IPC choice for this attempt. A peer strategy must "
            "name concrete companion_processes; a mock strategy must not start "
            "a peer for the same resource."
        ),
    )
    rootfs_actions: list[RootfsAction] = Field(
        default_factory=list,
        description=(
            "Complete cumulative static actions for the disposable rootfs used "
            "by the next attempt. Use ordinary files here instead of modeling "
            "them as IIB pseudo-files. Actions may address a Runner task without "
            "belonging to an Intervention Unit."
        ),
    )
    disabled_unit_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Complete cumulative set of existing execution Units omitted from "
            "the next runtime manifest because runtime evidence selects native "
            "or rootfs behavior instead."
        ),
    )
    changed_unit_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Controller-known Unit IDs whose Rust implementation changed. Non-empty "
            "only for action=edit_unit."
        ),
    )
    changed_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Workspace-relative paths actually changed by this decision, namespaced "
            "as intervention/<path>, test_harness/<path>, or environment/<path>. "
            "The Controller compares this declaration with the filesystem diff."
        ),
    )
    summary: str = Field(
        min_length=1,
        description="Concise rationale grounded in plan or runtime evidence. At bootstrap explain the selected major operations, distinct backend/state coverage, continuity checks, scope exclusions and unverified requirements. Do not claim final Interact acceptance from a narrow regression alone.",
    )

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        self.summary = self.summary.strip()
        self.changed_unit_ids = list(dict.fromkeys(self.changed_unit_ids))
        self.changed_paths = list(dict.fromkeys(path.strip() for path in self.changed_paths if path.strip()))
        self.disabled_unit_ids = list(dict.fromkeys(self.disabled_unit_ids))
        companions: list[CompanionProcess] = []
        seen_companions: set[str] = set()
        for process in self.companion_processes:
            identity = process.model_dump_json(exclude_none=True)
            if identity not in seen_companions:
                seen_companions.add(identity)
                companions.append(process)
        self.companion_processes = companions
        # Preserve the historical companion-only payload shape while making
        # the IPC choice explicit in the persisted decision.
        if self.companion_processes and self.ipc.strategy == "none":
            self.ipc = IpcDecision(
                strategy="peer",
                evidence_refs=[process.evidence_ref for process in self.companion_processes],
                rationale="Concrete companion_processes imply an evidence-backed peer.",
            )
        if self.ipc.strategy == "peer" and not self.companion_processes:
            raise ValueError("ipc.strategy=peer requires companion_processes")
        if self.ipc.strategy == "mock" and self.companion_processes:
            raise ValueError("ipc.strategy=mock cannot also start companion_processes")
        if self.ipc.strategy == "gap" and self.companion_processes:
            raise ValueError("ipc.strategy=gap cannot start an unverified peer")
        if any("\x00" in item for item in self.guest_args):
            raise ValueError("guest_args must not contain NUL")
        cwd = PurePosixPath(self.guest_working_directory)
        if (
            not cwd.is_absolute()
            or ".." in cwd.parts
            or self.guest_working_directory != cwd.as_posix()
        ):
            raise ValueError("guest_working_directory must be normalized and absolute")
        for name, value in self.guest_environment.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError(f"invalid guest environment name: {name!r}")
            if "\x00" in value:
                raise ValueError(
                    f"guest environment value must not contain NUL: {name!r}"
                )
        if self.browser_origin is not None:
            from urllib.parse import urlsplit
            origin = urlsplit(self.browser_origin)
            if origin.scheme not in {"http", "https"} or not origin.hostname or origin.username or origin.password:
                raise ValueError("browser_origin must be a native http(s) service URL without credentials")
            if self.probe is not None or self.scenario is not None:
                raise ValueError("direct browser interaction omits protocol probe and scenario")
        if self.action in {"run", "edit_unit", "edit_workspace", "propose_unit"} and self.probe is None and self.browser_origin is None:
            raise ValueError(f"{self.action} requires probe")
        if self.action in {"run", "edit_unit", "edit_workspace", "propose_unit"} and self.scenario is None and self.browser_origin is None:
            self.scenario = InteractionScenario(
                protocol="tcp", port=self.probe.port if self.probe else 1,
                steps=[InteractionStep(request_text=self.probe.request_text if self.probe else "legacy")],
                specification_gap=True,
                gap_reason="RunnerDecision omitted the explicit InteractionScenario",
            )
        if self.scenario is not None and self.probe is not None and self.scenario.port != self.probe.port:
            raise ValueError("scenario port must match probe port")
        if (self.action == "propose_unit") != (self.unit_proposal is not None):
            raise ValueError("propose_unit requires unit_proposal; other actions must omit it")
        if self.action == "propose_unit" and (self.changed_paths or self.changed_unit_ids):
            raise ValueError("Submit the Unit proposal before editing files")
        if (self.action == "request_input") != (self.input_request is not None):
            raise ValueError("request_input requires input_request; other actions must omit it")
        if self.action in {"continue", "request_input"} and self.scenario is not None:
            raise ValueError("non-executing decisions must not include a scenario")
        if (self.action == "complete") != (self.completion is not None):
            raise ValueError("complete requires completion; other actions must omit it")
        if self.action == "complete" and (self.probe is not None or self.scenario is not None):
            raise ValueError("complete references an executed attempt, without a new probe or scenario")
        if self.action in {"complete", "continue", "request_input"} and self.probe is not None:
            raise ValueError(f"{self.action} decisions must not include a probe")
        if self.request_correction is not None and (self.action != "run" or
                self.cookie_continuity_reason is not None or self.request_representation_reason is not None):
            raise ValueError("request_correction requires run and cannot combine with other request corrections")
        if self.action == "edit_unit" and not self.changed_unit_ids:
            raise ValueError("edit_unit requires at least one changed Unit")
        if self.action == "edit_workspace" and not self.changed_paths:
            raise ValueError("edit_workspace requires at least one changed path")
        if self.action == "run" and (self.changed_unit_ids or self.changed_paths):
            raise ValueError("run decisions must not declare source edits")
        if self.action in {"complete", "continue", "request_input"} and (self.changed_unit_ids or self.changed_paths):
            raise ValueError("non-executing decisions must not declare source edits")
        if self.action not in {"edit_unit", "edit_workspace"} and self.changed_unit_ids:
            raise ValueError("changed_unit_ids require action=edit_unit")
        for path in self.changed_paths:
            normalized = PurePosixPath(path)
            if (
                normalized.is_absolute()
                or ".." in normalized.parts
                or normalized.as_posix() != path
                or normalized.parts[0] not in {"intervention", "test_harness", "environment"}
            ):
                raise ValueError(
                    "changed_paths must be normalized under intervention/, test_harness/, or environment/"
                )
        return self


class ProbeResult(StrictModel):
    connected: bool
    interacted: bool
    attempts: int
    error: str | None = None
    response_text: str = ""
    response_truncated: bool = False
    status_code: int | None = None
    http_response: HttpResponseEvidence | None = Field(default=None, description="Framing parsed from captured response bytes before lossy text conversion; ignored for raw TCP scenarios.")


class RuntimeRegister(StrictModel):
    name: str
    value: int


class RuntimeMemorySnapshot(StrictModel):
    address: int
    requested_bytes: int = Field(ge=0)
    source_register: str
    bytes: list[int] = Field(default_factory=list)
    error: str | None = None


class RuntimeSourceLocation(StrictModel):
    runtime_pc: int
    binary_name: str
    runtime_base: int
    image_base: int
    static_ea: int
    function_name: str
    function_ea: int
    assembly_path: str
    assembly_context: list[str] = Field(default_factory=list)
    decompiled_path: str | None = None
    ctree_index: int | None = None
    snapshot_hash: str | None = None
    source_ea: int | None = None
    line_number: int | None = None
    column_number: int | None = None
    expression_text: str | None = None
    source_statement: str | None = None


class RuntimeFunctionSummary(StrictModel):
    binary_name: str
    function_name: str
    function_ea: int
    unique_blocks: int
    total_hits: int
    assembly_path: str
    decompiled_path: str | None = None


class RuntimeRecentBlock(StrictModel):
    runtime_pc: int
    consecutive_hits: int
    location: RuntimeSourceLocation | None = None


class RuntimeEventContext(StrictModel):
    sequence: int
    last_sequence: int
    repeat_count: int
    kind: str
    detail: str
    unit_id: str | None = None
    hook_id: str | None = None
    elapsed_ns: int = Field(default=0, ge=0)
    last_elapsed_ns: int = Field(default=0, ge=0)
    detail_dropped_bytes: int = Field(default=0, ge=0)
    runtime_pc: int | None = None
    registers: list[RuntimeRegister] = Field(default_factory=list)
    memory: list[RuntimeMemorySnapshot] = Field(default_factory=list)
    location: RuntimeSourceLocation | None = None


class RuntimeImageMapping(StrictModel):
    binary_name: str
    runtime_base: int
    image_base: int | None = None
    binary_path: str | None = None
    source_available: bool
    mapping_basis: str = Field(default="Legacy name/base association; executed ELF identity unverified.", description="Provenance of this address association, never proof of causality.")
    mapping_error: str | None = Field(default=None, description="Unusable or ambiguous image identity/load address; no source location is assigned.")
    source_elf_sha256: str | None = Field(default=None, description="Content hash of the source ELF consulted for this mapping.")
    staged_elf_sha256: str | None = Field(default=None, description="Matching staged path bytes before execution, not independently sampled loaded memory.")


class RuntimeTraceContext(StrictModel):
    schema_version: Literal[4] = 4
    raw_trace_schema_version: int
    guest_arch: str = "unknown"
    byte_order: str = "unknown"
    word_bits: int = 0
    started_unix_ns: int = 0
    host_pid: int = 0
    origin_pid: int = 0
    checkpoint_elapsed_ns: int = 0
    terminal_reason: str | None = None
    raw_trace_bytes: int = Field(default=0, ge=0)
    raw_trace_sha256: str | None = None
    integrity_status: Literal["complete", "partial", "invalid", "unknown"] = "unknown"
    dropped_events: int = 0
    dropped_image_loads: int = 0
    dropped_tail_entries: int = 0
    dropped_focus_tail_entries: int = 0
    observed_unique_blocks: int = 0
    dropped_unique_blocks: int = 0
    main_load_address: int
    total_block_executions: int
    mapped_unique_blocks: int
    unmapped_unique_blocks: int
    images: list[RuntimeImageMapping]
    functions: list[RuntimeFunctionSummary]
    recent_focus_blocks: list[RuntimeRecentBlock]
    recent_blocks: list[RuntimeRecentBlock]
    events: list[RuntimeEventContext]


class CookieSourceEvidence(StrictModel):
    step_index: int = Field(ge=1, description="Earlier response step that issued these cookie names.")
    response_path: str = Field(description="Original Controller-captured wire response, retained separately from guest-writable output.")
    response_sha256: str = Field(description="Digest verified against the capture receipt before admission.")
    cookie_names: list[str] = Field(min_length=1, description="Server-issued names used by the revision; no frozen cookie value is substituted on replay.")


class RequestRepresentationRevision(StrictModel):
    kind: Literal["header_representation", "cookie_continuity", "client_request", "scenario_revision"] = Field(default="header_representation", description="Historical request repair or Agent-authored scenario revision, retaining old/new tests and the reason. Test semantics are Agent-owned.")
    correction: ScenarioRequestCorrection | None = Field(default=None, description="Source-bound proposal for client_request corrections; original evidence is frozen with the publication.")
    source_attempt_path: str | None = Field(default=None, description="Prior failed attempt used for cookie continuity admission.")
    source_attempt_sha256: str | None = Field(default=None, description="Original bytes of the failed attempt record, not a rewritten snapshot.")
    cookie_sources: list[CookieSourceEvidence] = Field(default_factory=list, description="Captured server headers proving the cookie names originated in earlier scenario steps.")
    parent_sha256: str = Field(description="Hash of the original serialized scenario.")
    result_sha256: str = Field(description="Hash of the corrected serialized scenario.")
    reason: str = Field(description="Agent-provided reason for the explicit request correction.")
    before: InteractionScenario = Field(description="Unmodified prior scenario, including the erroneous request.")
    after: InteractionScenario = Field(description="Accepted correction with the same service acceptance floor.")

    @model_validator(mode="after")
    def validate_cookie_evidence(self) -> Self:
        if self.kind == "cookie_continuity" and not (self.source_attempt_path and self.source_attempt_sha256 and self.cookie_sources):
            raise ValueError("cookie continuity revisions require a failed attempt and captured response evidence")
        if self.kind == "client_request" and not (self.correction and self.source_attempt_path and self.source_attempt_sha256):
            raise ValueError("client request corrections require proposal and failed attempt identity")
        return self


class RuntimeAttempt(StrictModel):
    browser_origin: str | None = Field(default=None, description="Direct native browser entry, with no protocol scenario. Startup only observes readiness; the Agent's later browser evidence and completion establish the checked service behavior.")
    network: RuntimeNetwork = Field(default_factory=RuntimeNetwork, description="Internal network and probe destination used for this execution; default describes legacy Docker allocation with loopback-first probes.")
    adaptation_ids: list[str] = Field(default_factory=list, description="Active Controller-admitted runtime owner/Contract derivations used by this attempt.")
    experiment: RuntimeExperiment | None = Field(default=None, description="Agent hypothesis and prediction accepted for this attempt, distinct from independently observed results.")
    launch_resolution: RuntimeLaunchRecord | None = Field(default=None,
        description="Runtime-derived launch when the original Plan had no recipe. Original sources remain unchanged.")
    request_revisions: list[RequestRepresentationRevision] = Field(default_factory=list,
        description="Controller-accepted header representation or evidence-backed cookie continuity corrections retained with frozen execution evidence.")
    tree_identity_version: Literal[2] = Field(description="Required v2 tree hashes bind relative paths, file types, mode/uid/gid, device numbers, content and symlink targets. Timestamps/inodes are not bound; legacy content-only hashes are rejected.")
    attempt_number: int
    probe: InteractionProbe | None = None
    scenario: InteractionScenario | None = None
    scenario_result: ScenarioResult | None = None
    guest_args: list[str]
    guest_working_directory: str
    guest_environment: dict[str, str]
    companion_processes: list[CompanionProcess] = Field(default_factory=list)
    companion_log_paths: list[str] = Field(default_factory=list)
    ipc: IpcDecision = Field(default_factory=IpcDecision)
    rootfs_actions: list[RootfsAction]
    disabled_unit_ids: list[str]
    intervention_sha256: str | None = Field(
        default=None,
        description="SHA-256 of the generated Intervention source, if any.",
    )
    intervention_source_path: str | None = Field(
        default=None,
        description="Attempt snapshot of Intervention source, if any.",
    )
    intervention_binary_path: str | None = Field(
        default=None,
        description="Attempt snapshot of the Intervention cdylib, if any.",
    )
    container_exit_code: int | None = None
    target_exit_code: int | None = Field(
        default=None,
        description=(
            "Exit code of the harness-launched target, independent of the "
            "container supervisor; a daemon parent may exit while its serving "
            "child remains observable."
        ),
    )
    timed_out: bool = False
    outcome: Literal["success", "blocked"] = Field(
        description=(
            "Protocol execution outcome. success requires a satisfied protocol check; "
            "blocked also includes startup-only native candidates with no protocol check. "
            "Native business completion is recorded separately in completion and its client receipt."
        )
    )
    probe_result: ProbeResult
    runtime_trace_path: str
    runtime_trace_paths: list[str] = Field(default_factory=list)
    runtime_trace_context_path: str
    container_log_path: str
    runtime_trace_available: bool
    runtime_trace_context_available: bool
    runtime_trace_context_error: str | None = None
    runtime_dump_manifest_path: str | None = Field(default=None, description="Persisted guest dump manifest; unavailable/partial manifests retain the reason and missing evidence.")
    runtime_dump_capture_kind: Literal["crash", "pre_exit", "stall_capture", "last_checkpoint"] | None = None
    runtime_dump_available: bool = False
    runtime_trace_heartbeat_paths: list[str] = Field(default_factory=list)
    watchdog_path: str | None = Field(
        default=None,
        description="Machine-readable watchdog timeline for this attempt.",
    )
    watchdog_triggered: bool = False
    termination_reason: Literal[
        "probe_satisfied",
        "target_exit",
        "peer_exit",
        "observation_failed",
        "container_exit",
        "probe_timeout",
        "no_progress_watchdog",
        "unknown",
    ] = "unknown"
    rootfs_sha256: str | None = Field(
        default=None,
        description="Hash of the staged rootfs input for this attempt.",
    )
    rootfs_adaptations: list[str] = Field(
        default_factory=list,
        description=(
            "Controller-side staging adaptations required by the container "
            "runtime, kept separate from guest Intervention behavior."
        ),
    )
    target_binary_sha256: str | None = Field(
        default=None,
        description="Hash of the selected firmware executable in the staged rootfs.",
    )
    harness_sha256: str | None = Field(
        default=None,
        description="Hash of the host harness bundle used by this attempt.",
    )
    target_lifecycle_path: str | None = None
    probe_timeline_path: str | None = None
    agent_summary: str


class RunnerRevision(StrictModel):
    revision_number: int = Field(ge=1)
    parent_sha256: str
    result_sha256: str
    changed_unit_ids: list[str] = Field(default_factory=list)
    changed_paths: list[str] = Field(default_factory=list)
    action: Literal["edit_unit", "edit_workspace", "run", "propose_unit"]
    reason: str
    diff_path: str | None = None
    verification: Literal["not_run", "build_passed", "build_test_passed", "build_failed", "test_failed", "prepare_failed", "runtime_failed", "scenario_passed", "runtime_success"] = "not_run"
    verification_detail: str | None = None


class EnvironmentPreparation(StrictModel):
    status: Literal["not_needed", "not_started", "applied", "failed"] = Field(
        default="not_needed",
        description=(
            "Observed Runner handling of the generated static rootfs script."
        ),
    )
    source_script_path: str | None = None
    application_count: int = Field(default=0, ge=0)
    failure_reason: str | None = None


class AttemptExecutionReceipt(StrictModel):
    network: RuntimeNetwork = Field(default_factory=RuntimeNetwork, description="Controller-requested network and probe destination. Actual attempted destinations are in the host-owned probe connection ledger.")
    schema_version: Literal[1] = 1
    session_id: str = Field(description="Owning sandbox session identity.")
    attempt_number: int = Field(description="Controller-selected attempt number.")
    container_name: str = Field(description="Exact owned resource name; starting it may still fail.")
    artifact_root: str = Field(description="Raw evidence directory retained on interruption.")
    started_unix_ns: int = Field(description="Before Docker start; not proof the guest ran.")
    finished_unix_ns: int | None = Field(default=None, description="After bounded collection and cleanup.")
    state: Literal["starting", "running", "completed", "interrupted", "error"] = "starting"
    stop_reason: str | None = Field(default=None, description="Controller cancellation/budget/operation error; not guessed guest cause.")
    error: str | None = Field(default=None, description="Full execution exception, if any.")
    executable_path: str = Field(description="Guest executable requested at launch.")
    guest_args: list[str] = Field(description="Exact literal requested argv after argv0.")
    guest_working_directory: str = Field(description="Requested guest POSIX cwd.")
    guest_environment: dict[str, str] = Field(description="Explicit launch environment.")
    companion_processes: list[CompanionProcess] = Field(description="Requested peer launch configuration.")
    scenario: InteractionScenario | None = Field(description="Original acceptance conditions; partial receipts do not imply success.")
    probe_results: list[ProbeResult] = Field(default_factory=list, description="Completed probe responses before interruption, possibly empty.")
    cleanup: dict[str, object] = Field(default_factory=dict, description="Actual capture/removal outcomes, including failures.")


class RunnerSessionReceipt(StrictModel):
    schema_version: Literal[2] = 2
    session_id: str = Field(description="Identity of this Controller invocation, including initialization failures.")
    started_unix_ns: int = Field(description="Wall-clock start; enforcement uses a separate monotonic deadline.")
    finished_unix_ns: int | None = None
    budget_seconds: float = Field(description="Total per-target wall-clock budget, including cleanup.")
    elapsed_seconds: float = 0
    state: Literal["running", "success", "waiting_for_input", "stopped", "error", "cancelled"] = "running"
    input_request: RunnerInputRequest | None = Field(default=None, description="Unfinished external-input request, also retained with result and feedback.")
    phase: str = Field(default="initialization", description="Last Controller phase reached, not an inferred guest state.")
    stop_reason: str | None = None
    detail: str | None = None
    artifact_root: str | None = Field(default=None, description="Owned sandbox evidence, including incomplete attempts.")
    feedback_root: str | None = Field(default=None, description="Exact invocation messages, responses, admission and subsequent execution receipts; invocation start alone is not delivery proof.")
    result_path: str | None = None
    cleanup_records: list[dict[str, object]] = Field(default_factory=list, description="Actual cleanup results/errors; empty does not prove cleanup success.")


class RehostingResult(StrictModel):
    launch_resolution: RuntimeLaunchRecord | None = Field(default=None,
        description="Accepted runtime launch derivation, including when a later build or preparation fails.")
    schema_version: Literal[22] = 22
    completion: RunnerCompletion | None = Field(default=None, description="Agent's coverage assessment bound to the latest executed candidate and native or protocol evidence. Startup or scenario success alone does not complete a Runner session.")
    adaptation_history: list[RuntimeAdaptation] = Field(default_factory=list, description="Source-bound runtime derivations and rollbacks, separate from immutable Plan/Generator inputs.")
    target_binary: str
    guest_arch: str
    generation_baseline_id: str | None = None
    generation_baseline_path: str | None = None
    selected_recipe_id: str | None
    input_request: RunnerInputRequest | None = Field(default=None, description="Specific external-input request when the goal is unfinished and waiting for the caller.")
    status: Literal["success", "waiting_for_input", "stopped", "error", "attempts_exhausted"]
    stop_reason: str | None = Field(
        default=None,
        description="Controller stop category, distinct from guest failure and provider errors.",
    )
    session_receipt_path: str | None = Field(default=None, description="Controller budget, terminal phase and cleanup evidence for this invocation.")
    success_configuration_path: str | None = Field(default=None, description="Frozen replayable configuration manifest published by this invocation, never inherited from an older success. Historical v13 results may lack publication.")
    success_definition: Literal["agent_completed_interact"] = "agent_completed_interact"
    specification_gap: str | None = Field(default=None, description="Why no decidable scenario was available; never treated as success.")
    environment_preparation: EnvironmentPreparation = Field(
        default_factory=EnvironmentPreparation,
    )
    attempts: list[RuntimeAttempt] = Field(default_factory=list)
    decision_history: list[RunnerDecision] = Field(
        default_factory=list,
        description="Validated Runner decisions, including bootstrap decisions that produced no attempt.",
    )
    revision_history: list[RunnerRevision] = Field(default_factory=list)
    final_summary: str

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if (self.status == "waiting_for_input") != (self.input_request is not None):
            raise ValueError("waiting_for_input requires input_request; other results must omit it")
        if self.status == "success" and (
            self.completion is None or self.completion.unverified_requirements
        ):
            raise ValueError("Runner success requires an evidence-bound completion with no unverified requirements")
        return self


__all__ = [
    "CompanionProcess",
    "IpcDecision",
    "EnvironmentPreparation",
    "InteractionProbe",
    "InteractionScenario",
    "InteractionStep",
    "ObservationAssertion",
    "ProbeResult",
    "ScenarioResult",
    "ScenarioObservation",
    "ScenarioStepResult",
    "RehostingResult",
    "RuntimeEventContext",
    "RuntimeFunctionSummary",
    "RuntimeImageMapping",
    "RuntimeRecentBlock",
    "RuntimeRegister",
    "RuntimeMemorySnapshot",
    "RuntimeSourceLocation",
    "RuntimeTraceContext",
    "RunnerDecision",
    "RuntimeAttempt",
    "RunnerRevision",
]
