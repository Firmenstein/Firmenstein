# Firmenstein intervention contracts

Treat an intervention as a mock of the contract visible to firmware code. Do
not reconstruct unavailable hardware, kernel drivers, daemon internals, or
filesystems when a higher stable API boundary provides the observable behavior.

Emulating missing dependencies and their state is part of rehosting. Keep the
firmware's native service and client workflows responsible for business behavior.
Choose between ordinary environment preparation, native dependencies, intervention
code and backend repair according to the observed mismatch. An intervention is
useful when its behavior advances the service goal; it is not required for a
path the environment already supports.

## Shared contract

An Intervention Unit owns one coherent behavior and its state. Its contract
must describe the caller-visible return values, output parameters, guest-memory
writes, descriptor lifetime, state transitions, input-specific behavior, and
native fallback that matter to the target. Operations that share logical state
belong in the same Unit; independent owners remain separate.

Choose the highest stable owner covering every relevant target-reachable path.
Convenience or path presence does not establish ownership.
Use firmware defaults, caller inputs and explicit emulation assumptions as state
sources when they support the required behavior. Keep cooperating reads, writes
and subsequent operations consistent. Unknown physical measurements and
device-specific facts remain unknown; an emulated value is not an observation
of real hardware. A conservative error, empty wrapper or native fallback alone
does not demonstrate value for the service goal.

Preserve successful native behavior, validation, and unrelated side effects.
Repair the API or resource that triggers a failure rather than `exit`, `_exit`,
`abort`, or an assertion symptom. Do not force an operation to succeed without
also supplying the state or output subsequently consumed by the firmware.

## Service Interact acceptance

Rehosting success is relative to the declared service goal. Final Interact
acceptance requires representative major service operations and continuity of
the state they consume, with caller-visible business results. A listener,
HTTP 200, static page, issued token, or success message alone is insufficient.

Use 3–5 distinct business operations as a starting coverage guideline, chosen
from the service goal and actual firmware UI, routes, or protocol evidence.
Explain how they exercise different handlers, state owners, or state effects.
This is not a minimum request count: repeated static requests do not broaden
coverage, and a smaller service may justify fewer operations. For an HTTP
management service, consider native entry/navigation and required dynamic
resources, device information and distinct configuration categories, a
reversible setting change with independent readback and restoration when writes are in scope,
and subsequent operations that consume the same session or changed state.
Where authentication applies, prove protected access using the issued session
and incorrect-password or missing-session rejection. Logout must revoke the
old session's protected access, and a fresh login must restore protected
access; token issuance alone does not prove either transition. Unauthenticated
and read-only services do not acquire authentication or write requirements.

Keep the caller's service goal stable. Tests and expectations are hypotheses:
Runner may correct mistaken requests, assertions and operation selection based
on native source and actual interaction feedback. Retain each prior test and
failure, and explain the revision. Do not discard required failed behavior or
substitute easy pages merely to finish.
An existing narrow scenario remains a narrow regression baseline; stronger
acceptance needs explicit additional checks and new evidence, without relabeling
archived successes. Document coverage, exclusions, and unverified requirements.
Hardware, WAN, video, and restart persistence are required only when the service
goal includes them. Dynamic UI behavior needs real browser evidence when it is
part of that goal; protocol execution alone does not prove it.

Required scope follows the caller's goal and native service role, not candidate
readiness. Missing configuration, databases, resources or execution capability
are repair obstacles; they do not make required operations out of scope.
Completion needs current execution evidence for the required native operations
and their state continuity. Unsupported or unverified observations stay explicit.

## Evidence and decisions

When an API or tool cannot express a required operation, distinguish that
limitation from the service being impossible to restore. Retain the failed
operation and evidence. Descriptive capability names alone neither establish
support nor justify discarding a candidate.

Analyzer reports and Plan premises can contain errors or hallucinations.
Read-only preserves the source record; it does not certify its interpretation.
Check premises material to the current decision against available code,
assembly, scripts, or runtime evidence. Record supported disagreements without
rewriting original sources. Distinguish an observed fact from a hypothesis;
incomplete evidence can guide a reversible experiment. Formal proof of the
whole dependency chain is not a prerequisite for testing a useful hypothesis.
Use the result to revise the explanation as well as the implementation.

## Binary evidence precedence

Decompiled code interprets the binary, not ground truth.
When missing, contradictory, or ambiguous, inspect the function's
annotated assembly or the binary itself. Prefer assembly for direct
facts such as call targets, branches,
immediates, register/stack arguments, memory accesses, and return/error paths;
cite the `.s` path and instruction address when it resolves a question. The
assembly listing alone does not establish dynamic environment semantics. If
neither representation settles the issue, preserve the uncertainty instead of
inventing a value or behavior.

Source edits, compilation, loading and execution establish different facts.
Check which artifact a run selected, whether loading succeeded, and whether the
relevant behavior ran before attributing a changed result to a repair. Retain
the candidate, failed observations and execution identity. A source hash or a
selected library path alone does not prove an intervention was reached.

Provider, format, reference and execution failures remain visible as operational
failures, distinct from unknown firmware semantics. Preserve candidates with
errors and distinguish a completed authoring turn from successful checks or a
usable service. A failed turn cannot borrow pre-existing files as its own result.
