# Legacy Runtime Refinement

Use this reference for the legacy Runner's bootstrap and runtime refinement.
Its Controller admission and session protocol apply to that backend only.
The autonomous container Runner receives its own task guide and permissions.
Use [candidate engineering](candidate-engineering.md) for the shared crate layout.
For a web UI, bootstrap selects a concrete launch and browser_origin without probe/scenario;
implementation refinement requires evidence from a subsequent failure.

Apply the shared application contract's Service Interact acceptance standard.
Explain operation selection, distinct backend/state coverage, continuity, and
unverified requirements as native interaction proceeds. Observe actual business
results, protected access, and independent write/readback. An issued cookie or
success message is not sufficient. Native browser tools execute the original page JavaScript and client workflows;
protocol scenarios are revisable diagnostic/regression checks. Correct erroneous
requests, assertions or operation selection with a reason, retaining previous
versions and failures. The caller's service goal remains stable.

Every runtime result and browser failure returns to the same Agent. Runner owns
native interaction and completion; the executor manages build, instances, budgets and
evidence identity. Before completing a UI service, verify actual entry and
representative operations in a fresh native service/browser instance. Repair or
correct mistaken interaction choices after failure, then verify again. Bind completion to the current
unchanged candidate and client receipt, with coverage and honest limitations.
Required scope is derived from the caller's service goal, native service role
and shared acceptance contract. An absent database, resource or executor is a
repair obstacle or required gap, not by itself a scope exclusion. Do not move
required failed/unverified operations into completion limitations and declare
the required goal covered.

The current Runner starts with every generated execution Unit enabled after
the current candidate compiles. There is no mandatory generated self-test or
protocol-test phase before native interaction. Failed Generator
candidates are repair inputs, never evidence of readiness. It does not treat
`runner_task` entries as pre-approved commands. RunnerAgent receives them as
runtime objectives and decides whether a concrete peer, rootfs action, probe,
or existing Unit refinement is justified. Do not claim that a task has been
completed until the Controller records the corresponding runtime evidence.
There is no hidden plan-time activation guard: applicability and native fallback
belong in each Unit's implementation before the first execution. Provider or
generation errors are operational failures, not new semantic Runner tasks.

- Map an observed failure to the selected launch, Unit anchor, mock contract,
  preserved native behavior, or a missing semantic owner before changing code.
- Preserve successful native behavior and state already validated by earlier
  runs. Do not force exit, connect, bind, read, or write to succeed without
  supplying the caller-visible state subsequently consumed.
- Refine an existing Unit only when runtime evidence identifies an error in its
  implementation within `allowed_refinement_scope`. If the Contract guarantees
  must change or the owner is absent from the Plan, submit a source-bound
  `propose_unit` without editing files. Current runtime or partial execution evidence,
  exact anchors, caller-visible guarantees, state sources and retained native
  behavior must support it. Admission is a separate runtime derivation; it
  neither rewrites Catalog claims nor proves the proposed semantics. Implement
  and exercise the admitted owner in the same session. Logical service state can
  come from firmware defaults, caller inputs or explicit emulation assumptions;
  preserve its consistency and write/readback behavior. Unknown physical bytes
  or measurements remain unknown. Missing hardware does not require its exact
  reconstruction when a higher API can provide the required service behavior.
  Native browser and partial execution evidence support runtime derivations.
- Use disposable-rootfs actions only for evidence-backed ordinary directories,
  files, and symlinks. Device semantics, IPC peers, and live network services
  are not placeholder filesystem content.
- A concrete bundled peer may run as a companion process only when its ELF,
  argv, working directory, environment, and required protocol role are
  supported by evidence.
- Native socket creation and listener setup remain the default. Diagnose early
  startup return and actual socket/bind/listen results before concluding that
  network virtualization is missing.
- Prefer the smallest change to the semantic owner that explains the runtime
  evidence. Do not expand one input-specific correction into an unconditional
  replacement because of a single failed run.
- Record the previous behavior, runtime evidence, and exact implementation change within the existing Contract so
  refinement remains auditable.

The rehosting goal stays active across replies, failures and diagnoses. Carry out
useful investigations and repair experiments in this same session. Request a
specific external input only when it cannot be obtained through the available
environment, retaining the unfinished goal, candidate and evidence. The executor
handles resource limits and interruptions. Do not broaden the mock speculatively.

Use the deterministic attempt facts to compare expected/actual step assertions,
verified Cookie continuity, input changes and child-failure receipts. Cookie
transport does not establish authentication and input deltas do not prove guest
state contents. For diagnostic retries, record a focused experiment with the
hypothesis, supporting evidence, changed variable, predicted observations and
preserved behavior. Read original evidence when the bounded view is insufficient.

The latest active admission ID binds each new proposal. Explicit rollback
restores the entire disposable workspace and ownership definitions immediately
before that admission, including subsequent edits, while retaining the audit
history. Recheck cumulative launch/rootfs/disabled-Unit settings after rollback.
Build and real native interaction or the selected protocol regression are required again; no prior
success is inherited by a derived Contract or a restored candidate.
