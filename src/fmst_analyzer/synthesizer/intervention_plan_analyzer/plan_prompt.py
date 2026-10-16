"""Task contract for one target's global, revisable planning authority."""

PLAN_TASK_PROMPT = """\
<goal>
Apply the attached rehosting-planning Skill and its planning reference.
Use the selected GuestWeave Skill/references for mechanism and API semantics.
Produce one evidence-backed Plan for the selected target and service goal.
You own launch selection, native decisions, intervention boundaries and shared
state across the entire fixed Catalog. Save and revise coherent batches in
the same draft; batches do not divide semantic ownership.
</goal>

<criteria>
Account for every source claim under its material original conditions. Read
the complete finding and evidence needed for a decision; an index summary is
not enough to settle conditional behavior. Analyzer records are fallible.
Check material premises, preserve source references and explain disagreements;
do not repeat exhaustive analysis or seek formal proof of every detail.

Select an existing launch candidate suitable for the required service behavior
under the supplied baseline. An unproved original boot chain does not by itself
block a supported direct invocation. Required arguments, preparation, mode and
side effects still need evidence. Do not invent a new command or missing values.
Reconsider launch and affected decisions when evidence warrants it.

Prefer a minimum Unit when a credible target-reachable boundary can provide
useful behavior missing from the baseline and unknown portions have a justified
bounded response. Missing exact instance data need not discard a useful
mechanism; an error, EOF, native delegation or empty wrapper is not useful merely
because it is conservative. Success requires the state and outputs callers use.
Preserve successful native paths and choose one stable, semantically complete
owner for shared behavior and state. Shared source anchors are only hints;
explain material merging or ownership distinctions in the affected Unit or
decision, without a separate pairwise checklist.
Read the selected GuestWeave ABI reference for ABI-sensitive
contracts; do not leave required layouts for the Generator to guess.

No-intervention needs evidence of native satisfaction, failure immaterial to
the service goal, or a refuted claim with no remaining intervention need.
Process survival with the required interaction bypassed is not an acceptable
degradation. Baseline API support does not establish live vendor peers or state.
The Runner does not automatically execute firmware initialization chains;
reproducible static preparation belongs in environment Units.

Assess the selected service interaction as a dependency closure, from startup
through request handling: each material state consumer needs an available
producer before its first use. A working replacement for a later
accessor does not remove an earlier initializer or topology gate automatically.
When an initializer's original backing store is unavailable, inspect what its
callers and subsequent consumers actually require. Coordinated target-side
owners may supply the useful behavior without reconstructing unconsumed device
state; a success return alone cannot stand in for required state or outputs.
Preserve native validation and authentication, and make the candidate's initial
state and dependency assumptions explicit.

An encoded packaged configuration is usable evidence when the firmware's own
decoder and initializer can produce the required state. Missing plaintext or
an unidentified original peer does not establish that the state is unavailable.
Consider source-backed native initialization with its dependencies and caller
context before replacing accessors with permanent missing-state answers.
Check those answers against request classification, authorization and other
material consumers; keeping the listener alive does not satisfy the service.

For required native calls, check the selected runtime's address resolution and
the callee's ABI and caller context. Define the required guest-visible effects
and proven callable boundary. Allow equivalent source-backed wrappers or
import trampolines when they preserve those effects, rather than fixing an
unverified address spelling or one implementation sequence as the Contract.

Ordinary testing, trace collection and refinement belong in Contract verification
and the Runner's normal work, not separate Runner tasks. Reserve a Runner task
for a specific missing runtime fact or dependency that prevents defining useful
behavior from the available evidence. Explain why a Unit cannot supply it now,
what observation would resolve it and which decision would change. Tasks are
not behavior owners or completed dependencies. A Unit's initial contract must
already define useful behavior without hidden future inputs.
Check material runtime operations against the supplied public API sources;
capability names alone do not define an operation or prove it is supported.
Keep a precise unresolved decision when missing semantics, launch applicability
or capability prevents a justified decision. Tool/provider failures and omitted
claims are execution failures or unfinished work, not semantic unknowns.
</criteria>

<evidence_boundary>
Use the supplied rootfs, source records, implementation baseline, decompiled
code and assembly as read-only evidence. Do not execute or source firmware
files, generate implementation code, or edit the draft through the filesystem.
Only draft tools publish decisions. Preserve uncertainty about unobserved
device state and distinguish a falsifiable hypothesis from a firmware fact.
</evidence_boundary>

<termination>
Finish after the draft contains an assessed launch, a current decision for
every source claim, coherent intervention ownership, and no pending review
after launch changes. Explicit unresolved decisions complete accounting without
resolving the affected dependencies. Generation may still implement defined
Units; that does not establish runtime readiness for the service. Report the
accepted revision, not a rewritten copy of the Plan. If a batch is rejected,
correct its reported issue while preserving
accepted work. Never invent closure just to reach full coverage.
</termination>
"""
