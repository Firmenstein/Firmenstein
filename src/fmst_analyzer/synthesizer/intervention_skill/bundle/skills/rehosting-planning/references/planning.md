# Intervention Planning

Use this reference when selecting a launch and planning the entire target service. Analyzer evidence is neutral evidence, not a pre-confirmed roadblock.

Apply the shared evidence principles to source claims as well as decompiled
code. A claim is an analysis judgment, not a requirement to reproduce that
judgment. When evidence supports a different conclusion, preserve its source
reference and conditions and explain the disagreement in the decision. Check
only premises material to the selected launch or caller-visible behavior;
neither exhaustive re-analysis nor formal proof is required.

## Rehosting baseline

Firmenstein runs foreign-architecture firmware userspace with QEMU user-mode
inside Docker. Guest system calls use the container Linux kernel and
namespaces; files and libraries come from a writable staged firmware rootfs.

Under the supplied implementation baseline, normal Linux userspace behavior is
an explicit design assumption, not a target runtime observation: memory and process
primitives, System V IPC, descriptors, pipes, loopback, TCP/UDP/Unix sockets,
wildcard bind/listen/accept, low-port binding, ordinary privilege drop,
standard libc conversion, runtime-mounted generic procfs/sysfs, and files
already present in the staged rootfs. Preserve these native paths unless
evidence identifies an incompatible argument, result, or required initial
state. Lack of a runtime observation, or absence of a virtual file from the
static rootfs tree, is not evidence that a baseline capability is missing.

The current Runner does not execute a recipe's `initialization_chain` or
`preparation_actions` automatically. It applies generated rootfs setup and
then starts the selected target. Therefore a file or directory created only by
an unexecuted firmware init script is not present in the baseline unless an
Environment Unit reproduces it.

Do not assume the firmware kernel, modules, hardware, vendor drivers, original
LAN/WAN topology, firmware-specific interfaces, public services, or unlaunched
daemons exist. `/dev`, `/proc`, and `/sys` prefixes alone prove neither
compatibility nor incompatibility.

## Select useful behavior

Define initial Unit behavior in its Contract without hidden future Runner inputs.
Applicability conditions and native fallback belong in the implementation; a
future refinement cannot make an unsafe initial candidate acceptable. Cover the
dependencies and shared state of the required service operations rather than
selecting easier operations to suit a candidate. Put ordinary checks in Contract
verification; reserve `runner_task` for concrete runtime facts or dependencies
that prevent useful behavior, as described below.

Plan only when target-reachable code materially consumes a value, state, or
side effect that the
baseline, staged rootfs, selected launch, and known runtime participants are
unlikely to provide correctly. A checked return, `fatal_exit` consequence,
`expected_absent` resource, or different path literals does not by itself prove
a rehosting mismatch.

Use `no_intervention` when native semantics already satisfy the contract, or
when failure only logs, produces an ignored status, skips optional work, or
continues through a degraded path that still provides the stated service goal.
Process survival while the required protocol interaction is bypassed is not
meaningful success. Do not make every attempted operation report success.
When the service goal is unspecified, state that limitation
and preserve the selected service's material behavior rather than inventing a narrower goal.

Reachability applies to the behavior a Unit changes, not merely its anchor. A
conditional Unit needs credible caller, input, or dispatch evidence for its
selector, command, request, tag, or branch. A reachable function with only
unrelated observed inputs is not enough. Matching scripts, templates, or
configuration can support dynamic dispatch; formal call-graph proof is not
required. Retain a blocking applicability gap as `unresolved`, or use
`no_intervention` for supported dormant or immaterial paths. Do not safety-harden a
purely hypothetical branch.

Target-owned create, rewrite, copy, cleanup, and fallback paths are native
resource lifecycles. Preserve them unless the baseline breaks the path and a
material consumer loses required behavior.

One PlanAgent owns launch selection and all decisions for the fixed Catalog.
Read complete source findings and inspect material premises through rootfs,
scripts, archives, selected argv, callers, code and assembly. The initial index
organizes evidence; it does not contain every conditional behavior.

Merge findings into a Unit when they share a semantic provider and compatible
state, lifecycle and guarantees. Independent owners remain separate. Mechanical
anchor overlap is a hint for review; it does not establish equivalence.
A claim has one current owner even when several Analyzer findings describe it.
The Agent may revise earlier decisions in later batches. Framework progress is
computed from the accepted draft and does not prove semantic correctness.

Do not use an unexecuted chain as evidence for `no_intervention`. Check the
actual staged rootfs and the selected command's required paths. If the chain
would create a missing artifact, use `environment_setup` only when its exact
source/content and reproduction are known. Missing preparation that prevents
a justified decision remains `unresolved`.

Trace state required by the selected interaction to its producer and first
material consumer, including consumers reached only after a request arrives.
A bundled default accessor may supply later reads while an earlier initializer
still rejects an absent device image. Check both boundaries and their shared
state, including interface/address gates before listener creation. The original
device image is not itself required when target-side owners can provide all
material state and outputs from packaged sources under explicit conditions.
Do not infer that bypassing an initializer is sufficient from its return check:
inspect downstream pointers, tables, locks and accessors. Keep any unprovided
material effect unresolved and retain native behavior outside the replacement.
When several owners jointly supply the behavior, their initial Contracts must
identify the producer, initialization order and consumed values; no hidden
Runner result completes that dependency.

Encoded or compressed packaged data need not be decoded by the Planner to be
usable. The firmware's native decoder, parser and initializer can be a concrete
state producer when their inputs, dependencies and calling context are
supported by source evidence. Missing plaintext or an Analyzer's unidentified
original peer is not proof that this producer is unavailable. Assess whether a
bounded invocation can initialize the required state without launching an
entire daemon chain or duplicating listeners. Preserve existing state and the
native conditions that choose a packaged fallback. Runtime must still verify
the proposed path; do not assert a native call succeeded from source alone.

Evaluate missing-state replacements across the cooperating Units and required
request path. An error that avoids a startup crash may also force every client
into a rejected class or leave an authorization prerequisite absent. That is a
blocking dependency, not harmless degradation. Supply its source-backed state
or retain the precise unresolved consumer; do not change the native decision
or acceptance scenario merely to make a response pass.

## Choose an outcome

Every source claim must appear in an applicable behavior scope owned by a
Unit, closed by `no_intervention`, or retained as an explicit `unresolved`
decision. A `runner_task` never closes a claim by itself. A Runner task may complement a
Unit; a single conditional behavior cannot be both implemented and closed or
unresolved. Different claims in the same finding may receive different
decisions. This accounting preserves the questions and their conditions; it
does not endorse every claim. Unknown instance data alone is not a semantic or
capability gap.

Assess material overlaps when they affect ownership or guarantees. Shared
source evidence alone does not require a pairwise checklist. Equivalent behavior
has one shared owner; concrete intervention anchors cannot have competing Units. Explain the source conditions for distinct contexts and shared-state
effects in the affected Unit or decision. A blocking conflict remains an
`unresolved` decision; no separate relationship output is required. No array,
ID or pointer check proves these semantic claims.

- A Unit is a concrete, generatable hypothesis. Prefer the smallest useful
  mechanism when three conditions hold: a credible target-reachable boundary,
  at least one material behavior missing from the baseline, and justified
  bounded handling of unknown portions. Unknown instance data alone need not
  discard that mechanism. Its initial Contract must already be useful without
  future Runner inputs; error, EOF or native fallback alone does not establish
  value. Record the evidence or falsifiable assumption for that value. Put
  ordinary tests, traces and observations in `contract.verification`; permit
  bounded implementation refinement without requiring perfect initial answers.
- A `runner_task` is reserved for a specific missing runtime fact or dependency
  that prevents defining useful behavior from available evidence. Explain why
  source inspection and a Unit cannot supply it now, the concrete action or fact
  to recover, completion evidence and the decision its result would change.
  It is not a parking place for ordinary uncertainty, duplicate verification,
  or routine refinement. A task may accompany an independent useful Unit but
  does not resolve a blocking gap. Prefer no task when the existing Contract
  and normal Runner feedback already cover the uncertainty.
- `no_intervention` closes behavior already supplied by the baseline or
  immaterial to useful target execution, including a refuted claim that leaves
  no intervention need. Record the basis, not a generic dismissal.
- `unresolved` records the affected claims and owning boundary when missing or
  contradictory evidence prevents a justified decision. Preserve the specific
  conflict; do not substitute a speculative Unit or ordinary Runner task.

Use `environment_setup` for static rootfs state that can be supplied safely and
idempotently: known directories or contents, existing copy/move sources,
symlinks, modes, or stale-path removal. Firmware scripts and archives are
factual sources. When live persistent state is unavailable but a packaged
factory/default artifact is exactly what the selected launch consumes, use
that artifact under its source-proven initialization or fallback conditions.
Preserve existing persistent state and the conditions that select defaults.
Do not invent missing device-unique, credential, calibration, or other
security-sensitive values, or assume a packaged value applies merely because
it exists.
Do not create empty or guessed content for a parsed file.

`environment_setup` is only a pre-import filesystem transformation. Its
resource anchors must be `path` or `path_pattern`; it must not start a process,
peer, daemon, socket, FIFO, or network endpoint, and it must not change live
hostname/interface state. A missing daemon or socket is not by itself a missing semantic fact.
Assess whether a higher target-side API can supply the required state and
outputs from available sources without reproducing the peer or its transport.
A live dependency justifies a `runner_task` when a material effect or unknown
input cannot be supplied by such a Unit; identify that specific gap. Preserve
unprovided effects and native behavior outside the Unit's scope. Do not
convert live actions into static Units to reduce the task count.

Use `function_stub` when one function or coupled family owns the complete
target-visible contract and all relevant paths pass through it. Include raw
bypasses or choose another owner. Preserve returns, output memory, pointer
lifetime, caller-visible globals, shared state, retained native calls, and
side effects.

Use `pseudo_file` when an exact path and descriptor state own the required
runtime behavior, or raw file APIs bypass a complete wrapper. The directory
name does not determine whether a path can be bound. Prefer ordinary files
and static preparation when they provide the required configuration, data,
pid, lock, certificate, or key behavior. Pseudo-file ownership is path-wide,
so its behavior must be safe
for every target-reachable open of the anchored path. Define required bytes,
geometry, status and ioctl outputs from evidence or explicit bounded
assumptions. Error, EOF or native fallback for an unknown portion is useful
only if the resulting caller behavior advances the service goal. Apply the
same Unit and RunnerTask criteria above; the device path itself does not
justify either. Never turn an empty, down, invalid-marker, or guessed payload
into an asserted success.

Use `callsite_hook` only when one exact callsite has a local, stateless return
or output contract. Preserve native behavior outside the matched inputs.

External hardware, driver, network, or peer effects cannot be implemented by
returning success while omitting the effect. A success token such as a non-null
pointer, descriptor, or zero return is insufficient unless the Unit supplies
the associated object or payload consumed downstream. A safe unavailable
response can be useful when it enables a source-supported fallback needed by
the service; merely postponing all useful behavior to Runner is insufficient.
Prefer a higher target-side API when it can reproduce everything material
that callers observe. Otherwise preserve the specific unresolved effect.

Unknown operational state must not default to `up`, `ready`, `connected`, or
`enabled` merely because empty input or a parser quirk produces that result.
Use evidence-backed state or a stated, reversible hypothesis; a material
unknown that defeats useful behavior stays unresolved. A process-local peer substitute is valid only
when it covers the complete target-visible request/response contract and the
omitted peer has no material external hardware or network effect.

An empty file or permissive parser does not establish meaningful configuration.
Do not make parsers permissive to reconstruct unknown contents; use a packaged
artifact or an evidence-backed minimal configuration. Blocking content gaps
remain `unresolved`.

## Separate mechanism from instance data

New descriptors, input lengths, EOF, cache state, mutable key-value state, and
conventional missing-value behavior are runtime-determined values a Unit can
generate. Exact firmware bytes are not always required when evidence-backed
defaults form a safe, reversible hypothesis.

A future Runner result is not an implicit Unit input. If useful behavior needs
an exact image, address, credential, identity, calibration value, or protocol
payload that Plan does not contain, the Unit must not claim that value. It may
still provide an independently useful mechanism with bounded assumptions and
verification. Judge that usefulness by the downstream consumer, not by the
presence of allocation, length checking, EOF/error or fallback alone. Never substitute arbitrary
zero, erased `0xFF`, sample, credential, fixed status, or protocol contents as
if they were firmware facts merely to make tests pass.

## Minimum mock contract

Write each `contract.operations` item as one independently testable guarantee.
The structured Contract is required; older list-only plans are rejected. The
Contract must describe:

- applicability: path, function, exact callsite, arguments, or inputs;
- returns, errors, output parameters, and guest-memory writes;
- descriptor, buffer, cache, object, and shared-state lifecycle;
- preserved native fallback and unrelated behavior;
- the evidence or explicit falsifiable assumption behind caller-visible
  values. Never disguise an arbitrary value as firmware fact.

When a Unit crosses an ABI boundary, record the exact IIB operations and the
ABI source of every byte: logical scalar argument, core ABI word slot, guest
pointer, stack offset, or return register class. Use the selected GuestWeave ABI reference supplied with the task. A struct-by-value claim without a slot
layout or a hidden-sret pointer explanation is incomplete; do not leave the
Generator to infer it from a Rust type. Any capability metadata is descriptive
runtime context, not a separate generation approval gate.

For native calls, distinguish ELF link-time addresses, relocated guest addresses
and library offsets. Read the selected runtime's resolver implementation and
the callee's entry sequence; knowing a function EA does not establish that the
runtime can call it in the hook's current context. State the required operation,
arguments and effects, and permit equivalent source-backed wrappers or import
trampolines when they preserve the same resource, state and ABI semantics.
Do not require an unverified callee spelling as the only way to fulfill the
Contract. Runtime address checks and bounded implementation refinement belong
in verification; an operation the public API cannot express remains explicit.

For `environment_setup`, identify the final path, authoritative content or
copy/move source when content matters, timing, type or permissions, and
existing-destination behavior. If code parses the file, recover coherent
minimal contents from its parser, defaults, scripts, or rootfs; otherwise retain
a blocking content gap as `unresolved`.

For `pseudo_file`, define behavior for every target-reachable open of the exact
path: required operations, modes,
returns and errors, output-buffer layout, offsets, initial state, and shared
state. Check required operations against the supplied public API sources;
a capability name or a guest syscall does not prove that an owned virtual
descriptor supports it. If the API cannot express a material operation,
record the exact operation gap and preserve it for implementation or runtime
feedback; do not turn it into a separate capability verdict.
Do not invent unused operations, error codes, or a full driver.

For `function_stub`, cover applicable inputs and callers, returns, output
pointers, globals, lifetimes, shared state, retained native calls, and side
effects. For `callsite_hook`, cover the exact site, matched inputs, changed
return or output, lack of shared state, and native fallthrough.

Provider, structured-output, identity, or Controller failures are stage
failures, not Runner tasks.

## Representative examples

- `socket(AF_INET) -> bind(0.0.0.0:80) -> listen -> accept`, ordinary System V
  IPC, `/dev/null`, and generic procfs are native unless evidence shows a
  firmware-specific contract or required external initial state.
- Complete `nvram_get`/`nvram_set`/`nvram_commit` coverage uses one
  `function_stub` with shared key-value state. Raw `/dev/nvram` access without
  that owner uses `pseudo_file`; `mknod` is not driver emulation.
- A device Unit needs supported operations and useful initial data or behavior.
  Optional export or diagnostic failures use `no_intervention`.
- A known ordinary configuration uses `environment_setup`; unknown parsed
  contents require recovery rather than an empty placeholder.
- Native `gethostname` used only for logging needs no intervention; a required
  external identity value unavailable from sources can justify runtime recovery.
- One independent stateless `ioctl` output may use `callsite_hook`.
- A required bundled peer with no useful API substitute can justify a Runner
  task to establish the missing live dependency. An empty socket or forced
  `connect` success is not a protocol implementation.
- An ignored LED-control failure uses `no_intervention`; a successful no-op
  pseudo-file adds no caller-visible value.
