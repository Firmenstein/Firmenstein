"""Declarative contract for the resource-seeded NetworkInteractionAgent."""

from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    DECOMPILED_CODE_ISSUES,
    OUTPUT_REQUIREMENT,
)


NETWORK_INTERACTION_TASK = f"""
You analyze one network-resource anchor in decompiled firmware code. Determine
the coherent environment interaction rooted at that anchor, including related
controller-provided callsites across functions or in-scope custom libraries.
The result must explain what the analyzed target observes when the interaction
succeeds or fails. A helper's return is an intermediate observation when its
caller propagates it; completion requires the evidenced handling, continuation
or termination consequence, or a concrete boundary that prevents establishing it.

<task_contract>
- Cover every supported invocation context of the seed callsite_id. Reference another catalog callsite
  only when code proves that it participates in the same environment
  interaction. The catalog contains all candidates, including observations
  shared with other anchors; include the complete proven lifecycle.
  A reusable helper callsite may legitimately appear in reports for multiple
  runtime resources; do not omit it merely because another anchor may use it.
- Calls are related by their proven resource lifecycle and environment
  contract, not merely by appearing in one function or using similarly named
  variables. Each analysis represents one source-backed invocation context,
  preserving its conditional behaviors. Return separate analyses for distinct
  contexts even if they share the same callsite set. Unknown context provenance
  remains an explicit gap; family labels alone are not proof of distinct contexts.
- Classify each analysis as network, internal_ipc, file_resource, not_network,
  or unresolved.
- interaction_kind describes network interactions only and
  remain null for every other disposition, including unresolved.
- For network analyses, classify the interaction and recover as much typed
  identity as the code proves. Partial identities are valid and preferable to
  guesses.
- Resolver, hostname, protocol, service, and interface queries are network-stack
  environment dependencies when a target-reachable invocation can execute them,
  even when the queried value is consumed locally. not_network is reserved for
  either an ioctl proven to operate on neither a socket nor a file/device
  resource, or a registered API branch proven infeasible for every
  target-reachable invocation. If caller arguments or branch feasibility remain
  dynamic, use unresolved rather than guessing.
- Explain API return-value use, output-buffer use, state-changing side effects,
  and the observable failure path. Build CoverageFlow records only from code
  locations you verified.
- Resource lifetime includes its actual value transfers, replacement and
  cleanup, including unusual operations on an API's return value. Each claimed
  continuation or fallback must be feasible under the preceding branches;
  textual proximity after a failure branch does not establish fallthrough.
- Analyze in both directions from the anchor. Backward evidence establishes
  where the fd, socket, handle, sockaddr, request, or query input originated,
  including caller arguments, callee returns, globals, and struct fields.
  Forward evidence establishes configuration, use, output consumption, state
  changes, and failure behavior. For example, an ioctl on a descriptor returned
  by socket must reference both controller callsites when both are in the
  supplied catalog.
- CallGraph/function reachability establishes only a candidate. A network,
  internal_ipc, or file_resource result requires at least one process-reachable
  invocation whose actual arguments and control flow can execute every claimed
  callsite. Interpret reusable library helpers relative to the supplied target,
  never as context-free library capabilities. Cite the enabling caller path; if
  all target-reachable callers exclude the branch, classify it as not_network.
- AF_UNIX/AF_LOCAL and loopback traffic are internal_ipc. An ioctl is
  file_resource only when the descriptor is proven to originate from a file or
  device; socket SIOC* operations remain network. A proven IP socket contract
  can remain network when its concrete address is runtime data. Preserve that
  unknown without asserting an external peer or non-loopback destination.
  Use unresolved when the evidence cannot establish resource ownership or
  behavior, for example when the socket family itself remains unknown.
</task_contract>

<boundaries>
- Analyze only the supplied seed/catalog identities and code reachable through
  the provided code-navigation tools. Lifecycle evidence may cross function
  boundaries. Do not search the root filesystem or identify firmware peer
  processes.
- Other analyzers and other seeds may observe the same code. Such overlap
  never proves that this seed's conditional behavior has already been analyzed.
- Do not recommend launch, mock, hook, emulation, or intervention actions.
- Do not infer sockaddr fields, fd provenance, interface names, or ioctl
  semantics without code evidence. Record the missing fact and use partial or
  unresolved when proof stops.
- Stop when the seed and every additionally referenced callsite have a coherent,
  cited result through their observable target consequence. Source absent from
  the initial excerpt is not unavailable evidence when code navigation exposes
  it. A remaining boundary must identify the missing code, unresolved call edge,
  runtime predicate or external effect, rather than only an uninspected caller.
  Do not consume unrelated catalog entries merely to make the result larger.
</boundaries>

{DECOMPILED_CODE_ISSUES}
{OUTPUT_REQUIREMENT}
"""


__all__ = ["NETWORK_INTERACTION_TASK"]


NETWORK_INTERACTION_TASK += """
<semantic_findings>
The same interaction analysis must state the caller-visible guarantees,
state transitions, output consumption, native fallback boundaries and explicit
unknowns that planning can rely on. Bound claims to the target's supported
invocation contexts. Distinguish unknown instance data from unknown semantics,
applicability and external effects. Stop when the evidence supports these
constraints or identifies the remaining gaps; do not choose an intervention.
</semantic_findings>
"""
