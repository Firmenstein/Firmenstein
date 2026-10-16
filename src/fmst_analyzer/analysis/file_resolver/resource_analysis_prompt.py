"""Declarative contracts for whole-resource analysis and bounded map/reduce."""

_BEHAVIOR = """
<criteria>
Describe the caller-visible behavior under each supported invocation condition.
Preserve distinct source contexts and per-callsite outcomes; one fatal path does
not make every use fatal, and one tolerant caller does not prove target survival.
A library return, a request failure, a child exit, the daemon parent's normal
exit and termination of the target service are different effects. Main returning
terminates its process even without an explicit exit API.

API results include return values, errno, output-buffer mutation, object/global
state and descriptor lifetime. Preserve actual argument and value provenance,
including unusual code: a scalar success result passed to close is not a saved
descriptor. Initialization of memory before a failed read can determine the
observed state. Do not replace such behavior with conventional API usage.
Byte offsets and numerical result mappings must follow the actual address and
integer expressions. Decompiled stack locals may be separate names for parts
of one request buffer; declaration order is not field layout. Boolean arithmetic
must retain its numerical result, not an assumed success/error convention.
When a memory address escapes to an API, pre-call initialization of a nearby
local does not establish its post-call value. Whether that local belongs to the
passed object depends on actual storage offsets and access widths.

Known claims require source-backed support and complete applicability conditions.
An exact code locator proves location, not the truth of an interpretation.
Unknown device instance data does not erase known behavior or output constraints.
Preserve precise gaps in caller propagation, feasibility and external effects.
Coverage observations never assign semantic ownership to an analyzer.
</criteria>
<boundary>
Describe firmware behavior; intervention strategy and implementation belong to
planning. Preserve every supplied creating callsite and every supported distinct
use. Source reachability supplied by the Controller is authoritative data; it
does not establish branch feasibility or complete error propagation by itself.
</boundary>
<termination>
Stop when the subject's effects and conditions have supporting evidence or a
specific remaining gap. Continue relevant caller/state tracing as needed for that
judgment; unrelated fan-out and exhaustive firmware exploration are outside scope.
</termination>
"""

FILE_RESOURCE_FULL_REPORT_TASK = """
<goal>
Analyze this exact filesystem resource across its supplied creating callsites.
Produce per-callsite behavior and one coherent finding retaining their conditional
requirements, state, native fallback and explicit unknowns.
</goal>
""" + _BEHAVIOR

FILE_RESOURCE_MAP_TASK = """
<goal>
Analyze the supplied chunk of creating callsites for this exact filesystem
resource. The complete per-callsite records will be consumed without replacement
by a resource-level analysis. Preserve each operation's inputs, output use,
conditions, lifecycle and source coordinates.
</goal>
""" + _BEHAVIOR

FILE_RESOURCE_REDUCE_TASK = """
<goal>
Describe this resource's conditional semantics from the complete supplied
per-callsite reports and Controller reachability evidence.
</goal>
<input_boundary>
The map reports are observations, not automatically proven semantic truth.
Do not resolve conflicts by majority, choose a dominant outcome, invent missing
caller behavior or remove conflicting records. Preserve supported differences
with their conditions; unresolvable conflicts become precise semantic gaps.
You have no code tools. The original callsite records are attached unchanged
to the final report; cite their exact positions rather than regenerating them.
</input_boundary>
""" + _BEHAVIOR

FILE_RESOURCE_FULL_REPORT_USER = """\
Analyze this resource using the supplied source callsites.
resource_group_id: {resource_group_id}
primary_path: {primary_path}
resource_class: {resource_class}

Creating callsites ({n_callsites} total):
{open_callsites_bullets}
"""

FILE_RESOURCE_MAP_USER = FILE_RESOURCE_FULL_REPORT_USER

FILE_RESOURCE_REDUCE_USER = """\
Analyze the conditional resource semantics from these complete records.
resource_group_id: {resource_group_id}
primary_path: {primary_path}
resource_class: {resource_class}

callsite_reports ({n_reports} total):
{callsite_reports_json}
"""
