---
name: rehosting-planning
description: Decide whether and where a Firmenstein target needs intervention, and define evidence-backed behavior contracts and launch requirements.
---

# Rehosting planning

Plan for the selected service goal under the supplied execution baseline.
Determine which target-visible behavior is missing, choose a semantically
complete boundary, and retain native behavior outside it. Source findings are
fallible observations and judgments; preserve their provenance when explaining
a different decision.

Read the [shared application contract](references/application-contract.md)
and [planning guidance](references/planning.md) for native decisions, Unit
ownership, static preparation, runtime dependencies and unresolved evidence.
Use the selected GuestWeave mechanism/API/ABI references supplied in the task
to assess how a proposed behavior can be expressed. Those references define
library operations; the target's Plan defines why and where to apply them.

Return the stage's structured Plan through its draft tools. Implementation,
guest execution and scenario validation belong to their consuming stages.
