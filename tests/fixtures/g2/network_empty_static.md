# NetworkAnalyzer — empty-fixture

This report accounts for reachable calls that establish, identify, query, or configure network resources. `network` entries describe external network-stack dependencies. `internal_ipc` and `file_resource` are ownership hand-offs; `not_network` is a proven non-network use or target-infeasible API branch; `unresolved` records the exact missing evidence. Each analysis is rooted at one resource anchor. A shared helper callsite may be referenced by more than one analysis.

- Structured source of truth: [`network_analysis_result.json`](network_analysis_result.json)

## Summary

- schema_version: `9`
- phase: `static`
- root_binary: `empty-fixture`
- callsites: 0
- analyses: 0
- analysis_callsite_references: 0
- analyzed_unique_callsites: 0
- shared_callsite_ids: 0
- skipped: 0
- pending_callsite_ids: 0
- disposition `network`: 0
- disposition `internal_ipc`: 0
- disposition `file_resource`: 0
- disposition `not_network`: 0
- disposition `unresolved`: 0

## Analyses

_No full-phase analyses are present._

## skipped

_None._

## pending_callsite_ids

_None._

## finding_target

- finding_target:
  - path: ` "usr/sbin/ntpclient" `
  - sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `

## callsites

- callsites: ` {} `

## covered_api_calls

- covered_api_calls: ` [] `

## planning_findings

`{}`
