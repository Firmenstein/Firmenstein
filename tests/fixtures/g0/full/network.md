# NetworkAnalyzer — httpd

This report accounts for reachable calls that establish, identify, query, or configure network resources. `network` entries describe external network-stack dependencies. `internal_ipc` and `file_resource` are ownership hand-offs; `not_network` is a proven non-network use or target-infeasible API branch; `unresolved` records the exact missing evidence. Each analysis is rooted at one resource anchor. A shared helper callsite may be referenced by more than one analysis.

- Structured source of truth: [`network_analysis_result.json`](network_analysis_result.json)

## Summary

- schema_version: `8`
- phase: `full`
- root_binary: `httpd`
- callsites: 1
- analyses: 1
- analysis_callsite_references: 1
- analyzed_unique_callsites: 1
- shared_callsite_ids: 0
- skipped: 0
- pending_callsite_ids: 0
- disposition `network`: 1
- disposition `internal_ipc`: 0
- disposition `file_resource`: 0
- disposition `not_network`: 0
- disposition `unresolved`: 0

## Analyses

| disposition | interaction_kind | anchor_callsite_id | code_locations | identity | callsites | report | interaction_id |
|---|---|---|---|---|---:|---|---|
| `network` | `listener` | `network-callsite` | `httpd::serve` | family=AF_INET, type=SOCK_STREAM, protocol=TCP, local=0.0.0.0, local_port=80, resolution=exact | 1 | [md](listener__network-listener.md) / [json](listener__network-listener.json) | `network-listener` |

## Analysis details

### listener — httpd::serve

- interaction_id: `network-listener`
- anchor_callsite_id: `network-callsite`
- disposition: `network`
- interaction_kind: `listener`
- summary: httpd creates a TCP listener on port 80.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `httpd::serve:L30` | `bind` | `bind(fd, addr, 16)` | `network-callsite` |

#### missing_evidence

_None._


## skipped

_None._

## pending_callsite_ids

_None._
