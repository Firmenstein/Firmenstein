# listener — httpd::serve

- interaction_id: `network-listener`
- anchor_callsite_id: `network-callsite`
- disposition: `network`
- interaction_kind: `listener`
- callsite_ids: see the 1 entries under `callsites`

## summary

httpd creates a TCP listener on port 80.

## identity

- resolution: `exact`
- family: `AF_INET`
- socket_type: `SOCK_STREAM`
- protocol: `TCP`
- local_address: `0.0.0.0`
- local_port: `80`
- remote_address: null
- remote_port: null
- hostname: null
- service: null
- interface: null
- operation: null
- netlink_protocol: null

## contract

- expectation: `expected_absent`
- violation_effect: `fatal_exit`

## callsites

| location | api_name | expression_text | return_expression | callsite_id |
|---|---|---|---|---|
| `httpd::serve:L30` | `bind` | `bind(fd, addr, 16)` | `—` | `network-callsite` |

### callsites.network-callsite

- callsite_id: `network-callsite`
- location:
  - binary_name: `httpd`
  - binary_path: `usr/sbin/httpd`
  - binary_sha256: `1111111111111111111111111111111111111111111111111111111111111111`
  - function_name: `serve`
  - function_ea: `0x1100`
  - snapshot_hash: `network-snapshot`
  - ctree_index: `4`
  - source_ea: `0x1120`
  - line_number: `30`
  - column_number: `6`
- api_name: `bind`
- api_family: `socket_endpoint`
- api_binding:
  - symbol: `bind`
  - call_kind: `direct`
  - verified: `true`
- expression_text: `bind(fd, addr, 16)`
- arguments:
  - (none)
- return_expression: null

## api_effects

_None recorded._

## coverage_flows

_None recorded._

## evidence

_None recorded._

## missing_evidence

_None._
