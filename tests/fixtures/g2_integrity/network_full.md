# NetworkAnalyzer — ntpclient

This report accounts for reachable calls that establish, identify, query, or configure network resources. `network` entries describe external network-stack dependencies. `internal_ipc` and `file_resource` describe domain observations; `not_network` is a proven non-network use or target-infeasible API branch; `unresolved` records the exact missing evidence. Each analysis is rooted at one resource anchor. A shared helper callsite may be referenced by more than one analysis.

- Structured source of truth: [`network_analysis_result.json`](network_analysis_result.json)

## Summary

- schema_version: `11`
- phase: `full`
- root_binary: `ntpclient`
- callsites: 9
- analyses: 3
- analysis_callsite_references: 10
- analyzed_unique_callsites: 9
- shared_callsite_ids: 1
- pending_callsite_ids: 0
- disposition `network`: 2
- disposition `internal_ipc`: 0
- disposition `file_resource`: 0
- disposition `not_network`: 0
- disposition `unresolved`: 1

## Analyses

| disposition | interaction_kind | anchor_callsite_id | code_locations | identity | callsites | report | interaction_id |
|---|---|---|---|---|---:|---|---|
| `network` | `listener` | `network-cs:e9787221d8daea4979557966` | `ntpclient::main`<br>`ntpclient::setup_receive` | family=AF_INET (2) or AF_INET6 (10), selected from getaddrinfo output, socket_type=Numeric argument 1; semantic socket type unresolved, protocol=Numeric argument 17 (IPPROTO_UDP), local_address=0.0.0.0 for IPv4 or :: for IPv6, resolution=partial | 5 | [md](listener__0fa5c89fbd7ca2491c821208.md) / [json](listener__0fa5c89fbd7ca2491c821208.json) | `network:0fa5c89fbd7ca2491c821208` |
| `network` | `outbound_connection` | `network-cs:a8dd2b3fb261fbd1ee505766` | `ntpclient::setup_transmit`<br>`ntpclient::stuff_net_addr`<br>`ntpclient::stuff_net_addr6` | family=AF_INET when the selected getaddrinfo result has family 2; otherwise setup_transmit constructs AF_INET6, socket_type=numeric socket type argument 1, protocol=numeric socket protocol argument 17, remote_port=123, hostname=runtime name buffer, resolution=partial | 4 | [md](outbound_connection__ab212912e89e981c9cb27a9d.md) / [json](outbound_connection__ab212912e89e981c9cb27a9d.json) | `network:ab212912e89e981c9cb27a9d` |
| `unresolved` | — | `network-cs:39bb9f95507166c5fb900c1e` | `ntpclient::stuff_net_addr6` | — | 1 | [md](unresolved__bdd124e91bdd232909ffa932.md) / [json](unresolved__bdd124e91bdd232909ffa932.json) | `network:bdd124e91bdd232909ffa932` |

## Analysis details

### listener — ntpclient::setup_receive

- interaction_id: `network:0fa5c89fbd7ca2491c821208`
- anchor_callsite_id: `network-cs:e9787221d8daea4979557966`
- disposition: `network`
- interaction_kind: `listener`
- summary: For a non-special hostname token, ntpclient resolves the selected IP family, creates a socket, binds an IPv4 or IPv6 wildcard local address, and invokes listen. Resolution, socket creation, and bind failures are fatal; listen failure is ignored. The numeric socket-type argument is preserved as unresolved semantic detail.
- applicability: Scope is the captured seed invocation; caller applicability is not revalidated by this historical-response serialization fixture.
- context_anchor:
  - binary_name: ` "ntpclient" `
  - function_name: ` "main" `
  - line_number: ` 241 `
  - column_number: ` 16 `


#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::setup_receive:L14` | `bind` | `bind(fd, &addr, 0x10u)` | `network-cs:f92a752c1d859967a3e6eea0` |
| `ntpclient::setup_receive:L26` | `bind` | `bind(fd, &v8, 0x1Cu)` | `network-cs:363953ebe71c78115cc96dae` |
| `ntpclient::setup_receive:L33` | `listen` | `listen(fd, 3)` | `network-cs:7924a19494cb40a40d66ba2a` |
| `ntpclient::main:L235` | `getaddrinfo` | `getaddrinfo(name, 0, req, pai)` | `network-cs:a1d17dfad6ecd7edc5aa50e1` |
| `ntpclient::main:L241` | `socket` | `socket(v21, 1, 17)` | `network-cs:e9787221d8daea4979557966` |

#### missing_evidence

_None._

### outbound_connection — ntpclient::stuff_net_addr6

- interaction_id: `network:ab212912e89e981c9cb27a9d`
- anchor_callsite_id: `network-cs:a8dd2b3fb261fbd1ee505766`
- disposition: `network`
- interaction_kind: `outbound_connection`
- summary: The reachable ntpclient path resolves a runtime hostname, creates a socket, constructs either an IPv4 or IPv6 destination with port 123, and calls connect. Resolver or connect failure returns to main, which closes the descriptor and skips primary_loop; preliminary getaddrinfo or socket failure exits.
- applicability: Scope is the captured seed invocation; caller applicability is not revalidated by this historical-response serialization fixture.
- context_anchor:
  - binary_name: ` "ntpclient" `
  - function_name: ` "stuff_net_addr" `
  - line_number: ` 6 `
  - column_number: ` 7 `


#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::stuff_net_addr6:L9` | `gethostbyname2` | `gethostbyname2(a2, 10)` | `network-cs:39bb9f95507166c5fb900c1e` |
| `ntpclient::stuff_net_addr:L6` | `gethostbyname` | `gethostbyname(a2)` | `network-cs:a8dd2b3fb261fbd1ee505766` |
| `ntpclient::setup_transmit:L24` | `connect` | `connect(fd, &addr, 0x10u)` | `network-cs:8f599518f411b9ce79196d25` |
| `ntpclient::setup_transmit:L38` | `connect` | `connect(fd, &v9, 0x1Cu)` | `network-cs:82725831377ea8559bf93ed1` |

#### missing_evidence

- The runtime hostname and resolved remote address are not recoverable from the static code.
- The local address and local port are not established by the supplied target path.
- The exact symbolic meaning of socket type 1 and protocol 17 is not inferred beyond the numeric arguments.
- The behavior of primary_loop and the external peer after a successful connect is outside this interaction's inspected lifecycle.

### unresolved — ntpclient::stuff_net_addr6

- interaction_id: `network:bdd124e91bdd232909ffa932`
- anchor_callsite_id: `network-cs:39bb9f95507166c5fb900c1e`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.
- applicability: Scope is the captured seed invocation; caller applicability is not revalidated by this historical-response serialization fixture.
- context_anchor: ` null `


#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::stuff_net_addr6:L9` | `gethostbyname2` | `gethostbyname2(a2, 10)` | `network-cs:39bb9f95507166c5fb900c1e` |

#### missing_evidence

- evidence callsite network-cs:8f599518f411b9ce79196d25 disagrees with its catalog location: expected ntpclient::setup_transmit:L24 connect, got ntpclient::setup_transmit:L38 connect


## pending_callsite_ids

_None._

## finding_target

- finding_target:
  - path: ` "usr/sbin/ntpclient" `
  - sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `

## callsites

- callsites:
  - network-cs:f92a752c1d859967a3e6eea0:
    - callsite_id: ` "network-cs:f92a752c1d859967a3e6eea0" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "setup_receive" `
      - function_ea: ` 4200388 `
      - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
      - ctree_index: ` 80 `
      - source_ea: ` 4200540 `
      - line_number: ` 14 `
      - column_number: ` 9 `
    - api_name: ` "bind" `
    - api_family: ` "endpoint" `
    - api_binding:
      - symbol: ` "bind" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "bind(fd, &addr, 0x10u)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "fd" `
      - [1]:
        - index: ` 2 `
        - expression: ` "&addr" `
      - [2]:
        - index: ` 3 `
        - expression: ` "0x10u" `
    - return_expression: ` null `
  - network-cs:363953ebe71c78115cc96dae:
    - callsite_id: ` "network-cs:363953ebe71c78115cc96dae" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "setup_receive" `
      - function_ea: ` 4200388 `
      - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
      - ctree_index: ` 134 `
      - source_ea: ` 4200740 `
      - line_number: ` 26 `
      - column_number: ` 9 `
    - api_name: ` "bind" `
    - api_family: ` "endpoint" `
    - api_binding:
      - symbol: ` "bind" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "bind(fd, &v8, 0x1Cu)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "fd" `
      - [1]:
        - index: ` 2 `
        - expression: ` "&v8" `
      - [2]:
        - index: ` 3 `
        - expression: ` "0x1Cu" `
    - return_expression: ` null `
  - network-cs:7924a19494cb40a40d66ba2a:
    - callsite_id: ` "network-cs:7924a19494cb40a40d66ba2a" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "setup_receive" `
      - function_ea: ` 4200388 `
      - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
      - ctree_index: ` 145 `
      - source_ea: ` 4200868 `
      - line_number: ` 33 `
      - column_number: ` 9 `
    - api_name: ` "listen" `
    - api_family: ` "endpoint" `
    - api_binding:
      - symbol: ` "listen" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "listen(fd, 3)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "fd" `
      - [1]:
        - index: ` 2 `
        - expression: ` "3" `
    - return_expression: ` "DIRECT_RET" `
  - network-cs:39bb9f95507166c5fb900c1e:
    - callsite_id: ` "network-cs:39bb9f95507166c5fb900c1e" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "stuff_net_addr6" `
      - function_ea: ` 4200900 `
      - snapshot_hash: ` "a41f0f4733866ae8e6d0a177ab76ad46fa3e5dd43b1263d7e4c62f13cf62f0c3" `
      - ctree_index: ` 4 `
      - source_ea: ` 4200952 `
      - line_number: ` 9 `
      - column_number: ` 7 `
    - api_name: ` "gethostbyname2" `
    - api_family: ` "resolver" `
    - api_binding:
      - symbol: ` "gethostbyname2" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "gethostbyname2(a2, 10)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "a2" `
      - [1]:
        - index: ` 2 `
        - expression: ` "10" `
    - return_expression: ` "v4" `
  - network-cs:a8dd2b3fb261fbd1ee505766:
    - callsite_id: ` "network-cs:a8dd2b3fb261fbd1ee505766" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "stuff_net_addr" `
      - function_ea: ` 4201104 `
      - snapshot_hash: ` "b676da05e57f15fbb5430fc1a8131eb257dcba8b6d6803546c5593ced975eadc" `
      - ctree_index: ` 4 `
      - source_ea: ` 4201152 `
      - line_number: ` 6 `
      - column_number: ` 7 `
    - api_name: ` "gethostbyname" `
    - api_family: ` "resolver" `
    - api_binding:
      - symbol: ` "gethostbyname" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "gethostbyname(a2)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "a2" `
    - return_expression: ` "v4" `
  - network-cs:8f599518f411b9ce79196d25:
    - callsite_id: ` "network-cs:8f599518f411b9ce79196d25" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "setup_transmit" `
      - function_ea: ` 4201320 `
      - snapshot_hash: ` "c5eb2b1717658899c545ddfcd3b63c1da357c99127067a1980dadddaf68697fe" `
      - ctree_index: ` 81 `
      - source_ea: ` 4201496 `
      - line_number: ` 24 `
      - column_number: ` 9 `
    - api_name: ` "connect" `
    - api_family: ` "endpoint" `
    - api_binding:
      - symbol: ` "connect" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "connect(fd, &addr, 0x10u)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "fd" `
      - [1]:
        - index: ` 2 `
        - expression: ` "&addr" `
      - [2]:
        - index: ` 3 `
        - expression: ` "0x10u" `
    - return_expression: ` null `
  - network-cs:82725831377ea8559bf93ed1:
    - callsite_id: ` "network-cs:82725831377ea8559bf93ed1" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "setup_transmit" `
      - function_ea: ` 4201320 `
      - snapshot_hash: ` "c5eb2b1717658899c545ddfcd3b63c1da357c99127067a1980dadddaf68697fe" `
      - ctree_index: ` 139 `
      - source_ea: ` 4201632 `
      - line_number: ` 38 `
      - column_number: ` 9 `
    - api_name: ` "connect" `
    - api_family: ` "endpoint" `
    - api_binding:
      - symbol: ` "connect" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "connect(fd, &v9, 0x1Cu)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "fd" `
      - [1]:
        - index: ` 2 `
        - expression: ` "&v9" `
      - [2]:
        - index: ` 3 `
        - expression: ` "0x1Cu" `
    - return_expression: ` null `
  - network-cs:a1d17dfad6ecd7edc5aa50e1:
    - callsite_id: ` "network-cs:a1d17dfad6ecd7edc5aa50e1" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "main" `
      - function_ea: ` 4206032 `
      - snapshot_hash: ` "6f9b7e7aa827058b7de5c01cbf93c7d7c2e2e8ccae07a80427598832e3bb2c3d" `
      - ctree_index: ` 586 `
      - source_ea: ` 4208208 `
      - line_number: ` 235 `
      - column_number: ` 15 `
    - api_name: ` "getaddrinfo" `
    - api_family: ` "resolver" `
    - api_binding:
      - symbol: ` "getaddrinfo" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "getaddrinfo(name, 0, req, pai)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "name" `
      - [1]:
        - index: ` 2 `
        - expression: ` "0" `
      - [2]:
        - index: ` 3 `
        - expression: ` "req" `
      - [3]:
        - index: ` 4 `
        - expression: ` "pai" `
    - return_expression: ` null `
  - network-cs:e9787221d8daea4979557966:
    - callsite_id: ` "network-cs:e9787221d8daea4979557966" `
    - location:
      - binary_name: ` "ntpclient" `
      - binary_path: ` "usr/sbin/ntpclient" `
      - binary_sha256: ` "bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2" `
      - function_name: ` "main" `
      - function_ea: ` 4206032 `
      - snapshot_hash: ` "6f9b7e7aa827058b7de5c01cbf93c7d7c2e2e8ccae07a80427598832e3bb2c3d" `
      - ctree_index: ` 616 `
      - source_ea: ` 4208284 `
      - line_number: ` 241 `
      - column_number: ` 16 `
    - api_name: ` "socket" `
    - api_family: ` "socket" `
    - api_binding:
      - symbol: ` "socket" `
      - call_kind: ` "direct" `
      - verified: ` true `
    - expression_text: ` "socket(v21, 1, 17)" `
    - arguments:
      - [0]:
        - index: ` 1 `
        - expression: ` "v21" `
      - [1]:
        - index: ` 2 `
        - expression: ` "1" `
      - [2]:
        - index: ` 3 `
        - expression: ` "17" `
    - return_expression: ` "v23" `

## covered_api_calls

- covered_api_calls:
  - [0]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_receive" `
    - api_name: ` "exit" `
    - line_number: ` 18 `
    - column_number: ` 6 `
    - function_ea: ` 4200388 `
    - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
    - ctree_index: ` 76 `
    - source_ea: ` 4200648 `
    - reason: ` "termination: exit on bind(L14) == -1" `
  - [1]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_receive" `
    - api_name: ` "bind" `
    - line_number: ` 14 `
    - column_number: ` 9 `
    - function_ea: ` 4200388 `
    - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
    - ctree_index: ` 80 `
    - source_ea: ` 4200540 `
    - reason: ` "use: bind IPv4 wildcard address and selected local port" `
  - [2]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_receive" `
    - api_name: ` "exit" `
    - line_number: ` 30 `
    - column_number: ` 6 `
    - function_ea: ` 4200388 `
    - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
    - ctree_index: ` 130 `
    - source_ea: ` 4200848 `
    - reason: ` "termination: exit on bind(L26) == -1" `
  - [3]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_receive" `
    - api_name: ` "bind" `
    - line_number: ` 26 `
    - column_number: ` 9 `
    - function_ea: ` 4200388 `
    - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
    - ctree_index: ` 134 `
    - source_ea: ` 4200740 `
    - reason: ` "use: bind IPv6 wildcard address and selected local port" `
  - [4]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_receive" `
    - api_name: ` "listen" `
    - line_number: ` 33 `
    - column_number: ` 9 `
    - function_ea: ` 4200388 `
    - snapshot_hash: ` "6164471d5f4ec4dbbf05d9634455f45615c852aaf7b09014e25de393ea9149ad" `
    - ctree_index: ` 145 `
    - source_ea: ` 4200868 `
    - reason: ` "use: invoke listen with backlog 3" `
  - [5]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "stuff_net_addr6" `
    - api_name: ` "gethostbyname2" `
    - line_number: ` 9 `
    - column_number: ` 7 `
    - function_ea: ` 4200900 `
    - snapshot_hash: ` "a41f0f4733866ae8e6d0a177ab76ad46fa3e5dd43b1263d7e4c62f13cf62f0c3" `
    - ctree_index: ` 4 `
    - source_ea: ` 4200952 `
    - reason: ` "setup: resolve IPv6 address" `
  - [6]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "stuff_net_addr" `
    - api_name: ` "gethostbyname" `
    - line_number: ` 6 `
    - column_number: ` 7 `
    - function_ea: ` 4201104 `
    - snapshot_hash: ` "b676da05e57f15fbb5430fc1a8131eb257dcba8b6d6803546c5593ced975eadc" `
    - ctree_index: ` 4 `
    - source_ea: ` 4201152 `
    - reason: ` "setup: resolve IPv4 address" `
  - [7]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_transmit" `
    - api_name: ` "connect" `
    - line_number: ` 24 `
    - column_number: ` 9 `
    - function_ea: ` 4201320 `
    - snapshot_hash: ` "c5eb2b1717658899c545ddfcd3b63c1da357c99127067a1980dadddaf68697fe" `
    - ctree_index: ` 81 `
    - source_ea: ` 4201496 `
    - reason: ` "use: connect socket to resolved IPv4 address on port 123" `
  - [8]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "setup_transmit" `
    - api_name: ` "connect" `
    - line_number: ` 38 `
    - column_number: ` 9 `
    - function_ea: ` 4201320 `
    - snapshot_hash: ` "c5eb2b1717658899c545ddfcd3b63c1da357c99127067a1980dadddaf68697fe" `
    - ctree_index: ` 139 `
    - source_ea: ` 4201632 `
    - reason: ` "use: connect socket to resolved IPv6 address on port 123" `
  - [9]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "main" `
    - api_name: ` "exit" `
    - line_number: ` 236 `
    - column_number: ` 12 `
    - function_ea: ` 4206032 `
    - snapshot_hash: ` "6f9b7e7aa827058b7de5c01cbf93c7d7c2e2e8ccae07a80427598832e3bb2c3d" `
    - ctree_index: ` 583 `
    - source_ea: ` 4208236 `
    - reason: ` "termination: exit on getaddrinfo(L235) failure" `
  - [10]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "main" `
    - api_name: ` "getaddrinfo" `
    - line_number: ` 235 `
    - column_number: ` 15 `
    - function_ea: ` 4206032 `
    - snapshot_hash: ` "6f9b7e7aa827058b7de5c01cbf93c7d7c2e2e8ccae07a80427598832e3bb2c3d" `
    - ctree_index: ` 586 `
    - source_ea: ` 4208208 `
    - reason: ` "setup: resolve hostname and select socket family" `
  - [11]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "main" `
    - api_name: ` "socket" `
    - line_number: ` 241 `
    - column_number: ` 16 `
    - function_ea: ` 4206032 `
    - snapshot_hash: ` "6f9b7e7aa827058b7de5c01cbf93c7d7c2e2e8ccae07a80427598832e3bb2c3d" `
    - ctree_index: ` 616 `
    - source_ea: ` 4208284 `
    - reason: ` "setup: create socket descriptor" `
  - [12]:
    - binary_name: ` "ntpclient" `
    - function_name: ` "main" `
    - api_name: ` "exit" `
    - line_number: ` 245 `
    - column_number: ` 12 `
    - function_ea: ` 4206032 `
    - snapshot_hash: ` "6f9b7e7aa827058b7de5c01cbf93c7d7c2e2e8ccae07a80427598832e3bb2c3d" `
    - ctree_index: ` 628 `
    - source_ea: ` 4208348 `
    - reason: ` "termination: exit on socket(L241) < 0" `

## planning_findings

### finding:network:v1:7d0f2b11fb4f29ed0f84609beabd19929f5c21f11895725557f3324689064b51

- finding_ref: ` "finding:network:v1:7d0f2b11fb4f29ed0f84609beabd19929f5c21f11895725557f3324689064b51" `
- summary: ` "The target path establishes an outbound socket connection to runtime name on port 123 using an IPv4 or IPv6 resolver branch. Resolver/connect failures are reported and cause descriptor cleanup, while getaddrinfo and socket setup failures exit." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:39bb9f95507166c5fb900c1e" `
    - [1]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:82725831377ea8559bf93ed1" `
    - [2]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:8f599518f411b9ce79196d25" `
    - [3]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:a8dd2b3fb261fbd1ee505766" `
    - [4]:
      - kind: ` "function" `
      - ref: ` "/analyses/2/context_anchor" `
  - reachability_refs:
    - ` "/analyses/2/evidence/2" `
    - ` "/analyses/2/evidence/3" `
    - ` "/analyses/2/evidence/6" `
  - coverage_refs:
    - ` "/analyses/2/coverage_flows/0/setup/2" `
    - ` "/analyses/2/coverage_flows/0/use/0" `
    - ` "/analyses/2/coverage_flows/1/setup/2" `
    - ` "/analyses/2/coverage_flows/1/use/0" `
- claims:
  - [0]:
    - kind: ` "guarantee" `
    - statement: ` "When getaddrinfo and socket succeed, the IPv4 branch resolves the first IPv4 address or returns failure, then calls connect with a 16-byte sockaddr and port 123; the IPv6 branch analogously resolves four address words and calls connect with a 28-byte sockaddr and port 123." `
    - evidence_refs:
      - ` "/analyses/2/evidence/0" `
      - ` "/analyses/2/evidence/1" `
      - ` "/analyses/2/evidence/3" `
      - ` "/analyses/2/evidence/5" `
      - ` "/analyses/2/evidence/6" `
      - ` "/analyses/2/evidence/8" `
    - unknown_kind: ` null `
  - [1]:
    - kind: ` "state" `
    - statement: ` "A successful connect returns setup_transmit status 0, allowing main to pass the same descriptor to primary_loop; a resolver or connect failure returns status 1 and main closes the descriptor without entering primary_loop." `
    - evidence_refs:
      - ` "/analyses/2/evidence/2" `
      - ` "/analyses/2/evidence/5" `
      - ` "/analyses/2/evidence/8" `
    - unknown_kind: ` null `
  - [2]:
    - kind: ` "fallback" `
    - statement: ` "There is no native numeric-address or alternate-family fallback inside setup_transmit after resolver failure; the helper failure propagates as status 1, and main closes the descriptor. The IPv4 and IPv6 branches are selected before setup_transmit and are not retried within that invocation." `
    - evidence_refs:
      - ` "/analyses/2/evidence/3" `
      - ` "/analyses/2/evidence/6" `
      - ` "/analyses/2/evidence/2" `
    - unknown_kind: ` null `
  - [3]:
    - kind: ` "guarantee" `
    - statement: ` "Failure of the preliminary getaddrinfo or socket setup reaches exit(1), making the resource-level violation effect fatal for those setup failures." `
    - evidence_refs:
      - ` "/analyses/2/evidence/0" `
      - ` "/analyses/2/evidence/1" `
    - unknown_kind: ` null `
  - [4]:
    - kind: ` "unknown" `
    - statement: ` "The concrete hostname, resolved address, local endpoint, and external peer behavior remain runtime instance data not recoverable statically." `
    - evidence_refs:
      - ` "/analyses/2/missing_evidence/0" `
      - ` "/analyses/2/missing_evidence/1" `
      - ` "/analyses/2/missing_evidence/3" `
    - unknown_kind: ` "instance_data" `
  - [5]:
    - kind: ` "unknown" `
    - statement: ` "The symbolic transport semantics represented by socket type 1 and protocol 17 are not established beyond their exact numeric arguments." `
    - evidence_refs:
      - ` "/analyses/2/evidence/1" `
      - ` "/analyses/2/missing_evidence/2" `
    - unknown_kind: ` "semantics" `
  - [6]:
    - kind: ` "unknown" `
    - statement: ` "Caller applicability beyond the captured seed has not been revalidated in this serialization fixture." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "applicability" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:ab212912e89e981c9cb27a9d" `
  - interaction_kind: ` "outbound_connection" `
  - callsite_ids:
    - ` "network-cs:39bb9f95507166c5fb900c1e" `
    - ` "network-cs:82725831377ea8559bf93ed1" `
    - ` "network-cs:8f599518f411b9ce79196d25" `
    - ` "network-cs:a8dd2b3fb261fbd1ee505766" `

### finding:network:v1:950522e69433d995837a0a5f9a32726ae9fc34f9229f248e94bf33af83dd7ef2

- finding_ref: ` "finding:network:v1:950522e69433d995837a0a5f9a32726ae9fc34f9229f248e94bf33af83dd7ef2" `
- summary: ` "The target-reachable listener setup is an IP wildcard bind/listen path with fatal resolution, socket, and bind failures, but the exact runtime semantics of numeric socket type 1 with protocol 17 and listen on that descriptor are unresolved." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:363953ebe71c78115cc96dae" `
    - [1]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:7924a19494cb40a40d66ba2a" `
    - [2]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:a1d17dfad6ecd7edc5aa50e1" `
    - [3]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:e9787221d8daea4979557966" `
    - [4]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:f92a752c1d859967a3e6eea0" `
    - [5]:
      - kind: ` "function" `
      - ref: ` "/analyses/0/context_anchor" `
  - reachability_refs:
    - ` "/analyses/0/evidence/0" `
    - ` "/analyses/0/evidence/1" `
    - ` "/analyses/0/evidence/2" `
  - coverage_refs:
    - ` "/analyses/0/coverage_flows/0/setup/0" `
    - ` "/analyses/0/coverage_flows/0/setup/1" `
    - ` "/analyses/0/coverage_flows/0/use/0" `
    - ` "/analyses/0/coverage_flows/0/use/1" `
    - ` "/analyses/0/coverage_flows/0/use/2" `
- claims:
  - [0]:
    - kind: ` "guarantee" `
    - statement: ` "For a non-special hostname path, successful getaddrinfo supplies an address family, successful socket supplies the fd used by setup_receive, and bind failure reaches exit(1)." `
    - evidence_refs:
      - ` "/analyses/0/evidence/0" `
      - ` "/analyses/0/evidence/1" `
      - ` "/analyses/0/evidence/3" `
    - unknown_kind: ` null `
  - [1]:
    - kind: ` "state" `
    - statement: ` "setup_receive selects AF_INET with local address 0.0.0.0 or AF_INET6 with local address ::, using the configured local port; it then invokes listen with backlog 3." `
    - evidence_refs:
      - ` "/analyses/0/evidence/2" `
      - ` "/analyses/0/evidence/3" `
      - ` "/analyses/0/evidence/4" `
    - unknown_kind: ` null `
  - [2]:
    - kind: ` "fallback" `
    - statement: ` "listen's return value is propagated by setup_receive but ignored by main, so a listen failure does not directly terminate this path." `
    - evidence_refs:
      - ` "/analyses/0/evidence/4" `
    - unknown_kind: ` null `
  - [3]:
    - kind: ` "unknown" `
    - statement: ` "The target code does not establish whether the numeric socket-type argument 1 combined with protocol 17 succeeds with the target kernel/libc or produces an operational listener." `
    - evidence_refs:
      - ` "/analyses/0/evidence/1" `
      - ` "/analyses/0/api_effects/4" `
    - unknown_kind: ` "semantics" `
  - [4]:
    - kind: ` "unknown" `
    - statement: ` "Caller applicability beyond the captured seed has not been revalidated in this serialization fixture." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "applicability" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:0fa5c89fbd7ca2491c821208" `
  - interaction_kind: ` "listener" `
  - callsite_ids:
    - ` "network-cs:363953ebe71c78115cc96dae" `
    - ` "network-cs:7924a19494cb40a40d66ba2a" `
    - ` "network-cs:a1d17dfad6ecd7edc5aa50e1" `
    - ` "network-cs:e9787221d8daea4979557966" `
    - ` "network-cs:f92a752c1d859967a3e6eea0" `

### finding:network:v1:b0396c3dd70de751681ef7528c80cf767da4eda56537834afef11e25da00e735

- finding_ref: ` "finding:network:v1:b0396c3dd70de751681ef7528c80cf767da4eda56537834afef11e25da00e735" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:39bb9f95507166c5fb900c1e" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "evidence callsite network-cs:8f599518f411b9ce79196d25 disagrees with its catalog location: expected ntpclient::setup_transmit:L24 connect, got ntpclient::setup_transmit:L38 connect" `
    - evidence_refs:
      - ` "/analyses/1/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
  - [1]:
    - kind: ` "unknown" `
    - statement: ` "Caller applicability beyond the captured seed has not been revalidated in this serialization fixture." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "applicability" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:bdd124e91bdd232909ffa932" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:39bb9f95507166c5fb900c1e" `



## execution

- tasks: ` {} `
- status: ` "complete" `
