# NetworkAnalyzer — ntpclient

This report accounts for reachable calls that establish, identify, query, or configure network resources. `network` entries describe external network-stack dependencies. `internal_ipc` and `file_resource` are ownership hand-offs; `not_network` is a proven non-network use or target-infeasible API branch; `unresolved` records the exact missing evidence. Each analysis is rooted at one resource anchor. A shared helper callsite may be referenced by more than one analysis.

- Structured source of truth: [`network_analysis_result.json`](network_analysis_result.json)

## Summary

- schema_version: `9`
- phase: `full`
- root_binary: `ntpclient`
- callsites: 9
- analyses: 9
- analysis_callsite_references: 9
- analyzed_unique_callsites: 9
- shared_callsite_ids: 0
- skipped: 0
- pending_callsite_ids: 0
- disposition `network`: 0
- disposition `internal_ipc`: 0
- disposition `file_resource`: 0
- disposition `not_network`: 0
- disposition `unresolved`: 9

## Analyses

| disposition | interaction_kind | anchor_callsite_id | code_locations | identity | callsites | report | interaction_id |
|---|---|---|---|---|---:|---|---|
| `unresolved` | — | `network-cs:a1d17dfad6ecd7edc5aa50e1` | `ntpclient::main` | — | 1 | [md](unresolved__15b3dd1e35f9ad1f63007a30.md) / [json](unresolved__15b3dd1e35f9ad1f63007a30.json) | `network:15b3dd1e35f9ad1f63007a30` |
| `unresolved` | — | `network-cs:8f599518f411b9ce79196d25` | `ntpclient::setup_transmit` | — | 1 | [md](unresolved__37814a6aa78891eff9922f84.md) / [json](unresolved__37814a6aa78891eff9922f84.json) | `network:37814a6aa78891eff9922f84` |
| `unresolved` | — | `network-cs:39bb9f95507166c5fb900c1e` | `ntpclient::stuff_net_addr6` | — | 1 | [md](unresolved__48a704b09b9b0c145236d6ce.md) / [json](unresolved__48a704b09b9b0c145236d6ce.json) | `network:48a704b09b9b0c145236d6ce` |
| `unresolved` | — | `network-cs:a8dd2b3fb261fbd1ee505766` | `ntpclient::stuff_net_addr` | — | 1 | [md](unresolved__76dfbd2d97ce39d7ba4bc1b6.md) / [json](unresolved__76dfbd2d97ce39d7ba4bc1b6.json) | `network:76dfbd2d97ce39d7ba4bc1b6` |
| `unresolved` | — | `network-cs:363953ebe71c78115cc96dae` | `ntpclient::setup_receive` | — | 1 | [md](unresolved__7a3742e04185e0308bd058c3.md) / [json](unresolved__7a3742e04185e0308bd058c3.json) | `network:7a3742e04185e0308bd058c3` |
| `unresolved` | — | `network-cs:f92a752c1d859967a3e6eea0` | `ntpclient::setup_receive` | — | 1 | [md](unresolved__7c10423aa73844419a47481e.md) / [json](unresolved__7c10423aa73844419a47481e.json) | `network:7c10423aa73844419a47481e` |
| `unresolved` | — | `network-cs:7924a19494cb40a40d66ba2a` | `ntpclient::setup_receive` | — | 1 | [md](unresolved__82a8686c38d8dc65de12be4b.md) / [json](unresolved__82a8686c38d8dc65de12be4b.json) | `network:82a8686c38d8dc65de12be4b` |
| `unresolved` | — | `network-cs:e9787221d8daea4979557966` | `ntpclient::main` | — | 1 | [md](unresolved__bb1a51c108032ae4dc452897.md) / [json](unresolved__bb1a51c108032ae4dc452897.json) | `network:bb1a51c108032ae4dc452897` |
| `unresolved` | — | `network-cs:82725831377ea8559bf93ed1` | `ntpclient::setup_transmit` | — | 1 | [md](unresolved__d8aedc2bf7dd6159e3b3f571.md) / [json](unresolved__d8aedc2bf7dd6159e3b3f571.json) | `network:d8aedc2bf7dd6159e3b3f571` |

## Analysis details

### unresolved — ntpclient::main

- interaction_id: `network:15b3dd1e35f9ad1f63007a30`
- anchor_callsite_id: `network-cs:a1d17dfad6ecd7edc5aa50e1`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::main:L235` | `getaddrinfo` | `getaddrinfo(name, 0, req, pai)` | `network-cs:a1d17dfad6ecd7edc5aa50e1` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::setup_transmit

- interaction_id: `network:37814a6aa78891eff9922f84`
- anchor_callsite_id: `network-cs:8f599518f411b9ce79196d25`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::setup_transmit:L24` | `connect` | `connect(fd, &addr, 0x10u)` | `network-cs:8f599518f411b9ce79196d25` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::stuff_net_addr6

- interaction_id: `network:48a704b09b9b0c145236d6ce`
- anchor_callsite_id: `network-cs:39bb9f95507166c5fb900c1e`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::stuff_net_addr6:L9` | `gethostbyname2` | `gethostbyname2(a2, 10)` | `network-cs:39bb9f95507166c5fb900c1e` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::stuff_net_addr

- interaction_id: `network:76dfbd2d97ce39d7ba4bc1b6`
- anchor_callsite_id: `network-cs:a8dd2b3fb261fbd1ee505766`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::stuff_net_addr:L6` | `gethostbyname` | `gethostbyname(a2)` | `network-cs:a8dd2b3fb261fbd1ee505766` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::setup_receive

- interaction_id: `network:7a3742e04185e0308bd058c3`
- anchor_callsite_id: `network-cs:363953ebe71c78115cc96dae`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::setup_receive:L26` | `bind` | `bind(fd, &v8, 0x1Cu)` | `network-cs:363953ebe71c78115cc96dae` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::setup_receive

- interaction_id: `network:7c10423aa73844419a47481e`
- anchor_callsite_id: `network-cs:f92a752c1d859967a3e6eea0`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::setup_receive:L14` | `bind` | `bind(fd, &addr, 0x10u)` | `network-cs:f92a752c1d859967a3e6eea0` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::setup_receive

- interaction_id: `network:82a8686c38d8dc65de12be4b`
- anchor_callsite_id: `network-cs:7924a19494cb40a40d66ba2a`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::setup_receive:L33` | `listen` | `listen(fd, 3)` | `network-cs:7924a19494cb40a40d66ba2a` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::main

- interaction_id: `network:bb1a51c108032ae4dc452897`
- anchor_callsite_id: `network-cs:e9787221d8daea4979557966`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::main:L241` | `socket` | `socket(v21, 1, 17)` | `network-cs:e9787221d8daea4979557966` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.

### unresolved — ntpclient::setup_transmit

- interaction_id: `network:d8aedc2bf7dd6159e3b3f571`
- anchor_callsite_id: `network-cs:82725831377ea8559bf93ed1`
- disposition: `unresolved`
- interaction_kind: null
- summary: Resource-level network analysis did not produce a validated result.

#### callsite_ids

| location | api_name | expression_text | callsite_id |
|---|---|---|---|
| `ntpclient::setup_transmit:L38` | `connect` | `connect(fd, &v9, 0x1Cu)` | `network-cs:82725831377ea8559bf93ed1` |

#### missing_evidence

- Synthetic semantic analysis failure; retain the unresolved interaction.


## skipped

_None._

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

- covered_api_calls: ` [] `

## planning_findings

### finding:network:v1:27328daf7fb6f34a7b22f6143650b111f50cd9c0c030f7bef6941d8d6db35ac7

- finding_ref: ` "finding:network:v1:27328daf7fb6f34a7b22f6143650b111f50cd9c0c030f7bef6941d8d6db35ac7" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:82725831377ea8559bf93ed1" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/6/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:d8aedc2bf7dd6159e3b3f571" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:82725831377ea8559bf93ed1" `

### finding:network:v1:56b261fe31bad1f60f76390f257b9ebb93670e897f37bf0fd4d353d0e830fa29

- finding_ref: ` "finding:network:v1:56b261fe31bad1f60f76390f257b9ebb93670e897f37bf0fd4d353d0e830fa29" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:8f599518f411b9ce79196d25" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/5/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:37814a6aa78891eff9922f84" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:8f599518f411b9ce79196d25" `

### finding:network:v1:5b4f52389ee094bd23e0e336e27d8a179ab344eb84f21784f68fa86a385cf984

- finding_ref: ` "finding:network:v1:5b4f52389ee094bd23e0e336e27d8a179ab344eb84f21784f68fa86a385cf984" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:a8dd2b3fb261fbd1ee505766" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/4/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:76dfbd2d97ce39d7ba4bc1b6" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:a8dd2b3fb261fbd1ee505766" `

### finding:network:v1:5f4735dd3346086c5477e33a60ff0353c066337cc4b5a361ea3ee70ec678bb79

- finding_ref: ` "finding:network:v1:5f4735dd3346086c5477e33a60ff0353c066337cc4b5a361ea3ee70ec678bb79" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:a1d17dfad6ecd7edc5aa50e1" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/7/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:15b3dd1e35f9ad1f63007a30" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:a1d17dfad6ecd7edc5aa50e1" `

### finding:network:v1:aa2907d3689830cdd7f57171bcbd4ca859e6b97e1a765481ad0c4cb1bdc54af2

- finding_ref: ` "finding:network:v1:aa2907d3689830cdd7f57171bcbd4ca859e6b97e1a765481ad0c4cb1bdc54af2" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:363953ebe71c78115cc96dae" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/1/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:7a3742e04185e0308bd058c3" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:363953ebe71c78115cc96dae" `

### finding:network:v1:bd84022837f9e97b490daed1e6f75452a00abf3619fdb656e000aac36d82d67d

- finding_ref: ` "finding:network:v1:bd84022837f9e97b490daed1e6f75452a00abf3619fdb656e000aac36d82d67d" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:e9787221d8daea4979557966" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/8/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:bb1a51c108032ae4dc452897" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:e9787221d8daea4979557966" `

### finding:network:v1:bed39a663f4d5d131fc0bee4f1d0371d2f7d2898d7e9b306c7aa8c342bec10dc

- finding_ref: ` "finding:network:v1:bed39a663f4d5d131fc0bee4f1d0371d2f7d2898d7e9b306c7aa8c342bec10dc" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:f92a752c1d859967a3e6eea0" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/0/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:7c10423aa73844419a47481e" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:f92a752c1d859967a3e6eea0" `

### finding:network:v1:c98e0481c29f17de1c12eb659a6e944a603faff9d96455117bf1809a80bf2ebb

- finding_ref: ` "finding:network:v1:c98e0481c29f17de1c12eb659a6e944a603faff9d96455117bf1809a80bf2ebb" `
- summary: ` "Resource-level network analysis did not produce a validated result." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/network-cs:7924a19494cb40a40d66ba2a" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/2/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:82a8686c38d8dc65de12be4b" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:7924a19494cb40a40d66ba2a" `

### finding:network:v1:e21d2149222bb4c43e24a872ae4c11c2075401c096098ec0b6b7f1762bd9ee49

- finding_ref: ` "finding:network:v1:e21d2149222bb4c43e24a872ae4c11c2075401c096098ec0b6b7f1762bd9ee49" `
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
    - statement: ` "Synthetic semantic analysis failure; retain the unresolved interaction." `
    - evidence_refs:
      - ` "/analyses/3/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "network:48a704b09b9b0c145236d6ce" `
  - interaction_kind: ` null `
  - callsite_ids:
    - ` "network-cs:39bb9f95507166c5fb900c1e" `
