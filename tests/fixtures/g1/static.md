## planning_findings

### finding:file:v1:2d59a814916078856d28452063080ddd9883b4658aa6ea885dc3518d2bd36ff7

- finding_ref: ` "finding:file:v1:2d59a814916078856d28452063080ddd9883b4658aa6ea885dc3518d2bd36ff7" `
- summary: ` "Static subject captured; semantic analysis is pending." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "device" `
      - ref: ` "/evidence/resource" `
  - reachability_refs:
    - ` "/evidence/paths/0" `
  - coverage_refs:
    - ` "/evidence/coverage/0" `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "The caller-visible semantics have not yet been analyzed." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "file" `
  - resource_id: ` "file_dev_nvram" `
  - path: ` "/dev/nvram" `
  - resource_class: ` "pseudo_fs_dev" `
  - callsite_ids:
    - ` "file-open" `

### finding:file:v1:da7887e746d6348f2a769b607c0ce6c2b23aae394b43788d69d967d340254c67

- finding_ref: ` "finding:file:v1:da7887e746d6348f2a769b607c0ce6c2b23aae394b43788d69d967d340254c67" `
- summary: ` "Static subject captured; semantic analysis is pending." `
- boundary:
  - kind: ` "function" `
  - anchors:
    - [0]:
      - kind: ` "function" `
      - ref: ` "/evidence/nvram_code" `
  - reachability_refs:
    - ` "/evidence/paths/0" `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "The caller-visible semantics have not yet been analyzed." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain: ` null `

### finding:init_launch:v1:02d3c73a328fab4da227d586205314fa12b9cd68df330d2acf914c29cc4b61cc

- finding_ref: ` "finding:init_launch:v1:02d3c73a328fab4da227d586205314fa12b9cd68df330d2acf914c29cc4b61cc" `
- summary: ` "Static subject captured; semantic analysis is pending." `
- boundary:
  - kind: ` "environment" `
  - anchors:
    - [0]:
      - kind: ` "environment" `
      - ref: ` "/evidence/launch" `
  - reachability_refs:
    - ` "/evidence/paths/1" `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "The caller-visible semantics have not yet been analyzed." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "init_launch" `
  - recipe_id: ` "launch-httpd" `
  - preparation_refs:
    - ` "/evidence/launch/preparation" `

### finding:ipc:v1:e05ee805d03f3184ab3196a2711026e6ee17664b8ebbae88053d2847b391de4c

- finding_ref: ` "finding:ipc:v1:e05ee805d03f3184ab3196a2711026e6ee17664b8ebbae88053d2847b391de4c" `
- summary: ` "Static subject captured; semantic analysis is pending." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "ipc_channel" `
      - ref: ` "/evidence/ipc" `
  - reachability_refs:
    - ` "/evidence/paths/0" `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "The caller-visible semantics have not yet been analyzed." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "ipc" `
  - channel_id: ` "channel-uds" `
  - mechanism: ` "uds" `
  - endpoint_ids:
    - ` "endpoint-client" `

### finding:network:v1:2ab534c672027cefe3f8e2edcedc9c19a4a639f6d1aaa5f5bbdd36423df752c8

- finding_ref: ` "finding:network:v1:2ab534c672027cefe3f8e2edcedc9c19a4a639f6d1aaa5f5bbdd36423df752c8" `
- summary: ` "Static subject captured; semantic analysis is pending." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "fd" `
      - ref: ` "/evidence/network" `
  - reachability_refs:
    - ` "/evidence/paths/0" `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "The caller-visible semantics have not yet been analyzed." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "listener-http" `
  - interaction_kind: ` "listener" `
  - callsite_ids:
    - ` "net-bind" `

### finding:process:v1:c8c8ba3a354cbdc33ca4c0e17ec6fb7e7a3637dcc965ead34cc446b5c826940f

- finding_ref: ` "finding:process:v1:c8c8ba3a354cbdc33ca4c0e17ec6fb7e7a3637dcc965ead34cc446b5c826940f" `
- summary: ` "Static subject captured; semantic analysis is pending." `
- boundary:
  - kind: ` "callsite" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/evidence/process" `
  - reachability_refs:
    - ` "/evidence/paths/0" `
  - coverage_refs:
    - ` "/evidence/coverage/1" `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "The caller-visible semantics have not yet been analyzed." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "process" `
  - callsite_id: ` "exit-startup" `
  - event_kind: ` "termination" `

