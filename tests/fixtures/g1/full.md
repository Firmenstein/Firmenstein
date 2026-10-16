## planning_findings

### finding:file:v1:2d59a814916078856d28452063080ddd9883b4658aa6ea885dc3518d2bd36ff7

- finding_ref: ` "finding:file:v1:2d59a814916078856d28452063080ddd9883b4658aa6ea885dc3518d2bd36ff7" `
- summary: ` "NVRAM exposes cached strings; device-specific values remain unknown." `
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
    - kind: ` "guarantee" `
    - statement: ` "nvram_get returns the cached string for a known key and NULL for an unknown key." `
    - evidence_refs:
      - ` "/evidence/nvram_code" `
    - unknown_kind: ` null `
  - [1]:
    - kind: ` "state" `
    - statement: ` "The returned string remains valid until nvram_set replaces that value." `
    - evidence_refs:
      - ` "/evidence/nvram_code" `
    - unknown_kind: ` null `
  - [2]:
    - kind: ` "fallback" `
    - statement: ` "The caller selects its default value when nvram_get returns NULL." `
    - evidence_refs:
      - ` "/evidence/caller" `
    - unknown_kind: ` null `
  - [3]:
    - kind: ` "unknown" `
    - statement: ` "The device-specific MAC address is unavailable." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "instance_data" `
- domain:
  - kind: ` "file" `
  - resource_id: ` "file_dev_nvram" `
  - path: ` "/dev/nvram" `
  - resource_class: ` "pseudo_fs_dev" `
  - callsite_ids:
    - ` "file-open" `

### finding:file:v1:da7887e746d6348f2a769b607c0ce6c2b23aae394b43788d69d967d340254c67

- finding_ref: ` "finding:file:v1:da7887e746d6348f2a769b607c0ce6c2b23aae394b43788d69d967d340254c67" `
- summary: ` "Function identity can be represented with common anchors alone." `
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
    - statement: ` "Applicability outside this target's initialization path is not established." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "applicability" `
- domain: ` null `

### finding:init_launch:v1:02d3c73a328fab4da227d586205314fa12b9cd68df330d2acf914c29cc4b61cc

- finding_ref: ` "finding:init_launch:v1:02d3c73a328fab4da227d586205314fa12b9cd68df330d2acf914c29cc4b61cc" `
- summary: ` "The init script prepares the runtime directory before launch." `
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
    - kind: ` "guarantee" `
    - statement: ` "The script invokes mkdir -p /var/run/httpd before the target command." `
    - evidence_refs:
      - ` "/evidence/launch" `
    - unknown_kind: ` null `
- domain:
  - kind: ` "init_launch" `
  - recipe_id: ` "launch-httpd" `
  - preparation_refs:
    - ` "/evidence/launch/preparation" `

### finding:ipc:v1:e05ee805d03f3184ab3196a2711026e6ee17664b8ebbae88053d2847b391de4c

- finding_ref: ` "finding:ipc:v1:e05ee805d03f3184ab3196a2711026e6ee17664b8ebbae88053d2847b391de4c" `
- summary: ` "A request uses one direct peer socket." `
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
    - kind: ` "state" `
    - statement: ` "The target closes the connected descriptor after sending its request." `
    - evidence_refs:
      - ` "/evidence/ipc" `
    - unknown_kind: ` null `
  - [1]:
    - kind: ` "unknown" `
    - statement: ` "The peer's external side effects are not established." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "external_effects" `
- domain:
  - kind: ` "ipc" `
  - channel_id: ` "channel-uds" `
  - mechanism: ` "uds" `
  - endpoint_ids:
    - ` "endpoint-client" `

### finding:network:v1:2ab534c672027cefe3f8e2edcedc9c19a4a639f6d1aaa5f5bbdd36423df752c8

- finding_ref: ` "finding:network:v1:2ab534c672027cefe3f8e2edcedc9c19a4a639f6d1aaa5f5bbdd36423df752c8" `
- summary: ` "The service binds an IPv4 listener on port 80." `
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
    - kind: ` "guarantee" `
    - statement: ` "The bind input selects IPv4 address 0.0.0.0 and port 80." `
    - evidence_refs:
      - ` "/evidence/network" `
    - unknown_kind: ` null `
- domain:
  - kind: ` "network" `
  - interaction_id: ` "listener-http" `
  - interaction_kind: ` "listener" `
  - callsite_ids:
    - ` "net-bind" `

### finding:process:v1:c8c8ba3a354cbdc33ca4c0e17ec6fb7e7a3637dcc965ead34cc446b5c826940f

- finding_ref: ` "finding:process:v1:c8c8ba3a354cbdc33ca4c0e17ec6fb7e7a3637dcc965ead34cc446b5c826940f" `
- summary: ` "Failure to open the NVRAM device terminates startup." `
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
    - kind: ` "guarantee" `
    - statement: ` "The failed open branch calls exit with status 1." `
    - evidence_refs:
      - ` "/evidence/process" `
    - unknown_kind: ` null `
- domain:
  - kind: ` "process" `
  - callsite_id: ` "exit-startup" `
  - event_kind: ` "termination" `

