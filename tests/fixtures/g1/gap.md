## planning_findings

### finding:file:v1:2d59a814916078856d28452063080ddd9883b4658aa6ea885dc3518d2bd36ff7

- finding_ref: ` "finding:file:v1:2d59a814916078856d28452063080ddd9883b4658aa6ea885dc3518d2bd36ff7" `
- summary: ` "The returned value layout is unresolved." `
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
    - statement: ` "The evidence does not describe the output buffer layout." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "file" `
  - resource_id: ` "file_dev_nvram" `
  - path: ` "/dev/nvram" `
  - resource_class: ` "pseudo_fs_dev" `
  - callsite_ids:
    - ` "file-open" `

