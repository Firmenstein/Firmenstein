# IPC Channel — `channel-uds`

- schema_version: `26`
- phase: `full`
- target_process.executable_path: `usr/sbin/httpd`
- structured_source: [`channel-uds_result.json`](channel-uds_result.json)
- mechanism: `uds`
- resource: Unix domain socket `/var/run/peer.sock`
- status: `verified_agent`
- verified_peers:
  - `/usr/sbin/peer`

## channel

- channel_id: `channel-uds`
- mechanism: `uds`
- resources:
  - item:
    - resource_key: `uds-path`
    - kind: `uds_path`
    - canonical_value: `/var/run/peer.sock`
    - expressions:
      - `"/var/run/peer.sock"`
    - status: `verified_agent`
    - evidence:
      - (none)
    - missing_evidence:
      - (none)
- endpoints:
  - item:
    - endpoint_id: `endpoint-target`
    - callsite_id: `ipc-callsite`
    - role: `client`
    - api_binding:
      - kind: `dynamic_import`
      - symbol: `connect`
      - binary_path: null
      - binary_sha256: null
      - status: `verified_static`
      - reason: `undefined dynamic symbol`
    - wrapper_path:
      - (none)
    - coverage_claims:
      - (none)
    - status: `verified_agent`
    - evidence:
      - (none)
    - missing_evidence:
      - (none)
- retrieval_candidates:
  - (none)
- peer_candidates:
  - item:
    - executable_path: `usr/sbin/peer`
    - executable_sha256: `3333333333333333333333333333333333333333333333333333333333333333`
    - argv0: `peer`
    - role: `server`
    - endpoint_locations:
      - item:
        - binary_path: `usr/sbin/peer`
        - function_name: `main`
        - function_ea: `8192`
        - line_number: `8`
        - primitive: `bind`
    - status: `verified_agent`
    - reason: `binds the matching UDS path`
    - evidence:
      - (none)
    - missing_evidence:
      - (none)
- status: `verified_agent`
- missing_evidence:
  - (none)

## dependency_assessments

- item:
  - dependency_id: `dependency-uds`
  - channel_id: `channel-uds`
  - consumer_endpoint_ids:
    - `endpoint-target`
  - peer_requirement: `availability`
  - local_impact: `process_blocked`
  - summary: `httpd startup requires the peer UDS endpoint.`
  - status: `verified_agent`
  - evidence:
    - item:
      - claim: `connect failure reaches startup exit`
      - binary_path: `usr/sbin/httpd`
      - function_name: `main`
      - function_ea: `4096`
      - line_number: `20`
      - callsite_id: `ipc-callsite`
  - missing_evidence:
    - (none)

## unresolved_items

- (none)
