# File Resolver Report — `httpd`

- Structured source of truth: [`file_resolver_result.json`](file_resolver_result.json)

## How to Read This Report

FileResolver first recovers possible filesystem paths at reachable file-API callsites. A callsite can produce more than one path, so `callsites` contains **path-candidate records**, not a one-to-one list of source calls. It then selects only eligible creating-API records for lifecycle analysis and groups records with the same typed path `(path_kind, path_value)` into one `resources` entry. In the full phase, each selected resource may produce one `resource_reports` entry. Statically resolved query-only paths remain visible in `callsites`; unresolved query-only paths go directly to `path_resolution_gaps` without invoking the fallback Agent.

```text
reachable file-API callsites
  └─ path recovery → callsites (zero or more path candidates per source call)
       ├─ already in rootfs / query-only / outside policy → not selected
       └─ eligible creating APIs → resources (grouped by exact typed path)
            ├─ successful full analysis → resource_reports
            └─ failed full analysis → resource_analysis_gaps
```

The two gap collections describe different stages. `path_resolution_gaps` belongs to a source callsite and means path recovery was incomplete; it may coexist with resolved candidates. `resource_analysis_gaps` belongs only to an already selected resource and means its lifecycle analysis failed. Therefore, many Agent-recovered path candidates can legitimately produce only one selected resource.

## Analysis Funnel

_All callsites below are reachable from `httpd`; enumeration is filtered by `AnalysisView.collect_api_callsites`._

- schema_version: `9`
- phase: `static`
- Source callsites with at least one resolved path candidate: 0
- Resolved path-candidate records: 0
- Path-candidate records selected for lifecycle analysis: 0
- Resolved path-candidate records not selected: 0
- Exact typed resources selected: 0
- Lifecycle reports produced: 0
- Lifecycle analysis failures: 0
- Skipped callsites: 0
- Callsites with partial path recovery: 0
- Callsites with no resolved path candidate: 1
- Creating-API callsites queued for path fallback (static phase only): 1

- Path-candidate records by `resolution_source`:
  - `literal_static`: 0
  - `global_static`: 0
  - `dataflow_static`: 0
  - `file_path_agent`: 0
- Path-candidate records by `resource_class`:
  - `in_rootfs`: 0
  - `pseudo_fs_dev`: 0
  - `pseudo_fs_proc`: 0
  - `pseudo_fs_sys`: 0
  - `missing_non_pseudo_fs`: 0

## `resources` Selected for Lifecycle Analysis

_None — no callsite was eligible for the per-resource agent._

## `resource_analysis_gaps` — Lifecycle Analysis Failures

_These are failures after a resource was selected. They do not mean that path recovery failed._

_None._

## Resolved Paths Not Selected for Lifecycle Analysis

The following paths were resolved successfully but did not enter `resources`. A path is normally excluded because it already exists in the frozen rootfs, the callsite only queries it, or the configured FileResolver scope does not select it.

### Already Present in the Rootfs

_None resolved to paths already present in rootfs._

### Pseudo-filesystem Paths Not Selected

_None._

### Missing Paths Not Selected

_None — every MISSING_NON_PSEUDO_FS callsite entered resource analysis._

## Path Recovery Evidence and Gaps

This section explains how path candidates were recovered and where recovery remained incomplete. Its entries precede resource selection conceptually, so they must not be read as additional lifecycle-analyzed resources.

### `callsites` Recovered by the Path Fallback Agent

_These are pre-selection path-candidate records whose `resolution_source` is `file_path_agent`. They are evidence of path recovery, not evidence that the path became a selected resource._

_None._

### Guest Symlink Aliases

_None._

### `path_resolution_gaps` — Incomplete Path Recovery

_Each entry names the exact dynamic source, missing relationship, or Agent failure that prevented complete path recovery. An entry marked `partial` also has one or more candidates in `callsites`; an entry marked `unresolved` has none._

- `file-callsite` — `unresolved`
  - Working directory is unknown; relative path 'nvram' cannot be resolved.

### `queued_for_path_agent` (Static Phase Only)

_1 creating-API callsite(s) the static tier couldn't resolve. In phase=static they stay here; in phase=full they're handed to the file path fallback Agent. Unresolved query-only APIs are recorded directly in `path_resolution_gaps`._

- `file-callsite`

### `skipped` Callsites

_None._
