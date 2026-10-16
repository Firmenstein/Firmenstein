"""Test stage: file-resolver-static.

Runs FileResolver Nodes 1-4.5 plus persistence (no LLM). Exercises:
  - ApiDepGraph enumeration of creating + querying file APIs
  - optional IPC callsite-level dedup from persisted IPC JSON
  - static resolution (LITERAL / GLOBAL / dataflow / fallback queue)
  - Pure-Python classifier into FileResourceClass

The purpose is to let us see **how much the static tier resolves** and
**what the path fallback Agent must cover** in a full run.

Skips Nodes 3 and 5, then Node 6 writes the static JSON and Markdown. Re-runnable
cheaply from the existing graph and semantic caches.
"""
from __future__ import annotations

from fmst_analyzer.analysis.file_resolver.analyzer_schema import FILE_RESOLVER_SCHEMA_VERSION

from typing import TYPE_CHECKING, List, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_file_resolver_static(
    tester: "PipelineTester",
) -> Tuple[bool, str]:
    """Run FileResolver in phase='static' and validate the output."""
    result = await tester.ensure_file_resolver_result(phase="static")

    # --- Validation ---
    issues: List[str] = []
    if result.schema_version != FILE_RESOLVER_SCHEMA_VERSION:
        issues.append(
            f"unexpected FileResolver schema_version={result.schema_version}"
        )
    total_seen = (
        len(result.callsites)
        + len(result.queued_for_path_agent)
    )
    if total_seen == 0:
        issues.append(
            "FileResolver saw zero candidates — no file API callsites in "
            "the ApiDepGraph is suspicious; likely enumeration / name-"
            "normalization bug"
        )

    # Static phase must NOT produce fallback-Agent-resolved callsites.
    fallback_resolved = [
        key for key, cs in result.callsites.items()
        if cs.resolution_source == "file_path_agent"
    ]
    if fallback_resolved:
        issues.append(
            f"{len(fallback_resolved)} callsites have resolution_source="
            "'file_path_agent' but phase=static must not invoke an Agent"
        )

    # Static phase builds exact resources but must not produce Agent reports.
    if result.resource_reports:
        issues.append(
            f"{len(result.resource_reports)} resource_reports populated but "
            "phase=static should skip FileResourceAnalysisAgent"
        )
    resource_callsite_ids = {
        cs.profile_key
        for resource in result.resources.values()
        for cs in resource.callsites
    }
    missing_backlinks = [
        profile_key
        for profile_key in resource_callsite_ids
        if result.callsites[profile_key].resource_group_id is None
    ]
    if missing_backlinks:
        issues.append(
            "eligible static resources have callsites without resource ids: "
            f"{missing_backlinks}"
        )

    # Persisted artifacts on disk.
    workdir = tester.global_config.workdir
    if workdir:
        out_dir = (
            tester.global_config.target_diagnostic_reports_dir() / "file_reports"
        )
        index_md = out_dir / "index.md"
        json_path = out_dir / "file_resolver_result.json"
        if not out_dir.exists() or not any(out_dir.iterdir()):
            issues.append(f"file_reports dir missing/empty: {out_dir}")
        if not index_md.exists():
            issues.append(f"index.md not written: {index_md}")
        if not json_path.exists():
            issues.append(f"file_resolver_result.json not written: {json_path}")
    else:
        logger.warning("[TEST] workdir is None; skipping disk verification")

    # --- Terminal report ---
    by_src = result.counts_by_resolution_source
    by_cls = result.counts_by_resource_class
    total = (
        len(result.callsites)
        + len(result.queued_for_path_agent)
    )
    print(
        f"\n=== FileResolver static phase: {total} total seen "
        f"({len(result.callsites)} resolved, "
        f"{len(result.queued_for_path_agent)} queued_for_path_agent) ===",
        flush=True,
    )
    print(
        "  resolution source breakdown (file_path_agent should be 0): "
        + ", ".join(f"{k}={v}" for k, v in by_src.items()),
        flush=True,
    )
    print(
        "  resource class breakdown:    "
        + ", ".join(f"{k}={v}" for k, v in by_cls.items()),
        flush=True,
    )



    if result.queued_for_path_agent:
        print("\n  Queued for path fallback:", flush=True)
        for cs_id in result.queued_for_path_agent:
            print(f"    {cs_id}", flush=True)

    if issues:
        print(f"\n  Issues ({len(issues)}):", flush=True)
        for issue in issues:
            print(f"    - {issue}", flush=True)

    passed = not issues
    summary = (
        f"{len(result.callsites)} static-resolved "
        f"(literal={by_src.get('literal_static', 0)}, "
        f"global={by_src.get('global_static', 0)}, "
        f"dataflow={by_src.get('dataflow_static', 0)}), "
        f"{len(result.queued_for_path_agent)} queued_for_path_agent, "
        f"{len(result.resources)} exact resources"
    )
    if issues:
        summary += f"; {len(issues)} issues"
    return passed, summary
