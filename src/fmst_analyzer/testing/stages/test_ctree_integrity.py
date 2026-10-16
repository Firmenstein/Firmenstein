from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


COMMON_API_CANDIDATES = (
    "strlen", "strcpy", "strcmp", "memcpy", "open", "close",
)


async def test_ctree_integrity(
    tester: PipelineTester,
) -> Tuple[bool, str]:
    """Validate snapshot/C alignment and the local callsite query path."""
    await tester.ensure_analysis_view()
    view = tester.view
    issues: List[str] = []
    results = view.ctree_integrity_check()
    if not results:
        return False, "no binaries checked — cannot validate CTree integrity"

    total_decompiled = 0
    total_snapshots = 0
    for binary_name, result in results.items():
        total_decompiled += result.total_decompiled
        total_snapshots += result.total_snapshots
        logger.info(
            f"[TEST] {binary_name}: {result.total_snapshots}/"
            f"{result.total_decompiled} snapshots, "
            f"{result.missing_count} missing, {result.extra_count} extra"
        )
        if result.missing_funcs:
            issues.append(
                f"{binary_name}: missing or invalid snapshots: "
                + ", ".join(result.missing_funcs)
            )
        if result.extra_funcs:
            issues.append(
                f"{binary_name}: unexpected C artifacts: "
                + ", ".join(result.extra_funcs)
            )

    selected_api = None
    collected_count = 0
    for api_name in COMMON_API_CANDIDATES:
        try:
            callsites = view.collect_api_callsites(api_name)
        except Exception as error:
            issues.append(f"collect_api_callsites({api_name!r}) raised: {error}")
            continue
        if not callsites:
            continue
        selected_api = api_name
        collected_count = len(callsites)
        if any(not callsite.is_populated for callsite in callsites):
            issues.append(
                f"collect_api_callsites({api_name!r}) returned an "
                "unpopulated CTree callsite"
            )
        if len({callsite.identity_key for callsite in callsites}) != len(callsites):
            issues.append(
                f"collect_api_callsites({api_name!r}) returned duplicate "
                "CTree identities"
            )
        break

    if selected_api is None:
        issues.append(
            "no common API produced a reachable CTree callsite: "
            + ", ".join(COMMON_API_CANDIDATES)
        )

    detail = (
        f"{len(results)} binaries, {total_snapshots}/{total_decompiled} "
        f"valid semantic snapshots"
    )
    if selected_api is not None:
        detail += f" | collect_api_callsites({selected_api})={collected_count}"
    if issues:
        return False, detail + ":\n" + "\n".join(issues)
    return True, detail
