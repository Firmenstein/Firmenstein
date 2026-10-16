"""Zero-Agent smoke test for IPC provider-entry/caller matching."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester

from fmst_analyzer.analysis.ipc_analyzer.candidate_index import (
    ChannelCandidateIndex,
)
from fmst_analyzer.analysis.ipc_analyzer.peer import build_firmware_import_index
from fmst_analyzer.analysis.ipc_analyzer.peer.firmware_import_index import (
    FirmwareImportIndex,
)
from fmst_analyzer.analysis.ipc_analyzer.schema import (
    IPCChannel,
    IPCMechanism,
    ResourceIdentity,
    VerificationStatus,
)


async def test_ipc_peer_tools(
    tester: "PipelineTester",
) -> Tuple[bool, str]:
    """Exercise LIEF index queries and deterministic candidate classification."""
    issues: List[str] = []
    print("\n=== IPC Peer Tools Smoke Test ===", flush=True)
    logger.info(
        "[ipc-peer-tools] building FirmwareImportIndex on {}",
        tester.fw_rootfs_path,
    )
    index = build_firmware_import_index(tester.fw_rootfs_path)
    issues.extend(_check_index_invariants(index))
    _print_index_summary(index)

    await tester.ensure_lib_dep_graph()
    issues.extend(_check_negative_candidate_index(index, tester))

    if issues:
        print(f"\n  Issues ({len(issues)}):", flush=True)
        for issue in issues:
            print(f"    - {issue}", flush=True)
    summary = (
        f"elfs={len(index.elf_kind)} symbols={len(index.symbol_to_elfs)}"
    )
    if issues:
        summary += f"; {len(issues)} issues"
    return not issues, summary


def _check_index_invariants(index: FirmwareImportIndex) -> List[str]:
    issues: List[str] = []
    if not index.elf_kind:
        issues.append("FirmwareImportIndex.elf_kind is empty")
    if not index.symbol_to_elfs:
        issues.append("FirmwareImportIndex.symbol_to_elfs is empty")
    if not any(kind == "exec" for kind in index.elf_kind.values()):
        issues.append("FirmwareImportIndex has zero executable ELFs")
    if not any(kind == "so" for kind in index.elf_kind.values()):
        issues.append("FirmwareImportIndex has zero shared-library ELFs")
    if not any(index.defined_functions_per_elf.values()):
        issues.append("FirmwareImportIndex has zero defined dynamic functions")
    missing_reverse_entries = [
        (symbol, path)
        for symbol, paths in index.symbol_to_elfs.items()
        for path in paths
        if symbol not in index.undefined_functions_per_elf.get(path, set())
    ]
    if missing_reverse_entries:
        issues.append(
            "per-ELF undefined import index disagrees with reverse symbol index"
        )
    if index.ignored_elfs & set(index.elf_kind):
        issues.append("ignored ELF objects leaked into user-space classification")
    kernel_parse_leaks = sorted(
        path for path in index.unparseable_elfs if path.suffix == ".ko"
    )
    if kernel_parse_leaks:
        issues.append(
            f"kernel modules leaked into unresolved parse items: {kernel_parse_leaks}"
        )
    return issues


def _print_index_summary(index: FirmwareImportIndex) -> None:
    exec_count = sum(kind == "exec" for kind in index.elf_kind.values())
    so_count = sum(kind == "so" for kind in index.elf_kind.values())
    ambiguous = sum(
        len(paths) > 1 for paths in index.soname_candidates.values()
    )
    print(
        f"  FirmwareImportIndex: elfs={len(index.elf_kind)} "
        f"(exec={exec_count} so={so_count}), "
        f"ambiguous loader names={ambiguous}, "
        f"ignored={len(index.ignored_elfs)}, "
        f"unparseable={len(index.unparseable_elfs)}",
        flush=True,
    )


def _check_negative_candidate_index(
    index: FirmwareImportIndex, tester: "PipelineTester",
) -> List[str]:
    issues: List[str] = []
    channel = IPCChannel(
        channel_id="ipc-peer-tools-smoke",
        mechanism=IPCMechanism.UDS,
        resources=[ResourceIdentity(
            resource_key="var-run-smoke",
            kind="uds_path",
            canonical_value="/__fmst_ipc_peer_tools_missing__.sock",
            expressions=["smoke-test absent complete identifier"],
            status=VerificationStatus.VERIFIED_STATIC,
            evidence=[],
            missing_evidence=[],
        )],
        endpoints=[],
        retrieval_candidates=[],
        peer_candidates=[],
        status=VerificationStatus.VERIFIED_STATIC,
        missing_evidence=[],
    )
    candidate_index = ChannelCandidateIndex(tester.fw_rootfs_path, index)
    batch = candidate_index.prepare_many(
        [channel], tester.lib_dep_graph,
        exclude_paths={
            tester.target_binary_path.relative_to(
                tester.fw_rootfs_path,
            ).as_posix()
        },
    )
    candidates = batch.candidates_by_channel[channel.channel_id]
    if candidates:
        issues.append(
            "absent complete identifier produced executable candidates: "
            + ", ".join(item.executable_path for item in candidates)
        )
    gap_codes = {
        gap.reason_code for gap in batch.gaps_by_channel[channel.channel_id]
    }
    if "no_indexed_candidate" not in gap_codes:
        issues.append("absent complete identifier has no explicit unresolved item")
    print(
        f"  Candidate index negative smoke: {len(candidates)} candidates, "
        f"{len(batch.gaps_by_channel[channel.channel_id])} coverage gaps, "
        "LIEF calls only; Hex-Rays calls=0, IDA additions=0, Agent calls=0",
        flush=True,
    )
    return issues


__all__ = ["test_ipc_peer_tools"]
