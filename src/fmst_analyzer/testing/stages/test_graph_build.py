from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


def _validate_api_dep_graph(adg, label: str) -> Tuple[list, str]:
    """Validate a single ApiDepGraph projection, return (issues, summary)."""
    from fmst_analyzer.graphs.base_graph import EdgeType
    from fmst_analyzer.graphs.api_dep_graph import ImplStatus
    from fmst_analyzer.nodes.function import FunctionAttr

    issues = []
    num_binaries = len(adg.binary_callgraphs)
    if num_binaries == 0:
        issues.append(f"[{label}] No binaries in ApiDepGraph")
        return issues, f"{label}: 0 bins"

    total_concretized = 0
    impl_count = 0
    no_impl_count = 0
    default_impl_count = 0

    for bin_node, cg in adg.binary_callgraphs.items():
        concretized = sum(1 for f in cg.get_node_for_analysis() if f.concretized)
        total_concretized += concretized
        if concretized == 0:
            issues.append(f"[{label}] {bin_node.name}: 0 concretized functions")

    # Validate scope isolation: all function nodes belong to in-scope binaries
    scope_binary_names = {b.name for b in adg.binary_callgraphs}
    for func_node in adg.get_nodes():
        if func_node.module not in scope_binary_names:
            issues.append(
                f"[{label}] Function {func_node.name}@{func_node.module} "
                f"is outside scope {scope_binary_names}"
            )
            break  # one example is enough

    # Count impl-status buckets via the per-ADG query API. Impl state lives
    # on the ADG instance now (see ApiDepGraph.get_impl_status); shared
    # FunctionNode objects no longer carry this info.
    for func_node in adg.get_nodes():
        if not func_node.has_attr(FunctionAttr.EXTERNAL):
            continue
        status = adg.get_impl_status(func_node)
        if status is ImplStatus.RESOLVED_IN_SCOPE:
            impl_count += 1
        elif status is ImplStatus.DEFAULT_LIB:
            default_impl_count += 1
        else:
            no_impl_count += 1

    # Validate IMPL edges point to real implementations
    for func_node in adg.get_nodes():
        if not func_node.has_attr(FunctionAttr.EXTERNAL):
            continue
        for impl_func in adg.get_successors_by_type(func_node, EdgeType.IMPL):
            if impl_func not in adg:
                issues.append(
                    f"[{label}] IMPL edge target {impl_func.name} not in graph"
                )
                break

    # Validate reachability: the root binary's functions must all be reachable
    root_cg = adg.binary_callgraphs.get(adg.root)
    if root_cg:
        for func_node in root_cg.get_nodes():
            if func_node not in adg.reachable_nodes:
                issues.append(
                    f"[{label}] Root function {func_node.name}@{adg.root.name} "
                    f"not reachable"
                )
                break

    logger.info(
        f"[graph-build] [{label}] ApiDepGraph detail: "
        f"{adg.size()} nodes, {adg.edge_count()} edges, "
        f"{impl_count} IMPL, {no_impl_count} no-impl, "
        f"{default_impl_count} default-impl, "
        f"{len(adg.reachable_nodes)}/{adg.size()} reachable"
    )

    return issues, f"{label}: {num_binaries} bins, {total_concretized} concretized"


def _validate_lib_dep_graph(ldg, global_config) -> List[str]:
    """Structural validation of the LibDepGraph after all additions."""
    from fmst_analyzer.graphs.base_graph import Recursion

    issues = []

    # 1. Check all roots are in graph
    for root in ldg.roots:
        if root not in ldg:
            issues.append(f"Root {root.name} not in LibDepGraph")

    # 2. Detect and report circular dependencies (SCCs)
    scc_info = []
    for entry in ldg.reverse_topo_order:
        if isinstance(entry, Recursion):
            members = [n.name for n in entry.nodes]
            scc_info.append(f"SCC({', '.join(members)})")
    if scc_info:
        logger.info(f"[graph-build] Circular dependencies detected: {scc_info}")

    # 3. Validate DEPENDENCY edges match actual binary dependencies
    for node in ldg.get_nodes():
        declared_deps = set(node.dependencies)
        successors = set()
        for other in ldg.get_nodes():
            if ldg.has_edge(node, other):
                successors.add(other.name)

        # Every declared dep should have a node in graph (if in rootfs)
        for dep_name in declared_deps:
            dep_node = ldg.get_node_by_name(dep_name)
            if dep_node is not None and dep_name not in successors:
                # Dep exists in graph but no edge — possible fix_missing_edges gap
                issues.append(
                    f"Dependency {node.name} -> {dep_name}: node exists but no edge"
                )

    # 4. Verify node deduplication: no two nodes share the same name
    seen_names = {}
    for node in ldg.get_nodes():
        if node.name in seen_names:
            issues.append(f"Duplicate node name: {node.name}")
        seen_names[node.name] = node

    # 5. Verify scope isolation per transitive closure
    for root in ldg.roots:
        closure = ldg.transitive_closure_from(root)
        logger.info(
            f"[graph-build] Transitive closure from {root.name}: "
            f"{len(closure)} binaries = {{{', '.join(sorted(n.name for n in closure))}}}"
        )

    # 6. Verify symbol export index covers all non-default-lib exports
    indexed_symbols = set(ldg._symbol_export_index.keys())
    for node in ldg.get_nodes():
        if any(dl in node.name for dl in global_config.DEFAULT_LIB):
            continue
        for func in node.exported_funcs.values():
            if func.name not in indexed_symbols:
                issues.append(
                    f"Exported function {func.name} from {node.name} "
                    f"not in symbol export index"
                )
                break

    return issues


def _validate_decompiled_artifacts(ldg, global_config) -> List[str]:
    """Verify the production C/S contract for every decompiled binary."""
    from fmst_analyzer.nodes.function import FunctionAttr

    issues = []
    for binary in ldg.get_nodes():
        if not binary.has_decompiled_artifacts:
            continue

        expected_s = {
            function.artifact_stem
            for function in binary.call_graph.get_node_for_analysis()
            if not function.has_attr(FunctionAttr.EXTERNAL)
        }
        failed_eas = {
            failure.function_ea
            for failure in binary.call_graph.semantic_failures
        }
        expected_c = {
            function.artifact_stem
            for function in binary.call_graph.get_node_for_analysis()
            if (
                not function.has_attr(FunctionAttr.EXTERNAL)
                and function.ea not in failed_eas
            )
        }
        c_dir = global_config.decompiled_code_dir / binary.name
        s_dir = global_config.disassembled_code_dir / binary.name
        c_stems = {path.stem for path in c_dir.glob("*.c")}
        s_stems = {path.stem for path in s_dir.glob("*.s")}

        if c_stems != expected_c:
            issues.append(
                f"[{binary.name}] C artifact set mismatch: "
                f"expected {len(expected_c)}, found {len(c_stems)}"
            )
        if s_stems != expected_s:
            issues.append(
                f"[{binary.name}] S artifact set mismatch: "
                f"expected {len(expected_s)}, found {len(s_stems)}"
            )
        if not c_stems <= s_stems:
            issues.append(
                f"[{binary.name}] one or more C artifacts lack an S counterpart"
            )
        if not binary.idb_path.is_file():
            issues.append(f"[{binary.name}] IDB missing: {binary.idb_path}")
    assembly_in_c_input = list(
        global_config.decompiled_code_dir.rglob("*.s")
    )
    if assembly_in_c_input:
        issues.append(
            f"Assembly files leaked into decompiled C directory: "
            f"{assembly_in_c_input}"
        )
    return issues


# Additional explicit roots used to exercise independent per-root projections.
ADDITIONAL_ANALYSIS_ROOTS = ["upnpd", "bftpd"]

# A lib that is in httpd's DT_NEEDED closure (cascade-decompiled during
# Phase 1), used by Phase 3 to exercise the "upgrade a cascade-decompiled
# lib to an analysis root" path.
LIB_UPGRADE_CANDIDATE = "libacos_shared.so"


async def test_graph_build(tester: "PipelineTester") -> Tuple[bool, str]:
    """Build LibDepGraph + ApiDepGraph and verify basic structure.

    Phase 1: Build the primary target's ApiDepGraph via ensure_api_dep_graph()
    (existing behavior).

    Phase 2: Incrementally add explicit analysis roots to the shared
    LibDepGraph via add_binary(), then project an independent ApiDepGraph from
    each root. This exercises graph expansion with overlapping dependency
    subtrees, per-root IMPL edge resolution, and idempotent decompilation.

    Phase 3: Structural validation of LibDepGraph — edge correctness, node
    deduplication, SCC detection, transitive closure verification, and symbol
    export index integrity.
    """
    # Phase 1: Primary target
    await tester.ensure_api_dep_graph()

    all_issues = []
    summaries = []

    issues, summary = _validate_api_dep_graph(
        tester.api_dep_graph, tester.target_binary_name
    )
    all_issues.extend(issues)
    summaries.append(summary)

    logger.info(f"[graph-build] Primary target: {summary}")

    # Phase 2: Decompile each explicit binary as a fresh analysis root, then
    # retrieve its per-root ApiDepGraph from the LibDepGraph cache.
    for peer_name in ADDITIONAL_ANALYSIS_ROOTS:
        peer_path = tester.binary_name2path.get(peer_name)
        if peer_path is None:
            logger.warning(
                f"[graph-build] Peer binary {peer_name} not found in rootfs, skipping"
            )
            continue

        logger.info(
            f"[graph-build] Adding explicit analysis root {peer_name} to LibDepGraph"
        )
        tester.lib_dep_graph.add_binary(peer_path)

        peer_node = tester.lib_dep_graph.get_node_by_name(peer_name)
        if peer_node is None:
            all_issues.append(f"[{peer_name}] add_binary succeeded but node not found")
            continue

        logger.info(
            f"[graph-build] Decompiling peer root and building its ApiDepGraph: {peer_name}"
        )
        await tester.lib_dep_graph.decompile_analysis(
            peer_node,
        )
        peer_adg = tester.lib_dep_graph.get_decompiled_adg(peer_node)

        issues, summary = _validate_api_dep_graph(peer_adg, peer_name)
        all_issues.extend(issues)
        summaries.append(summary)

        logger.info(f"[graph-build] Peer target: {summary}")

    # Phase 2b: upgrade a cascade-decompiled lib to an analysis root.
    # Regression test for the structural-vs-view layer split in
    # decompile_analysis — previously the semantic early-return short-
    # circuited ADG construction for a lib that had already been cascade-
    # decompiled, so calling get_decompiled_adg(lib) would raise.
    lib_node = tester.lib_dep_graph.get_node_by_name(LIB_UPGRADE_CANDIDATE)
    if lib_node is None:
        logger.warning(
            f"[graph-build] {LIB_UPGRADE_CANDIDATE} not in LibDepGraph, "
            f"skipping cascade-upgrade regression"
        )
    elif not lib_node.has_decompiled_artifacts:
        all_issues.append(
            f"[{LIB_UPGRADE_CANDIDATE}] expected to be cascade-decompiled "
            f"during Phase 1 but artifacts are absent"
        )
    else:
        logger.info(
            f"[graph-build] Upgrading cascade-decompiled lib to analysis root: "
            f"{LIB_UPGRADE_CANDIDATE}"
        )
        await tester.lib_dep_graph.decompile_analysis(
            lib_node,
        )
        try:
            lib_adg = tester.lib_dep_graph.get_decompiled_adg(lib_node)
        except ValueError as e:
            all_issues.append(
                f"[{LIB_UPGRADE_CANDIDATE}] upgrade failed: {e}"
            )
        else:
            issues, summary = _validate_api_dep_graph(
                lib_adg, LIB_UPGRADE_CANDIDATE
            )
            all_issues.extend(issues)
            summaries.append(summary)
            logger.info(f"[graph-build] Upgraded lib target: {summary}")

    # Phase 3: LibDepGraph structural validation
    logger.info("[graph-build] Running LibDepGraph structural validation...")
    ldg = tester.lib_dep_graph
    ldg_issues = _validate_lib_dep_graph(ldg, tester.global_config)
    all_issues.extend(ldg_issues)
    artifact_issues = _validate_decompiled_artifacts(
        ldg, tester.global_config,
    )
    all_issues.extend(artifact_issues)

    ldg_nodes = ldg.size()
    ldg_edges = ldg.edge_count()
    logger.info(
        f"[graph-build] LibDepGraph final: "
        f"{ldg_nodes} nodes, {ldg_edges} edges, "
        f"{len(ldg.roots)} roots, "
        f"{len(ldg_issues)} structural issues, "
        f"{len(artifact_issues)} artifact issues"
    )

    if all_issues:
        return False, "; ".join(all_issues)
    return True, " | ".join(summaries)
