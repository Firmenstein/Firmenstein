from __future__ import annotations

from enum import Enum

from .base_graph import BaseGraph, EdgeType
from .lib_dep_graph import LibDepGraph
from .call_graph import CallGraph
from ..nodes.function import FunctionNode
from ..nodes.binary import BinaryNode
from ..nodes.function import FunctionAttr
from ..global_config import GlobalConfig

from loguru import logger
from pathlib import Path
from typing import List, Dict, Set, Optional, Literal
import networkx as nx


class ImplStatus(Enum):
    """Result of resolving an external function's implementation against a
    specific ApiDepGraph projection.

    This is a *view fact*, not a property of the function itself — different
    ADG instances (rooted at different binaries) can produce different
    ImplStatus values for the same external stub.
    """
    RESOLVED_IN_SCOPE = "resolved"   # implementer lives in this ADG's scope; IMPL edge present
    DEFAULT_LIB = "default"          # implementer is a DEFAULT_LIB (libc/libm/...); no IMPL edge
    NO_IMPL = "no_impl"              # no implementer found in this ADG's scope


class ApiDepGraph(BaseGraph[FunctionNode]):
    """Per-root projection over per-binary CallGraphs.

    Each ApiDepGraph instance is rooted at exactly one analysis target and
    its scope is that target's transitive DT_NEEDED closure. FunctionNode and
    BinaryNode identity is shared across all ADGs (they live on the binaries
    themselves), but each ADG owns its own nx graph (CALL + IMPL edges) and
    its own impl-resolution state (`_default_lib_impls`) — so two ADGs never
    pollute each other's view.

    Constructed via `build(...)` and frozen thereafter — there is deliberately
    no `add_binary` method. ``add_binary(B)`` creates a structural ADG;
    ``LibDepGraph.decompile_analysis(B)`` creates a fresh semantic ADG.
    """

    def __init__(
        self,
        lib_dep_graph: LibDepGraph,
        root: BinaryNode,
        scope: Set[BinaryNode],
        global_config: GlobalConfig,
        analysis_level: Literal["structural", "semantic"],
    ):
        super().__init__()
        self.lib_dep_graph = lib_dep_graph
        self.global_config = global_config
        self.analysis_level = analysis_level

        self.root: BinaryNode = root
        self.scope: Set[BinaryNode] = set(scope)

        # Mirrors `binary._call_graph` for every in-scope binary available at
        # this projection's analysis level.
        # Populated by build() and never mutated afterwards.
        self.binary_callgraphs: Dict[BinaryNode, CallGraph] = {}

        # Minimal impl-resolution state. Only DEFAULT_LIB externals need
        # explicit storage — RESOLVED_IN_SCOPE is derivable from IMPL edges,
        # and NO_IMPL is the implicit "neither" case.
        # Keyed by caller-side external stub (FunctionNode with EXTERNAL
        # attr), valued by the default library BinaryNode that exports it.
        self._default_lib_impls: Dict[FunctionNode, BinaryNode] = {}

        # Set of function nodes reachable from the root binary (via CALL
        # edges transitively through in-scope IMPL edges).
        self.reachable_nodes: Set[FunctionNode] = set()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @staticmethod
    def build(
        lib_dep_graph: LibDepGraph,
        root: BinaryNode,
        global_config: GlobalConfig,
        *,
        analysis_level: Literal["structural", "semantic"] = "semantic",
    ) -> "ApiDepGraph":
        """Build a frozen ApiDepGraph rooted at `root`.

        ``analysis_level="structural"`` consumes IDA auto-analysis CallGraphs
        only. ``"semantic"`` consumes their CTree-enriched form after
        ``LibDepGraph.decompile_analysis(root)``.  The ADG algorithm itself is
        identical at both levels: it has no direct Hex-Rays dependency.

        Synchronous — no I/O, no subprocess. Async decompilation lives one
        layer up in `LibDepGraph.decompile_analysis`.
        """
        logger.info(
            "Building {} ApiDepGraph rooted at {}...",
            analysis_level,
            root.name,
        )

        scope = lib_dep_graph.transitive_closure_from(root)
        logger.info(f"Projection scope: {len(scope)} binaries (root={root.name})")

        adg = ApiDepGraph(
            lib_dep_graph=lib_dep_graph,
            root=root,
            scope=scope,
            global_config=global_config,
            analysis_level=analysis_level,
        )

        # Generated C/S files are a separate publication concern and are not
        # needed to build either ADG form. Default libs + C++ unsupported
        # binaries remain outside both views.
        for bin_node in scope:
            ready = (
                bin_node.structural_ready
                if analysis_level == "structural"
                else bin_node.semantic_ready
            )
            if ready and bin_node._call_graph is not None:
                adg.binary_callgraphs[bin_node] = bin_node._call_graph

        logger.info(
            f"Integrating {len(adg.binary_callgraphs)} in-scope CallGraphs "
            f"(root={root.name})"
        )

        adg._integrate_callgraphs()
        adg._resolve_impl_edges()
        adg._compute_reachable_nodes()

        logger.success(
            f"ApiDepGraph(level={analysis_level}, root={root.name}): "
            f"{adg.size()} nodes, {adg.edge_count()} edges, "
            f"{len(adg.binary_callgraphs)} binaries, "
            f"{len(adg.reachable_nodes)} reachable, "
            f"{len(adg._default_lib_impls)} default-lib externals"
        )

        return adg

    def _integrate_callgraphs(self):
        """Copy all in-scope CallGraph nodes/edges into this ADG's nx graph."""
        for binary_node, call_graph in self.binary_callgraphs.items():
            logger.debug(
                f"Integrating CallGraph for {binary_node.name}: "
                f"{call_graph.size()} nodes, {call_graph.edge_count()} edges"
            )
            for func_node in call_graph.get_nodes():
                self.add_node(func_node)
            if self.analysis_level == "structural":
                # A cached CallGraph may already contain CTree-supplemented
                # edges. Reconstruct this view from IDA's native callee facts
                # so add_binary never inherits hidden decompiler state.
                for src in call_graph.get_nodes():
                    for dst in call_graph.get_structural_callees_of(src):
                        self.add_edge(src, dst, EdgeType.CALL)
            else:
                for src, dst in call_graph.get_edges():
                    edge_type = call_graph.get_edge_type(src, dst)
                    self.add_edge(src, dst, edge_type)

    def _resolve_impl_edges(self) -> None:
        """Resolve IMPL edges and DEFAULT_LIB entries for every external stub
        in this ADG's integrated graph.

        Strictly scoped to `self.scope`: symbols whose implementers live
        outside this projection are marked NO_IMPL (by omission from both
        the IMPL edge set and `_default_lib_impls`). Cross-process IPC is
        handled separately by IPCAnalyzer and never represented as an IMPL edge.
        """
        impl_edge_count = 0
        default_impl_count = 0
        no_impl_count = 0

        default_libs = self.global_config.DEFAULT_LIB

        for func_node in self.get_nodes():
            if not func_node.has_attr(FunctionAttr.EXTERNAL):
                continue

            implement_lib, implement_ea = self.lib_dep_graph.find_implementation_in_scope(
                func_node.name, self.scope
            )

            if implement_lib is None or implement_ea is None:
                no_impl_count += 1
                logger.debug(f"{func_node.name} --> < NO IMPL (in scope) >")
                continue

            if any(dl in implement_lib.name for dl in default_libs):
                self._default_lib_impls[func_node] = implement_lib
                default_impl_count += 1
                logger.debug(f"{func_node.name} --> < DEFAULT IMPL {implement_lib.name} >")
                continue

            # In-scope custom library: add an IMPL edge into its real impl
            # function. The implementer's CallGraph must already be integrated.
            if implement_lib not in self.binary_callgraphs:
                raise ValueError(
                    f"CallGraph for in-scope library {implement_lib.name} "
                    f"missing from ApiDepGraph (impl resolution invariant broken)"
                )
            impl_func = implement_lib.get_function_by_ea(implement_ea)
            if impl_func not in self._graph:
                raise ValueError(
                    f"Implementation function {impl_func.name} "
                    f"not integrated into ApiDepGraph"
                )
            self.add_edge(func_node, impl_func, edge_type=EdgeType.IMPL)
            impl_edge_count += 1
            logger.debug(f"{func_node.name} -- IMPL --> {impl_func.name} in {implement_lib.name}")

        logger.success(
            f"Resolved impl: {impl_edge_count} IMPL edges, "
            f"{default_impl_count} default-lib, "
            f"{no_impl_count} no-impl"
        )

    def _compute_reachable_nodes(self) -> None:
        """BFS from the root binary's functions over CALL+IMPL edges.

        Reachability semantics:
        1. All functions in the root binary's CallGraph are reachable.
        2. External stubs follow IMPL edges into in-scope lib impls.
        3. All reachable functions follow CALL edges to their callees.
        Exported-but-uncalled library functions are NOT reachable unless
        some reachable caller transitively reaches them.
        """
        root_cg = self.binary_callgraphs.get(self.root)
        if root_cg is None:
            logger.warning(f"Root binary {self.root.name} has no CallGraph")
            self.reachable_nodes = set()
            return

        reachable: Set[FunctionNode] = set()
        queue: List[FunctionNode] = []

        for func_node in root_cg.get_nodes():
            reachable.add(func_node)
            queue.append(func_node)

        while queue:
            current = queue.pop(0)
            for succ in self.get_successors_by_type(current, EdgeType.IMPL):
                if succ not in reachable:
                    reachable.add(succ)
                    queue.append(succ)
            for succ in self.get_successors_by_type(current, EdgeType.CALL):
                if succ not in reachable:
                    reachable.add(succ)
                    queue.append(succ)

        self.reachable_nodes = reachable

        total = self.size()
        pct = (len(reachable) / total * 100) if total > 0 else 0
        logger.info(
            f"Reachability (root={self.root.name}): "
            f"{len(reachable)}/{total} nodes ({pct:.1f}%)"
        )

    # ------------------------------------------------------------------
    # Impl-status query API — the replacement for FunctionAttr.NO_IMPL /
    # DEFAULT_IMPL. Strict: raises on non-EXTERNAL / out-of-scope so bugs
    # surface loudly.
    # ------------------------------------------------------------------

    def get_impl_status(self, func: FunctionNode) -> ImplStatus:
        """Classify `func`'s implementation in this ADG's projection.

        Strict: `func` must be an EXTERNAL FunctionNode that is already
        integrated into this ADG. Raises otherwise — non-EXTERNAL functions
        have no impl-status concept, and out-of-scope functions would return
        a silently misleading answer.
        """
        if not func.has_attr(FunctionAttr.EXTERNAL):
            raise ValueError(
                f"{func.name}@{func.module} is not EXTERNAL; "
                f"impl status is not applicable"
            )
        if func not in self._graph:
            raise ValueError(
                f"{func.name}@{func.module} is not in ApiDepGraph "
                f"(root={self.root.name}) scope"
            )
        if self.get_successors_by_type(func, EdgeType.IMPL):
            return ImplStatus.RESOLVED_IN_SCOPE
        if func in self._default_lib_impls:
            return ImplStatus.DEFAULT_LIB
        return ImplStatus.NO_IMPL

    def get_impl_binary(self, func: FunctionNode) -> Optional[BinaryNode]:
        """Return the binary that implements `func` in this projection, or
        None when NO_IMPL. Works for both RESOLVED_IN_SCOPE and DEFAULT_LIB.
        """
        if func not in self._graph:
            return None
        impl_successors = self.get_successors_by_type(func, EdgeType.IMPL)
        if impl_successors:
            # RESOLVED_IN_SCOPE — recover the binary via module name lookup.
            impl_func = next(iter(impl_successors))
            return self.lib_dep_graph.get_node_by_name(impl_func.module)
        return self._default_lib_impls.get(func)

    # ------------------------------------------------------------------
    # CallGraph lookup (kept for in-ADG iteration / visualization). Note
    # that AnalysisView does NOT go through this — it queries LibDepGraph
    # directly for per-binary CallGraph lookups.
    # ------------------------------------------------------------------

    def get_callgraph(self, binary_node: BinaryNode) -> Optional[CallGraph]:
        """Return the CallGraph of an in-scope binary, or None if not in scope."""
        return self.binary_callgraphs.get(binary_node)

    def get_callgraph_by_name(self, binary_name: str) -> Optional[CallGraph]:
        """Like `get_callgraph`, keyed by binary name. Only returns for
        in-scope binaries; out-of-scope queries should go through LibDepGraph.
        """
        for binary_node, call_graph in self.binary_callgraphs.items():
            if binary_node.name == binary_name:
                return call_graph
        return None

    def get_binary_callgraphs(self) -> Dict[BinaryNode, CallGraph]:
        return self.binary_callgraphs

    def is_reachable(self, node: FunctionNode) -> bool:
        return node in self.reachable_nodes

    def get_reachable_nodes(self) -> Set[FunctionNode]:
        return self.reachable_nodes.copy()

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def get_node_info(self, node: FunctionNode) -> str:
        return f"FunctionNode(name={node.name}, ea={hex(node.ea)}, module={node.module})"

    def get_node_by_name(self, name: str) -> FunctionNode:
        raise NotImplementedError(
            "You should NOT call `get_node_by_name` on ApiDepGraph: multiple "
            "FunctionNodes from different binaries may share the same name. "
            "Use get_callgraph(binary).get_node_by_name(name) instead."
        )

    # ------------------------------------------------------------------
    # DOT visualization (unchanged from before — pure rendering)
    # ------------------------------------------------------------------

    def dump_full_graph(self, output_dir: Path):
        """Dump the entire ApiDepGraph and individual CallGraphs to DOT files."""
        try:
            import pydot
        except ImportError:
            logger.error("pydot is required to dump the graph. Please install it via 'pip install pydot'.")
            return

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Dumping complete ApiDepGraph...")
        api_graph_path = output_dir / f"api_dep_graph_{self.root.name}.dot"
        self._dump_api_dep_graph(api_graph_path)

        logger.info(f"Dumping {len(self.binary_callgraphs)} individual CallGraphs...")
        for binary_node, call_graph in self.binary_callgraphs.items():
            callgraph_path = output_dir / f"{binary_node.name}_CallGraph.dot"
            self._dump_call_graph(call_graph, callgraph_path, binary_node.name)

        logger.success(f"All graphs dumped to {output_dir}")
        logger.info(f"  - ApiDepGraph: {api_graph_path.name}")
        for binary_node in self.binary_callgraphs.keys():
            logger.info(f"  - CallGraph: {binary_node.name}_CallGraph.dot")

    def _dump_api_dep_graph(self, output_path: Path):
        try:
            import pydot
        except ImportError:
            return

        dot = pydot.Dot(graph_type='digraph', label=f'ApiDepGraph(root={self.root.name})', labelloc='t')

        for node in self.get_nodes():
            if node.has_attr(FunctionAttr.EXPORTED):
                color = 'lightgreen'
            elif node.has_attr(FunctionAttr.THUNK) or node.has_attr(FunctionAttr.PLT):
                color = 'lightpink'
            elif node.has_attr(FunctionAttr.EXTERNAL):
                color = 'lightcoral'
            else:
                color = 'lightblue'

            label = f"{node.name}\\n({node.module})"
            dot_node = pydot.Node(
                node.node_repr,
                label=label,
                style='filled',
                fillcolor=color
            )
            dot.add_node(dot_node)

        for src, dst in self.get_edges():
            edge_type = self.get_edge_type(src, dst)
            if edge_type == EdgeType.IMPL:
                dot_edge = pydot.Edge(
                    src.node_repr,
                    dst.node_repr,
                    label=edge_type.value,
                    color='red',
                    style='bold,dashed'
                )
            elif edge_type == EdgeType.CALL:
                dot_edge = pydot.Edge(
                    src.node_repr,
                    dst.node_repr,
                    label=edge_type.value,
                    color='lightblue'
                )
            else:
                dot_edge = pydot.Edge(src.node_repr, dst.node_repr, label=str(edge_type.value) if edge_type else '')
            dot.add_edge(dot_edge)

        if output_path.exists():
            output_path.unlink()

        dot.write_raw(str(output_path))
        logger.info(f"ApiDepGraph with {len(self.get_nodes())} nodes and {self.edge_count()} edges dumped to {output_path}")

    def _dump_call_graph(self, call_graph: CallGraph, output_path: Path, binary_name: str):
        try:
            import pydot
        except ImportError:
            return

        dot = pydot.Dot(
            graph_type='digraph',
            label=f'CallGraph for {binary_name}',
            labelloc='t'
        )

        for node in call_graph.get_nodes():
            if node.has_attr(FunctionAttr.EXPORTED):
                color = 'lightgreen'
            elif node.has_attr(FunctionAttr.THUNK) or node.has_attr(FunctionAttr.PLT):
                color = 'lightpink'
            elif node.has_attr(FunctionAttr.EXTERNAL):
                color = 'lightcoral'
            else:
                color = 'lightblue'

            label = f"{node.name}\\n{hex(node.ea)}"
            dot_node = pydot.Node(
                node.node_repr,
                label=label,
                style='filled',
                fillcolor=color
            )
            dot.add_node(dot_node)

        for src, dst in call_graph.get_edges():
            edge_type = call_graph.get_edge_type(src, dst)
            dot_edge = pydot.Edge(
                src.node_repr,
                dst.node_repr,
                label=edge_type.value if edge_type else 'call',
                color='lightblue'
            )
            dot.add_edge(dot_edge)

        if output_path.exists():
            output_path.unlink()

        dot.write_raw(str(output_path))
        logger.debug(f"CallGraph for {binary_name} with {call_graph.size()} nodes and {call_graph.edge_count()} edges dumped to {output_path}")

    def dump_sub_graph(self, output_path: Path, selection: List[str]):
        """Dump a subgraph containing all ancestors and descendants of selected functions."""
        try:
            import pydot
        except ImportError:
            logger.error("pydot is required to dump the graph. Please install it via 'pip install pydot'.")
            return

        selected_nodes = set()
        for node in self.get_nodes():
            if node.name in selection:
                selected_nodes.add(node)

        if not selected_nodes:
            logger.warning(f"No nodes found matching selection: {selection}")
            return

        logger.info(f"Found {len(selected_nodes)} nodes matching selection: {[n.name for n in selected_nodes]}")

        ancestors = set()
        for selected_node in selected_nodes:
            for node in self.get_nodes():
                if node != selected_node and nx.has_path(self._graph, node, selected_node):
                    ancestors.add(node)

        descendants = set()
        for selected_node in selected_nodes:
            for node in self.get_nodes():
                if node != selected_node and nx.has_path(self._graph, selected_node, node):
                    descendants.add(node)

        subgraph_nodes = selected_nodes | ancestors | descendants

        logger.info(f"Subgraph contains {len(subgraph_nodes)} nodes:")
        logger.info(f"  - Selected: {len(selected_nodes)}")
        logger.info(f"  - Ancestors (callers): {len(ancestors)}")
        logger.info(f"  - Descendants (callees): {len(descendants)}")

        subgraph = self._graph.subgraph(subgraph_nodes)

        dot = pydot.Dot(
            graph_type='digraph',
            label=f'ApiDepGraph Subgraph for {", ".join(selection)}',
            labelloc='t'
        )

        for node in subgraph_nodes:
            if node.has_attr(FunctionAttr.EXPORTED):
                color = 'lightgreen'
            elif node.has_attr(FunctionAttr.THUNK) or node.has_attr(FunctionAttr.PLT):
                color = 'lightpink'
            elif node.has_attr(FunctionAttr.EXTERNAL):
                color = 'lightcoral'
            else:
                color = 'lightblue'

            if node in selected_nodes:
                style = 'filled'
                penwidth = '5.0'
                color_attr = 'black'
            else:
                style = 'filled'
                penwidth = '1.0'
                color_attr = None

            label = f"{node.name}\\n({node.module})"
            if color_attr:
                dot_node = pydot.Node(
                    node.node_repr,
                    label=label,
                    style=style,
                    fillcolor=color,
                    penwidth=penwidth,
                    color=color_attr
                )
            else:
                dot_node = pydot.Node(
                    node.node_repr,
                    label=label,
                    style=style,
                    fillcolor=color,
                    penwidth=penwidth
                )
            dot.add_node(dot_node)

        edge_count = 0
        for src, dst in subgraph.edges():
            edge_type = self.get_edge_type(src, dst)
            if edge_type == EdgeType.IMPL:
                dot_edge = pydot.Edge(
                    src.node_repr,
                    dst.node_repr,
                    label=edge_type.value,
                    color='red',
                    style='bold,dashed'
                )
            elif edge_type == EdgeType.CALL:
                dot_edge = pydot.Edge(
                    src.node_repr,
                    dst.node_repr,
                    label=edge_type.value,
                    color='lightblue'
                )
            else:
                dot_edge = pydot.Edge(
                    src.node_repr,
                    dst.node_repr,
                    label=str(edge_type.value) if edge_type else ''
                )
            dot.add_edge(dot_edge)
            edge_count += 1

        if output_path.exists():
            output_path.unlink()

        dot.write_raw(str(output_path))
        logger.success(f"Subgraph with {len(subgraph_nodes)} nodes and {edge_count} edges dumped to {output_path}")
