from __future__ import annotations

from .base_graph import BaseGraph, EdgeType, Recursion
from ..nodes.binary import BinaryNode
from ..global_config import GlobalConfig
from fmst_basic.utils.file_utils import (
    AmbiguousBinaryError,
)
from fmst_basic.utils.guest_libraries import GuestLibraryResolver

from loguru import logger
from pathlib import Path
from typing import Literal, Tuple, Dict, List, Set, Optional, TYPE_CHECKING
import networkx as nx

if TYPE_CHECKING:
    from .api_dep_graph import ApiDepGraph
    from .call_graph import CallGraph


LIB_DEP_GRAPH_TOPOLOGY_SCHEMA_VERSION = 3


class LibDepGraph(BaseGraph[BinaryNode]):
    """Graph representing library dependencies.

    Constructed via ``__init__`` (stores config) + ``add_binary()`` (populates
    the graph one root binary at a time, BFS-expanding its dependency subtree).
    Cache is transparent: loaded on the first ``add_binary()`` call, updated
    after every subsequent call.
    """
    def __init__(
        self,
        rootfs_path: Path,
        global_config: GlobalConfig,
        decompiler: Literal["ida", "ghidra"] = "ida",
        use_cache: bool = True,
        cache_label: str = "default",
    ):
        super().__init__()
        self.roots: List[BinaryNode] = []
        self.reverse_topo_order: List[BinaryNode|Recursion] = []
        # Symbol export index: scope-limited to binaries currently in this graph.
        self._symbol_export_index: Dict[str, List[BinaryNode]] = {}

        # Config stored on instance so add_binary() doesn't need extra args.
        self._rootfs_path = rootfs_path
        self._global_config = global_config
        self._use_cache = use_cache
        self._cache_label = cache_label
        self._cache_loaded = False  # whether we've attempted cache load

        # Per-explicit-root projections.  The structural form is produced by
        # add_binary(); the semantic form is rebuilt only after Hex-Rays/CTree
        # enrichment.  They must never share one mutable graph object.
        self._structural_adgs: Dict[BinaryNode, "ApiDepGraph"] = {}
        self._semantic_adgs: Dict[BinaryNode, "ApiDepGraph"] = {}

        BinaryNode.set_decompiler(decompiler, global_config.decompiler_db_dir)

    def add_binary(
        self,
        new_binary_path: Path,
        *,
        expand_dependencies: bool = True,
        build_structural_adg: bool = True,
    ) -> BinaryNode:
        """Add a binary and its dependency subtree to the graph.

        On the first call, transparently loads topology + per-binary caches.
        After every call that adds new nodes, both caches are updated.  A
        structural-only root can opt out of DT_NEEDED expansion when the
        caller only needs its own direct CALL edges (for example, an
        executable that directly calls an IPC primitive).  Such a root can
        also skip the cross-binary structural ADG because no imported entry
        needs to be resolved.  The defaults keep the original full-closure
        behavior used by semantic analysis.

        This extends LibDepGraph and guarantees an IDA-auto-analysis-level
        structural CallGraph for the executable and its custom-library
        closure. It does not invoke Hex-Rays, create CTree snapshots, publish
        CTree snapshots or C artifacts. It publishes IDA listings, then builds
        a structural ApiDepGraph for this root.

        Returns:
            The newly created (or existing) BinaryNode for the added binary.
        """
        # 1. First call: attempt topology cache load
        if not self._cache_loaded:
            self._cache_loaded = True
            if self._use_cache and self._global_config.graph_cache_dir:
                self._load_from_topology_cache()

        # 2. Already in graph (from cache or prior add_binary call)?
        existing = self.get_node_by_name(new_binary_path.name)
        if existing is not None:
            existing_path = existing.binary_path.absolute().resolve()
            requested_path = new_binary_path.absolute().resolve()
            if existing_path == requested_path:
                changed_nodes = [
                    node
                    for node in self.transitive_closure_from(existing)
                    if self._ensure_structural_callgraph(node)
                ]
                if self._use_cache and self._global_config.binary_cache_dir:
                    for node in changed_nodes:
                        node.save_cache(self._global_config.binary_cache_dir)
                if changed_nodes:
                    self._structural_adgs.pop(existing, None)
                    self._semantic_adgs.pop(existing, None)
                for node in self.transitive_closure_from(existing):
                    self._publish_structural_artifacts(node)
                if build_structural_adg:
                    self._ensure_structural_adg(existing)
                logger.info(
                    f"Binary {new_binary_path.name} already in graph, "
                    f"returning existing node"
                )
                return existing
            raise AmbiguousBinaryError(
                f"Cannot add {requested_path}: basename "
                f"{new_binary_path.name!r} is already represented by "
                f"{existing_path}. Path-qualified binary identity is not "
                f"supported in the current analysis contract."
            )

        # 3. BFS dependency expansion.  Direct executable endpoint matching
        # does not need imported provider semantics; avoiding its dependency
        # closure prevents an unrelated multimedia/Samba subtree from being
        # loaded merely because the executable imports one generic socket API.
        logger.info(f"Adding binary {new_binary_path.name} to LibDepGraph")
        new_node = self._load_or_create_binary(new_binary_path)

        self.add_node(new_node)
        self.roots.append(new_node)

        processed_nodes = {node.name for node in self.get_nodes()}
        nodes_to_process = [(new_node, ())]
        library_resolver = None
        processed_nodes.add(new_binary_path.name)
        newly_added: List[BinaryNode] = [new_node]

        while expand_dependencies and nodes_to_process:
            current_node, loader_chain = nodes_to_process.pop(0)
            logger.info(f"Processing dependencies for node: {current_node.binary_path}")

            for dynlib_name in current_node.dependencies:
                if library_resolver is None:
                    library_resolver = GuestLibraryResolver(self._rootfs_path, new_binary_path)
                lib_path = library_resolver.resolve(dynlib_name, current_node.binary_path, loader_chain)

                if lib_path:
                    lib_name = lib_path.name
                    if lib_name not in processed_nodes:
                        try:
                            lib_node = self._load_or_create_binary(lib_path)
                            self.add_edge(current_node, lib_node, EdgeType.DEPENDENCY)
                            nodes_to_process.append((lib_node, (current_node.binary_path, *loader_chain)))
                            processed_nodes.add(lib_name)
                            newly_added.append(lib_node)
                        except AmbiguousBinaryError:
                            raise
                        except Exception as e:
                            logger.error(f"Failed to create BinaryNode for {lib_path}: {e}")
                            raise RuntimeError(f"Failed to create BinaryNode for {lib_path}")
                    else:
                        existing_node = self.get_node_by_name(lib_name)
                        if existing_node:
                            if (
                                existing_node.binary_path.absolute().resolve()
                                != lib_path.absolute().resolve()
                            ):
                                raise AmbiguousBinaryError(
                                    f"Dependency basename {lib_name!r} "
                                    f"resolved to both "
                                    f"{existing_node.binary_path} and {lib_path}"
                                )
                            self.add_edge(current_node, existing_node, EdgeType.DEPENDENCY)
                        else:
                            raise RuntimeError(f"Existing node for {lib_name} not found in graph")
                else:
                    logger.error(f"Dependency {dynlib_name} not found in rootfs {self._rootfs_path}")
                    raise NotImplementedError(f"Dependency {dynlib_name} not found in rootfs {self._rootfs_path}")

        # 4. Index symbols, then sort the exact DT_NEEDED topology. Undefined
        #    imports do not justify edges to arbitrary roots that happen to
        #    export the same name; doing so would contaminate per-root closure.
        for node in newly_added:
            self._index_binary_symbols(node)
        self.reverse_topo_order = self.topological_sort(reverse=True, validate=True)

        # IDA auto-analysis already discovered functions and direct call
        # edges while each BinaryNode was created. Materialize that cheap,
        # decompiler-independent graph now; Hex-Rays/CTree enrichment remains
        # the explicit responsibility of decompile_analysis().
        structurally_changed = [
            node
            for node in self.transitive_closure_from(new_node)
            if self._ensure_structural_callgraph(node)
        ]
        for node in self.transitive_closure_from(new_node):
            self._publish_structural_artifacts(node)
        if build_structural_adg:
            self._ensure_structural_adg(new_node)

        logger.success(
            f"Added binary {new_binary_path.name}. "
            f"Graph now has {self.size()} nodes, {self.edge_count()} edges"
        )

        # 5. Save topology cache + per-binary caches for new nodes
        if self._use_cache and self._global_config.graph_cache_dir:
            self._save_topology_cache()
            binary_cache_dir = self._global_config.binary_cache_dir
            cache_nodes = {
                node.binary_path.absolute().resolve(): node
                for node in [*newly_added, *structurally_changed]
            }
            for node in cache_nodes.values():
                node.save_cache(binary_cache_dir)

        # 6. Dump graph visualization
        if self._global_config.graph_dots_dir:
            self.dump_graph(self._global_config.graph_dots_dir / "lib_dep_graph.dot")

        return new_node

    def _ensure_structural_callgraph(self, binary: BinaryNode) -> bool:
        """Ensure the IDA-analysis-level CallGraph, without decompilation."""
        if any(
            default_lib in binary.name
            for default_lib in self._global_config.DEFAULT_LIB
        ):
            return False
        if binary.structural_ready:
            return False

        from .call_graph import CallGraph

        logger.info(f"[add_binary] Building structural CallGraph for {binary.name}")
        binary._call_graph = CallGraph.build_structural(
            binary_node=binary,
            decompiler=BinaryNode.decompiler,
            global_config=self._global_config,
        )
        binary._artifacts_ready = False
        return True

    def _publish_structural_artifacts(self, binary: BinaryNode) -> None:
        """Publish the assembly artifact available directly from the IDB.

        Structural consumers query raw xrefs directly from the IDB. Writing
        them into ``decompiled_code`` here would blur the artifact boundary
        and duplicate the semantic publication pass. Semantic publication
        later adds C-paired ``.s`` names and writes the C/xref contract together,
        preserving listings already referenced by structural consumers.
        """
        if not binary.structural_ready:
            return
        binary.call_graph.dump_disassembled_code(
            self._global_config.disassembled_code_dir,
            artifact_level=(
                "semantic" if binary.semantic_ready else "structural"
            ),
        )

    # ------------------------------------------------------------------
    # Per-binary cache helper
    # ------------------------------------------------------------------

    def _load_or_create_binary(self, binary_path: Path) -> BinaryNode:
        """Try to load a BinaryNode from per-binary cache; fall back to
        BinaryNode.create() if cache miss."""
        if self._use_cache and self._global_config.binary_cache_dir:
            cached = BinaryNode.load_cache(
                binary_path.name,
                self._global_config.binary_cache_dir,
                expected_binary_path=binary_path,
            )
            if cached is not None:
                cached_path = cached.binary_path.absolute().resolve()
                requested_path = binary_path.absolute().resolve()
                if cached_path != requested_path:
                    raise AmbiguousBinaryError(
                        f"Binary cache {binary_path.name!r} belongs to "
                        f"{cached_path}, not requested path {requested_path}"
                    )
                return cached
        return BinaryNode.create(binary_path)

    # ------------------------------------------------------------------
    # Topology cache — stores only node identifiers + edges, no objects
    # ------------------------------------------------------------------

    def _save_topology_cache(self) -> None:
        """Save LibDepGraph topology (node names/paths + edges) to cache."""
        cache_dir = self._global_config.graph_cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"LibDepGraph_{self._cache_label}.pkl"

        import pickle
        topo_data = {
            'schema_version': LIB_DEP_GRAPH_TOPOLOGY_SCHEMA_VERSION,
            'nodes': [(n.name, str(n.binary_path)) for n in self.get_nodes()],
            'edges': [(s.name, d.name) for s, d in self.get_edges()],
            'roots': [r.name for r in self.roots],
            'rootfs_path': str(self._rootfs_path),
        }
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(topo_data, f, protocol=pickle.HIGHEST_PROTOCOL)
            logger.info(f"Saved LibDepGraph topology cache ({len(topo_data['nodes'])} nodes)")
        except Exception as e:
            logger.error(f"Failed to save topology cache: {e}")
            if cache_file.exists():
                cache_file.unlink()

    def _load_from_topology_cache(self) -> bool:
        """Load LibDepGraph from topology cache + per-binary caches.

        Returns True if topology cache was found and reconstruction succeeded.
        """
        import pickle

        cache_dir = self._global_config.graph_cache_dir
        cache_file = cache_dir / f"LibDepGraph_{self._cache_label}.pkl"
        if not cache_file.exists():
            logger.info(f"Topology cache miss: {cache_file.name}")
            return False

        try:
            with open(cache_file, 'rb') as f:
                topo_data = pickle.load(f)
        except Exception as e:
            logger.error(f"Failed to load topology cache: {e}")
            if cache_file.exists():
                cache_file.unlink()
            return False

        cached_schema = topo_data.get('schema_version')
        cached_rootfs = Path(topo_data.get('rootfs_path', '')).absolute().resolve()
        current_rootfs = self._rootfs_path.absolute().resolve()
        if (
            cached_schema != LIB_DEP_GRAPH_TOPOLOGY_SCHEMA_VERSION
            or cached_rootfs != current_rootfs
        ):
            logger.info(
                "Ignoring incompatible LibDepGraph topology cache: "
                "schema={} (expected {}), rootfs={} (expected {})",
                cached_schema,
                LIB_DEP_GRAPH_TOPOLOGY_SCHEMA_VERSION,
                cached_rootfs,
                current_rootfs,
            )
            cache_file.unlink(missing_ok=True)
            return False

        logger.info(
            f"Loaded topology cache: {len(topo_data['nodes'])} nodes, "
            f"{len(topo_data['edges'])} edges"
        )

        # Reject old/corrupt topology caches that relied on basename-keyed
        # overwrite semantics. Reconstructing either entry would otherwise
        # silently bind edges and roots to whichever path appeared last.
        topology_paths: Dict[str, Path] = {}
        for name, path_str in topo_data['nodes']:
            candidate_path = Path(path_str).absolute().resolve()
            existing_path = topology_paths.get(name)
            if existing_path is not None and existing_path != candidate_path:
                raise AmbiguousBinaryError(
                    f"Topology cache contains ambiguous basename {name!r}:\n"
                    f"  - {existing_path}\n"
                    f"  - {candidate_path}"
                )
            topology_paths[name] = candidate_path

        # Reconstruct BinaryNode objects from per-binary caches (or create fresh)
        name_to_node: Dict[str, BinaryNode] = {}
        binary_cache_dir = self._global_config.binary_cache_dir
        for name, expected_path in topology_paths.items():
            cached_binary = BinaryNode.load_cache(
                name,
                binary_cache_dir,
                expected_binary_path=expected_path,
            )
            if cached_binary is not None:
                cached_path = cached_binary.binary_path.absolute().resolve()
                if cached_path != expected_path:
                    raise AmbiguousBinaryError(
                        f"Binary cache {name!r} belongs to {cached_path}, "
                        f"but topology cache requires {expected_path}"
                    )
                name_to_node[name] = cached_binary
            else:
                logger.warning(f"Binary cache miss for {name}, recreating from IDB")
                new_binary = BinaryNode.create(expected_path)
                new_binary.save_cache(binary_cache_dir)
                name_to_node[name] = new_binary

        # Rebuild NetworkX graph with canonical BinaryNode instances
        for node in name_to_node.values():
            self._graph.add_node(node)
        for src_name, dst_name in topo_data['edges']:
            src = name_to_node.get(src_name)
            dst = name_to_node.get(dst_name)
            if src is not None and dst is not None:
                self.add_edge(src, dst, EdgeType.DEPENDENCY)
            else:
                logger.warning(
                    f"Dropping cached edge {src_name} -> {dst_name}: "
                    f"node not found in binary cache"
                )

        # Rebuild roots
        self.roots = [
            name_to_node[r] for r in topo_data['roots']
            if r in name_to_node
        ]

        # Rebuild derived state
        self._build_symbol_indices()
        self.reverse_topo_order = self.topological_sort(reverse=True, validate=True)

        logger.success(
            f"Reconstructed LibDepGraph from topology cache: "
            f"{self.size()} nodes, {self.edge_count()} edges"
        )
        return True

    # ------------------------------------------------------------------
    # Symbol index (instance-level, scope-limited to binaries in graph)
    # ------------------------------------------------------------------

    def _index_binary_symbols(self, binary: BinaryNode) -> None:
        """Add a binary's exported symbols to the index.
        Only invoked from add_binary() right after a binary is first inserted."""
        for func in binary.exported_funcs.values():
            self._symbol_export_index.setdefault(func.name, []).append(binary)

    def _build_symbol_indices(self) -> None:
        """(Re)build symbol export index from scratch over current nodes."""
        self._symbol_export_index.clear()
        for node in self.get_nodes():
            self._index_binary_symbols(node)

    def find_binaries_exporting(self, symbol: str) -> List[BinaryNode]:
        """Return binaries in the graph that export `symbol`."""
        return list(self._symbol_export_index.get(symbol, []))

    # ------------------------------------------------------------------
    # Transitive closure helper (DEPENDENCY edges)
    # ------------------------------------------------------------------

    def transitive_closure_from(self, root: BinaryNode) -> Set[BinaryNode]:
        """Return root + all transitively reachable libraries via DEPENDENCY
        edges. LibDepGraph only has DEPENDENCY edges, so a plain descendants
        traversal is correct."""
        if root not in self._graph:
            raise ValueError(f"{root.name} not in LibDepGraph")
        return nx.descendants(self._graph, root) | {root}

    def _transitive_deps_reverse_topo(
        self, binary: BinaryNode
    ) -> List[BinaryNode]:
        """Return `binary`'s transitive DT_NEEDED dependencies (not including
        `binary` itself) in reverse-topological order — deepest dependencies
        first.

        Reuses `self.reverse_topo_order` to preserve the same ordering
        guarantee that dependent CallGraph builds rely on. SCC wrappers
        (`Recursion`) are flattened: every member node of the SCC is yielded
        in its appearance order. Default libraries are NOT filtered here —
        the caller (`decompile_analysis`) handles that.
        """
        deps = self.transitive_closure_from(binary) - {binary}
        if not deps:
            return []

        ordered: List[BinaryNode] = []
        for entry in self.reverse_topo_order:
            if isinstance(entry, Recursion):
                for node in entry.nodes:
                    if node in deps:
                        ordered.append(node)
            elif entry in deps:
                ordered.append(entry)
        return ordered

    # ------------------------------------------------------------------
    # Decompilation entry point: enrich a structural graph with CTree semantics
    # ------------------------------------------------------------------

    async def decompile_analysis(
        self,
        binary: BinaryNode,
    ) -> None:
        """Run decompiler-dependent analysis for ``binary`` as a root.

        Ensures both layers are ready, each idempotent:

        - **Decompiler layer**: cascade transitive DT_NEEDED deps in
          reverse-topo order and enrich their existing structural CallGraphs
          with CTree snapshots.
        - **Artifact layer**: publish C and CTree-enriched global xrefs; S
          listings already exist from structural analysis and are republished
          under C-paired names.
        - **View layer**: rebuild the semantic ``ApiDepGraph`` rooted at
          ``binary``.  The structural ADG was already created by add_binary.

        Cascade recursion bypasses the view layer by calling
        ``_ensure_decompiled_semantics`` directly, so only explicit roots
        receive a semantic ADG.

        **Upgrading a cascade-decompiled lib to an analysis root is a
        supported use case**: a lib that was previously cascade-decompiled
        (semantic snapshots ready, no ADG) can later be promoted by calling
        ``decompile_analysis(lib_node)``; semantic enrichment and artifact
        publication no-op when current, while the view layer builds its ADG.

        Default libraries and C++-unsupported binaries are skipped in the
        decompiler layer and therefore get no semantic ADG either.

        The async API keeps the existing analyzer call shape.
        """
        if binary.is_cxx_unsupported:
            raise RuntimeError(
                f"Binary {binary.name} contains C++ content. Structural IDA "
                "analysis is available, but Firmenstein does not currently "
                "support C++ Hex-Rays semantic analysis."
            )
        await self._ensure_decompiled_semantics(binary)
        if not binary.semantic_ready:
            return
        for dependency in self._transitive_deps_reverse_topo(binary):
            if dependency.semantic_ready:
                self._publish_decompiled_binary_artifacts(dependency)
        self._publish_decompiled_binary_artifacts(binary)
        self._semantic_adgs.pop(binary, None)
        self._ensure_semantic_adg(binary)

    def _ensure_structural_adg(
        self,
        binary: BinaryNode,
    ) -> "ApiDepGraph":
        """Build the IDA-auto-analysis ADG for one explicit root."""
        if not binary.structural_ready:
            raise RuntimeError(
                f"Cannot build structural ApiDepGraph for {binary.name} "
                "before add_binary()"
            )
        adg = self._structural_adgs.get(binary)
        if adg is None:
            from .api_dep_graph import ApiDepGraph
            logger.info(
                "[add_binary] Building structural ApiDepGraph for {}",
                binary.name,
            )
            adg = ApiDepGraph.build(
                self, binary, self._global_config,
                analysis_level="structural",
            )
            self._structural_adgs[binary] = adg
        return adg

    def _ensure_semantic_adg(
        self,
        binary: BinaryNode,
    ) -> "ApiDepGraph":
        """Build the CTree-enriched ADG after decompiler analysis."""
        if not binary.semantic_ready:
            raise RuntimeError(
                f"Cannot build ApiDepGraph for {binary.name} before semantics"
            )
        if binary not in self._semantic_adgs:
            from .api_dep_graph import ApiDepGraph
            logger.info(
                "[decompile_analysis] Building semantic ApiDepGraph for {}",
                binary.name,
            )
            self._semantic_adgs[binary] = ApiDepGraph.build(
                self, binary, self._global_config, analysis_level="semantic",
            )
        return self._semantic_adgs[binary]

    def _publish_decompiled_binary_artifacts(
        self,
        binary: BinaryNode,
    ) -> None:
        if binary._artifacts_ready:
            return
        global_config = self._global_config
        binary.call_graph.dump_decompiled_code(
            global_config.decompiled_code_dir, mark_callsites=False,
        )
        binary.call_graph.dump_disassembled_code(
            global_config.disassembled_code_dir,
        )
        # String xrefs are structural, but may have been cleared separately
        # while the semantic graph cache survived. Re-establish them here
        # without invoking Hex-Rays again.
        binary.call_graph.dump_string_xrefs(
            global_config.decompiled_code_dir,
        )
        binary.call_graph.dump_global_var_xrefs(
            global_config.decompiled_code_dir,
            include_semantic_aliases=True,
        )
        binary.call_graph.verify_artifacts(
            global_config.decompiled_code_dir,
            global_config.disassembled_code_dir,
        )
        binary._artifacts_ready = True
        if self._use_cache and global_config.binary_cache_dir:
            binary.save_cache(global_config.binary_cache_dir)

    async def _ensure_decompiled_semantics(
        self,
        binary: BinaryNode,
        _seen: Optional[Set[BinaryNode]] = None,
    ) -> None:
        """Ensure `binary`'s semantic layer is ready: transitive non-default
        DT_NEEDED deps all decompiled first (reverse-topo order), then this
        binary's existing structural CallGraph and semantic snapshots.

        Idempotent via ``binary.semantic_ready``. Default libraries and
        C++-unsupported binaries are skipped (they have no custom
        CallGraph in Firmenstein's pipeline). Cascade recursion calls
        back into this same method directly — NOT through
        ``decompile_analysis`` — so the view layer is never entered during
        cascade, which keeps ``_semantic_adgs`` exclusively populated by
        explicit analysis roots.

        Without the cascade, semantic enrichment may raise ``RuntimeError:
        Implementation function ... not concretized yet`` whenever
        ``binary`` references a custom-lib function whose CallGraph
        hasn't been built (see ``call_graph.py:115-121``).

        Cache: if ``BinaryNode`` was loaded from per-binary cache with its
        CallGraph already attached (same pickle stream), the CallGraph
        build is skipped. ``FunctionNode`` identity is guaranteed by
        pickle's memo — no state hoisting needed.

        ``_seen`` is an internal cycle guard for the cascade recursion;
        external callers should leave it unset.
        """
        if binary not in self._graph:
            raise ValueError(
                f"{binary.name} not in LibDepGraph; cannot decompile"
            )

        if any(
            default_lib in binary.name
            for default_lib in self._global_config.DEFAULT_LIB
        ):
            logger.debug(
                f"Skipping decompile analysis for default library: {binary.name}"
            )
            return

        if binary.is_cxx_unsupported:
            logger.warning(
                f"Skipping decompile analysis for C++ binary: {binary.name}. "
                f"Firmenstein does not currently support C++ deep analysis. "
                f"Any external functions resolving to this library will "
                f"be treated as NO_IMPL by ApiDepGraph."
            )
            return

        if binary.semantic_ready:
            return

        # Cycle guard: a pathological cycle in DEPENDENCY edges that
        # survived the SCC topo sort must not infinite-loop here.
        seen = _seen if _seen is not None else set()
        if binary in seen:
            return
        seen.add(binary)

        # Cascade: decompile non-default transitive deps in reverse-topo
        # order before this binary's CallGraph build. Fail-fast: any
        # exception in a transitive dependency propagates up and
        # aborts the caller. C++ binaries are skipped upstream via the
        # is_cxx_unsupported check, so remaining dep failures reflect
        # real bugs that should not be silently swallowed.
        for dep in self._transitive_deps_reverse_topo(binary):
            if dep is binary:
                continue
            if any(
                default_lib in dep.name
                for default_lib in self._global_config.DEFAULT_LIB
            ):
                continue
            if dep.semantic_ready:
                continue
            await self._ensure_decompiled_semantics(
                dep, _seen=seen,
            )

        self._ensure_structural_callgraph(binary)
        if not binary.semantic_ready:
            # Reuse the assembly-derived graph and add only Hex-Rays/CTree
            # state. No second graph object or parallel identity is created.
            logger.info(
                f"[decompile_analysis] Enriching CallGraph semantics for "
                f"{binary.name}"
            )
            binary._artifacts_ready = False
            binary.call_graph.enrich_semantics(self)
        else:
            logger.info(
                f"[decompile_analysis] Semantic CallGraph for {binary.name} loaded "
                f"from cache"
            )

        if self._use_cache and self._global_config.binary_cache_dir:
            binary.save_cache(self._global_config.binary_cache_dir)

    # ------------------------------------------------------------------
    # Per-root ApiDepGraph accessors
    # ------------------------------------------------------------------

    def get_structural_adg(self, binary: BinaryNode) -> "ApiDepGraph":
        """Return the IDA-auto-analysis ADG rooted at ``binary``."""
        adg = self._structural_adgs.get(binary)
        if adg is None:
            raise ValueError(
                f"No structural ApiDepGraph for {binary.name}; "
                "call add_binary() first"
            )
        return adg

    def get_decompiled_adg(self, binary: BinaryNode) -> "ApiDepGraph":
        """Return the CTree-enriched ADG rooted at ``binary``."""
        adg = self._semantic_adgs.get(binary)
        if adg is None:
            raise ValueError(
                f"No semantic ApiDepGraph for {binary.name}; "
                "call decompile_analysis() first"
            )
        return adg

    def resolve_view(
        self,
        binary_name: str,
        *,
        prefer: Optional["ApiDepGraph"] = None,
    ) -> Optional["ApiDepGraph"]:
        """Pick the ADG that best covers queries about `binary_name`.

        `prefer` is the caller's "anchor" ADG — typically the ADG of the
        analyzer that's invoking this resolution. It is NOT session-wide
        state; it's whatever view the caller currently cares about. If
        `prefer` covers `binary_name`, returning it keeps queries
        consistent with the analyzer's own view.

        Rules (in order):
        1. If ``prefer`` is given and ``binary_name`` is in ``prefer.scope``,
           return ``prefer``. The caller's view wins for in-scope queries.
        2. Else if ``binary_name`` has its own semantic per-root ADG (because
           it was explicitly decompiled as an analysis root by an evidence-gated
           analysis tool or the top-level target analyzer), return that ADG.
        3. Else return None — ``binary_name`` is unknown, not decompiled,
           or is a cascade-decompiled lib that has not been promoted to a
           root and isn't covered by ``prefer``.
        """
        bin_node = self.get_node_by_name(binary_name)
        if bin_node is None or not bin_node.semantic_ready:
            return None
        if prefer is not None and bin_node in prefer.scope:
            return prefer
        return self._semantic_adgs.get(bin_node)

    def get_callgraph_by_name(self, binary_name: str) -> Optional["CallGraph"]:
        """Look up a per-binary CallGraph by binary name.

        Semantic lookup used by AnalysisView's single-binary query helpers.
        Returns None if the binary is unknown or has only structural state.
        Bypasses ADGs entirely because CallGraph is per-binary state, not a
        view artifact.
        """
        node = self.get_node_by_name(binary_name)
        if node is None or not node.semantic_ready:
            return None
        return node.call_graph

    def find_implementation_by_name(self, func_name: str) -> Tuple[Optional[BinaryNode], Optional[int]]:
        """Find the library and function address that implements the given function name.

        C++ libraries are skipped: they are treated as if they don't provide
        the symbol, so external functions resolving only to C++ libs end up
        as NO_IMPL downstream.
        """
        if func_name.startswith("__imp_"):
            func_name = func_name[len("__imp_"):]
        possible_names = self.get_possible_implement_names(func_name)
        for name in possible_names:
            for lib_node in self._symbol_export_index.get(name, []):
                if lib_node.is_cxx_unsupported:
                    continue
                for ea, func in lib_node.exported_funcs.items():
                    if func.name == name:
                        return lib_node, ea
        return None, None

    def find_implementation_in_scope(
        self,
        func_name: str,
        scope: Set[BinaryNode],
    ) -> Tuple[Optional[BinaryNode], Optional[int]]:
        """Like find_implementation_by_name, but restricted to binaries in
        `scope`. Used by ApiDepGraph.build to keep IMPL edges scoped to
        the root's transitive DT_NEEDED closure — different analysis roots
        produce independent projections over the same LibDepGraph.

        C++ libraries are skipped (same as find_implementation_by_name).
        """
        if func_name.startswith("__imp_"):
            func_name = func_name[len("__imp_"):]
        possible_names = self.get_possible_implement_names(func_name)
        for name in possible_names:
            for lib_node in self._symbol_export_index.get(name, []):
                if lib_node not in scope:
                    continue
                if lib_node.is_cxx_unsupported:
                    continue
                for ea, func in lib_node.exported_funcs.items():
                    if func.name == name:
                        return lib_node, ea
        return None, None
        
    def get_possible_implement_names(self, func_name: str):
        """
        Generate possible valid function names by adding/removing common prefixes.
        For example, "gethostname" may be defined as "__GI_gethostname" or "__libc_gethostname" in some libraries.
        """
        possible_names = [func_name]
        prefixes = ["__GI_", "__libc_"]
        for prefix in prefixes:
            if not func_name.startswith(prefix):
                possible_names.append(prefix + func_name)
        return list(possible_names)

    def get_node_info(self, node: BinaryNode) -> str:
        """Get string representation of a BinaryNode."""
        return f"BinaryNode(path={node.path})"
    
    def dump_graph(self, output_path: Path):
        """Dump the graph to a file in DOT format."""
        try:
            import pydot
        except ImportError:
            logger.error("pydot is required to dump the graph. Please install it via 'pip install pydot'.")
            return
        
        dot = pydot.Dot(graph_type='digraph')
        
        for node in self.get_nodes():
            dot_node = pydot.Node(node.name)
            dot.add_node(dot_node)
        
        for src, dst in self.get_edges():
            dot_edge = pydot.Edge(src.name, dst.name)
            dot.add_edge(dot_edge)
        
        if output_path.exists():
            output_path.unlink()

        dot.write_raw(str(output_path))
        logger.info(f"Graph dumped to {output_path}")
