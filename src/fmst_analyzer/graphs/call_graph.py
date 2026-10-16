from .lib_dep_graph import LibDepGraph
from .base_graph import BaseGraph, EdgeType, Recursion
from ..nodes.function import FunctionNode
from ..nodes.binary import BinaryNode
from ..nodes.function import FunctionAttr
from ..global_config import GlobalConfig

import json
import os
import tempfile
from dataclasses import dataclass

from loguru import logger
from pathlib import Path
from typing import Literal, List, Dict, Union
import networkx as nx

CALL_GRAPH_CACHE_SCHEMA_VERSION = 5


@dataclass(frozen=True)
class SemanticExtractionFailure:
    """A function Hex-Rays could not snapshot under one exact IDB/runtime."""

    binary_name: str
    function_ea: int
    function_name: str
    error: str
    binary_identity: str
    idb_identity: str
    ida_version: str
    ida_domain_version: str


class CallGraph(BaseGraph[FunctionNode]):
    """Call graph for a single binary (not cross-binary).
    
    This class represents the call graph for a single BinaryNode, containing
    only the functions within that binary and their call relationships.
    Cross-binary calls are handled by ApiDepGraph via IMPL edges.
    """
    
    def __init__(self, binary_node: BinaryNode, global_config: GlobalConfig = None):
        super().__init__()
        self._cache_schema_version = CALL_GRAPH_CACHE_SCHEMA_VERSION
        self.binary_node = binary_node  # The binary this call graph belongs to
        self.global_config = global_config
        self.external_funcs: List[FunctionNode] = []  # External functions
        self._reverse_topological_sorted_nodes: List[Union[FunctionNode, Recursion]] = []  # Cached reverse topological order
        self._nodes_for_analysis: List[FunctionNode] = []  # Nodes that require deep analysis
        self._decompiled_name_map: Dict[str, FunctionNode] = {} # Cache for decompiled name to node mapping
        self._semantic_failures: Dict[int, SemanticExtractionFailure] = {}
        self._structural_complete = False
        self._semantic_complete = False

    @staticmethod
    def build_structural(
        binary_node: BinaryNode,
        decompiler: Literal["ida", "ghidra"],
        global_config: GlobalConfig,
    ) -> "CallGraph":
        """Build the IDA-analysis-level function graph without Hex-Rays.

        Function discovery and direct callee edges come from the IDB created by
        ``BinaryNode``.  No function is decompiled and no CTree snapshot or
        source artifact is produced here.
        """
        graph = CallGraph(binary_node, global_config)
        FunctionNode.set_decompiler(decompiler)

        # Mark external functions as roots for later analysis
        for external_func_ea in binary_node.external_funcs.keys():
            func_node = binary_node.get_function_by_ea(external_func_ea)
            graph.external_funcs.append(func_node)

        # build fast callgraph
        for ea, func_node in binary_node.all_funcs.items():
            graph.add_node(func_node)
            for callee_addr in func_node.get_structural_callees():
                callee = binary_node.all_funcs.get(callee_addr)
                if callee is None:
                    logger.warning(
                        f"Cannot add fast call edge in {binary_node.name}: "
                        f"{func_node.name} targets unregistered function EA "
                        f"0x{callee_addr:x}"
                    )
                    continue
                graph.add_edge(func_node, callee, edge_type=EdgeType.CALL)
                logger.debug(f"Fast CallGraph build: {func_node.name} -- CALLS --> {callee.name}")

        graph._reverse_topological_sorted_nodes = graph.topological_sort(reverse=True, validate=True)
        graph._structural_complete = True
        return graph

    def enrich_semantics(self, lib_dep_graph: LibDepGraph) -> None:
        """Incrementally add Hex-Rays/CTree semantics to a structural graph."""
        if self.semantic_ready:
            return
        if not self.structural_ready:
            raise RuntimeError(
                f"Structural CallGraph for {self.binary_node.name} is incomplete"
            )
        self.invalidate_semantics()
        try:
            self.deep_analysis(lib_dep_graph)
            self._semantic_complete = True
        finally:
            # Deep analysis switches among IDBs; no failure may leak an open
            # database into the next binary's decompile analysis.
            FunctionNode.close_database()

    @property
    def structural_ready(self) -> bool:
        return (
            getattr(self, "_structural_complete", False)
            and getattr(self, "_cache_schema_version", 0)
            == CALL_GRAPH_CACHE_SCHEMA_VERSION
        )

    @property
    def semantic_ready(self) -> bool:
        """Whether every analysis function has a snapshot or an explicit failure."""
        if not self.structural_ready or not getattr(
            self, "_semantic_complete", False,
        ):
            return False
        binary_identity = getattr(self.binary_node, "_binary_identity", None)
        idb_identity = str(self.binary_node.idb_path.absolute().resolve())
        import ida_domain
        import idaapi

        ida_version = str(idaapi.get_kernel_version())
        for function in self._nodes_for_analysis:
            if function.has_attr(FunctionAttr.EXTERNAL):
                continue
            snapshot = getattr(function, "_semantic_snapshot", None)
            failure = self._semantic_failures.get(function.ea)
            if failure is not None:
                if (
                    failure.binary_identity == binary_identity
                    and failure.idb_identity == idb_identity
                    and failure.ida_version == ida_version
                    and failure.ida_domain_version == str(ida_domain.__version__)
                ):
                    continue
                return False
            if (
                snapshot is None
                or not snapshot.is_current
                or getattr(snapshot, "binary_identity", None) != binary_identity
                or getattr(snapshot, "idb_identity", None) != idb_identity
                or getattr(snapshot, "ida_version", None) != ida_version
                or getattr(snapshot, "ida_domain_version", None)
                != str(ida_domain.__version__)
            ):
                return False
        return True

    def invalidate_semantics(self) -> None:
        """Drop only Hex-Rays-derived state while retaining structural edges."""
        for function in self.get_nodes():
            invalidate = getattr(function, "invalidate_semantic_snapshot", None)
            if invalidate is not None:
                invalidate()
        # deep_analysis() may have supplemented this graph with direct targets
        # found only in CTree. Rebuild CALL edges from IDA-native callee facts
        # so a subsequent semantic pass cannot inherit stale decompiler edges.
        self._graph.remove_edges_from(list(self._graph.edges()))
        for function in self.get_nodes():
            for callee in self.get_structural_callees_of(function):
                self.add_edge(function, callee, edge_type=EdgeType.CALL)
        self._reverse_topological_sorted_nodes = self.topological_sort(
            reverse=True, validate=True,
        )
        self._nodes_for_analysis = []
        self._decompiled_name_map = {}
        self._semantic_failures = {}
        self._semantic_complete = False

    def deep_analysis(self, lib_dep_graph: LibDepGraph):
        """
        Conducting deep analysis related to decompilation and function concretization.

        IMPORTANT: Pay special attention to the decompilation order of functions, 
            as the decompilation result of certain functions may affect the decompilation of other functions.
        - Example 1: If an External Function with unknown prototype is decompiled first, all functions calling this External Function 
                will treat it as having an unknown prototype during decompilation, rather than inferring it based on CallSite information,
                which will greatly affect the accuracy of subsequent analysis.
        - Example 2: If a function A is decompiled before its Callee B, the inference of A's Callsites may be incomplete because B has not been decompiled yet, 
                leading to inaccurate decompilation results for A.

        Our strategy is that: 
        1. If the external callee function is in GlobalConfig.DEFAULT_LIB, we use the results inferred from the callsite information
            (i.e., we do not pre-modify or decompile external functions and their thunk functions).
        2. If the called external function is in CustomLib, we modify the definitions of external functions using the corresponding function prototypes from the IMPL library.
        3. For other functions, we decompile them in reverse topological order to ensure that callees are decompiled before their callers.
        """
        implementation_scope = lib_dep_graph.transitive_closure_from(
            self.binary_node
        )

        def collect_node_for_processing(func_node: FunctionNode):
            if func_node in self._nodes_for_analysis:
                return # Already collected

            if func_node.has_attr(FunctionAttr.TEXT):
                # If Thunk function in .text segment and its target function is an External function, we do not process it here.
                # Since it will be processed when handling the External function
                if func_node.has_attr(FunctionAttr.THUNK):
                    target_func = self.binary_node.find_thunk_target(func_node)
                    if target_func and target_func.has_attr(FunctionAttr.EXTERNAL):
                        return            
                        
                self._nodes_for_analysis.append(func_node)
                for thunk_func in self.binary_node.find_thunk_funcs(func_node):
                    self._nodes_for_analysis.append(thunk_func)

            elif func_node.has_attr(FunctionAttr.EXTERNAL):
                # Prototype inference must use the current binary's DT_NEEDED
                # closure.  A different analysis root may export the same
                # symbol but is neither a valid implementation for this
                # binary nor guaranteed to have semantic analysis yet.
                impl_lib, impl_ea = lib_dep_graph.find_implementation_in_scope(
                    func_node.name,
                    implementation_scope,
                )
                if impl_lib is None or impl_ea is None:
                    # No IMPL found, skip processing
                    return
                elif any(default_lib in impl_lib.name for default_lib in self.global_config.DEFAULT_LIB):
                    # Default library function, skip processing
                    return
                else:
                    # Custom library function, collect its prototype from IMPL library
                    impl_func_node = impl_lib.get_function_by_ea(impl_ea)
                    if not impl_func_node.concretized:
                        logger.warning(
                            "Skipping prototype propagation for {}::{}: "
                            "implementation {}::{} has no semantic snapshot",
                            self.binary_node.name,
                            func_node.name,
                            impl_lib.name,
                            impl_func_node.name,
                        )
                        return
                    try:
                        prototype = impl_func_node.get_prototype_info()
                    except RuntimeError as error:
                        # Cross-library prototype propagation improves Hex-Rays
                        # output, but it is not a correctness prerequisite for
                        # decompiling the caller. A callee may have an explicit
                        # semantic frontier while its callers remain fully
                        # analyzable.
                        logger.warning(
                            "Skipping prototype propagation for {}::{} from "
                            "{}::{}: {}",
                            self.binary_node.name,
                            func_node.name,
                            impl_lib.name,
                            impl_func_node.name,
                            error,
                        )
                        return
                    func_node.save_predefined_prototype(prototype)
                    
                    # Current External function and its corresponding 
                    # thunk functions (if exists, maybe located in .PLT or .text) need to be processed
                    self._nodes_for_analysis.append(func_node)
                    for thunk_func in self.binary_node.find_thunk_funcs(func_node):
                        self._nodes_for_analysis.append(thunk_func)
        
        def process_function(func_node: FunctionNode):
            """Helper function to process a single function node."""
            func_node.activate()
            func_node.concretize()
            # Supplement call edges discovered during concretization
            for callee_addr in func_node.get_callees():
                try:
                    callee = self.binary_node.get_function_by_ea(callee_addr)
                except RuntimeError:
                    # Hex-Rays may recover a direct target that IDA did not
                    # register as a function.  The semantic snapshot still
                    # retains that callsite and callee EA, but a normal graph
                    # edge requires an actual FunctionNode.
                    logger.warning(
                        "Cannot add CTree-discovered call edge in {}: {} "
                        "targets unregistered function EA {}; retaining "
                        "the CallSite without a CallGraph edge",
                        self.binary_node.name,
                        func_node.name,
                        hex(callee_addr),
                    )
                    continue
                if callee.ea == func_node.ea:
                    continue  # Skip self-call-recursion edges
                if not self.has_edge(func_node, callee):
                    self.add_edge(func_node, callee, edge_type=EdgeType.CALL)
                    logger.debug(f"Supplemented edge in {self.binary_node.name}: {func_node.name} -- CALLS --> {callee.name}")
        
        for node in self._reverse_topological_sorted_nodes:
            if isinstance(node, Recursion):
                for func_node in node.nodes:
                    collect_node_for_processing(func_node)
            elif isinstance(node, FunctionNode):
                collect_node_for_processing(node)
            else:
                raise RuntimeError(f"Unknown node type in CallGraph deep_analysis: {type(node)}")
            
        # Thunks can be collected both independently and through their target.
        # Keep each function once, preserving dependency order.
        self._nodes_for_analysis = list(dict.fromkeys(self._nodes_for_analysis))
        for func_node in self._nodes_for_analysis:
            logger.info(f"Deep analyzing function: {self.get_node_info(func_node)}")
            try:
                process_function(func_node)
            except Exception as error:
                from ida_domain.pseudocode import PseudocodeError

                if not isinstance(error, PseudocodeError):
                    raise
                import ida_domain
                import idaapi

                failure = SemanticExtractionFailure(
                    binary_name=self.binary_node.name,
                    function_ea=func_node.ea,
                    function_name=func_node.name,
                    error=str(error) or type(error).__name__,
                    binary_identity=self.binary_node._binary_identity,
                    idb_identity=str(self.binary_node.idb_path.absolute().resolve()),
                    ida_version=str(idaapi.get_kernel_version()),
                    ida_domain_version=str(ida_domain.__version__),
                )
                self._semantic_failures[func_node.ea] = failure
                logger.warning(
                    "Semantic snapshot unavailable for {}::{} at {}: {}",
                    self.binary_node.name,
                    func_node.name,
                    hex(func_node.ea),
                    failure.error,
                )
        
        # Resolve all global variables while IDB is still open.
        # Aggregate ALL aliases observed at each EA across concretized
        # functions — different functions may emit different IDA
        # auto-generated type prefixes (dword_XXX vs byte_XXX vs
        # unk_XXX) for the same memory depending on how each
        # function's decompiled expression dereferenced it. Pass every
        # alias down so the binary-level resolver can register the
        # same value under all of them (first-seen-wins would drop
        # losing aliases and leave function-level lookups unresolvable).
        func_globals: Dict[int, List[str]] = {}
        for func_node in self._nodes_for_analysis:
            if func_node.concretized:
                for ea, name in func_node._global_vars.items():
                    aliases = func_globals.setdefault(ea, [])
                    if name not in aliases:
                        aliases.append(name)

        self.binary_node.resolve_all_global_values(func_globals)

        FunctionNode.close_database()
        self._assign_artifact_stems()
        self._build_decompiled_name_map()
        return self

    def _assign_artifact_stems(self) -> None:
        """Keep C/S paths unique when Hex-Rays display names collide."""
        groups: Dict[str, List[FunctionNode]] = {}
        for node in self._nodes_for_analysis:
            if node.has_attr(FunctionAttr.EXTERNAL):
                continue
            groups.setdefault(node.decompiled_name, []).append(node)

        for name, nodes in groups.items():
            ordered = sorted(nodes, key=lambda node: node.ea)
            ordered[0].set_artifact_stem(name)
            for node in ordered[1:]:
                node.set_artifact_stem(f"{name}@{node.ea:x}")
            if len(ordered) > 1:
                logger.warning(
                    "Decompiler name collision in {} for {!r}; artifact "
                    "stems are {}",
                    self.binary_node.name,
                    name,
                    [node.artifact_stem for node in ordered],
                )

        # macOS commonly uses a case-insensitive filesystem.  Distinct ELF
        # symbols such as ``SYSTEM`` and ``system`` therefore still collide
        # even though their stems differ on Linux.  Resolve those collisions
        # deterministically while retaining the readable stem for the first
        # function in EA order.
        used_casefold: Dict[str, FunctionNode] = {}
        for node in sorted(
            (candidate for candidate in self._nodes_for_analysis
             if not candidate.has_attr(FunctionAttr.EXTERNAL)),
            key=lambda candidate: (candidate.artifact_stem.casefold(), candidate.ea),
        ):
            stem = node.artifact_stem
            key = stem.casefold()
            if key in used_casefold:
                stem = f"{stem}@{node.ea:x}"
                while stem.casefold() in used_casefold:
                    stem = f"{stem}@{node.ea:x}"
                node.set_artifact_stem(stem)
                logger.warning(
                    "Case-insensitive artifact stem collision in {}: {} -> {}",
                    self.binary_node.name,
                    key,
                    stem,
                )
                key = stem.casefold()
            used_casefold[key] = node

    def _build_decompiled_name_map(self):
        """Build the mapping from decompiled name to FunctionNode for all concretized functions."""
        self._decompiled_name_map = {}
        for node in self.binary_node.all_funcs.values():
            if node.concretized:
                self._decompiled_name_map[node.artifact_stem] = node
                key = node.decompiled_name
                if key in self._decompiled_name_map:
                    existing = self._decompiled_name_map[key]
                    if existing is node:
                        continue
                    logger.warning(
                        f"Decompiled name collision in {self.binary_node.name}: "
                        f"'{key}' at {hex(existing.ea)} and {hex(node.ea)}, "
                        f"keeping first occurrence"
                    )
                else:
                    self._decompiled_name_map[key] = node

    def get_node_for_analysis(self) -> List[FunctionNode]:
        """Get the list of meaningful nodes that require deep analysis.
        Specifically, only Non-thunk functions in `.text` segment and External functions (with their thunks) in Custom libraries are included.
        
        Returns:
            List[FunctionNode]: List of function nodes that need deep analysis
        """
        return self._nodes_for_analysis

    @property
    def semantic_failures(self) -> List[SemanticExtractionFailure]:
        """Stable, explicitly accounted functions without a CTree snapshot."""
        return [self._semantic_failures[ea] for ea in sorted(self._semantic_failures)]

    def _artifact_nodes(self) -> List[FunctionNode]:
        return [
            node
            for node in self._nodes_for_analysis
            if not node.has_attr(FunctionAttr.EXTERNAL)
            and node.ea not in self._semantic_failures
        ]

    def _structural_artifact_nodes(self) -> List[FunctionNode]:
        """Functions whose IDA listings are available without Hex-Rays."""
        return sorted(
            (
                node
                for node in self.binary_node.all_funcs.values()
                if not node.has_attr(FunctionAttr.EXTERNAL)
            ),
            key=lambda node: node.ea,
        )
    
    def get_node_info(self, node: FunctionNode) -> str:
        """Get string representation of a FunctionNode."""
        return f"FunctionNode(name={node.name}, ea={hex(node.ea)}, binary={self.binary_node.name})"
    
    def get_node_by_ea(self, ea: int) -> FunctionNode:
        """Get FunctionNode by its effective address (EA) within the binary."""
        func_node = self.binary_node.get_function_by_ea(ea)
        if func_node is None:
            raise ValueError(f"Function with EA {hex(ea)} not found in binary {self.binary_node.name}")
        return func_node
    
    def get_node_by_name(self, name: str) -> FunctionNode:
        """
        Get FunctionNode by its name.
        First tries to find by symbol name, then falls back to decompiled name.
        """
        try:
            func_node = self.binary_node.get_function_by_name(name)
            if func_node:
                return func_node
        except (ValueError, RuntimeError):
            pass
        
        # Fallback: try to find by decompiled name using the cached map
        if name in self._decompiled_name_map:
            return self._decompiled_name_map[name]

        raise ValueError(f"Function with name {name} not found in binary {self.binary_node.name}")
    
    def has_node_by_name(self, name: str) -> bool:
        """Check if a FunctionNode with the given name exists in the CallGraph.

        Checks both original symbol names and decompiled names to stay
        consistent with get_node_by_name's lookup behavior.
        """
        if self.binary_node.has_function_by_name(name):
            return True
        return name in self._decompiled_name_map
    
    def get_callers_of(self, func_node: FunctionNode) -> List[FunctionNode]:
        """Get the list of caller FunctionNodes for a given FunctionNode.

        Args:
            func_node: The FunctionNode to find callers for
        Returns:
            List[FunctionNode]: List of caller function nodes
        """
        return list(self.get_predecessors_by_type(func_node, EdgeType.CALL))

    def get_structural_callees_of(
        self, func_node: FunctionNode,
    ) -> List[FunctionNode]:
        """Return only IDA auto-analysis callees for ``func_node``.

        The normal graph may later contain CTree-supplemented CALL edges. This
        accessor keeps add-binary consumers independent of cached decompiler
        state.
        """
        callees: List[FunctionNode] = []
        for callee_ea in func_node.get_structural_callees():
            callee = self.binary_node.all_funcs.get(callee_ea)
            if callee is not None:
                callees.append(callee)
        return callees

    def dump_decompiled_code(self, decompiled_code_dir: Path,
                             mark_callsites: bool = False) -> None:
        """Dump processed decompiled code for every analysis node in this
        binary's CallGraph to `decompiled_code_dir / <module> / <name>.c`.
        Existing matching files are reused; stale content is atomically
        replaced directly from the semantic snapshot.
        """
        expected_paths: set[Path] = set()
        for func_node in self._artifact_nodes():

            module_path = (decompiled_code_dir / f"{func_node.module}").resolve()
            decompiled_code_path = (
                module_path / f"{func_node.artifact_stem}.c"
            ).resolve()
            if decompiled_code_path in expected_paths:
                raise RuntimeError(
                    f"Duplicate decompiled artifact stem in "
                    f"{self.binary_node.name}: {decompiled_code_path.name}"
                )
            expected_paths.add(decompiled_code_path)
            code = func_node.get_processed_decompiled_code(
                with_line_numbers=False,
                replace_cast=True,
                replace_gvar=True,
                mark_callsites=mark_callsites,
            )
            expected_lines = len(func_node.semantic_snapshot.rendered_code.splitlines())
            if len(code.splitlines()) != expected_lines:
                raise RuntimeError(
                    f"Rendered C line count drift for {func_node.name}: "
                    f"expected {expected_lines}, got {len(code.splitlines())}"
                )
            if (
                decompiled_code_path.exists()
                and decompiled_code_path.read_text(encoding="utf-8") == code
            ):
                continue

            module_path.mkdir(parents=True, exist_ok=True)
            self._atomic_write_text(decompiled_code_path, code)
            logger.debug(
                f"Decompiled code for {func_node.name} saved to "
                f"{decompiled_code_path}"
            )

        module_path = (decompiled_code_dir / self.binary_node.name).resolve()
        if module_path.exists():
            for stale_path in module_path.glob("*.c"):
                if stale_path.resolve() not in expected_paths:
                    stale_path.unlink()

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        fd, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary_path.replace(path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    def dump_disassembled_code(
        self,
        disassembled_code_dir: Path,
        *,
        artifact_level: Literal["structural", "semantic"] = "semantic",
    ) -> None:
        """Publish IDA listings without invoking Hex-Rays.

        Structural publication covers every non-external IDA function and uses
        ``<IDA symbol>@<EA>.s``. Semantic publication uses the C-paired stems
        for functions selected by deep analysis, including explicit Hex-Rays
        failures. Both sets can be referenced by live consumers: publication
        does not delete listings outside its selection. Workspace cleanup owns
        their lifetime; required listings are checked against the source hash.
        """
        if artifact_level == "structural":
            functions = self._structural_artifact_nodes()
            stem_for = lambda function: function.structural_artifact_stem
        else:
            functions = [
                function
                for function in self._nodes_for_analysis
                if not function.has_attr(FunctionAttr.EXTERNAL)
            ]
            stem_for = lambda function: function.artifact_stem

        any_dumped = False
        expected_paths: set[Path] = set()
        try:
            for func_node in functions:
                module_path = (
                    disassembled_code_dir / f"{func_node.module}"
                ).resolve()
                disassembly_path = (
                    module_path / f"{stem_for(func_node)}.s"
                ).resolve()
                if disassembly_path in expected_paths:
                    raise RuntimeError(
                        f"Duplicate {artifact_level} disassembly stem in "
                        f"{self.binary_node.name}: {disassembly_path.name}"
                    )
                expected_paths.add(disassembly_path)
                if disassembly_path.exists():
                    existing = disassembly_path.read_text(encoding="utf-8")
                    source_sha256 = getattr(
                        self.binary_node, "_source_sha256", None,
                    )
                    identity_matches = (
                        not isinstance(source_sha256, str)
                        or not source_sha256
                        or f"; source_sha256: {source_sha256}" in existing
                    )
                    if existing.strip() and identity_matches:
                        continue

                if not any_dumped:
                    self.binary_node.activate()
                    any_dumped = True

                listing = func_node.get_disassembly()
                module_path.mkdir(parents=True, exist_ok=True)
                self._atomic_write_text(disassembly_path, listing)
                logger.debug(
                    f"Disassembly for {func_node.name} saved to "
                    f"{disassembly_path}"
                )
        finally:
            if any_dumped:
                self.binary_node.deactivate()

    def dump_string_xrefs(self, xref_dir: Path) -> None:
        """Dump the binary's string → [function xref] index to
        ``xref_dir / <module> / string_xrefs.json``.

        This reads IDA strings and data xrefs only; it is deliberately
        independent of Hex-Rays and belongs to structural analysis.
        """
        extractor = getattr(self.binary_node, "extract_string_xrefs", None)
        if extractor is None:
            raise RuntimeError(
                f"[{self.binary_node.name}] decompiler does not expose "
                "extract_string_xrefs"
            )

        module_path = (xref_dir / f"{self.binary_node.name}").resolve()
        json_path = module_path / "string_xrefs.json"
        if json_path.exists():
            try:
                cached = json.loads(json_path.read_text(encoding="utf-8"))
                if self._valid_string_xref_index(cached):
                    return
            except (OSError, json.JSONDecodeError):
                pass

        self.binary_node.activate()
        try:
            xrefs = extractor()
        finally:
            self.binary_node.deactivate()

        module_path.mkdir(parents=True, exist_ok=True)
        self._atomic_write_text(
            json_path,
            json.dumps(xrefs, indent=2, ensure_ascii=False),
        )
        logger.info(
            f"[{self.binary_node.name}] string xref index written: "
            f"{len(xrefs)} unique strings at {json_path}"
        )

    @staticmethod
    def _valid_string_xref_index(value: object) -> bool:
        """Recognize the structural-xref schema required by peer matching."""
        if not isinstance(value, dict):
            return False
        for string_value, hits in value.items():
            if not isinstance(string_value, str) or not isinstance(hits, list):
                return False
            for hit in hits:
                if not isinstance(hit, dict) or not {
                    "func", "func_ea", "ea",
                } <= hit.keys():
                    return False
        return True

    def dump_global_var_xrefs(
        self,
        xref_dir: Path,
        *,
        include_semantic_aliases: bool,
    ) -> None:
        """Dump the binary's global-var → [function xref] index to
        ``xref_dir / <module> / global_var_xrefs.json``.

        Raw IDA names and data xrefs are available structurally.  CTree-only
        aliases such as ``dword_XXXX`` are added only when
        ``include_semantic_aliases`` is true after decompilation.

        Builds ``func_globals`` (EA → list of decompiler-emitted aliases)
        from the concretized function nodes and passes it to the
        extractor. Without this, the on-disk index would have the right
        EAs but no key under the ``dword_XXXX`` / ``byte_XXXX`` form
        that the agent's ``find_global_var_xref`` tool actually queries.
        """
        extractor = getattr(self.binary_node, "extract_global_var_xrefs", None)
        if extractor is None:
            raise RuntimeError(
                f"[{self.binary_node.name}] decompiler does not expose "
                "extract_global_var_xrefs"
            )

        module_path = (xref_dir / f"{self.binary_node.name}").resolve()
        json_path = module_path / "global_var_xrefs.json"
        if not include_semantic_aliases and json_path.exists():
            try:
                if isinstance(
                    json.loads(json_path.read_text(encoding="utf-8")), dict
                ):
                    return
            except (OSError, json.JSONDecodeError):
                pass

        func_globals: Dict[int, List[str]] = {}
        if include_semantic_aliases:
            # Mirror deep_analysis's func_globals collection: aggregate every
            # CTree alias observed for each EA after decompilation.
            for func_node in self._nodes_for_analysis:
                if not getattr(func_node, "concretized", False):
                    continue
                for ea, name in func_node._global_vars.items():
                    aliases = func_globals.setdefault(ea, [])
                    if name not in aliases:
                        aliases.append(name)

        self.binary_node.activate()
        try:
            xrefs = extractor(func_globals)
        finally:
            self.binary_node.deactivate()

        module_path.mkdir(parents=True, exist_ok=True)
        self._atomic_write_text(
            json_path,
            json.dumps(xrefs, indent=2, ensure_ascii=False),
        )
        logger.info(
            f"[{self.binary_node.name}] global var xref index written: "
            f"{len(xrefs)} unique alias keys at {json_path}"
        )

    def verify_artifacts(
        self,
        decompiled_code_dir: Path,
        disassembled_code_dir: Path,
    ) -> None:
        """Verify the complete C/S/xref artifact contract for one binary."""
        expected_c_stems = {
            function.artifact_stem
            for function in self._artifact_nodes()
        }
        expected_s_stems = {
            function.artifact_stem
            for function in self._nodes_for_analysis
            if not function.has_attr(FunctionAttr.EXTERNAL)
        }
        c_dir = (decompiled_code_dir / self.binary_node.name).resolve()
        s_dir = (disassembled_code_dir / self.binary_node.name).resolve()
        actual_c = {path.stem for path in c_dir.glob("*.c")}
        actual_s = {path.stem for path in s_dir.glob("*.s")}
        # Structural consumers and earlier selections may still reference other
        # assembly listings. Verify the required semantic set, not sole ownership.
        if actual_c != expected_c_stems or not expected_s_stems <= actual_s:
            raise RuntimeError(
                f"Incomplete C/S artifacts for {self.binary_node.name}: "
                f"expected_C={sorted(expected_c_stems)}, C={sorted(actual_c)}, "
                f"expected_S={sorted(expected_s_stems)}, S={sorted(actual_s)}"
            )
        for function in self._artifact_nodes():
            snapshot = function.semantic_snapshot
            semantic_errors = snapshot.integrity_errors()
            callsites = function.get_callsites()
            if set(snapshot.callsites) != set(callsites):
                semantic_errors.append("snapshot/function callsite keys differ")
            for ctree_index, info in snapshot.callsites.items():
                callsite = callsites.get(ctree_index)
                if callsite is None:
                    continue
                location = info.location
                if (
                    not callsite.is_populated
                    or callsite.identity_key
                    != (
                        snapshot.binary_identity,
                        snapshot.function_ea,
                        snapshot.snapshot_hash,
                        ctree_index,
                    )
                    or location is None
                    or callsite.source_ea != location.source_ea
                    or callsite.callee_ea != (info.callee_ea or 0)
                    or [argument.index for argument in callsite.args]
                    != list(range(1, len(info.arguments) + 1))
                ):
                    semantic_errors.append(
                        f"call {ctree_index}: Function/CallSite mapping drift"
                    )
            if semantic_errors:
                raise RuntimeError(
                    f"Invalid semantic snapshot for {self.binary_node.name}::"
                    f"{function.decompiled_name}: " + "; ".join(semantic_errors)
                )
            c_path = c_dir / f"{function.artifact_stem}.c"
            expected = function.get_processed_decompiled_code()
            if c_path.read_text(encoding="utf-8") != expected:
                raise RuntimeError(f"C artifact hash mismatch: {c_path}")
        for function in self._nodes_for_analysis:
            if function.has_attr(FunctionAttr.EXTERNAL):
                continue
            s_path = s_dir / f"{function.artifact_stem}.s"
            listing = s_path.read_text(encoding="utf-8")
            if not listing.strip():
                raise RuntimeError(f"Empty disassembly artifact: {s_path}")
            source_sha256 = getattr(self.binary_node, "_source_sha256", None)
            if (
                isinstance(source_sha256, str)
                and source_sha256
                and f"; source_sha256: {source_sha256}" not in listing
            ):
                raise RuntimeError(
                    f"Stale disassembly artifact for {source_sha256}: {s_path}"
                )
        for name in ("string_xrefs.json", "global_var_xrefs.json"):
            path = c_dir / name
            if not path.is_file() or not isinstance(
                json.loads(path.read_text(encoding="utf-8")), dict
            ):
                raise RuntimeError(f"Invalid xref artifact: {path}")

    def __getstate__(self):
        """Prepare for serialization.

        binary_node is NOT included — CallGraph is serialized as part of
        its parent BinaryNode's pickle stream, which handles the
        BinaryNode ↔ CallGraph relationship and preserves FunctionNode
        identity via pickle's memo mechanism.
        """
        from ..nodes.decompiler.ida.idb_manager import IDBManager

        # Close all open IDBs to avoid file handle leaks
        IDBManager.close_current_idb()

        # Serialize the NetworkX graph structure with edge data
        graph_data = nx.node_link_data(self._graph, edges="edges")

        return {
            'cache_schema_version': CALL_GRAPH_CACHE_SCHEMA_VERSION,
            'graph_data': graph_data,
            'global_config': self.global_config,
            'external_funcs': self.external_funcs,
            "reverse_topological_sorted_nodes": self._reverse_topological_sorted_nodes,
            'nodes_for_analysis': self._nodes_for_analysis,
            '_decompiled_name_map': self._decompiled_name_map,
            'semantic_failures': self._semantic_failures,
            'structural_complete': self._structural_complete,
            'semantic_complete': self._semantic_complete,
        }

    def __setstate__(self, state):
        """Restore from serialization.

        binary_node is set to None here — the parent BinaryNode's
        __setstate__ reattaches itself via ``self._call_graph.binary_node = self``.
        """
        # Restore the NetworkX graph from serialized data
        self._graph = nx.node_link_graph(state['graph_data'], edges="edges")
        self._cache_schema_version = state.get('cache_schema_version', 0)
        # binary_node reattached by parent BinaryNode.__setstate__
        self.binary_node = None
        self.external_funcs = state['external_funcs']
        self.global_config = state['global_config']
        self._reverse_topological_sorted_nodes = state["reverse_topological_sorted_nodes"]
        self._nodes_for_analysis = list(dict.fromkeys(state['nodes_for_analysis']))
        self._semantic_failures = state.get('semantic_failures', {})
        # Existing cache schema-5 graphs were always created by the former
        # combined build path, so they are both structurally and semantically
        # complete. New structural-only graphs persist the flags explicitly.
        self._structural_complete = state.get('structural_complete', True)
        self._semantic_complete = state.get(
            'semantic_complete',
            bool(self._nodes_for_analysis or self._semantic_failures),
        )
        if '_decompiled_name_map' in state:
            self._decompiled_name_map = state['_decompiled_name_map']
        else:
            self._build_decompiled_name_map()
