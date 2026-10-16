from __future__ import annotations

import pickle
from abc import ABC, abstractmethod
from typing import Literal, TYPE_CHECKING
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from loguru import logger

from .function import FunctionNode

if TYPE_CHECKING:
    from ..graphs.call_graph import CallGraph


class BinaryNode(ABC):
    decompiler: Literal["ida", "ghidra"] = None

    # Structural CallGraph is populated by LibDepGraph.add_binary(); semantic
    # snapshots and source artifacts are added later by decompile_analysis().
    # _call_graph is included in __getstate__ so that BinaryNode and its
    # CallGraph share the same pickle stream (preserving FunctionNode
    # identity via pickle's memo mechanism).
    _call_graph: Optional["CallGraph"] = None
    # Disk artifacts are verified on every cache load and therefore this flag
    # is intentionally never serialized.
    _artifacts_ready: bool = False

    # C++ support remains outside the current function-name/data-flow contract.
    _is_cxx_unsupported: bool = False

    @property
    def is_cxx_unsupported(self) -> bool:
        return self._is_cxx_unsupported

    @staticmethod
    def _detect_cxx_unsupported(elf_path: Path) -> bool:
        """Return True if binary contains unsupported C++ content.

        Any of the following signals flips the flag:
          1. DT_NEEDED contains libstdc++ or libc++
          2. .dynsym contains C++ ABI runtime symbols (__cxa_*)
          3. Ratio of mangled (_Z*) defined function symbols > 5%
        """
        import lief
        binary = lief.parse(str(elf_path))
        if binary is None:
            return False

        for dependency in getattr(binary, "libraries", []):
            # ELF exposes library names as strings, while LIEF's Mach-O
            # backend exposes DylibCommand objects. Host-side fixture scans
            # must remain harmless when a macOS binary is supplied.
            dep_name = getattr(dependency, "name", str(dependency))
            if "libstdc++" in dep_name or "libc++" in dep_name:
                return True

        try:
            dyn_syms = list(binary.dynamic_symbols)
        except Exception:
            return False

        cxa_runtime = {
            "__cxa_throw", "__cxa_allocate_exception",
            "__cxa_begin_catch", "__cxa_rethrow", "__cxa_guard_acquire",
        }
        for sym in dyn_syms:
            if sym.name in cxa_runtime:
                return True

        try:
            defined_funcs = [
                s for s in dyn_syms
                if int(s.shndx) != 0 and s.type == lief.ELF.Symbol.TYPE.FUNC
            ]
        except Exception:
            return False
        if not defined_funcs:
            return False
        mangled = sum(1 for s in defined_funcs if s.name.startswith("_Z"))
        return (mangled / len(defined_funcs)) > 0.05

    @property
    def call_graph(self) -> "CallGraph":
        if self._call_graph is None:
            raise RuntimeError(
                f"Binary {self.name} has no structural CallGraph. "
                f"Call LibDepGraph.add_binary() first."
            )
        return self._call_graph

    @property
    def structural_ready(self) -> bool:
        return (
            self._call_graph is not None
            and self._call_graph.structural_ready
        )

    @property
    def has_decompiled_artifacts(self) -> bool:
        """Whether CTree semantics and their published C/S artifacts exist."""
        return (
            self._call_graph is not None
            and self._call_graph.semantic_ready
            and self._artifacts_ready
        )

    @property
    def semantic_ready(self) -> bool:
        return self._call_graph is not None and self._call_graph.semantic_ready

    @staticmethod
    def set_decompiler(decompiler: Literal["ida", "ghidra"],
                       decompiler_workdir: Path = None):
        BinaryNode.decompiler = decompiler
        if decompiler == "ida":
            if decompiler_workdir is None:
                raise ValueError("IDA workdir must be provided when using IDA decompiler")
            from .decompiler.ida.ida_binary import IDABinary
            IDABinary.set_workdir(decompiler_workdir)
            # Restored CallGraphs bypass build_fast(); function teardown must
            # still use the backend selected for this graph session.
            FunctionNode.set_decompiler(decompiler)
        else:
            raise NotImplementedError(f"Decompiler {decompiler} not supported yet")

    @staticmethod
    def create(binary_path: Path):
        if BinaryNode.decompiler == "ida":
            from .decompiler.ida import IDABinary
            return IDABinary.create(binary_path)
        else:
            raise NotImplementedError(f"Decompiler {BinaryNode.decompiler} not supported yet")    

    @property
    @abstractmethod
    def name(self):
        pass

    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        pass
    
    @property
    @abstractmethod
    def external_funcs(self) -> Dict[int, FunctionNode]:
        pass
    
    @property
    @abstractmethod
    def exported_funcs(self) -> Dict[int, FunctionNode]:
        pass
    
    @property
    @abstractmethod
    def all_funcs(self) -> Dict[int, FunctionNode]:
        """Get all functions in the binary (external, text, plt, etc.)."""
        pass

    @abstractmethod
    def activate(self):
        """Open the corresponding IDB/Ghidra database, so the following analysis can be performed."""
        pass

    @abstractmethod
    def deactivate(self):
        """Close the corresponding IDB/Ghidra database."""
        pass

    @abstractmethod
    def get_function_by_name(self, func_name: str) -> FunctionNode:
        pass

    @abstractmethod
    def get_function_by_ea(self, func_ea: int) -> FunctionNode:
        pass

    @abstractmethod
    def has_function_by_name(self, func_name: str) -> bool:
        pass

    @abstractmethod
    def find_thunk_funcs(self, target_func: FunctionNode) -> List[FunctionNode]:
        """Find all thunk functions that call the given target function."""
        pass

    @abstractmethod
    def find_thunk_target(self, thunk_func: FunctionNode) -> FunctionNode:
        """Find the target function that the given thunk function calls."""
        pass

    @abstractmethod
    def get_global_string(self, gvar_name: str, parse_as_string: bool = False) -> str:
        pass

    @abstractmethod
    def resolve_all_global_values(
        self,
        func_globals: Dict[int, List[str]] = None,
    ):
        """Resolve global variable values from symbol names and
        function-level globals.

        ``func_globals`` maps each EA observed in any concretized
        function to the list of ALL aliases any function used for that
        EA. Different functions can see the same memory with different
        IDA auto-generated type prefixes (``dword_XXX``, ``byte_XXX``,
        ``unk_XXX``) depending on how each function's decompiled
        expression dereferenced it; every alias must resolve to the
        same underlying value at the binary level.

        Must be called while the database is open.
        """
        pass

    @abstractmethod
    def get_global_var_value(self, original_name: str) -> Optional[Tuple[str, str]]:
        """Lookup a pre-resolved global variable value. No database access needed."""
        pass

    @abstractmethod
    def __getstate__(self):
        pass

    @abstractmethod
    def __setstate__(self, state):
        pass

    # ------------------------------------------------------------------
    # Per-binary cache — BinaryNode + CallGraph in a single pickle stream
    # ------------------------------------------------------------------

    def save_cache(self, cache_dir: Path) -> None:
        """Save this BinaryNode (with its CallGraph if available) to a
        per-binary cache file. Since both objects share the same pickle
        stream, FunctionNode object identity is automatically preserved."""
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{self.name}.pkl"
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)
            cache_size = cache_file.stat().st_size / (1024 * 1024)
            logger.debug(f"Saved binary cache for {self.name} ({cache_size:.2f} MB)")
        except Exception as e:
            logger.error(f"Failed to save binary cache for {self.name}: {e}")
            if cache_file.exists():
                cache_file.unlink()

    @staticmethod
    def load_cache(
        name: str,
        cache_dir: Path,
        expected_binary_path: Path | None = None,
    ) -> Optional["BinaryNode"]:
        """Load a BinaryNode from per-binary cache. Returns None on cache miss."""
        cache_file = cache_dir / f"{name}.pkl"
        if not cache_file.exists():
            return None
        # Cache files are portable across checkouts as long as the source ELF
        # is unchanged. IDAFunction objects are restored before IDABinary's
        # own __setstate__, so install this short-lived context while the
        # pickle is being reconstructed. The IDA adapter consumes it to
        # rebind old absolute source/IDB paths, then clears it here.
        rebase_manager = None
        if expected_binary_path is not None:
            try:
                from .decompiler.ida.idb_manager import IDBManager
                from .decompiler.ida.ida_binary import IDABinary
                rebase_manager = IDBManager
                rebase_manager.begin_cache_rebase(
                    expected_binary_path,
                    IDABinary.workdir,
                )
            except Exception:
                # Non-IDA backends and test doubles do not need rebasing.
                rebase_manager = None
        try:
            with open(cache_file, 'rb') as f:
                binary = pickle.load(f)
            cache_size = cache_file.stat().st_size / (1024 * 1024)
            logger.info(
                f"Loaded binary cache for {name} ({cache_size:.2f} MB, "
                f"call_graph={'yes' if binary._call_graph is not None else 'no'})"
            )
            return binary
        except Exception as e:
            logger.error(f"Failed to load binary cache for {name}: {e}")
            if cache_file.exists():
                cache_file.unlink()
            return None
        finally:
            if rebase_manager is not None:
                rebase_manager.end_cache_rebase()
