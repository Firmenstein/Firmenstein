import idapro  # Initialize native bindings at the backend boundary.
from ida_domain.database import IdaCommandOptions
from ida_domain.functions import FunctionFlags
import hashlib
import ida_name
import ida_bytes
import idaapi
import ida_segment
import idautils
import subprocess
from loguru import logger
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ida_function import IDAFunction
from .idb_manager import IDBManager
from ... import BinaryNode, FunctionAttr
from ....global_config import GlobalConfig

IDA_BINARY_LAYOUT_SCHEMA_VERSION = 2

class IDABinary(BinaryNode):
    ida_binary_cache: Dict[Tuple[Path, Path], 'IDABinary'] = {}
    workdir = None

    @staticmethod
    def set_workdir(workdir: Path):
        resolved = Path(workdir).absolute().resolve()
        if IDABinary.workdir is not None and IDABinary.workdir != resolved:
            IDABinary.clear_cache()
        IDABinary.workdir = resolved

    @classmethod
    def clear_cache(cls):
        """Clear the in-memory IDABinary cache.

        Should be called when the decompiler DB cache on disk is cleared
        (e.g. --clear-decompiler-db-cache) to avoid returning stale
        instances whose IDB files no longer exist.
        """
        IDBManager.close_current_idb()
        cls.ida_binary_cache.clear()
        IDAFunction.clear_cache()

    @staticmethod
    def create(binary_path: Path) -> 'IDABinary':
        if IDABinary.workdir is None:
            raise RuntimeError("IDA workdir is not configured")
        binary_path = Path(binary_path).absolute().resolve()
        cache_key = (binary_path, IDABinary.workdir)
        if cache_key in IDABinary.ida_binary_cache:
            cached = IDABinary.ida_binary_cache[cache_key]
            if not hasattr(cached, "idb_path"):
                return cached
            if (
                cached.idb_path.exists()
                and cached._source_sha256 == IDABinary._sha256_file(binary_path)
            ):
                logger.debug(f"Using cached IDA database for {binary_path}")
                return cached
            IDBManager.close_current_idb()
            IDAFunction.clear_cache()
            del IDABinary.ida_binary_cache[cache_key]
        
        # Different guest files may share a basename (including peer programs
        # outside the target graph). Never replace another live object's IDB.
        source_hash = IDABinary._sha256_file(binary_path)
        idb_path = IDABinary.workdir / source_hash / (binary_path.name + ".i64")
        idb_path.parent.mkdir(parents=True, exist_ok=True)
        ida_binary = IDABinary(binary_path, idb_path)
        IDABinary.ida_binary_cache[cache_key] = ida_binary
        return ida_binary

    def __init__(self, binary_path: Path, idb_path: Path):
        self.binary_path = binary_path
        self.idb_path = idb_path
        self._source_sha256 = self._sha256_file(binary_path)
        self._binary_identity = (
            f"{binary_path.absolute().resolve()}:{self._source_sha256}"
        )
        self.ida_cmd_options = IdaCommandOptions(new_database=False)

        if idb_path.exists() and not self._idb_matches_source():
            logger.warning(
                f"IDA database input hash does not match {binary_path}; "
                f"recreating {idb_path}"
            )
            idb_path.unlink()

        if not idb_path.exists():
            logger.info(f"Creating new IDA database at {idb_path}")
            ida_cmd_options = IdaCommandOptions(
                auto_analysis=True, 
                new_database=True,
                output_database=str(idb_path),
                db_compression="pack"
            )
            IDBManager.create_idb(binary_path, idb_path, ida_cmd_options)
        else:
            logger.debug(f"IDA database existing at {idb_path}")

        self.arch = None
        self._dyn_libs: List[str] = []
        self._default_libs = False
        self._artifacts_ready = False

        self.segments: List[Tuple[str, int, int, int]] = []
        self._name_to_ea: Dict[str, Dict[int, IDAFunction]] = {}

        self._ea_to_func: Dict[int, IDAFunction] = {}
        self._text_funcs: Dict[int, IDAFunction] = {}
        self._exported_funcs: Dict[int, IDAFunction] = {}
        self._external_funcs: Dict[int, IDAFunction] = {}
        self._thunk_funcs: Dict[int, IDAFunction] = {}
        self._plt_funcs: Dict[int, IDAFunction] = {}

        self._thunk_to_target: Dict[IDAFunction, IDAFunction] = {}
        self._target_to_thunks: Dict[IDAFunction, List[IDAFunction]] = {}

        # Pre-resolved global variable values: original_name -> (type, repr)
        self._global_var_values: Dict[str, Tuple[str, str]] = {}

        try:
            self.arch = self.idb.architecture
            # The selected source path is the graph identity. IDA's optional
            # root filename may be absent (or stale after relocating an IDB).
            self._name = binary_path.name
            self._dyn_libs = self.__get_dynamic_libraries()

            logger.info(f"Binary {self.name} has architecture {self.arch}")
            if any(default_lib in binary_path.name for default_lib in GlobalConfig.DEFAULT_LIB):
                self._default_libs = True
                logger.debug(f"{binary_path.name} is identified as a default library")

            self._is_cxx_unsupported = BinaryNode._detect_cxx_unsupported(binary_path)
            if self._is_cxx_unsupported:
                logger.warning(
                    f"{binary_path.name} is detected as a C++ binary. "
                    f"Firmenstein does not currently support C++ analysis; "
                    f"this binary will be skipped during decompile analysis."
                )

            # Do initial analysis ...
            self.traverse_segments()
            self.traverse_functions()
            if (
                not self._default_libs
                and not self._is_cxx_unsupported
                and not self._text_funcs
            ):
                raise RuntimeError(
                    f"IDA found no executable functions in {binary_path}; "
                    "refusing an empty semantic analysis"
                )
        finally:
            IDBManager.close_current_idb()

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _idb_matches_source(self) -> bool:
        """Compare a loaded IDB's input hash; propagate native load/read failures.

        Only a successfully read, different identity is a cache mismatch.
        A native failure says nothing about the on-disk IDB and must not
        cause the caller to delete and recreate it.
        """
        try:
            IDBManager.open_idb(self.idb_path, self.ida_cmd_options)
            import ida_nalt

            stored = ida_nalt.retrieve_input_file_sha256()
            if not stored:
                raise RuntimeError(
                    f"IDA database lost its input SHA256: {self.idb_path}; "
                    "cannot determine whether the existing IDB matches its source"
                )
            return stored.hex() == self._source_sha256
        finally:
            IDBManager.close_current_idb()

    @property
    def name(self) -> str:
        return self._name

    @property
    def dyn_libs(self) -> List[str]:
        return self._dyn_libs
    
    @property
    def dependencies(self) -> List[str]:
        return self._dyn_libs
    
    @property
    def external_funcs(self) -> Dict[int, IDAFunction]:
        return self._external_funcs
    
    @property
    def text_funcs(self) -> Dict[int, IDAFunction]:
        return self._text_funcs

    @property
    def thunk_funcs(self) -> Dict[int, IDAFunction]:
        return self._thunk_funcs
    
    @property
    def plt_funcs(self) -> Dict[int, IDAFunction]:
        return self._plt_funcs
    
    @property
    def exported_funcs(self) -> Dict[int, IDAFunction]:
        return self._exported_funcs
    
    @property
    def all_funcs(self) -> Dict[int, IDAFunction]:
        """Get all functions in the binary (external, text, plt, etc.)."""
        return self._ea_to_func
    
    def traverse_segments(self):
        for seg in self.idb.segments:
            seg_name = self.idb.segments.get_name(seg)
            self.segments.append(
                (seg_name, seg.start_ea, seg.end_ea, int(seg.perm))
            )
            logger.debug(f"Segment: {seg_name} at {hex(seg.start_ea)} - {hex(seg.end_ea)}")
    
    def traverse_functions(self):
        for seg_name, seg_start_ea, seg_end_ea, seg_perm in self.segments:
            if seg_name == "extern":
                funcs = self.idb.functions.get_between(seg_start_ea, seg_end_ea)
                for func in funcs:
                    func_name = func.name
                    func_ea = func.start_ea
                    func_type = FunctionAttr.EXTERNAL
                    func_obj = IDAFunction.create(
                        self.name, func_ea, func_name, func_type,
                        self.idb_path, self._binary_identity,
                    )
                    self._external_funcs[func_ea] = func_obj
                    self._ea_to_func[func_ea] = func_obj
                    self._name_to_ea.setdefault(func_name, {})[func_ea] = func_obj

            elif seg_name.startswith(".plt"):
                funcs = self.idb.functions.get_between(seg_start_ea, seg_end_ea)
                for func in funcs:
                    func_type = FunctionAttr.PLT
                    is_thunk = self.idb.functions.get_flags(func) & FunctionFlags.THUNK
                    if is_thunk:
                        func_type |= FunctionAttr.THUNK
                    func_name = func.name
                    func_ea = func.start_ea
                    func_obj = IDAFunction.create(
                        self.name, func_ea, func_name, func_type,
                        self.idb_path, self._binary_identity,
                    )
                    self._plt_funcs[func_ea] = func_obj
                    self._ea_to_func[func_ea] = func_obj
                    self._name_to_ea.setdefault(func_name, {})[func_ea] = func_obj

                    if is_thunk:
                        self._thunk_funcs[func_ea] = func_obj

            elif seg_name == ".text" or seg_perm & ida_segment.SEGPERM_EXEC:
                funcs = self.idb.functions.get_between(seg_start_ea, seg_end_ea)
                for func in funcs:
                    func_name = func.name
                    func_ea = func.start_ea
                    func_type = FunctionAttr.TEXT
                    is_export = ida_name.is_public_name(func_ea)
                    func_type |= (
                        FunctionAttr.EXPORTED if is_export else FunctionAttr.LOCAL
                    )
                    is_thunk = self.idb.functions.get_flags(func) & FunctionFlags.THUNK
                    if is_thunk:
                        func_type |= FunctionAttr.THUNK
                    func_obj = IDAFunction.create(
                        self.name, func_ea, func_name, func_type,
                        self.idb_path, self._binary_identity,
                    )
                    self._text_funcs[func_ea] = func_obj
                    self._ea_to_func[func_ea] = func_obj
                    self._name_to_ea.setdefault(func_name, {})[func_ea] = func_obj
                    if is_thunk:
                        self._thunk_funcs[func_ea] = func_obj
                    if is_export:
                        self._exported_funcs[func_ea] = func_obj
            
        # build thunk to target mapping
        for thunk_ea, thunk_func in self._thunk_funcs.items():
            callees = self.idb.functions.get_callees(self.idb.functions.get_at(thunk_ea))
            if len(callees) != 1:
                # IDA marks some architecture-specific import stubs as
                # thunks even when it cannot resolve their destination.
                # Keep the function and its THUNK attribute, but do not
                # invent a target edge or abort the whole binary.
                logger.warning(
                    f"Unresolved thunk {thunk_func.name} at {hex(thunk_ea)}: "
                    f"expected one target, found {len(callees)}"
                )
                continue
            target_ea = callees[0].start_ea
            try:
                target_func = self.get_function_by_ea(target_ea)
            except RuntimeError:
                logger.warning(
                    f"Unresolved thunk {thunk_func.name} at {hex(thunk_ea)}: "
                    f"target {hex(target_ea)} is not a known function"
                )
                continue
            self._thunk_to_target[thunk_func] = target_func
            if target_func not in self._target_to_thunks:
                self._target_to_thunks[target_func] = []
            self._target_to_thunks[target_func].append(thunk_func)
                
        logger.info(f"Total external functions found: {len(self._external_funcs)}")
        logger.info(f"Total text functions found: {len(self._text_funcs)}")
    
    def find_thunk_funcs(self, target_func):
        return self._target_to_thunks.get(target_func, [])
    
    def find_thunk_target(self, thunk_func):
        return self._thunk_to_target.get(thunk_func, None)

    def get_function_by_ea(self, func_ea: int) -> IDAFunction:
        if func_ea in self._ea_to_func:
            return self._ea_to_func[func_ea]
        else:
            raise RuntimeError(f"Function at address {hex(func_ea)} not found in binary {self.name}")

    def get_function_by_name(self, func_name: str) -> IDAFunction:
        # Check if it's func_name@address format
        if '@' in func_name:
            base_name, addr_str = func_name.rsplit('@', 1)
            try:
                addr = int(addr_str, 16)  # Convert hex string to int
                if base_name in self._name_to_ea and addr in self._name_to_ea[base_name]:
                    return self._name_to_ea[base_name][addr]
                else:
                    raise RuntimeError(f"Function '{func_name}' not found in binary {self.name}")
            except ValueError:
                raise RuntimeError(f"Invalid address format in '{func_name}'. Expected hex format like 'func@0x401000'")
        
        # Check base function name
        if func_name not in self._name_to_ea:
            raise RuntimeError(f"Function name '{func_name}' not found in binary {self.name}")
        
        func_dict = self._name_to_ea[func_name]
        if len(func_dict) == 1:
            # Only one function with this name, return it
            return next(iter(func_dict.values()))
        else:
            # Multiple functions with same name, require specific address
            addrs = [hex(addr) for addr in func_dict.keys()]
            raise RuntimeError(f"Function name '{func_name}' is duplicated at addresses: {addrs}. "
                               f"Please use func_name@address format instead. For example, '{func_name}@{addrs[0]}'")
        
    def has_function_by_name(self, func_name: str) -> bool:
        """Check if a function exists by name.
        
        Args:
            func_name: Function name, can be in 'func_name@0xaddress' format
            
        Returns:
            True if function exists, False otherwise
        """
        # Check if it's func_name@address format
        if '@' in func_name:
            base_name, addr_str = func_name.rsplit('@', 1)
            try:
                addr = int(addr_str, 16)  # Convert hex string to int
                return base_name in self._name_to_ea and addr in self._name_to_ea[base_name]
            except ValueError:
                return False
        
        # Check base function name
        return func_name in self._name_to_ea
    
    def extract_string_xrefs(
        self, min_length: int = 3
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Enumerate all string literals in the binary and collect the
        functions that reference them (data xrefs).

        Requires the IDB to be open — callers should wrap with
        ``activate()`` / ``deactivate()`` or call via a context that
        already holds the IDB open (e.g. ``dump_decompiled_code``'s
        active block).

        Returns a mapping ``{string_value: [{"func": name, "func_ea": hex,
        "ea": hex}, ...]}``. Strings shorter than ``min_length`` (default 3) are
        skipped — alignment with the deterministic named-constant index upstream.
        Strings that have no xrefs from inside any function are also
        skipped since they are indistinguishable from dead metadata
        for peer-matching purposes.
        """
        _ = self.idb  # activate lazily
        xrefs: Dict[str, List[Dict[str, Any]]] = {}
        n_strings = 0
        n_with_xrefs = 0
        for s in idautils.Strings():
            n_strings += 1
            if s.length is None or s.length < min_length:
                continue
            try:
                text = str(s)
            except Exception:
                continue
            if not text:
                continue
            local_hits: List[Dict[str, Any]] = []
            seen_eas = set()
            # DataRefsTo restricts to data references only. Code
            # xrefs to a string's address are essentially unheard-of
            # (you don't branch into a string), but being explicit
            # avoids pulling in any disassembler edge cases.
            for src_ea in idautils.DataRefsTo(s.ea):
                src_ea = int(src_ea)
                if src_ea in seen_eas:
                    continue
                seen_eas.add(src_ea)
                func = idaapi.get_func(src_ea)
                if func is None:
                    # Xref from data, not from a function — not useful
                    # for "where is this string used in code"
                    continue
                func_name = idaapi.get_func_name(func.start_ea) or ""
                if not func_name:
                    continue
                local_hits.append({
                    "func": func_name,
                    "func_ea": f"0x{int(func.start_ea):x}",
                    "ea": f"0x{src_ea:x}",
                })
            if local_hits:
                # Multiple string literals may share the same text
                # (duplicate strings in different .rodata slots); merge.
                existing = xrefs.setdefault(text, [])
                existing.extend(local_hits)
                n_with_xrefs += 1

        logger.info(
            f"[{self.name}] string xref index: {n_with_xrefs}/{n_strings} "
            f"strings with in-function xrefs"
        )
        return xrefs

    def extract_global_var_xrefs(
        self,
        func_globals: Optional[Dict[int, List[str]]] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Enumerate addressable items in writable data segments and
        collect the functions that reference them (data xrefs).

        Parallel of ``extract_string_xrefs`` but scoped to **mutable**
        globals — ``.data`` (initialized), ``.bss`` (zero-init),
        ``.tdata`` / ``.tbss`` (thread-local). ``.rodata`` is excluded:
        string literals and read-only constants there are already
        indexed by ``extract_string_xrefs``, and FileResolver's
        fd-propagation use case cares about mutable state (fd handles,
        state vars), never read-only constants. Requires the IDB to be
        open.

        Why two sources (``heads.get_between`` + ``func_globals``):
        IDA only stores user-/symbol-named addresses in
        ``names.get_all()``. Decompiler-synthesized auto-names like
        ``dword_XXXX``/``byte_XXXX``/``unk_XXXX`` are emitted per
        decompilation pass and never enter the names table — so any
        index that keys on ``names.get_all()`` alone silently misses
        every unnamed .bss/.data slot (including the cached fd / mmap
        ptr globals that FileResolver's fd-trace agent needs).

        Coverage strategy mirrors ``resolve_all_global_values``:
          * Source 1 — every head in writable data segments via
            ``heads.get_between``. Includes both named items
            (``aDevNvram``) and unnamed ones the decompiler refers to
            as ``dword_XXXX`` etc.
          * Source 2 — ``func_globals`` (optional) carries every alias
            the ctree visitor recorded for each EA across concretized
            functions. This is the source of the actual ``dword_XXXX``
            keys the agent later looks up. Without it, the index has
            the right EAs but only canonical IDA-name keys.

        Returns ``{var_name: [{"func": name, "ea": hex}, ...]}``.
        Functions/PLT/.rodata/.text are skipped. Downstream agent tool
        strips a leading ``GVar_`` prefix before lookup to match the
        analyzer's renamed form.
        """
        _ = self.idb  # activate lazily
        # .rodata excluded — already covered by string_xrefs.json, and
        # FileResolver tracks MUTABLE globals (fds, state).
        data_segments = {".data", ".bss", ".tdata", ".tbss"}
        func_globals = func_globals or {}

        # EA → list of aliases (order-preserving, deduped).
        ea_to_aliases: Dict[int, List[str]] = {}

        def _add_alias(ea: int, name: Optional[str]) -> None:
            bucket = ea_to_aliases.setdefault(ea, [])
            if name and name not in bucket:
                bucket.append(name)

        # Source 1: every head in writable data segments.
        for seg in self.idb.segments.get_all():
            seg_name = self.idb.segments.get_name(seg)
            if seg_name not in data_segments:
                continue
            for ea in self.idb.heads.get_between(seg.start_ea, seg.end_ea):
                ea = int(ea)
                # Reserve the bucket so source 2 can attach aliases
                # even when the head has no canonical IDA name.
                ea_to_aliases.setdefault(ea, [])
                user_name = self.idb.names.get_at(ea)
                if user_name:
                    _add_alias(ea, user_name)

        # Source 2: every alias the ctree visitor emitted across
        # concretized functions. Catches the dword_XXXX / byte_XXXX
        # auto-names the agent actually looks up.
        for ea, aliases in func_globals.items():
            for alias in aliases:
                _add_alias(ea, alias)

        xrefs: Dict[str, List[Dict[str, Any]]] = {}
        n_eas = 0
        n_with_xrefs = 0
        for ea, aliases in ea_to_aliases.items():
            n_eas += 1
            local_hits: List[Dict[str, Any]] = []
            seen_eas = set()
            for src_ea in idautils.DataRefsTo(ea):
                src_ea = int(src_ea)
                if src_ea in seen_eas:
                    continue
                seen_eas.add(src_ea)
                func = idaapi.get_func(src_ea)
                if func is None:
                    continue
                func_name = idaapi.get_func_name(func.start_ea) or ""
                if not func_name:
                    continue
                local_hits.append({
                    "func": func_name,
                    "ea": f"0x{src_ea:x}",
                })
            if not local_hits or not aliases:
                continue
            n_with_xrefs += 1
            for alias in aliases:
                xrefs.setdefault(alias, []).extend(local_hits)

        logger.info(
            f"[{self.name}] global var xref index: {n_with_xrefs}/{n_eas} "
            f"data EAs with in-function xrefs (across "
            f"{len(xrefs)} alias keys)"
        )
        return xrefs

    def get_global_string(self, gvar_name: str) -> str:
        self.activate()
        ea = ida_name.get_name_ea(idaapi.BADADDR, gvar_name)
        if ea == idaapi.BADADDR:
            logger.warning(f"Global variable not found {gvar_name} from {self.name}")
            return None

        result = self.idb.bytes.get_string_at(ea)
        if result is None or result == "":
            logger.debug(f"Failed to get string for global variable {gvar_name} at {hex(ea)} in {self.name}")
            return None
        return result

    def resolve_all_global_values(
        self,
        func_globals: Dict[int, List[str]] = None,
    ):
        """Resolve global variable values from two sources:
        1. idb.names.get_all() — real symbol names in data segments
        2. func_globals — ctree_visitor discovered globals from all
           functions (includes IDA auto-names like dword_XXX,
           byte_XXX, unk_XXX that names.get_all() misses)

        Different concretized functions can observe the same memory
        address with different IDA auto-generated type prefixes
        depending on how each function's decompiled expression
        dereferenced that memory (e.g., `*(int*)0x1A2134` →
        ``dword_1A2134`` while ``*(char*)0x1A2134`` → ``byte_1A2134``).
        ``func_globals`` therefore carries EVERY alias any function
        used at each EA; this method resolves the value once per EA
        and registers the result under all of that EA's aliases so
        that a subsequent name-based lookup always succeeds
        regardless of which function's naming context the caller has
        in hand.

        Must be called while IDB is open (before close_database()).
        """
        self._global_var_values = {}
        initialized_segments = {".data", ".rodata", ".tdata"}
        uninitialized_segments = {".bss", ".tbss"}
        all_data_segments = initialized_segments | uninitialized_segments

        # EA → list of aliases (order-preserving, deduped).
        globals_to_resolve: Dict[int, List[str]] = {}

        def _add_alias(ea: int, name: str) -> None:
            bucket = globals_to_resolve.setdefault(ea, [])
            if name not in bucket:
                bucket.append(name)

        # Source 1: named addresses in data segments (canonical symbols).
        for ea, name in self.idb.names.get_all():
            try:
                seg = self.idb.segments.get_at(ea)
            except Exception:
                continue
            seg_name = self.idb.segments.get_name(seg)
            if seg_name in all_data_segments:
                _add_alias(ea, name)

        # Source 2: every alias IDA emitted for each EA across all
        # concretized functions.
        if func_globals:
            for ea, aliases in func_globals.items():
                for alias in aliases:
                    _add_alias(ea, alias)

        # Resolve each EA once; register the result under every alias.
        # Defense-in-depth: every alias from any source is GUARANTEED
        # to appear in self._global_var_values, even when the
        # underlying value cannot be extracted. The reason is the
        # load-bearing invariant for downstream consumers — every name
        # referenced by any concretized function's _global_vars MUST
        # be findable here. If we instead silently dropped EAs whose
        # value resolution failed, we'd reintroduce the same class of
        # bug the alias collection was meant to fix, just on a
        # different axis.
        #
        # When the value cannot be extracted (segment lookup raised,
        # non-data segment, or the byte read failed), the alias is
        # registered with an ``("unresolved", "<reason>")`` sentinel.
        # The sentinel keeps the name-lookup invariant intact while
        # making the quality issue visible: ``test_global_vars``
        # explicitly fails on any sentinel value so we never silently
        # produce a half-resolved analysis.
        for ea, aliases in globals_to_resolve.items():
            seg_name: Optional[str] = None
            try:
                seg = self.idb.segments.get_at(ea)
                seg_name = self.idb.segments.get_name(seg)
            except Exception:
                seg_name = None

            if seg_name in uninitialized_segments:
                resolved: Tuple[str, str] = (
                    "bss", f"uninitialized ({seg_name})",
                )
            elif seg_name in initialized_segments:
                value = self._resolve_value_at(ea)
                if value is None:
                    resolved = (
                        "unresolved",
                        f"value resolution failed at 0x{ea:x}",
                    )
                else:
                    resolved = value
            else:
                # Non-data segment (.text, .plt, .got, ...) or segment
                # lookup raised entirely. A function still references
                # this address as a "global" — keep the alias visible
                # via a sentinel so the name-lookup invariant holds.
                seg_label = seg_name or "unknown segment"
                resolved = (
                    "unresolved",
                    f"non-data segment ({seg_label}) at 0x{ea:x}",
                )

            for alias in aliases:
                self._global_var_values[alias] = resolved

        n_unresolved = sum(
            1 for v in self._global_var_values.values()
            if v[0] == "unresolved"
        )
        logger.info(
            f"Resolved {len(self._global_var_values)} global variable "
            f"aliases (from {len(globals_to_resolve)} distinct EAs) "
            f"in {self.name}"
        )
        if n_unresolved:
            logger.warning(
                f"{self.name}: {n_unresolved} global var aliases "
                f"registered with 'unresolved' sentinel — name lookup "
                f"will succeed but value content is missing"
            )

    def _resolve_value_at(self, ea: int) -> Optional[Tuple[str, str]]:
        """Resolve the value at a given address using type detection chain:
        string -> integer -> address.

        Returns None if the value cannot be resolved. Never raises.
        """
        try:
            return self._resolve_value_at_inner(ea)
        except Exception as e:
            logger.debug(f"Failed to resolve global at 0x{ea:x} in {self.name}: {e}")
            return None

    def _resolve_value_at_inner(self, ea: int) -> Optional[Tuple[str, str]]:
        # 1. Try string
        if self.idb.bytes.is_string_literal_at(ea):
            result = self.idb.bytes.get_string_at(ea)
            if result:
                return ("string", result)

        # 2. Read as integer (pointer-sized)
        if self.idb.bitness == 64:
            int_val = self.idb.bytes.get_qword_at(ea)
        else:
            int_val = self.idb.bytes.get_dword_at(ea)

        # 3. Check if value is an address (falls within a known segment)
        if int_val != 0:
            try:
                target_seg = self.idb.segments.get_at(int_val)
                seg_name = self.idb.segments.get_name(target_seg)
                try:
                    target_name = self.idb.names.get_at(int_val)
                except Exception:
                    target_name = None
                if target_name:
                    return ("address", f"0x{int_val:x} -> {target_name} ({seg_name})")
                else:
                    return ("address", f"0x{int_val:x} ({seg_name})")
            except Exception:
                pass

        # 4. Plain integer
        return ("integer", str(int_val))

    def get_global_var_value(self, original_name: str) -> Optional[Tuple[str, str]]:
        """Lookup a pre-resolved global variable value. No IDB access needed."""
        return self._global_var_values.get(original_name)

    def __get_dynamic_libraries(self):
        dynamic_libs = []
        try:
            # `readelf` is not part of a stock macOS host.  Prefer the same
            # cross-platform ELF parser used by the Analyzer and retain the
            # command-line path for stripped-down IDA installations.
            import lief

            parsed = lief.ELF.parse(str(self.binary_path))
            if parsed is not None:
                dynamic_libs = [
                    entry.name
                    for entry in parsed.dynamic_entries
                    if isinstance(entry, lief.ELF.DynamicEntryLibrary)
                ]
        except Exception as lief_error:  # noqa: BLE001 - IDA may lack LIEF
            cmd = "readelf -d {} | grep NEEDED".format(self.binary_path)
            try:
                output = subprocess.check_output(cmd, shell=True, text=True)
                for line in output.splitlines():
                    parts = line.split("[")
                    if len(parts) < 2:
                        continue
                    lib_name = parts[1].split("]")[0]
                    dynamic_libs.append(lib_name)
            except (OSError, subprocess.CalledProcessError) as readelf_error:
                logger.warning(
                    f"Failed to get dynamic libraries for {self.binary_path.name}: "
                    f"LIEF={lief_error}; readelf={readelf_error}. NEEDEDs may be empty."
                )

        logger.info(f"Found Dynamic libraries in .dyn for {self.binary_path.name}: {dynamic_libs}")
        return dynamic_libs
    
    @property
    def idb(self):
        """Get the current IDB, automatically open if needed."""
        _current_idb_path = IDBManager.get_current_idb_path()
        if _current_idb_path != str(self.idb_path):
            IDBManager.open_idb(self.idb_path, self.ida_cmd_options)
        return IDBManager.get_current_idb()
    
    def activate(self):
        return IDBManager.open_idb(self.idb_path, self.ida_cmd_options)
    
    def deactivate(self):
        return IDBManager.close_idb(self.idb_path)
    
    def __getstate__(self):
        """Prepare for serialization by closing IDB and selecting essential attributes.

        _call_graph is included so that BinaryNode and its CallGraph share the
        same pickle stream. This guarantees FunctionNode object identity is
        preserved by pickle's memo mechanism — the FunctionNode instances in
        CallGraph's NetworkX graph are the exact same objects as in _ea_to_func.
        """
        # Close IDB if currently opened to avoid holding file handles
        if IDBManager.get_current_idb_path() == str(self.idb_path):
            IDBManager.close_current_idb()

        return {
            'binary_path_str': str(self.binary_path),
            'idb_path_str': str(self.idb_path),
            'arch': self.arch,
            '_dyn_libs': self._dyn_libs,
            '_default_libs': self._default_libs,
            '_is_cxx_unsupported': self._is_cxx_unsupported,
            '_name': self._name,
            'segments': self.segments,
            '_name_to_ea': self._name_to_ea,
            '_ea_to_func': self._ea_to_func,
            '_external_funcs': self._external_funcs,
            '_text_funcs': self._text_funcs,
            '_exported_funcs': self._exported_funcs,
            '_thunk_funcs': self._thunk_funcs,
            '_plt_funcs': self._plt_funcs,
            '_thunk_to_target': self._thunk_to_target,
            '_target_to_thunks': self._target_to_thunks,
            '_global_var_values': self._global_var_values,
            '_source_sha256': self._source_sha256,
            '_binary_identity': self._binary_identity,
            '_call_graph': self._call_graph,
            '_layout_schema_version': IDA_BINARY_LAYOUT_SCHEMA_VERSION,
        }

    def __setstate__(self, state):
        """Restore from serialization and rebuild runtime objects."""
        # Restore paths
        self.binary_path = Path(state['binary_path_str'])
        self.idb_path = Path(state['idb_path_str'])

        # Binary caches are keyed by the ELF basename and source hash, not by
        # the checkout that created them. Rebind stale absolute paths to the
        # current request while the source and IDB are still available.
        rebase_path = IDBManager._cache_rebase_binary_path
        if rebase_path is not None:
            self.binary_path = rebase_path
        current_source_sha256 = self._sha256_file(self.binary_path)
        cached_source_sha256 = state.get('_source_sha256')
        if cached_source_sha256 != current_source_sha256:
            raise RuntimeError(
                f"Source ELF changed for cached binary {self.binary_path}"
            )

        from ...cache_paths import restored_idb_path
        self.idb_path = restored_idb_path(self.idb_path, IDBManager._cache_rebase_idb_dir)

        # Restore basic attributes
        self.arch = state['arch']
        self._dyn_libs = state['_dyn_libs']
        self._default_libs = state['_default_libs']
        self._is_cxx_unsupported = state.get('_is_cxx_unsupported', False)
        self._name = state['_name']

        if (
            state.get('_layout_schema_version', 0)
            != IDA_BINARY_LAYOUT_SCHEMA_VERSION
            and not state.get('_text_funcs')
            and not self._default_libs
            and not self._is_cxx_unsupported
        ):
            raise RuntimeError(
                f"Legacy binary cache for {self.binary_path} has no code "
                "functions; rebuild with executable-segment classification"
            )

        # Restore analysis results
        self.segments = state['segments']
        self._name_to_ea = state['_name_to_ea']
        self._ea_to_func = state['_ea_to_func']
        self._external_funcs = state['_external_funcs']
        self._text_funcs = state['_text_funcs']
        self._exported_funcs = state['_exported_funcs']
        self._thunk_funcs = state['_thunk_funcs']
        self._plt_funcs = state['_plt_funcs']
        self._thunk_to_target = state['_thunk_to_target']
        self._target_to_thunks = state['_target_to_thunks']
        self._global_var_values = state.get('_global_var_values', {})
        self._source_sha256 = current_source_sha256
        self._binary_identity = (
            f"{self.binary_path.absolute().resolve()}:{current_source_sha256}"
        )

        # Restore CallGraph and reattach this BinaryNode as its owner.
        # Since both live in the same pickle stream, FunctionNode identity
        # is preserved by pickle's memo — no __dict__.update hack needed.
        self._call_graph = state.get('_call_graph')
        if self._call_graph is not None:
            self._call_graph.binary_node = self
            # Artifact stems and the decompiled-name lookup are deterministic
            # derivatives of the restored function set.  Rebuild both after
            # reattaching the owner so caches written before stems were
            # persisted cannot publish two functions to the same C/S path.
            self._call_graph._assign_artifact_stems()
            self._call_graph._build_decompiled_name_map()

        # Generated C/S/xref files may have been cleared independently of the
        # graph pickle, so disk readiness is always re-established.
        self._artifacts_ready = False

        # Rebuild non-serializable runtime objects
        self.ida_cmd_options = IdaCommandOptions(new_database=False)
        # A legacy basename-only IDB may have been overwritten by a different
        # binary. The pickle's ELF hash alone does not validate the database.
        if self.idb_path.parent.name != current_source_sha256 and not self._idb_matches_source():
            raise RuntimeError(f"Cached IDB does not belong to source ELF: {self.binary_path}")
