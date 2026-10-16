import idapro  # Initialize native bindings at the backend boundary.
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_typeinf
import ida_ida
import ida_lines
import idautils
from ida_domain.database import IdaCommandOptions
from pathlib import Path
from typing import List, Dict, Tuple
import re
from loguru import logger
from sortedcontainers import SortedSet
from .idb_manager import IDBManager
from .ctree_visitor import CTreeVisitor
from ...semantic import FunctionSemanticSnapshot
from ... import CallSite, PrototypeInfo, ParameterInfo
from ... import FunctionNode, FunctionAttr

class IDAFunction(FunctionNode):
    node_cache = {}
    
    # Compile regex patterns once for all instances (Linux platform only)
    # Maps IDA type to (compiled_regex, C_replacement_type)
    _type_replacements = None
    
    @classmethod
    def _init_type_replacements(cls):
        """Initialize compiled regex patterns for type replacements."""
        if cls._type_replacements is not None:
            return
        
        # Type mappings: IDA type -> Standard C type (Linux/GCC)
        type_map = {
            # Basic IDA types for Linux/GCC (__GNUC__)
            '__int64': 'long long',
            '__int32': 'int',
            '__int16': 'short',
            '__int8': 'char',
            
            # Basic signed/unsigned types
            'int8': 'char',
            'sint8': 'signed char',
            'uint8': 'unsigned char',
            'int16': 'short',
            'sint16': 'signed short',
            'uint16': 'unsigned short',
            'int32': 'int',
            'sint32': 'signed int',
            'uint32': 'unsigned int',
            'int64': 'long long',
            'sint64': 'long long',
            'uint64': 'unsigned long long',
            
            # Partially defined types
            '_BYTE': 'unsigned char',
            '_WORD': 'unsigned short',
            '_DWORD': 'unsigned int',
            '_QWORD': 'unsigned long long',
            '_LONGLONG': '__int128',
            
            # Boolean types
            '_BOOL1': 'char',
            '_BOOL2': 'short',
            '_BOOL4': 'int',
            '_BOOL8': 'long long',
            
            # Windows-style types (also used in IDA on Linux)
            'BYTE': 'char',
            'WORD': 'short',
            'DWORD': 'int',
            'QWORD': 'long long',
            'LONG': 'int',
            'BOOL': 'int',
        }
        
        # Compile regex for each type (match whole words only)
        cls._type_replacements = []
        for ida_type, c_type in type_map.items():
            # Use word boundary \b to match complete words only
            pattern = re.compile(r'\b' + re.escape(ida_type) + r'\b')
            cls._type_replacements.append((pattern, c_type))
    
    @staticmethod
    def create(module_name: str, func_ea: int, func_name: str, func_type: FunctionAttr,
               idb_path: Path, binary_identity: str = None) -> 'IDAFunction':
        # Initialize type replacements on first use
        IDAFunction._init_type_replacements()
        
        # Identical ELF bytes may share an IDB, but their guest source paths
        # still have distinct owners. Keep both source and analysis identity.
        key = (Path(idb_path).absolute().resolve(), binary_identity, func_ea)
        if key in IDAFunction.node_cache:
            logger.debug(f"Cache hit for {module_name} at {hex(func_ea)}")
            return IDAFunction.node_cache[key]
        else:
            func_node = IDAFunction(module_name, func_ea, func_name,
                                    func_type, idb_path, binary_identity)
            IDAFunction.node_cache[key] = func_node
            return func_node

    @classmethod
    def clear_cache(cls) -> None:
        cls.node_cache.clear()

    def invalidate_semantic_snapshot(self) -> None:
        """Discard data derived from a prior decompilation snapshot."""
        # CTree can discover direct targets that IDA's assembly-level call
        # analysis did not. Remove those semantic additions before rebuilding
        # so the lightweight layer remains an exact IDA auto-analysis view.
        self._callee_addrs = SortedSet(self.get_structural_callees())
        self._semantic_snapshot = None
        self._callsites = {}
        self._linenum_to_callsite = {}
        self._global_vars = {}
        self._gvar_name_to_original = {}
        self._original_to_gvar_name = {}
        self._prototype_info = None
        self._saved_predefined_prototypes = None
        self._decompiled_name = self._name
        self.__dict__.pop("_artifact_stem", None)
        # External functions are concretized by applying a provider prototype.
        # That prototype is semantic state too, so every function kind must be
        # eligible for a clean enrichment pass.
        self._concretized = False

    def __init__(self, module_name: str, func_ea: int, func_name: str,
                 func_attr: FunctionAttr, idb_path: Path,
                 binary_identity: str = None):
        self._module_name = module_name
        self._name = func_name
        self._decompiled_name = func_name
        self._ea = func_ea
        self._attr = func_attr
        self._callee_addrs: SortedSet[int] = SortedSet()
        self._structural_callee_addrs: SortedSet[int] | None = SortedSet()
        # New callsites are keyed by their CTree item index.  Old pickles may
        # still contain (line, column) keys and are invalidated at CallGraph
        # semantic analysis before being used.
        self._callsites: Dict[int, CallSite] = {}
        # Global variable mappings: ea -> original_name
        self._global_vars: Dict[int, str] = {}
        # Bidirectional mapping: original_name <-> GVar_name
        self._gvar_name_to_original: Dict[str, str] = {}  # GVar_xxx -> original
        self._original_to_gvar_name: Dict[str, str] = {}  # original -> GVar_xxx
        self._decompiled_code: str = ""
        self._prototype_info: PrototypeInfo = None
        self._saved_predefined_prototypes: PrototypeInfo = None
        self._linenum_to_callsite: Dict[int, List[CallSite]] = {}
        self._semantic_snapshot: FunctionSemanticSnapshot = None
        self._binary_identity = binary_identity or str(Path(idb_path).resolve())

        self.idb_path = idb_path
        if not idb_path.exists():
            raise FileNotFoundError(f"IDB path {idb_path} does not exist")
        else:
            self.ida_cmd_options = IdaCommandOptions(new_database=False)

        # Calculate _callee_addrs simply by asm
        for callee in self.idb.functions.get_callees(self.idb.functions.get_at(self._ea)):
            self._callee_addrs.add(callee.start_ea)
            self._structural_callee_addrs.add(callee.start_ea)

        self._concretized = False

    def concretize(self):
        if self._concretized:
            return
        
        if self.has_attr(FunctionAttr.EXTERNAL):
            self.apply_predefined_prototype()
        
        elif self.has_attr(FunctionAttr.TEXT) or self.has_attr(FunctionAttr.PLT):
            # decompile the function so the cache will be saved in idb
            self.post_decompile_analysis()

        self._concretized = True
        logger.info(f"Concretized IDAFunction: {self.name} at {hex(self.ea)}, attr: {self.attr}")
    
    def apply_predefined_prototype(self):
        if self._saved_predefined_prototypes is None:
            raise RuntimeError(f"No predefined prototype saved for external function {self.name} at {hex(self.ea)}, should not happen.")
        decl_str = self._saved_predefined_prototypes.decl_str
        if decl_str is None or decl_str == "":
            raise RuntimeError(f"Invalid declaration string for external function {self.name} at {hex(self.ea)}: {decl_str}")
        self.activate()

        # A declaration is printed in the provider IDB and parsed again in
        # the caller IDB.  Provider-local aliases such as _DWORD are not
        # guaranteed to exist in the caller type library, so normalize the
        # same IDA scalar aliases already normalized in published C code.
        parse_decl_str = self._replace_casts_in_decompiled_code(decl_str)
        # ``tinfo_t._print()`` may emit a typedef that only exists in the
        # provider IDB's local type library.  DT_NEEDED providers and callers
        # share an ABI, so lower pointer-sized ``size_t`` to an ABI primitive
        # before parsing the declaration in the caller IDB.
        size_type = "unsigned long" if ida_ida.inf_is_64bit() else "unsigned int"
        parse_decl_str = re.sub(r"\bsize_t\b", size_type, parse_decl_str)
        new_tinfo = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(
            new_tinfo, None, parse_decl_str, ida_typeinf.PT_SIL,
        ):
            # A provider may use private typedefs that do not exist in the
            # caller IDB.  Prototype propagation is a refinement; retaining
            # IDA's caller-local import type is safer than aborting all
            # structural analysis or guessing the private ABI type.
            logger.warning(
                "Could not import provider prototype for {} at {}: {}; "
                "keeping caller-local type",
                self.name,
                hex(self.ea),
                parse_decl_str,
            )
            return False
        
        flags = ida_typeinf.TINFO_DEFINITE 
        success = ida_typeinf.apply_tinfo(self._ea, new_tinfo, flags)
        if success:
            logger.info(f"Applied prototype to {hex(self._ea)}: {decl_str}")
            self._prototype_info = self._saved_predefined_prototypes
        else:
            logger.warning(
                "Could not apply provider prototype for {} at {}: {}; "
                "keeping caller-local type",
                self.name,
                hex(self.ea),
                parse_decl_str,
            )
        return success

    def post_decompile_analysis(self) -> FunctionSemanticSnapshot:
        self.activate()
        self._init_type_replacements()
        if ida_hexrays.init_hexrays_plugin():
            func = ida_funcs.get_func(self.ea)
            if func is None:
                raise RuntimeError(f"Function at {hex(self.ea)} not found")

            # One authoritative decompilation.  Pseudocode, CTree semantics,
            # coordinates, and the emitted C file all derive from this wrapper.
            pseudocode = self.idb.functions.get_pseudocode(func)
            cfunc = pseudocode.raw_cfunc
            logger.debug(f"Decompiled function {self.name} at {hex(self.ea)}")
            
            # Function Prototype Analysis
            self._prototype_info = self._get_function_prototype(cfunc)
            
            # =============================================================================
            # Callsite Analysis using CTreeVisitor (ctree/pseudo code layer)
            # =============================================================================
            # IMPORTANT: We analyze callsites from the ctree (decompiled pseudo code) rather
            # than from microcode (CallVisitor) for the following critical reason:
            #
            # IDA's decompiler performs control flow structuring when lifting microcode to
            # pseudo code. This may DUPLICATE a single microcode call instruction to multiple
            # locations in the output pseudo code. Common cases include:
            #   - Switch-case recovery: same 'return func()' duplicated to multiple cases
            #   - Loop unrolling optimizations
            #   - Conditional tail merging
            #
            # Analyzing CTree directly preserves every displayed call object,
            # including multiple calls that share a machine address.
            # =============================================================================
            ctree_visitor = CTreeVisitor(
                pseudocode,
                binary_name=self._module_name,
                binary_identity=self._binary_identity,
                idb_identity=str(self.idb_path.absolute().resolve()),
                func_ea=self.ea,
                func_name=self._name
            )
            ctree_visitor.apply_to(cfunc.body, None)
            self._semantic_snapshot = ctree_visitor.finalize(
                self._type_replacements
            )
            
            # Get callsites (keyed by CTree index) and build the display-line index.
            self._callsites = ctree_visitor.get_callsites()
            self._linenum_to_callsite = ctree_visitor.build_linenum_to_callsites()
            
            # Update callee addresses from ctree analysis
            for callee_addr in ctree_visitor.get_callee_addrs():
                self._callee_addrs.add(callee_addr)
            
            # Global Variable Analysis
            self._global_vars = ctree_visitor.get_global_vars()

            # get decompiler displayed name (may differ from symbol name in IDB)
            self._decompiled_name = self.get_hexrays_displayed_name(cfunc)
            if self._decompiled_name != self._name:
                logger.warning(f"Function name changed by decompiler: {self._name} -> {self._decompiled_name} at {hex(self.ea)} in {self._module_name}")
            
            # Build bidirectional mappings for global variables
            for var_addr, var_name in self._global_vars.items():
                old_name = var_name
                if old_name.startswith("GVar_"):
                    new_name = old_name
                else:
                    new_name = f"GVar_{old_name}"
                
                # Build bidirectional mappings
                self._original_to_gvar_name[old_name] = new_name
                self._gvar_name_to_original[new_name] = old_name

            return self._semantic_snapshot
        else:
            raise RuntimeError("Hex-Rays decompiler is not available")
    
    def get_callees(self):
        return self._callee_addrs

    def get_structural_callees(self):
        """Return only IDA auto-analysis callees, never CTree-added targets.

        Old binary pickles predate this split. Recompute their structural set
        lazily from the existing IDB instead of treating the cached semantic
        union as an assembly-level fact.
        """
        if self._structural_callee_addrs is None:
            structural = SortedSet()
            function = self.idb.functions.get_at(self._ea)
            if function is not None:
                for callee in self.idb.functions.get_callees(function):
                    structural.add(callee.start_ea)
            self._structural_callee_addrs = structural
        return self._structural_callee_addrs
    
    def get_callsites(self) -> Dict[int, CallSite]:
        """Return callsites keyed by the immutable snapshot's CTree index."""
        return self._callsites

    @property
    def semantic_snapshot(self) -> FunctionSemanticSnapshot:
        if self._semantic_snapshot is None:
            raise RuntimeError(
                f"Semantic snapshot unavailable for {self.name} in "
                f"{self._module_name}"
            )
        return self._semantic_snapshot
    
    def get_hexrays_displayed_name(self, cfunc: ida_hexrays.cfunc_t) -> str:
        sv = cfunc.get_pseudocode()
        if not sv or len(sv) == 0:
            raise RuntimeError(f"Failed to get pseudocode for function at {hex(self.ea)}")
        # MIPS PLT symbols may carry a leading dot in the IDB (for example
        # ``.__register_frame_info``), which Hex-Rays must remove to emit a
        # valid C identifier.  Treat that dot like the already-supported
        # leading underscore normalization.
        core_func_name = self._name.lstrip("_.")
        # GCC clone names such as ``foo.part.0`` are legal ELF symbols but
        # Hex-Rays renders them as C identifiers (``foo_part_0``).
        displayed_core_name = re.sub(r"[^A-Za-z0-9_]", "_", core_func_name)
        func_def_line = None
        in_block_comment = False
        for i in range(len(sv)):
            line_raw = sv[i].line
            line_text = ida_lines.tag_remove(line_raw).strip()
            if not line_text:
                continue

            if in_block_comment:
                if "*/" in line_text:
                    in_block_comment = False
                continue
            
            if line_text.startswith("/*"):
                if "*/" not in line_text:
                    in_block_comment = True
                continue

            if line_text.startswith("//"):
                continue

            func_def_line = line_text
            break
        
        if not func_def_line:
            raise RuntimeError(f"Warning: Could not find function definition line at {hex(self.ea)} @ {self._module_name}")
                
        prefix_pattern = r'[a-zA-Z0-9_:]*'
        suffix_pattern = r'[a-zA-Z0-9_:]*'

        # ``__usercall`` prototypes annotate the return register between the
        # displayed function name and ``(``, for example
        # ``func@<$v0>(arg@<$f12>)`` on MIPS.  The annotation belongs to the
        # calling convention, not to the function's source-level identity.
        pattern = (
            r'(' + prefix_pattern + re.escape(displayed_core_name)
            + suffix_pattern + r')(?:@<[^>]+>)?\s*\('
        )
        match = re.search(pattern, func_def_line)

        if match:
            return match.group(1)
        else:
            raise RuntimeError(
                f"Could not parse function name from definition line: "
                f"'{func_def_line}' at {hex(self.ea)} @ {self._module_name}"
            )
    
    def get_raw_decompiled_code(self, with_line_numbers: bool = False) -> str:
        if self._concretized == False:
            raise RuntimeError(f"Function {self.name} in {self._module_name} must be concretized before getting decompiled code")
        code = self.semantic_snapshot.raw_code
        if not with_line_numbers:
            return code
        return "\n".join(
            f"{line_number:05d}: {line}"
            for line_number, line in enumerate(code.splitlines(), start=1)
        )
    
    def get_processed_decompiled_code(self, 
                                      with_line_numbers: bool = False,
                                      replace_cast: bool=True, 
                                      replace_gvar: bool=True,
                                      mark_callsites: bool=False,
                                      remove_leading_comments: bool=False) -> str:
        if replace_cast and replace_gvar and not remove_leading_comments:
            code = self.semantic_snapshot.rendered_code
            if with_line_numbers:
                code = "\n".join(
                    f"{line_number:05d}: {line}"
                    for line_number, line in enumerate(
                        code.splitlines(), start=1
                    )
                )
        else:
            code = self.get_raw_decompiled_code(
                with_line_numbers=with_line_numbers
            )
        if remove_leading_comments:
            code = self._remove_leading_comments(code)
        if replace_cast and code != self.semantic_snapshot.rendered_code:
            code = self._replace_casts_in_decompiled_code(code)
        if replace_gvar and code != self.semantic_snapshot.rendered_code:
            code = self._replace_global_varname(code)
        if mark_callsites:
            code = self._mark_callsites_in_code(code)

        code = self._clean_decompiler_keywords(code)
        return code

    def get_disassembly(self) -> str:
        """Return an IDA listing for every chunk owned by this function.

        Each instruction retains its effective address, original bytes, and
        IDA-rendered text (including recovered labels and comments). Function
        tails are included via ``idautils.Chunks`` rather than assuming the
        entry chunk is contiguous.
        """
        # Disassembly is intentionally independent of Hex-Rays.  In
        # particular, a function whose pseudocode extraction failed must still
        # retain an auditable assembly artifact and an explicit semantic
        # frontier.  The instruction/chunk APIs below only require the IDB to
        # be active; they do not consume the CTree snapshot.
        self.activate()
        if ida_funcs.get_func(self.ea) is None:
            raise RuntimeError(f"Function at {hex(self.ea)} not found")

        chunks = sorted((int(start), int(end)) for start, end in idautils.Chunks(self.ea))
        if not chunks:
            raise RuntimeError(
                f"No function chunks found for {self.name} at {hex(self.ea)}"
            )

        chunk_records: List[Tuple[int, int, List[Tuple[int, str, str]]]] = []
        max_raw_width = 0
        for start_ea, end_ea in chunks:
            records: List[Tuple[int, str, str]] = []
            for insn in self.idb.instructions.get_between(start_ea, end_ea):
                raw = ida_bytes.get_bytes(insn.ea, insn.size)
                if raw is None or len(raw) != insn.size:
                    raise RuntimeError(
                        f"Failed to read {insn.size} instruction bytes at "
                        f"{hex(insn.ea)} in {self.name}"
                    )
                text = self.idb.instructions.get_disassembly(
                    insn, remove_tags=True
                )
                if not text:
                    raise RuntimeError(
                        f"Failed to disassemble instruction at {hex(insn.ea)} "
                        f"in {self.name}"
                    )
                raw_hex = raw.hex(" ")
                max_raw_width = max(max_raw_width, len(raw_hex))
                records.append((int(insn.ea), raw_hex, text))
            chunk_records.append((start_ea, end_ea, records))

        max_ea = max(end_ea - 1 for _, end_ea in chunks)
        address_width = max(8, len(f"{max_ea:x}"))
        lines = [
            f"; binary: {self.module}",
            f"; function: {self.decompiled_name}",
            f"; symbol: {self.name}",
            f"; entry_ea: 0x{self.ea:x}",
        ]
        binary_identity = getattr(self, "_binary_identity", "")
        if binary_identity:
            lines.append(
                f"; source_sha256: {binary_identity.rsplit(':', 1)[-1]}"
            )
        for start_ea, end_ea, records in chunk_records:
            lines.append(f"; chunk: 0x{start_ea:x}-0x{end_ea:x}")
            for insn_ea, raw_hex, text in records:
                lines.append(
                    f"0x{insn_ea:0{address_width}x}:  "
                    f"{raw_hex:<{max_raw_width}}  {text}"
                )
        return "\n".join(lines) + "\n"

    def add_attr(self, attr: FunctionAttr):
        if self._attr is None:
            self._attr = attr
        else:
            self._attr |= attr

    def has_attr(self, attr: FunctionAttr) -> bool:
        if self._attr is None:
            return False
        return (self._attr & attr) == attr
    
    def get_prototype_info(self) -> PrototypeInfo:
        """Get the function prototype information.
        
        Returns:
            PrototypeInfo: Function prototype information
            
        Raises:
            RuntimeError: If function has not been concretized
        """
        if not self._concretized:
            raise RuntimeError(f"Function {self.name} must be concretized before accessing prototype info")
        if self._prototype_info is None:
            raise RuntimeError(f"Prototype info not available for {self.name}")
        return self._prototype_info
    
    def save_predefined_prototype(self, prototype_info: PrototypeInfo):
        """
        Save the predefined function prototype information for the given function.
        """
        self._saved_predefined_prototypes = prototype_info
        logger.info(f"Save Predefined Prototype for external function {self._name} in {self._module_name}@{hex(self.ea)}: {prototype_info}")
    
    def _get_function_prototype(self, cfunc: ida_hexrays.cfunc_t) -> PrototypeInfo:
        """Extract and parse function prototype information from decompiled function.
        
        Args:
            cfunc: IDA Hex-Rays decompiled function object
            
        Returns:
            PrototypeInfo: Complete function prototype information
            
        Raises:
            RuntimeError: If function type information cannot be retrieved
        """
        tinfo = ida_typeinf.tinfo_t()
        if not cfunc.get_func_type(tinfo):
            raise RuntimeError(f"Failed to get function type for {self.name} at {hex(self.ea)}")
        if not tinfo.is_func():
            raise RuntimeError(f"Type info is not a function for {self.name} at {hex(self.ea)}")
        
        func_data = ida_typeinf.func_type_data_t()
        if not tinfo.get_func_details(func_data):
            raise RuntimeError(f"Failed to get function details for {self.name} at {hex(self.ea)}")
        
        # Extract return type
        return_type = func_data.rettype.dstr()
        
        # Extract argument information
        args_info = []
        for i, func_arg in enumerate(func_data):
            arg_name = func_arg.name if func_arg.name else f"arg_{i}"
            arg_type = func_arg.type.dstr()
            arg_location = func_arg.argloc.atype()
            
            args_info.append(ParameterInfo(
                index=i + 1,
                name=arg_name,
                type=arg_type,
                location=arg_location
            ))
        
        # Generate declaration string for later use with parse_decl
        decl_str = tinfo._print(self.name, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_SEMI)
        
        # Create and store PrototypeInfo
        prototype_info = PrototypeInfo(
            ea=self.ea,
            name=self.name,
            ret_type=return_type,
            args=args_info,
            decl_str=decl_str
        )

        logger.info(f"Extracted prototype for {self.name} in {hex(self._ea)}@{self._module_name}: {prototype_info}" )
        
        return prototype_info
    
    def _replace_casts_in_decompiled_code(self, code: str) -> str:
        """Replace IDA-specific casts in decompiled code with standard C casts.
        
        Args:
            code: Decompiled code as a string
            
        Returns:
            str: Decompiled code with casts replaced
        """
        # Ensure type replacements are initialized
        if self._type_replacements is None:
            self._init_type_replacements()
        
        # Apply all type replacements
        for pattern, replacement in self._type_replacements:
            code = pattern.sub(replacement, code)
        
        return code
    
    def _replace_global_varname(self, code: str) -> str:
        """Replace global variable names with GVar_ prefix.
        
        Args:
            code: Decompiled code as a string
            
        Returns:
            str: Decompiled code with global variables renamed
        """
        if not self._original_to_gvar_name:
            return code
        
        # Replace global variable names in the entire code
        for original_name, gvar_name in self._original_to_gvar_name.items():
            if original_name != gvar_name:  # Only replace if different
                # Use word boundary to match whole words only
                pattern = re.compile(r'\b' + re.escape(original_name) + r'\b')
                code = pattern.sub(gvar_name, code)
        
        return code
    
    def _mark_callsites_in_code(self, code: str) -> str:
        """Mark callsites in decompiled code with comments while preserving indentation.
        
        Args:
            code: Decompiled code as a string
            
        Returns:
            str: Decompiled code with callsite annotations
        """
        if not self._linenum_to_callsite:
            return code
        
        lines = code.split('\n')
        modified_lines = []
        
        for idx, line in enumerate(lines):
            # Line numbers in decompiled code may start with "00001: " format
            # We need to extract the actual line number
            line_match = re.match(r'^(\d{5}):\s', line)
            if line_match:
                line_number = int(line_match.group(1))
            else:
                # If no line number prefix, use index + 1
                line_number = idx + 1
            
            # Check if this line has callsites
            if line_number in self._linenum_to_callsite:
                callsites = self._linenum_to_callsite[line_number]
                
                # Build callsite comment
                callsite_info_parts = []
                for cs in callsites:
                    cs_info = f"{{callee: {cs.callee_name}@{hex(cs.callee_ea)}, callsite: {hex(cs.callsite_ea)}}}"
                    callsite_info_parts.append(cs_info)
                
                callsite_comment = " // CALLSITE_INFO: " + ", ".join(callsite_info_parts)
                modified_lines.append(line + callsite_comment)
            else:
                modified_lines.append(line)
        
        return '\n'.join(modified_lines)
    
    def _clean_decompiler_keywords(self, code: str) -> str:
        """Remove IDA-specific keywords from the human-readable C output.
        
        This function removes keywords and attributes that are specific to IDA's
        decompiler output but are not valid in standard C code, which can cause
        issues in downstream source-oriented tooling.
        
        Args:
            code: Decompiled code as a string
            
        Returns:
            str: Cleaned code with incompatible keywords removed
        """
        # List of IDA-specific keywords to remove
        ida_keywords = [
            r'__noreturn',      # Function attribute indicating no return
        ]
        
        # Remove each keyword using regex
        for keyword in ida_keywords:
            # Match keyword as whole word or with parentheses
            pattern = r'\b' + keyword + r'\b'
            code = re.sub(pattern, '', code)
        
        return code
    
    def _remove_leading_comments(self, code: str) -> str:
        """Remove leading comments from decompiled code.
        
        This function removes comments that appear at the beginning of the code,
        including single-line comments (//) and multi-line comments (/* ... */).
        Comments in the middle of the code are preserved.
        
        Args:
            code: Decompiled code as a string
            
        Returns:
            str: Code with leading comments removed
        """
        lines = code.split('\n')
        in_block_comment = False
        
        for idx, line in enumerate(lines):
            stripped = line.strip()
            
            # Handle block comments
            if in_block_comment:
                if '*/' in stripped:
                    in_block_comment = False
                continue
            
            # Skip empty lines at the beginning
            if not stripped:
                continue
            
            # Check for block comment start
            if stripped.startswith('/*'):
                if '*/' not in stripped:
                    in_block_comment = True
                continue
            
            # Check for single-line comment
            if stripped.startswith('//'):
                continue
            
            # Found actual code, return this and all remaining lines
            return '\n'.join(lines[idx:])
        
        # All lines were comments or empty
        return ''

    @property
    def ea(self):
        return self._ea

    @property
    def name(self):
        return self._name
    
    @property
    def decompiled_name(self):
        return self._decompiled_name
    
    @property
    def repr(self):
        return f"{self.name} @ <{self.module}+{hex(self.ea)}>"
    
    @property
    def node_repr(self):
        return f"{self.name} @ <{self.module}+{hex(self.ea)}>\n[{self.attr}]"
    
    @property
    def module(self):
        return self._module_name
    
    @property
    def attr(self):
        return self._attr
    
    @property
    def concretized(self) -> bool:
        return self._concretized
    
    @property
    def linenum_to_callsite(self) -> Dict[int, List[CallSite]]:
        return self._linenum_to_callsite
    
    def activate(self):
        return self.idb # Trigger the idb property to open the IDB if needed
    
    def deactivate(self):
        return IDBManager.close_idb(self.idb_path)

    @property
    def idb(self):
        """Get the current IDB, automatically open if needed."""
        _current_idb_path = IDBManager.get_current_idb_path()
        if _current_idb_path != str(self.idb_path):
            IDBManager.open_idb(self.idb_path, self.ida_cmd_options)
        return IDBManager.get_current_idb()
    
    def __getstate__(self):
        """Prepare for serialization by closing IDB and selecting essential attributes."""        
        # Close IDB if currently opened to avoid holding file handles
        if IDBManager.get_current_idb_path() == str(self.idb_path):
            IDBManager.close_current_idb()
        
        return {
            '_module_name': self._module_name,
            '_name': self._name,
            '_decompiled_name': self._decompiled_name,
            '_ea': self._ea,
            '_attr': self._attr,
            '_callee_addrs': self._callee_addrs,
            '_structural_callee_addrs': self._structural_callee_addrs,
            '_callsites': self._callsites,
            '_global_vars': self._global_vars,
            '_gvar_name_to_original': self._gvar_name_to_original,
            '_original_to_gvar_name': self._original_to_gvar_name,
            '_linenum_to_callsite': self._linenum_to_callsite,
            '_semantic_snapshot': self._semantic_snapshot,
            '_binary_identity': self._binary_identity,
            '_prototype_info': self._prototype_info,
            '_saved_predefined_prototypes': self._saved_predefined_prototypes,
            'idb_path_str': str(self.idb_path),
            'concretized': self._concretized,
        }
    
    def __setstate__(self, state):
        """Restore from serialization and rebuild runtime objects."""        
        # Restore attributes
        self._module_name = state['_module_name']
        self._name = state['_name']
        self._decompiled_name = state['_decompiled_name']
        self._ea = state['_ea']
        self._attr = state['_attr']
        self._callee_addrs = state['_callee_addrs']
        self._structural_callee_addrs = state.get(
            '_structural_callee_addrs',
        )
        self._callsites = state['_callsites']
        self._global_vars = state['_global_vars']
        self._gvar_name_to_original = state['_gvar_name_to_original']
        self._original_to_gvar_name = state['_original_to_gvar_name']
        self._linenum_to_callsite = state['_linenum_to_callsite']
        self._semantic_snapshot = state.get('_semantic_snapshot')
        self._binary_identity = state.get(
            '_binary_identity', str(Path(state['idb_path_str']).resolve())
        )
        self._concretized = state['concretized']
        self._prototype_info = state['_prototype_info']
        self._saved_predefined_prototypes = state['_saved_predefined_prototypes']
        
        # Restore path and validate
        self.idb_path = Path(state['idb_path_str'])
        from ...cache_paths import restored_idb_path
        self.idb_path = restored_idb_path(self.idb_path, IDBManager._cache_rebase_idb_dir)
        rebase_binary = IDBManager._cache_rebase_binary_path
        if rebase_binary is not None:
            cached_hash = self._binary_identity.rsplit(":", 1)[-1]
            if len(cached_hash) == 64:
                self._binary_identity = f"{rebase_binary}:{cached_hash}"
        if not self.idb_path.exists():
            raise RuntimeError(f"IDB not found: {self.idb_path}")
        
        # Rebuild non-serializable runtime objects
        self.ida_cmd_options = IdaCommandOptions(new_database=False)
