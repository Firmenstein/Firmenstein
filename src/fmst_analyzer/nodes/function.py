from .common import FunctionAttr
from .callsite import CallSite, ArgInfo, ArgType
from typing import Literal, List, Dict, Tuple
from sortedcontainers import SortedSet
from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import re
from loguru import logger


_MAX_ARTIFACT_STEM_LENGTH = 180


def _bounded_artifact_stem(value: str) -> str:
    """Return a stable filename component accepted by common filesystems.

    C++/template symbols can exceed NAME_MAX when structural listings are
    emitted.  Keep readable names whenever possible and use a deterministic
    digest only for the long-tail case; the EA remains part of the digest
    input, so truncation cannot alias two functions.
    """
    value = re.sub(r"[\\/\x00]", "_", str(value))
    if len(value) <= _MAX_ARTIFACT_STEM_LENGTH:
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    prefix_length = _MAX_ARTIFACT_STEM_LENGTH - len(digest) - 1
    return f"{value[:prefix_length]}@{digest}"

@dataclass
class ParameterInfo:
    """Information about a function argument."""
    index: int
    name: str
    type: str
    location: int  # Argument location type from IDA
    
    def __str__(self) -> str:
        return f"{self.type} {self.name}"

@dataclass
class PrototypeInfo:
    """Complete function prototype information."""
    ea: int
    name: str
    ret_type: str
    args: List[ParameterInfo]
    decl_str: str  # Full declaration string for parse_decl
    
    def __str__(self) -> str:
        """Generate a readable function prototype string."""
        if not self.args:
            args_str = ""
        else:
            args_str = ", ".join(str(arg) for arg in self.args)
        return f"Repr: {self.ret_type} {self.name}({args_str}), Origin Decl: {self.decl_str}"

class FunctionNode(ABC):
    decompiler: Literal["ida", "ghidra"] = None
    node_cache = {}

    @staticmethod
    def set_decompiler(decompiler: Literal["ida", "ghidra"]):
        FunctionNode.decompiler = decompiler

    # Semantic identity: a function is uniquely identified by its
    # owning binary (module name) and its effective address. This ensures
    # correct set/dict membership across different contexts. Both `module`
    # and `ea` are stable across pickle cycles.
    def __eq__(self, other) -> bool:
        if not isinstance(other, FunctionNode):
            return NotImplemented
        return self.module == other.module and self.ea == other.ea

    def __hash__(self) -> int:
        return hash((self.module, self.ea))

    @staticmethod
    def close_database():
        if FunctionNode.decompiler == "ida":
            from .decompiler.ida.idb_manager import IDBManager
            IDBManager.close_current_idb()
        else:
            raise NotImplementedError(f"Decompiler {FunctionNode.decompiler} not supported yet")

    @property
    @abstractmethod
    def ea(self) -> int:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def decompiled_name(self) -> str:
        """
        `name` is the symbol name in the idb, while `decompiled_name` may be different from it due to decompiler's renaming mechanism.
        e.g. __func_name -> _func_name
        """
        pass

    @property
    def artifact_stem(self) -> str:
        """Stable C/S filename stem for this function.

        It normally equals ``decompiled_name``.  A CallGraph assigns an EA
        suffix only when Hex-Rays gives multiple functions in one binary the
        same displayed name.
        """
        return _bounded_artifact_stem(
            getattr(self, "_artifact_stem", self.decompiled_name),
        )

    def set_artifact_stem(self, stem: str) -> None:
        self._artifact_stem = stem

    @property
    def structural_artifact_stem(self) -> str:
        """Stable listing filename before Hex-Rays assigns a C name.

        ``decompiled_name`` is initially the IDA symbol and can later change
        when Hex-Rays renders the function.  Structural artifacts must remain
        addressable before that happens, so their identity is always the IDA
        symbol plus entry EA. Semantic publication adds C-paired
        ``artifact_stem`` names without removing existing structural evidence.
        """
        return _bounded_artifact_stem(f"{self.name}@{self.ea:x}")
    
    @property
    @abstractmethod
    def repr(self) -> str:
        pass
    
    @property
    @abstractmethod
    def node_repr(self) -> str:
        pass
        
    @property
    @abstractmethod
    def attr(self) -> FunctionAttr:
        pass

    @property
    @abstractmethod
    def module(self) -> str:
        pass

    @property
    @abstractmethod
    def concretized(self) -> bool:
        pass

    @property
    @abstractmethod
    def linenum_to_callsite(self) -> Dict[int, List[CallSite]]:
        """
        Get the mapping from line numbers to callsites in the decompiled code.
        Should be called after concretization.
        """
        pass
    
    @abstractmethod
    def activate(self):
        """
        Open the corresponding IDB/Ghidra database, so the following analysis can be performed.
        """
        pass

    @abstractmethod
    def deactivate(self):
        """
        Close the corresponding IDB/Ghidra database.
        """
        pass

    @abstractmethod
    def concretize(self):
        """
        Create the internal decompiler Function instance.
        Should be called after opening the IDB/Ghidra database.
        """
        pass

    @abstractmethod
    def get_callees(self) -> SortedSet[int]:
        """
        Get all callee addresses known after optional semantic enrichment.
        """
        pass

    @abstractmethod
    def get_structural_callees(self) -> SortedSet[int]:
        """Get callees discovered by IDA auto-analysis without Hex-Rays."""
        pass

    @abstractmethod
    def get_callsites(self) -> Dict[object, CallSite]:
        """
        Get callsites keyed by their decompiler-specific stable identity.
        Should be called after concretization.
        """
        pass

    @abstractmethod
    def get_prototype_info(self) -> PrototypeInfo:
        """Get the function prototype information for the given function."""
        pass

    @abstractmethod
    def save_predefined_prototype(self, prototype_info: PrototypeInfo):
        """
        Save the predefined function prototype information for the given function.
        These Infomation will be useful when generating the correct function prototype during decompilation.
        """
        pass

    @abstractmethod
    def get_raw_decompiled_code(self) -> str:
        """
        Get the decompiled code of the function.
        Should be called after concretization.
        """
        pass

    @abstractmethod
    def get_processed_decompiled_code(self, 
                                      with_line_numbers: bool = False,
                                      replace_cast: bool=True, 
                                      replace_gvar: bool=True,
                                      mark_callsites: bool=False,
                                      remove_leading_comments: bool=False) -> str:
        """
        Get the decompiled code of the function with marked 
        callsite addresses, global variables, comments, etc.
        """
        pass

    @abstractmethod
    def get_disassembly(self) -> str:
        """Return an address- and byte-annotated disassembly listing.

        The listing is a human/analysis reference artifact, not guaranteed
        to be accepted as assembler input.
        """
        pass
    
    @abstractmethod
    def add_attr(self, attr: FunctionAttr):
        pass

    @abstractmethod
    def has_attr(self, attr: FunctionAttr) -> bool:
        pass

    @abstractmethod
    def __getstate__(self):
        pass

    @abstractmethod
    def __setstate__(self, state):
        pass

    def get_callsites_by_linenum(self, line_num: int, callee_name: str = None) -> List[CallSite]:
        """
        Get callsites at the given line number.
        If callee_name is provided, filter callsites by the given callee name.
        """
        if line_num not in self.linenum_to_callsite.keys():
            raise RuntimeError(f"Line number {line_num} not found in function {self.decompiled_name} callsites mapping.")
        
        if callee_name is None:
            return self.linenum_to_callsite[line_num]
        else:
            # linenum_to_callsite is sorted by `column_number` in CTreeVisitor,
            # so the result is also sorted by `column_number`.
            result = []
            for cs in self.linenum_to_callsite[line_num]:
                if cs.callee_name == callee_name:
                    result.append(cs)
            if len(result) == 0:
                logger.warning(f"No callsite found for API {callee_name} at line number {line_num} in function {self.decompiled_name}.")
            if len(result) > 1:
                logger.warning(f"Multiple callsites found for API {callee_name} at LineNum {line_num} in function {self.decompiled_name}.")
            return result
