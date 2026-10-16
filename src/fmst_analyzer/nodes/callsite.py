from enum import Enum
from loguru import logger
from typing import List, Optional

class ArgType(Enum):
    LOCAL = "local"
    GLOBAL = "global"
    LITERAL = "literal"
    CALL = "call"
    OTHER = "other"

class ArgInfo:
    def __init__(self, index: int, value: str, type: ArgType):
        self.index = index
        self.value = value
        self.type = type

    def __str__(self) -> str:
        return f"ArgInfo [Index: {self.index}, Type: {self.type.value}, Value: {self.value}]"

class CallSite():
    def __init__(self, binary_name: str, caller_ea: int, caller_name: str, 
                 callee_ea: int, callee_name: str, 
                 callsite_ea: int, line_number: int, column_number: int,
                 is_indirect: bool = False,
                 *,
                 binary_identity: Optional[str] = None,
                 snapshot_hash: Optional[str] = None,
                 ctree_index: Optional[int] = None,
                 opcode: Optional[int] = None,
                 source_ea: Optional[int] = None,
                 ida_line: Optional[int] = None,
                 ida_column: Optional[int] = None,
                 expression_text: str = "",
                 call_kind: str = "direct"):
        self.binary_name = binary_name
        self.caller_ea = caller_ea
        self.callee_ea = callee_ea
        self.caller_name = caller_name
        self.callee_name = callee_name
        self.callsite_ea = callsite_ea
        self.is_indirect = is_indirect
        self.line_number = line_number
        self.column_number = column_number
        self.binary_identity = binary_identity or binary_name
        self.snapshot_hash = snapshot_hash
        self.ctree_index = ctree_index
        self.opcode = opcode
        self.source_ea = source_ea
        self.ida_line = ida_line if ida_line is not None else line_number
        self.ida_column = ida_column if ida_column is not None else column_number
        self.expression_text = expression_text
        self.call_kind = call_kind
        self.is_populated = False
        # Return var's index is -1
        self.return_var: ArgInfo = None
        # Argument's index is 1-based
        self.args: List[ArgInfo] = []
        logger.debug(f"Recorded Callsite: {self.binary_name} - {self.caller_name} calling {self.callee_name} @ {hex(self.callsite_ea)}, line: {self.line_number}, col: {self.column_number} - {'Indirect' if self.is_indirect else ''}")
    
    # -------------
    # Line number and column number are set by ctree visitor after decompilation.
    # -------------
    def set_line_number(self, line_number: int):
        self.line_number = line_number

    def set_column_number(self, column_number: int):
        self.column_number = column_number

    # -------------
    # Argument and return-variable information comes from the local CTree
    # semantic snapshot.
    # -------------
    def set_return_var(self, return_var: ArgInfo):
        self.return_var = return_var

    def set_arguments(self, args: List[ArgInfo]):
        self.args = args

    def get_argument(self, index: int) -> ArgInfo:
        for arg in self.args:
            if arg.index == index:
                return arg
        return None
    
    def get_return_var(self) -> ArgInfo:
        return self.return_var

    def __str__(self) -> str:
        return f"CallSite [{hex(self.callsite_ea)} @ {self.binary_name}] {self.caller_name} -> {self.callee_name}, position ({self.line_number}, {self.column_number}), {'Indirect' if self.is_indirect else 'Direct'}"

    def __hash__(self) -> int:
        """Hash by immutable CTree identity, with a legacy-coordinate fallback."""
        return hash(self.identity_key)
    
    def __eq__(self, other) -> bool:
        """
        Two callsites are equal if they have the same identity key.
        """
        if not isinstance(other, CallSite):
            return False
        return self.identity_key == other.identity_key

    @property
    def identity_key(self) -> tuple:
        """Stable identity inside one immutable decompilation snapshot."""
        if self.snapshot_hash is not None and self.ctree_index is not None:
            return (
                self.binary_identity,
                self.caller_ea,
                self.snapshot_hash,
                self.ctree_index,
            )
        # Compatibility for old pickles and tests constructed without CTree
        # identity.  New onboarding never uses this fallback.
        return (
            self.binary_identity,
            self.caller_ea,
            self.line_number,
            self.column_number,
        )
    
    @property
    def key(self) -> object:
        """Return the CTree index used by new per-function callsite mappings."""
        if self.ctree_index is not None:
            return self.ctree_index
        return (self.line_number, self.column_number)
