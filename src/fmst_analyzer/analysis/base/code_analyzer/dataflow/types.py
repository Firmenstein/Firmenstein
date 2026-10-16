"""
Data types for dataflow analysis.

This module contains all the data structures used in dataflow tracing,
including the core VariableNode class and edge types.

Design principles:
- VariableNode is the unified node type containing all variable information
- Nodes are uniquely identified by (binary_name, func_name, var_name)
- Edge attributes are stored directly in networkx edge data
- Literals and globals are represented as special VariableNode instances
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Optional, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from fmst_analyzer.nodes.semantic import VariablePropInfo

# =============================================================================
# Enums
# =============================================================================

class TraceDirection(Enum):
    """Direction for dataflow tracing."""
    BACKWARD = "backward"   # Trace where data comes from (sources)
    FORWARD = "forward"     # Trace where data flows to (sinks)
    BOTH = "both"           # Trace in both directions


class FlowEdgeType(Enum):
    """Type of data flow edge in the graph."""
    INTRA_FUNC = "intra_func"        # Within same function (from flows_to/flows_from)
    PARAM_PASSING = "param_passing"  # Cross-function via argument passing
    RETURN_VALUE = "return_value"    # Cross-function via return value


class VariableNodeType(Enum):
    """Type of variable node in the dataflow graph."""
    IDENTIFIER = "identifier"       # Regular local/parameter variable
    LITERAL_STRING = "literal_string"       # Literal constant (string, number, etc.)
    LITERAL_NUMBER = "literal_number"       # Literal constant (string, number, etc.)
    CALL = "call"                     # Function call expression (e.g., "func(a,b)")
    EXPR = "expr"                     # Other complex expressions
    GLOBAL = "global"         # Global variable

NodeKey = Tuple[str, str, str]

# =============================================================================
# Core Node Type
# =============================================================================

@dataclass
class VariableNode:
    """
    Core node type for the dataflow graph.
    
    This class represents a variable in the dataflow graph. It serves as
    the unified node type containing all variable information.
    
    Identity:
        Nodes are uniquely identified by (binary_name, func_name, var_name).
        This allows the same variable name in different functions to be
        distinguished.
    
    Node types:
        - REGULAR: Normal local variables and function parameters
        - LITERAL: Literal constants (strings, numbers) as data sources
        - GLOBAL: Global variables
    """
    # === Identity (used for hash/eq) ===
    binary_name: str
    func_name: str
    var_name: str
    
    # === Node type ===
    node_type: VariableNodeType = VariableNodeType.IDENTIFIER
    
    # === Variable attributes ===
    is_parameter: bool = False
    param_index: int = -1           # 1-based parameter index, -1 if not a parameter
    is_return_value: bool = False
    declaration_line: int = -1
    usage_lines: List[int] = field(default_factory=list)
    
    # === Literal-specific attributes ===
    literal_value: Optional[str] = None
    literal_type: Optional[str] = None  # "STRING", "INT", etc.

    # === Expression-specific attributes ===
    expr_code: Optional[str] = None
    
    # === Call-specific attributes ===
    call_callee: Optional[str] = None  # Callee name for CALL type nodes
    
    # === Original prop_info (for advanced queries) ===
    prop_info: Optional['VariablePropInfo'] = None
    
    # === Concretization status ===
    concretized: bool = False  # True if this node has been fully analyzed, False for placeholder nodes
    
    def __hash__(self) -> int:
        """Hash based on identity tuple."""
        return hash((self.binary_name, self.func_name, self.var_name))
    
    def __eq__(self, other) -> bool:
        """Equality based on identity tuple."""
        if not isinstance(other, VariableNode):
            return False
        return (self.binary_name == other.binary_name and
                self.func_name == other.func_name and
                self.var_name == other.var_name)
    
    @property
    def key(self) -> Tuple[str, str, str]:
        """Identity key for lookup: (binary_name, func_name, var_name)."""
        return (self.binary_name, self.func_name, self.var_name)
    
    # === Factory methods ===
    
    @classmethod
    def create_literal(
        cls,
        binary_name: str,
        func_name: str,
        value: str,
        literal_type: str,
    ) -> 'VariableNode':
        """
        Create a literal source node.
        
        Args:
            binary_name: Name of the binary
            func_name: Function where the literal appears
            value: The literal value
            literal_type: Type of literal ("STRING", "INT", etc.)
        """
        # Determine node type
        node_type = VariableNodeType.LITERAL_STRING if literal_type == "STRING" else VariableNodeType.LITERAL_NUMBER
        
        # Use a unique name for the literal based on value hash
        var_name = f"<lit:{literal_type}:{hash(value)}>"
        return cls(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            node_type=node_type,
            literal_value=value,
            literal_type=literal_type,
            concretized=True
        )
    
    @classmethod
    def create_expr(
        cls,
        binary_name: str,
        func_name: str,
        expr_code: str,
    ) -> 'VariableNode':
        """
        Create an expression node.
        
        Args:
            binary_name: Name of the binary
            func_name: Function where the expression appears
            expr_code: The expression code
        """
        # Use a unique name for the expression based on code hash
        var_name = f"<expr:{hash(expr_code)}>"
        return cls(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            node_type=VariableNodeType.EXPR,
            expr_code=expr_code,
            concretized=True
        )
    
    @classmethod
    def create_call(
        cls,
        binary_name: str,
        func_name: str,
        call_code: str,
        callee_name: str,
    ) -> 'VariableNode':
        """
        Create a function call node.
        
        Args:
            binary_name: Name of the binary
            func_name: Function where the call expression appears
            call_code: The call expression code (e.g., "(int)func(a,b)")
            callee_name: Name of the called function
        """
        # Use a unique name for the call based on code hash
        var_name = f"<call:{hash(call_code)}>"
        return cls(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            node_type=VariableNodeType.CALL,
            expr_code=call_code,
            call_callee=callee_name,
            concretized=True
        )
    
    @classmethod
    def create_global(
        cls,
        binary_name: str,
        func_name: str,
        gvar_name: str
    ) -> 'VariableNode':
        """
        Create a global variable node.
        
        Args:
            binary_name: Name of the binary
            func_name: Function where the global is referenced
            gvar_name: Name of the global variable
        """
        return cls(
            binary_name=binary_name,
            func_name=func_name,
            var_name=gvar_name,
            node_type=VariableNodeType.GLOBAL,
            concretized=True
        )
    
    @classmethod
    def from_prop_info(
        cls,
        binary_name: str,
        func_name: str,
        prop_info: 'VariablePropInfo'
    ) -> 'VariableNode':
        """
        Create a VariableNode from VariablePropInfo.
        
        Args:
            binary_name: Name of the binary
            func_name: Function containing the variable
            prop_info: Variable propagation info from the CTree snapshot
        """
        node_type = VariableNodeType.IDENTIFIER
        if prop_info.is_global:
            node_type = VariableNodeType.GLOBAL
        
        return cls(
            binary_name=binary_name,
            func_name=func_name,
            var_name=prop_info.varname,
            node_type=node_type,
            is_parameter=prop_info.is_parameter,
            param_index=prop_info.param_index,
            is_return_value=prop_info.is_return_value,
            declaration_line=prop_info.declaration_line,
            usage_lines=prop_info.usage_lines,
            prop_info=prop_info,
            concretized=True
        )
    
    def __repr__(self) -> str:
        type_str = self.node_type.value if self.node_type != VariableNodeType.IDENTIFIER else ""
        type_suffix = f"[{type_str}]" if type_str else ""
        return f"VariableNode({self.binary_name}::{self.func_name}::{self.var_name}{type_suffix})"
