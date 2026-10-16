"""
Dataflow analysis module for variable propagation tracking.

This module provides graph-based dataflow tracing that tracks specified
variables across functions. It's designed to work with LLM agents that
need precise context about variable data flow.

Call ``AnalysisView.trace_variables`` to build a ``DataFlowGraph``.  The
worklist traversal is private so downstream analyzers have one query entry.
"""

from .types import (
    # Enums
    TraceDirection,
    FlowEdgeType,
    VariableNodeType,
    # Core node type
    VariableNode,
    # Type aliases
    NodeKey,
)

from .graph import (
    DataFlowGraph,
)

__all__ = [
    # Enums
    "TraceDirection",
    "FlowEdgeType",
    "VariableNodeType",
    # Core node type
    "VariableNode",
    # Type aliases
    "NodeKey",
    # Graph
    "DataFlowGraph",
]
