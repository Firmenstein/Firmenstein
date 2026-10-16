"""
DataFlowGraph - Graph-based representation of dataflow analysis results.

This module provides a graph structure built on top of networkx for
representing and querying data flow relationships between variables.

Design principles:
- Nodes are VariableNode objects (self-contained with all info)
- Edge attributes stored directly in networkx edge data
- No duplicate storage of information
- Literals and globals are special VariableNode instances in the graph
"""

from typing import Dict, List, Optional
from loguru import logger

import networkx as nx

from .types import (
    VariableNode,
    FlowEdgeType,
    NodeKey,
)

class DataFlowGraph:
    """
    Graph-based representation of dataflow trace results.

    This class uses networkx.DiGraph internally with VariableNode objects
    as nodes. Edge attributes (type, line, param_idx) are stored directly
    in networkx edge data.

    Key design decisions:
    - Nodes are VariableNode instances (hashable by identity tuple)
    - Quick lookup via _node_index: (func_name, var_name) -> VariableNode
    - Literals and globals are represented as special VariableNode types
    - add_edge() ensures both nodes exist before adding the edge
    """

    def __init__(self):
        """Initialize a DataFlowGraph."""
        # Internal networkx graph
        self._graph: nx.DiGraph = nx.DiGraph()

        # Quick lookup index: (binary_name, func_name, var_name) -> VariableNode
        self._node_index: Dict[NodeKey, VariableNode] = {}

    # =========================================================================
    # Node Operations
    # =========================================================================

    def add_node(self, node: VariableNode) -> bool:
        """
        Add a node to the graph.

        If a node with the same (func_name, var_name) exists:
        - If the existing node is a placeholder (no prop_info), update it
        - Otherwise, keep the existing node

        Args:
            node: The VariableNode to add

        Returns:
            True if node was newly added, False if it already existed
        """
        key = node.key

        if key in self._node_index:
            existing = self._node_index[key]
            # Only upgrade the placeholder node with the SAME key (binary, func, var)
            # This ensures we don't accidentally replace unrelated nodes
            assert existing.key == key, f"Node index inconsistency: {existing.key} != {key}"

            # Update placeholder nodes with concretized data
            if not existing.concretized and node.concretized:
                # Save existing edges before removing the placeholder node
                in_edges = list(self._graph.in_edges(existing, data=True))
                out_edges = list(self._graph.out_edges(existing, data=True))

                # Remove old placeholder and add new concretized node
                self._graph.remove_node(existing)
                self._graph.add_node(node)
                self._node_index[key] = node

                # Migrate edges to the new node
                for src, _, data in in_edges:
                    if src in self._graph:  # Source node still exists
                        self._graph.add_edge(src, node, **data)

                for _, tgt, data in out_edges:
                    if tgt in self._graph:  # Target node still exists
                        self._graph.add_edge(node, tgt, **data)

                return True
            return False

        self._graph.add_node(node)
        self._node_index[key] = node
        return True

    def get_node(self, binary_name: str, func_name: str, var_name: str) -> Optional[VariableNode]:
        """
        Get a node by binary, function and variable name.

        Args:
            binary_name: Binary name
            func_name: Function name
            var_name: Variable name

        Returns:
            VariableNode if found, None otherwise
        """
        return self._node_index.get((binary_name, func_name, var_name))

    def get_or_create_node(
        self,
        binary_name: str,
        func_name: str,
        var_name: str
    ) -> VariableNode:
        """
        Get existing node or create a placeholder node.

        This is useful when adding edges where one end may not be
        fully traced yet. The created placeholder node will have
        concretized=False and can be upgraded later with full data.

        Args:
            binary_name: Name of the binary
            func_name: Function name
            var_name: Variable name

        Returns:
            Existing or newly created VariableNode (placeholder if new)
        """
        existing = self.get_node(binary_name, func_name, var_name)
        if existing is not None:
            return existing

        # Create placeholder node (concretized=False by default)
        node = VariableNode(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name
        )
        self.add_node(node)
        return node

    def get_or_create_param_node(
        self,
        binary_name: str,
        func_name: str,
        var_name: str,
        param_index: int
    ) -> VariableNode:
        """
        Get existing node or create a placeholder node with parameter info.
        Args:
            binary_name: Name of the binary
            func_name: Function name
            var_name: Variable/parameter name
            param_index: 1-based parameter index

        Returns:
            Existing or newly created VariableNode with parameter info
        """
        existing = self.get_node(binary_name, func_name, var_name)
        if existing is not None:
            # If already concretized, return as-is
            if existing.concretized:
                return existing
            # Merge partial info (don't overwrite if already set)
            if not existing.is_parameter:
                existing.is_parameter = True
                existing.param_index = param_index
            return existing

        # Create placeholder node with parameter info
        node = VariableNode(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            is_parameter=True,
            param_index=param_index,
            concretized=False
        )
        self.add_node(node)
        return node

    def get_or_create_return_node(
        self,
        binary_name: str,
        func_name: str,
        var_name: str
    ) -> VariableNode:
        """
        Get existing node or create a placeholder node with return value info.

        Args:
            binary_name: Name of the binary
            func_name: Function name
            var_name: Variable name (or "DIRECT_RET" for direct returns)

        Returns:
            Existing or newly created VariableNode with return value info
        """
        existing = self.get_node(binary_name, func_name, var_name)
        if existing is not None:
            # If already concretized, return as-is
            if existing.concretized:
                return existing
            # Merge partial info (don't overwrite if already set)
            if not existing.is_return_value:
                existing.is_return_value = True
            return existing

        # Create placeholder node with return value info
        node = VariableNode(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            is_return_value=True,
            concretized=False
        )
        self.add_node(node)
        return node

    # =========================================================================
    # Edge Operations
    # =========================================================================

    def add_edge(
        self,
        source: VariableNode,
        target: VariableNode,
        edge_type: FlowEdgeType,
        line: int = -1,
        param_idx: int = -1
    ) -> bool:
        """
        Add an edge between two nodes.

        Both source and target nodes are automatically added to the graph
        if they don't exist yet.

        Args:
            source: Source VariableNode
            target: Target VariableNode
            edge_type: Type of the edge
            line: Line number where the flow occurs
            param_idx: Parameter index for PARAM_PASSING edges

        Returns:
            True if edge was newly added, False if it already existed
        """
        # Ensure both nodes exist
        self.add_node(source)
        self.add_node(target)

        # Check if edge already exists
        if self._graph.has_edge(source, target):
            return False

        self._graph.add_edge(
            source,
            target,
            edge_type=edge_type,
            line=line,
            param_idx=param_idx
        )
        return True

    # =========================================================================
    # Utility Properties
    # =========================================================================

    @property
    def nodes(self) -> List[VariableNode]:
        """Get all nodes in the graph."""
        return list(self._graph.nodes())

    @property
    def node_count(self) -> int:
        """Get the number of nodes."""
        return self._graph.number_of_nodes()
