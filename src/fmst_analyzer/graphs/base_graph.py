"""Base graph module for Firmenstein framework.

This module provides an abstract base class for directed graphs used in firmware analysis.
It serves as the foundation for API dependency graphs and library dependency graphs.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, List, Set, Optional, Iterator, Tuple, Any, Union
from enum import Enum
import networkx as nx
from ..nodes.function import FunctionNode
from ..nodes.binary import BinaryNode
from pathlib import Path
from loguru import logger

class EdgeType(Enum):
    """Edge types for graph relationships."""
    DEPENDENCY = "dependency"
    IMPL = "implementation"
    CALL = "call"

# Type variable for node types
NodeType = TypeVar('NodeType', FunctionNode, BinaryNode)

class Recursion(Generic[NodeType]):
    """Strongly Connected Component (SCC) — a group of nodes forming a cycle.

    Consumers iterate over ``.nodes`` to process all members. The ordering
    within an SCC is arbitrary (no topological order exists for a cycle).
    """
    def __init__(self, nodes: List[NodeType]):
        if not nodes:
            raise ValueError("Recursion must contain at least one node")
        self.nodes = nodes

    @property
    def size(self) -> int:
        return len(self.nodes)

    def __getstate__(self):
        return {'nodes': self.nodes}

    def __setstate__(self, state):
        self.nodes = state['nodes']

class BaseGraph(Generic[NodeType], ABC):
    """Abstract base class for directed graphs.
    
    This class provides a generic interface for directed graphs that can be used
    with different node types (FunctionNode, BinaryNode, etc.).
    
    The implementation uses NetworkX as the underlying graph library for efficiency
    and to leverage existing graph algorithms.
    """
    
    def __init__(self):
        """Initialize an empty directed graph."""
        self._graph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        """Get the underlying NetworkX directed graph."""
        return self._graph
    
    def add_node(self, node: NodeType) -> bool:
        """Add a node to the graph.
        
        Args:
            node: The node to add to the graph.
            
        Returns:
            bool: True if the node was added, False if it already existed.
        """
        if node in self._graph:
            return False
        self._graph.add_node(node)
        return True
    
    def remove_node(self, node: NodeType) -> bool:
        """Remove a node and all its edges from the graph.
        
        Args:
            node: The node to remove from the graph.
            
        Returns:
            bool: True if the node was removed, False if it didn't exist.
        """
        if node not in self._graph:
            return False
        self._graph.remove_node(node)
        return True
    
    def add_edge(self, src: NodeType, dst: NodeType, edge_type: EdgeType) -> bool:
        """Add an edge between two nodes with specified type.
        
        If either node doesn't exist in the graph, it will be added automatically.
        
        Args:
            src: The source node.
            dst: The destination node.
            edge_type: The type of the edge.
            
        Returns:
            bool: True if the edge was added, False if it already existed with the same type.
        """
        # Check if edge with same type already exists
        if self._graph.has_edge(src, dst):
            existing_edge_data = self._graph[src][dst]
            if existing_edge_data.get('type') == edge_type:
                return False
            # If edge exists but with different type, update it
            existing_edge_data['type'] = edge_type
            return True
        
        # Add nodes if they don't exist
        if src not in self._graph:
            self._graph.add_node(src)
        if dst not in self._graph:
            self._graph.add_node(dst)
            
        self._graph.add_edge(src, dst, type=edge_type)
        return True
    
    def remove_edge(self, src: NodeType, dst: NodeType) -> bool:
        """Remove an edge between two nodes.
        
        Args:
            src: The source node.
            dst: The destination node.
            
        Returns:
            bool: True if the edge was removed, False if it didn't exist.
        """
        if not self._graph.has_edge(src, dst):
            return False
        self._graph.remove_edge(src, dst)
        return True
    
    def has_node(self, node: NodeType) -> bool:
        """Check if a node exists in the graph.
        
        Args:
            node: The node to check for.
            
        Returns:
            bool: True if the node exists, False otherwise.
        """
        return node in self._graph
    
    def has_edge(self, src: NodeType, dst: NodeType) -> bool:
        """Check if an edge exists between two nodes.
        
        Args:
            src: The source node.
            dst: The destination node.
            
        Returns:
            bool: True if the edge exists, False otherwise.
        """
        return self._graph.has_edge(src, dst)
    
    def get_nodes(self) -> Set[NodeType]:
        """Get all nodes in the graph.
        
        Returns:
            Set[NodeType]: A set containing all nodes in the graph.
        """
        return set(self._graph.nodes())
    
    def get_node_by_name(self, name: str) -> Optional[NodeType]:
        """Get a node by its name attribute.
        
        Args:
            name: The name of the node to find.
            
        Returns:
            Optional[NodeType]: The node if found, None otherwise.
        """
        for node in self._graph.nodes():
            if hasattr(node, 'name') and node.name == name:
                return node
        return None
    
    def get_edges(self) -> Set[Tuple[NodeType, NodeType]]:
        """Get all edges in the graph.
        
        Returns:
            Set[Tuple[NodeType, NodeType]]: A set of (source, destination) tuples.
        """
        return set(self._graph.edges())
    
    def get_edge_type(self, src: NodeType, dst: NodeType) -> Optional[EdgeType]:
        """Get the type of an edge between two nodes.
        
        Args:
            src: The source node.
            dst: The destination node.
            
        Returns:
            Optional[EdgeType]: The edge type if the edge exists, None otherwise.
        """
        if not self._graph.has_edge(src, dst):
            return None
        edge_data = self._graph[src][dst]
        return edge_data.get('type')
    
    def get_predecessors(self, node: NodeType) -> Set[NodeType]:
        """Get all nodes that have edges pointing to the given node.
        
        Args:
            node: The target node.
            
        Returns:
            Set[NodeType]: A set of predecessor nodes.
        """
        if node not in self._graph:
            return set()
        return set(self._graph.predecessors(node))
    
    def get_predecessors_by_type(self, node: NodeType, edge_types: Union[EdgeType, List[EdgeType]]) -> Set[NodeType]:
        """Get all nodes that point to the given node via edges of specified type(s).
        
        Args:
            node: The target node.
            edge_types: The edge type(s) to filter by. Can be a single EdgeType or a list of EdgeTypes.
            
        Returns:
            Set[NodeType]: A set of predecessor nodes connected by edges of the specified type(s).
        """
        if node not in self._graph:
            return set()
        
        # Convert single edge type to list for uniform processing
        if isinstance(edge_types, EdgeType):
            edge_types = [edge_types]
        
        predecessors = set()
        for predecessor in self._graph.predecessors(node):
            edge_data = self._graph[predecessor][node]
            edge_type = edge_data.get('type')
            if edge_type in edge_types:
                predecessors.add(predecessor)
        
        return predecessors
    
    def get_successors(self, node: NodeType) -> Set[NodeType]:
        """Get all nodes that the given node points to.
        
        Args:
            node: The source node.
            
        Returns:
            Set[NodeType]: A set of successor nodes.
        """
        if node not in self._graph:
            return set()
        return set(self._graph.successors(node))
    
    def get_successors_by_type(self, node: NodeType, edge_types: Union[EdgeType, List[EdgeType]]) -> Set[NodeType]:
        """Get all nodes that the given node points to via edges of specified type(s).
        
        Args:
            node: The source node.
            edge_types: The edge type(s) to filter by. Can be a single EdgeType or a list of EdgeTypes.
            
        Returns:
            Set[NodeType]: A set of successor nodes connected by edges of the specified type(s).
        """
        if node not in self._graph:
            return set()
        
        # Convert single edge type to list for uniform processing
        if isinstance(edge_types, EdgeType):
            edge_types = [edge_types]
        
        successors = set()
        for successor in self._graph.successors(node):
            edge_data = self._graph[node][successor]
            edge_type = edge_data.get('type')
            if edge_type in edge_types:
                successors.add(successor)
        
        return successors
    
    def get_in_degree(self, node: NodeType) -> int:
        """Get the in-degree of a node (number of incoming edges).
        
        Args:
            node: The node to get the in-degree for.
            
        Returns:
            int: The in-degree of the node, 0 if the node doesn't exist.
        """
        if node not in self._graph:
            return 0
        return self._graph.in_degree(node)
    
    def get_out_degree(self, node: NodeType) -> int:
        """Get the out-degree of a node (number of outgoing edges).
        
        Args:
            node: The node to get the out-degree for.
            
        Returns:
            int: The out-degree of the node, 0 if the node doesn't exist.
        """
        if node not in self._graph:
            return 0
        return self._graph.out_degree(node)
    
    def is_empty(self) -> bool:
        """Check if the graph is empty (no nodes).
        
        Returns:
            bool: True if the graph has no nodes, False otherwise.
        """
        return len(self._graph) == 0
    
    def size(self) -> int:
        """Get the number of nodes in the graph.
        
        Returns:
            int: The number of nodes.
        """
        return len(self._graph)
    
    def edge_count(self) -> int:
        """Get the number of edges in the graph.
        
        Returns:
            int: The number of edges.
        """
        return self._graph.number_of_edges()
    
    def clear(self) -> None:
        """Remove all nodes and edges from the graph."""
        self._graph.clear()
    
    def copy(self) -> 'BaseGraph[NodeType]':
        """Create a shallow copy of the graph.

        Uses object.__new__ to avoid calling subclass __init__ (which may
        require positional arguments like rootfs_path or binary_node).
        Only the NetworkX graph is copied; subclass-specific attributes
        are NOT carried over.
        """
        new_graph = object.__new__(self.__class__)
        new_graph._graph = self._graph.copy()
        return new_graph
    
    def __contains__(self, node: NodeType) -> bool:
        """Support 'in' operator for checking node existence."""
        return node in self._graph
    
    def __len__(self) -> int:
        """Support len() function to get number of nodes."""
        return len(self._graph)
    
    def __iter__(self) -> Iterator[NodeType]:
        """Support iteration over nodes."""
        return iter(self._graph)
    
    def __str__(self) -> str:
        """String representation of the graph."""
        edge_type_counts = {}
        for _, _, data in self._graph.edges(data=True):
            edge_type = data.get('type')
            edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
        
        edge_info = ", ".join([f"{edge_type.value}: {count}" for edge_type, count in edge_type_counts.items()])
        return f"{self.__class__.__name__}(nodes={self.size()}, edges={self.edge_count()}, types=[{edge_info}])"
    
    def __repr__(self) -> str:
        """Detailed string representation of the graph."""
        return self.__str__()
    
    @abstractmethod
    def get_node_info(self, node: NodeType) -> str:
        """Get string representation of a node.
        
        This method should be implemented by subclasses to provide
        node-specific information.
        
        Args:
            node: The node to get information for.
            
        Returns:
            str: String representation of the node.
        """
        pass

    def topological_sort(self, reverse: bool = False, validate: bool = True) -> List[Union[NodeType, 'Recursion[NodeType]']]:
        """Return a topologically sorted list of nodes and Recursion objects.
        
        This method performs topological sorting on the graph, treating
        recursive structures (SCCs) as single units. Uses NetworkX's condensation graph
        to handle cycles properly.
        
        Args:
            reverse: If True, return reverse topological order (leaves to roots).
                    If False, return normal topological order (roots to leaves).
            validate: If True, validate that all successors are in correct positions.
                     For forward order: successors should come after predecessors.
                     For reverse order: successors should come before predecessors.
                    
        Returns:
            List[NodeType|Recursion]: Topologically sorted list where recursive
            structures are represented as Recursion objects.
            
        Raises:
            ValueError: If validation fails (when validate=True)
        """
        if self.is_empty():
            return []
        
        # Create condensation graph with mapping
        # This contracts SCCs to single nodes and provides node->scc_id mapping
        condensed_graph = nx.condensation(self.graph)
        mapping = condensed_graph.graph['mapping']  # original_node -> scc_id
        
        # Group nodes by their SCC
        scc_groups = {}
        for node, scc_id in mapping.items():
            if scc_id not in scc_groups:
                scc_groups[scc_id] = []
            scc_groups[scc_id].append(node)
        
        # Create SCC to object mapping
        scc_to_object = {}
        for scc_id, nodes in scc_groups.items():
            if len(nodes) == 1:
                node = nodes[0]
                # Check if it's a self-recursive node
                if self.graph.has_edge(node, node):
                    scc_to_object[scc_id] = Recursion([node])
                else:
                    scc_to_object[scc_id] = node
                    
            else:
                # Multi-node SCC - create recursion
                scc_to_object[scc_id] = Recursion(nodes)
        
        try:
            # Perform topological sort on the condensed graph
            if reverse:
                topo_order = list(nx.topological_sort(condensed_graph.reverse()))
            else:
                topo_order = list(nx.topological_sort(condensed_graph))
            
            # Convert SCC indices to NodeType|Recursion objects
            result = [scc_to_object[scc_id] for scc_id in topo_order]
            
            # Validate if requested
            if validate:
                self._validate_topological_order(result, reverse)
            
            return result
            
        except nx.NetworkXError as e:
            # This should not happen with condensation graph, but handle gracefully
            raise ValueError(f"Unexpected error in topological sort: {e}")
    
    def _validate_topological_order(self, topological_order: List[Union[NodeType, 'Recursion[NodeType]']], reverse: bool):
        """Validate that all successors are in correct positions in topological order.
        
        For forward order (reverse=False): 
            - Each successor should appear AFTER its predecessor in the list
            - i.e., for edge A -> B, B's position > A's position
            
        For reverse order (reverse=True):
            - Each successor should appear BEFORE its predecessor in the list
            - i.e., for edge A -> B, B's position < A's position
        
        Note: Edges within the same SCC (same position) are allowed and expected
        as they represent recursive relationships.
        
        Args:
            topological_order: The topological order to validate
            reverse: Whether this is a reverse topological order
            
        Raises:
            ValueError: If validation fails with detailed error message
        """        
        # Build position mapping for all nodes
        node_positions = {}
        for idx, item in enumerate(topological_order):
            if isinstance(item, Recursion):
                # All nodes in a recursion have the same position
                for node in item.nodes:
                    node_positions[node] = idx
            else:
                node_positions[item] = idx
        
        # Validate all edges
        violations = []
        for src, dst in self.get_edges():
            src_pos = node_positions.get(src)
            dst_pos = node_positions.get(dst)
            
            if src_pos is None or dst_pos is None:
                violations.append(f"Node missing from topological order: src={src.name if hasattr(src, 'name') else src}, dst={dst.name if hasattr(dst, 'name') else dst}")
                continue
            
            # Skip validation for edges within the same SCC (same position)
            # These represent recursive relationships and are expected
            if src_pos == dst_pos:
                continue
            
            # Check position constraint based on order direction
            if reverse:
                # Reverse order: successor (dst) should come BEFORE predecessor (src)
                if dst_pos > src_pos:
                    edge_type = self.get_edge_type(src, dst)
                    violations.append(
                        f"Reverse order violation: {src.name if hasattr(src, 'name') else src} (pos={src_pos}) "
                        f"-> {dst.name if hasattr(dst, 'name') else dst} (pos={dst_pos}), "
                        f"edge_type={edge_type.value if edge_type else 'unknown'}, "
                        f"but successor should come BEFORE predecessor in reverse order"
                    )
            else:
                # Forward order: successor (dst) should come AFTER predecessor (src)
                if dst_pos < src_pos:
                    edge_type = self.get_edge_type(src, dst)
                    violations.append(
                        f"Forward order violation: {src.name if hasattr(src, 'name') else src} (pos={src_pos}) "
                        f"-> {dst.name if hasattr(dst, 'name') else dst} (pos={dst_pos}), "
                        f"edge_type={edge_type.value if edge_type else 'unknown'}, "
                        f"but successor should come AFTER predecessor in forward order"
                    )
        
        if violations:
            error_msg = f"Topological sort validation failed with {len(violations)} violations:\n"
            # Show first 10 violations
            for violation in violations[:10]:
                error_msg += f"  - {violation}\n"
            if len(violations) > 10:
                error_msg += f"  ... and {len(violations) - 10} more violations\n"
            
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info(f"Topological sort validation passed: all {self.edge_count()} edges satisfy "
                   f"{'reverse' if reverse else 'forward'} order constraints")
