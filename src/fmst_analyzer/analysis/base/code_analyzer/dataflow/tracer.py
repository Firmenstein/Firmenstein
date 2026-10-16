"""Private worklist implementation for ``AnalysisView.trace_variables``."""

from typing import TYPE_CHECKING, List, Dict, Tuple, Optional, Union
from collections import deque
from dataclasses import dataclass
from loguru import logger

from fmst_analyzer.nodes.callsite import ArgType
from fmst_analyzer.nodes.semantic import (
    VariablePropResult, 
    VariableCallsiteInfo,
    VariablePropInfo,
)

from .types import (
    TraceDirection,
    FlowEdgeType,
    VariableNode,
    NodeKey,
)
from .graph import DataFlowGraph

if TYPE_CHECKING:
    from ..analysis_view import AnalysisView

@dataclass(frozen=True)
class _TraceTask:
    """
    Represents a single task in the dataflow tracing worklist.

    Depth semantics:
    - sink_depth: How many levels we have descended into callees (parameter passing)
    - rise_depth: How many levels we have ascended to callers (return value passing)
    
    These are tracked independently to allow fine-grained control over tracing bounds.
    """
    binary_name: str
    func_name: str
    var_name: str
    sink_depth: int      # Depth descended into callees (forward arg, backward return)
    rise_depth: int      # Depth ascended to callers (forward return, backward param)
    direction: TraceDirection
    
    @property
    def node_key(self) -> NodeKey:
        """Get the (binary_name, func_name, var_name) tuple for visited tracking."""
        return (self.binary_name, self.func_name, self.var_name)
    
class _DataFlowTraversal:
    """Bounded, same-binary inter-procedural variable traversal."""
    
    def __init__(self, view: "AnalysisView"):
        self.view = view
    
    def trace(
        self,
        binary_name: str,
        func_name: str,
        var_name: str,
        direction: Union[str, TraceDirection] = TraceDirection.BOTH,
        max_sink_depth: int = 2,
        max_rise_depth: int = 3,
    ) -> DataFlowGraph:
        """
        Trace dataflow for a specified variable across functions.
        
        This is the main entry point for dataflow tracing. It traces the
        specified variable starting from the given function, following
        data flow edges within the specified depth bounds.
        
        Depth semantics:
        - sink_depth: Tracks how deep we descend into callees
            - Forward: parameter passing (A calls B with var -> trace into B)
        - rise_depth: Tracks how high we ascend to callers
            - Forward: return value passing (A returns var -> trace to callers)
            - Backward: parameter tracing (var is param -> trace to callers)
        
        Args:
            binary_name: Name of the binary being analyzed
            func_name: Starting function name
            var_name: Variable name to trace
            direction: Tracing direction - "backward", "forward", or "both"
            max_sink_depth: Maximum depth to descend into callees
            max_rise_depth: Maximum depth to ascend to callers
            
        Returns:
            DataFlowGraph containing all traced variables as nodes and
            data flow relationships as edges
        """
        #TODO: thunk function 不计入 depth 限制
        #TODO: 追踪 fd 时，Global Variable 如何处理，连成一个 DataflowGraph 还是多个 Graph？

        # Normalize direction input
        if isinstance(direction, str):
            direction = TraceDirection(direction)
        
        # Initialize the graph
        graph = DataFlowGraph()
        
        # Worklist of same-binary traversal tasks.
        worklist: deque[_TraceTask] = deque()
        
        # Depth-aware visited tracking:
        # Maps (NodeKey, Direction) -> List[(sink_depth, rise_depth)]
        # We track the Pareto frontier of depths seen for each node + direction.
        # A new task is skipped only if it is dominated by ANY existing state.
        visited: Dict[Tuple[NodeKey, TraceDirection], List[Tuple[int, int]]] = {}
        
        # Initialize worklist with entry point
        initial_task = _TraceTask(
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            sink_depth=0,
            rise_depth=0,
            direction=direction
        )
        logger.info(f"Adding initial trace task: {initial_task}")
        worklist.append(initial_task)
        
        while worklist:
            task = worklist.popleft()
            
            # Depth-aware visited check:
            # Skip if this task is "dominated" by any previous visit state
            # Dominated means: existing_sink <= task_sink AND existing_rise <= task_rise
            visited_key = (task.node_key, task.direction)
            is_dominated = False
            if visited_key in visited:
                for (v_sink, v_rise) in visited[visited_key]:
                    if task.sink_depth >= v_sink and task.rise_depth >= v_rise:
                        is_dominated = True
                        break
            
            if is_dominated:
                continue

            # Add current state to visited
            if visited_key not in visited:
                visited[visited_key] = []
            visited[visited_key].append((task.sink_depth, task.rise_depth))

            # === Special handling for DIRECT_RET virtual variable ===
            # DIRECT_RET represents a direct return statement (e.g., return api_call(...))
            # Skip intra-procedural tracing and directly trace to callers
            if task.var_name == "DIRECT_RET":
                # Create a node for this DIRECT_RET in the graph
                direct_ret_node = graph.get_or_create_node(
                    binary_name=task.binary_name,
                    func_name=task.func_name,
                    var_name="DIRECT_RET"
                )
                
                new_tasks: List[_TraceTask] = []
                
                # Forward: trace to callers (RISE)
                if task.direction in (TraceDirection.FORWARD, TraceDirection.BOTH):
                    if task.rise_depth < max_rise_depth:
                        tasks = self._trace_forward_through_return(
                            graph, task, "DIRECT_RET"
                        )
                        new_tasks.extend(tasks)
                
                # Add collected tasks to worklist
                self._add_non_dominated_tasks(new_tasks, worklist, visited, "from DIRECT_RET")
                
                continue  # Skip normal processing for DIRECT_RET

            # === Normal variable processing ===
            # 1. Get intra-procedural propagation from the CTree snapshot
            prop_result = self._get_variable_prop(
                task.binary_name, task.func_name, task.var_name
            )
            if prop_result is None:
                warning_msg = f"Failed to trace '{task.var_name}' in '{task.func_name}' ({task.binary_name})"
                logger.warning(warning_msg)
                continue
            
            # 2. Process each traced variable
            for var_info in prop_result.variables:
                # NOTE: We intentionally do NOT mark other variables as visited here.
                # Each variable's "best depth" should be determined by its own path.
                # Marking them now with the current task's depth could block
                # better paths that arrive later.

                # Record the trace (adds node + intra-func edges from flows_from)
                # Literals in flows_from are also added as nodes by _record_var_trace
                _ = self._record_var_trace(
                    graph, task.binary_name, task.func_name, var_info
                )
                
                new_tasks: List[_TraceTask] = []

                # === Backward tracing ===
                if task.direction in (TraceDirection.BACKWARD, TraceDirection.BOTH):
                    # If parameter, trace to callers (RISE: ascending to caller)
                    if var_info.is_parameter and var_info.param_index > 0:
                        if task.rise_depth < max_rise_depth:
                            tasks = self._trace_backward_through_param(
                                graph, task,
                                var_info.varname, var_info.param_index
                            )
                            new_tasks.extend(tasks)
                
                # === Forward tracing ===
                if task.direction in (TraceDirection.FORWARD, TraceDirection.BOTH):
                    # If passed as arg to other functions (SINK: descending into callee)
                    for cs_arg in var_info.callsite_args:
                        if task.sink_depth < max_sink_depth:
                            tasks = self._trace_forward_through_arg(
                                graph, task,
                                var_info.varname, cs_arg
                            )
                            new_tasks.extend(tasks)
                    
                    # If return value, trace to callers (RISE: ascending to caller)
                    if var_info.is_return_value:
                        if task.rise_depth < max_rise_depth:
                            tasks = self._trace_forward_through_return(
                                graph, task,
                                var_info.varname
                            )
                            new_tasks.extend(tasks)
                
                # Add collected tasks to worklist (with depth-aware check)
                self._add_non_dominated_tasks(new_tasks, worklist, visited)
        
        return graph
    
    # =========================================================================
    # Internal Methods
    # =========================================================================
    
    def _is_task_dominated(
        self,
        task: _TraceTask,
        visited: Dict[Tuple[NodeKey, TraceDirection], List[Tuple[int, int]]]
    ) -> bool:
        """
        Check if a task is dominated by any existing visited state.
        
        A task is dominated if there exists a visited state with the same
        (node_key, direction) where both sink_depth and rise_depth are <= the task's.
        """
        visited_key = (task.node_key, task.direction)
        if visited_key in visited:
            for (v_sink, v_rise) in visited[visited_key]:
                if v_sink <= task.sink_depth and v_rise <= task.rise_depth:
                    return True
        return False
    
    def _add_non_dominated_tasks(
        self,
        tasks: List[_TraceTask],
        worklist: deque,
        visited: Dict[Tuple[NodeKey, TraceDirection], List[Tuple[int, int]]],
        source_label: str = ""
    ) -> None:
        """
        Add tasks to worklist if they are not dominated by visited states.
        
        Args:
            tasks: List of tasks to potentially add
            worklist: The worklist deque to add tasks to
            visited: The visited state dictionary
            source_label: Optional label for logging (e.g., "from DIRECT_RET")
        """
        for t in tasks:
            if not self._is_task_dominated(t, visited):
                label_suffix = f" ({source_label})" if source_label else ""
                logger.info(f"Adding new trace task{label_suffix}: {t}")
                worklist.append(t)
    
    def _get_variable_prop(
        self,
        binary_name: str,
        func_name: str,
        var_name: str
    ) -> Optional[VariablePropResult]:
        """
        Get variable propagation info for a single variable in a function.
        
        This wraps the cached CTree trace_variable_prop query.
        """
        try:
            return self.view._trace_variable_prop(
                binary_name=binary_name,
                func_name=func_name,
                initial_var_name=var_name
            )
        except Exception as e:
            logger.exception(f"Exception tracing {var_name} in {func_name}: {e}")
            return None
    
    def _record_var_trace(
        self,
        graph: DataFlowGraph,
        binary_name: str,
        func_name: str,
        var_info: VariablePropInfo
    ) -> VariableNode:
        """
        Record a variable trace in the graph and add intra-function edges.
        
        This method:
        1. Creates a VariableNode from the prop_info and adds it to the graph
        2. Creates intra-function edges from flows_from relationships (all types)
        3. Creates intra-function edges from flows_to relationships (EXPR only)
        
        Returns:
            The created or existing VariableNode
        """
        # Check if node already exists with concretized data
        existing = graph.get_node(binary_name, func_name, var_info.varname)
        if existing is not None and existing.concretized:
            return existing
        
        # Create concretized node from prop_info
        node = VariableNode.from_prop_info(
            binary_name=binary_name,
            func_name=func_name,
            prop_info=var_info
        )
        graph.add_node(node)
        
        # 1. Process flows_from (Sources -> this var)
        for source in var_info.flows_from:
            source_node = None
            
            if source.type == "IDENTIFIER" and source.name:
                # Get or create source node (may be placeholder)
                source_node = graph.get_or_create_node(
                    binary_name=binary_name,
                    func_name=func_name,
                    var_name=source.name
                )
            elif source.type in ("LITERAL_STRING", "LITERAL_NUMBER"):
                lit_type = "STRING" if source.type == "LITERAL_STRING" else "NUMBER"
                source_node = VariableNode.create_literal(
                    binary_name=binary_name,
                    func_name=func_name,
                    value=source.code,
                    literal_type=lit_type,
                )
                graph.add_node(source_node)
            elif source.type == "CALL":
                source_node = VariableNode.create_call(
                    binary_name=binary_name,
                    func_name=func_name,
                    call_code=source.code,
                    callee_name=source.name,
                )
                graph.add_node(source_node)
            elif source.type == "EXPR":
                source_node = VariableNode.create_expr(
                    binary_name=binary_name,
                    func_name=func_name,
                    expr_code=source.code,
                )
                graph.add_node(source_node)
            else:
                raise ValueError(f"Unknown source type: {source.type}")
            
            if source_node:
                graph.add_edge(
                    source=source_node,
                    target=node,
                    edge_type=FlowEdgeType.INTRA_FUNC,
                    line=source.line
                )

        # 2. Process flows_to (this var -> Targets) - ONLY for EXPR
        # IDENTIFIER targets will be handled when they are processed as the main variable
        for target in var_info.flows_to:
            if target.type == "EXPR":
                target_node = VariableNode.create_expr(
                    binary_name=binary_name,
                    func_name=func_name,
                    expr_code=target.code
                )
                graph.add_node(target_node)
                graph.add_edge(
                    source=node,
                    target=target_node,
                    edge_type=FlowEdgeType.INTRA_FUNC,
                    line=target.line
                )
        
        return node
    
    def _trace_backward_through_param(
        self,
        graph: DataFlowGraph,
        task: _TraceTask,
        var_name: str,
        param_idx: int
    ) -> List[_TraceTask]:
        """
        Trace backward: variable is a parameter, find callers' arguments.
        
        This is a RISE operation (ascending to caller), so rise_depth is incremented.
        """
        new_tasks: List[_TraceTask] = []
        # Get callers via CallGraph
        callers = self.view.get_function_caller_nodes(
            task.binary_name, task.func_name
        )
        
        for caller_node in callers:            
            # Find callsites in caller that call target_name
            callsites = self.view.get_callsites_to(caller_node, task.func_name)
            
            if not callsites:
                logger.warning(f"No callsites found in {caller_node.name} calling {task.func_name}, this should not happen.")
                continue

            for cs in callsites:
                if not cs.is_populated:
                    raise RuntimeError(
                        f"Onboarded callsite at line {cs.line_number} in "
                        f"{caller_node.name} calling {task.func_name} is not populated"
                    )
                
                # Get the argument at param_idx position
                arg = cs.get_argument(param_idx)
                if arg is None:
                    warning_msg = (
                        f"No argument at index {param_idx} for call to {task.func_name} "
                        f"from {caller_node.name} @ line {cs.line_number}"
                    )
                    logger.warning(warning_msg)
                    continue
                
                # Create callee param node (with known parameter info)
                callee_param_node = graph.get_or_create_param_node(
                    binary_name=task.binary_name,
                    func_name=task.func_name,
                    var_name=var_name,
                    param_index=param_idx
                )
                
                # Create caller variable node based on arg type
                if arg.type == ArgType.LOCAL:
                    caller_var_node = graph.get_or_create_node(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        var_name=arg.value
                    )
                elif arg.type == ArgType.GLOBAL:
                    caller_var_node = VariableNode.create_global(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        gvar_name=arg.value
                    )
                    graph.add_node(caller_var_node)
                elif arg.type == ArgType.LITERAL:
                    lit_type = "STRING" if arg.value.startswith('"') or arg.value.startswith("'") else "INT"
                    caller_var_node = VariableNode.create_literal(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        value=arg.value,
                        literal_type=lit_type,
                    )
                    graph.add_node(caller_var_node)
                else:
                    # Other types (CALL, OTHER): create expression node
                    caller_var_node = VariableNode.create_expr(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        expr_code=arg.value,
                    )
                    graph.add_node(caller_var_node)
                
                # Add cross-function edge
                graph.add_edge(
                    source=caller_var_node,
                    target=callee_param_node,
                    edge_type=FlowEdgeType.PARAM_PASSING,
                    line=cs.line_number or -1,
                    param_idx=param_idx
                )
                
                # RISE: ascending to caller, increment rise_depth
                if arg.type == ArgType.LOCAL or arg.type == ArgType.GLOBAL:
                    new_task = _TraceTask(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        var_name=arg.value,
                        sink_depth=task.sink_depth,
                        rise_depth=task.rise_depth + 1,  # RISE increment
                        direction=TraceDirection.BACKWARD
                    )
                    new_tasks.append(new_task)
        
        return new_tasks
    def _trace_forward_through_return(
        self,
        graph: DataFlowGraph,
        task: _TraceTask,
        return_var_name: str
    ) -> List[_TraceTask]:
        """
        Trace forward: variable is returned, find callers' receiver variables.
        
        This is a RISE operation (ascending to caller), so rise_depth is incremented.
        """
        new_tasks: List[_TraceTask] = []
        # Get callers via CallGraph
        callers = self.view.get_function_caller_nodes(
            task.binary_name, task.func_name
        )
        
        for caller_node in callers:            
            # Find callsites in caller that call target_name
            callsites = self.view.get_callsites_to(caller_node, task.func_name)
            
            if not callsites:
                logger.error(f"No callsites found in {caller_node.name} calling {task.func_name} (resolved from {task.func_name}), this should not happen.")
                continue

            for cs in callsites:
                if not cs.is_populated:
                    raise RuntimeError(
                        f"Onboarded callsite at line {cs.line_number} in "
                        f"{caller_node.name} calling {task.func_name} is not populated"
                    )
                
                # Get return variable
                ret_var = cs.get_return_var()
                if ret_var is None:
                    logger.info(f"No return variable info for callsite at line {cs.line_number} in {caller_node.name} calling {task.func_name} ({task.binary_name}).")
                    continue
                
                # Create return node (with known return value info)
                return_node = graph.get_or_create_return_node(
                    binary_name=task.binary_name,
                    func_name=task.func_name,
                    var_name=return_var_name
                )
                
                if ret_var.type == ArgType.LOCAL:
                    receiver_node = graph.get_or_create_node(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        var_name=ret_var.value
                    )
                elif ret_var.type == ArgType.GLOBAL:
                    receiver_node = VariableNode.create_global(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        gvar_name=ret_var.value
                    )
                    graph.add_node(receiver_node)
                elif ret_var.type == ArgType.LITERAL:
                    # Should not happen for L-values (assignment targets), but handled for completeness
                    lit_type = "STRING" if ret_var.value.startswith('"') or ret_var.value.startswith("'") else "INT"
                    receiver_node = VariableNode.create_literal(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        value=ret_var.value,
                        literal_type=lit_type,
                    )
                    graph.add_node(receiver_node)
                else:
                    # Other types (EXPR, OTHER): create expression node
                    receiver_node = VariableNode.create_expr(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        expr_code=ret_var.value,
                    )
                    graph.add_node(receiver_node)
                
                # Add cross-function return edge
                graph.add_edge(
                    source=return_node,
                    target=receiver_node,
                    edge_type=FlowEdgeType.RETURN_VALUE,
                    line=cs.line_number or -1
                )
                
                # RISE: ascending to caller, increment rise_depth
                if ret_var.type == ArgType.LOCAL or ret_var.type == ArgType.GLOBAL:
                    new_task = _TraceTask(
                        binary_name=task.binary_name,
                        func_name=caller_node.name,
                        var_name=ret_var.value,
                        sink_depth=task.sink_depth,
                        rise_depth=task.rise_depth + 1,  # RISE increment
                        direction=TraceDirection.FORWARD
                    )
                    new_tasks.append(new_task)
        
        return new_tasks


    def _trace_forward_through_arg(
        self,
        graph: DataFlowGraph,
        task: _TraceTask,
        var_name: str,
        cs_arg: VariableCallsiteInfo
    ) -> List[_TraceTask]:
        """
        Trace forward: variable is passed as argument, trace into callee.
        
        This is a SINK operation (descending into callee), so sink_depth is incremented.
        """
        new_tasks: List[_TraceTask] = []
        callee_name = cs_arg.callee
        arg_idx = cs_arg.arg_index
        
        # Try to get callee's parameter name
        param_name = self.view.get_function_param_name(
            task.binary_name, callee_name, arg_idx
        )
        callee_var = param_name if param_name else f"param_{arg_idx}"
        
        # Get or create nodes
        caller_var_node = graph.get_or_create_node(
            binary_name=task.binary_name,
            func_name=task.func_name,
            var_name=var_name
        )
        # Create callee param node (with known parameter info)
        callee_param_node = graph.get_or_create_param_node(
            binary_name=task.binary_name,
            func_name=callee_name,
            var_name=callee_var,
            param_index=arg_idx
        )
        
        # Add cross-function edge
        graph.add_edge(
            source=caller_var_node,
            target=callee_param_node,
            edge_type=FlowEdgeType.PARAM_PASSING,
            line=cs_arg.line,
            param_idx=arg_idx
        )
        
        # Check if callee is **External** or **External Thunk** If so, stop tracing into it
        if self.view.is_external_function(
            task.binary_name, callee_name, resolve_thunk=True
        ):
            return new_tasks

        # SINK: descending into callee, increment sink_depth
        if param_name:
            new_task = _TraceTask(
                binary_name=task.binary_name,
                func_name=callee_name,
                var_name=param_name,
                sink_depth=task.sink_depth + 1,  # SINK increment
                rise_depth=task.rise_depth,
                direction=TraceDirection.FORWARD
            )
            new_tasks.append(new_task)
        else:
            warning_msg = (
                f"Cannot resolve param name for {callee_name}::param[{arg_idx}] "
                f"(may be external function)"
            )
            logger.warning(warning_msg)
        
        return new_tasks


def _trace_variables(
    view: "AnalysisView",
    binary_name: str,
    func_name: str,
    var_name: str,
    direction: Union[str, TraceDirection] = TraceDirection.BOTH,
    max_sink_depth: int = 2,
    max_rise_depth: int = 3,
) -> DataFlowGraph:
    """Build one bounded same-binary dataflow graph for ``view``."""
    return _DataFlowTraversal(view).trace(
        binary_name=binary_name,
        func_name=func_name,
        var_name=var_name,
        direction=direction,
        max_sink_depth=max_sink_depth,
        max_rise_depth=max_rise_depth,
    )
