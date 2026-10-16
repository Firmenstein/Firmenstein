"""Relocate live analysis handles while preserving historical producer evidence."""
import pickle
from pathlib import Path

from .common import TASK


def load_view(task: dict, *, task_root: Path = TASK, bootstrap_path: str | None = None):
    from fmst_analyzer.global_config import GlobalConfig
    from fmst_analyzer.graphs.lib_dep_graph import LibDepGraph
    from fmst_analyzer.graphs.api_dep_graph import ApiDepGraph
    from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView

    config = GlobalConfig()
    config.setup_workdir(task_root / "analysis")
    config.current_target = task["target"]
    config.fw_rootfs_path = task_root / "work/rootfs"
    old_root = Path(task.get('analysis_source_rootfs', task['source_rootfs']))
    # Only topology locations are live handles. Never replace strings in
    # reports, CTree snapshots, semantic failures or source identity receipts.
    for path in config.graph_cache_dir.glob("LibDepGraph_*.pkl"):
        topology = pickle.loads(path.read_bytes())
        if Path(topology["rootfs_path"]) == config.fw_rootfs_path:
            continue
        topology["nodes"] = [(name, str(config.fw_rootfs_path / Path(binary).relative_to(old_root)))
                             for name, binary in topology["nodes"]]
        topology["rootfs_path"] = str(config.fw_rootfs_path)
        path.write_bytes(pickle.dumps(topology))
    graph = LibDepGraph(config.fw_rootfs_path, config)
    if not graph._load_from_topology_cache() and bootstrap_path is None:
        raise RuntimeError("Relocated analysis topology is unavailable; original reports remain in /task/input")
    graph._cache_loaded = True
    target = graph.get_node_by_name(task["target"])
    if target is None and bootstrap_path:
        from ..rootfs_actions import _guest_host_path
        target = graph.add_binary(_guest_host_path(config.fw_rootfs_path, bootstrap_path, follow_final_symlink=True))
    if target is None:
        raise RuntimeError("Analysis topology lacks the target")
    scope = graph.transitive_closure_from(target)
    adg = ApiDepGraph(lib_dep_graph=graph, root=target, scope=scope, global_config=config,
                     analysis_level="semantic")
    for binary in scope:
        if binary._call_graph is not None:
            adg.binary_callgraphs[binary] = binary._call_graph
    adg._integrate_callgraphs()
    adg._resolve_impl_edges()
    adg._compute_reachable_nodes()

    class TaskAnalysisView(AnalysisView):
        def _get_callgraph_for_binary(self, binary_name):
            binary = self.lib_dep_graph.get_node_by_name(binary_name)
            retained = self.adg.binary_callgraphs.get(binary)
            return retained if retained is not None else super()._get_callgraph_for_binary(binary_name)

    return TaskAnalysisView(adg)
