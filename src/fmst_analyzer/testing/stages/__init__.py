from .test_graph_build import test_graph_build
from .test_global_vars import test_global_vars
from .test_tools import test_tools
from .test_ctree_integrity import test_ctree_integrity
from .test_code_tools import test_code_tools
from .test_dataflow import test_dataflow
from .test_ipc_analysis import test_ipc_analysis, test_ipc_analysis_static
from .test_ipc_peer_tools import test_ipc_peer_tools
from .test_agent_api import test_agent_api
from .test_file_resolver_static import test_file_resolver_static
from .test_file_resolver import test_file_resolver
from .test_network_analyzer_static import test_network_analyzer_static
from .test_network_analyzer import test_network_analyzer
from .test_process_lifecycle_static import test_process_lifecycle_static
from .test_process_lifecycle import test_process_lifecycle
from .test_init_launch import test_init_launch, test_init_launch_static
from .test_intervention_catalog import test_intervention_catalog
from .test_intervention_plan import test_intervention_plan
from .test_intervention_generate import test_intervention_generate
from .test_intervention_runner import test_intervention_runner

STAGE_REGISTRY = {
    "agent-api": test_agent_api,
    "graph-build": test_graph_build,
    "global-vars": test_global_vars,
    "tools": test_tools,
    "ctree-integrity": test_ctree_integrity,
    "code-tools": test_code_tools,
    "dataflow": test_dataflow,
    "ipc-analysis": test_ipc_analysis,
    "ipc-analysis-static": test_ipc_analysis_static,
    "ipc-peer-tools": test_ipc_peer_tools,
    "file-resolver-static": test_file_resolver_static,
    "file-resolver": test_file_resolver,
    "network-analyzer-static": test_network_analyzer_static,
    "network-analyzer": test_network_analyzer,
    "process-lifecycle-static": test_process_lifecycle_static,
    "process-lifecycle": test_process_lifecycle,
    "init-launch": test_init_launch,
    "init-launch-static": test_init_launch_static,
    "intervention-planner-inputs": test_intervention_catalog,
    "intervention-plan": test_intervention_plan,
    "intervention-generate": test_intervention_generate,
    # Explicit only: this starts Docker and a paid persistent Agent, so
    # it is intentionally absent from STAGE_ORDER / `--stage all`.
    "intervention-runner": test_intervention_runner,
}

STAGE_ORDER = [
    "agent-api",
    "graph-build",
    "global-vars",
    "tools",
    "ctree-integrity",
    "code-tools",
    "dataflow",
    "ipc-analysis-static",
    "ipc-analysis",
    "ipc-peer-tools",
    "file-resolver-static",
    "file-resolver",
    "network-analyzer-static",
    "network-analyzer",
    "process-lifecycle-static",
    "process-lifecycle",
    "init-launch-static",
    "init-launch",
    "intervention-planner-inputs",
    "intervention-plan",
    "intervention-generate",
]

from ._utils import format_fail_detail

__all__ = ["STAGE_REGISTRY", "STAGE_ORDER", "format_fail_detail"]
