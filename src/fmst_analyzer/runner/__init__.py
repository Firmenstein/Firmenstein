"""Container-isolated validation; Agent controller imports only on demand."""
from .schema import RehostingResult, RunnerDecision

__all__ = ["RehostingResult", "RehostingRunner", "RunnerDecision", "create_runner", "runner_succeeded"]


def create_runner(global_config, **kwargs):
    """Select exactly one backend. Never silently retry through the old Runner."""
    backend = getattr(global_config, "runner_backend", "agent_container")
    if backend == "agent_container":
        from .task.runner import ContainerRehostingRunner
        return ContainerRehostingRunner(global_config, **kwargs)
    if backend == "legacy":
        from .runner import RehostingRunner
        return RehostingRunner(global_config, **kwargs)
    raise ValueError(f"Unknown Runner backend: {backend}")


def runner_succeeded(result):
    from .task.schema import TaskResult
    return result.status == ("serving" if isinstance(result, TaskResult) else "success")

def __getattr__(name):
    if name == "RehostingRunner":
        from .runner import RehostingRunner
        return RehostingRunner
    raise AttributeError(name)
