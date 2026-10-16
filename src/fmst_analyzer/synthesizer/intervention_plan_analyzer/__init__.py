"""Production intervention-plan entry points."""

from .schema import InterventionPlanResult, LaunchChoice, NoIntervention, UnitPlanReport


def __getattr__(name):
    """Keep schema and Markdown replay independent of native/Agent entry points."""
    from importlib import import_module

    modules = {
        "InterventionPlanAnalyzer": "analyzer",
        "load_persisted_intervention_plan": "analyzer",
        "PlanAgent": "plan_agent",
    }
    if name not in modules:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{modules[name]}"), name)


__all__ = [
    "UnitPlanReport",
    "PlanAgent",
    "InterventionPlanResult",
    "InterventionPlanAnalyzer",
    "LaunchChoice",
    "NoIntervention",
    "load_persisted_intervention_plan",
]
