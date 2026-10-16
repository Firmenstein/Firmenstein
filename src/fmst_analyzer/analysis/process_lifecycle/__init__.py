"""ProcessLifecycleAnalyzer public API."""
from .analyzer_schema import (
    PROCESS_LIFECYCLE_SCHEMA_VERSION,
    ProcessCodeEvidence,
    ProcessEventAssessment,
    ProcessEventAssessmentReport,
    ProcessEventCallsite,
    ProcessEventDisposition,
    ProcessEventKind,
    ProcessLifecycleAgentResult,
    ProcessLifecycleAnalysisResult,
    ProcessTriggerCallsite,
    ProcessTriggerCallsiteDraft,
    ProcessTriggerInput,
)


def __getattr__(name):
    if name in {"PROCESS_EVENT_API_REGISTRY", "ProcessLifecycleAnalyzer"}:
        from . import analyzer
        return getattr(analyzer, name)
    raise AttributeError(name)

__all__ = [
    "PROCESS_EVENT_API_REGISTRY",
    "PROCESS_LIFECYCLE_SCHEMA_VERSION",
    "ProcessCodeEvidence",
    "ProcessEventAssessment",
    "ProcessEventAssessmentReport",
    "ProcessEventCallsite",
    "ProcessEventDisposition",
    "ProcessEventKind",
    "ProcessLifecycleAgentResult",
    "ProcessLifecycleAnalysisResult",
    "ProcessLifecycleAnalyzer",
    "ProcessTriggerCallsite",
    "ProcessTriggerCallsiteDraft",
    "ProcessTriggerInput",
]
