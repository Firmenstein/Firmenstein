from .schema import IPCAnalysisResult, IPC_ANALYSIS_SCHEMA_VERSION


def __getattr__(name):
    if name in {"IPCAnalyzer", "PeerMatchingContext"}:
        from . import analyzer
        return getattr(analyzer, name)
    raise AttributeError(name)


__all__ = [
    "IPCAnalyzer",
    "IPCAnalysisResult",
    "IPC_ANALYSIS_SCHEMA_VERSION",
    "PeerMatchingContext",
]
