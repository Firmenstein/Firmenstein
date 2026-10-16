"""Agent-first NetworkAnalyzer.

Static collection preserves immutable CTree facts and persisted IPC/File
coverage dedup. Full analysis discovers environment interactions from bounded
parallel resource-anchor waves.
"""
from .analyzer_schema import (
    NETWORK_ANALYSIS_SCHEMA_VERSION,
    IdentityResolution,
    NetworkAnalysisResult,
    NetworkAPIEffect,
    NetworkCallsite,
    NetworkDisposition,
    NetworkResourceAgentResult,
    NetworkIdentity,
    NetworkInteractionAnalysis,
    NetworkInteractionDraft,
    NetworkInteractionKind,
    NetworkInteractionReport,
)
from .registry import lookup_network_api, normalize_api_name


def __getattr__(name):
    if name == "NetworkAnalyzer":
        from .analyzer import NetworkAnalyzer
        return NetworkAnalyzer
    raise AttributeError(name)

__all__ = [
    "NETWORK_ANALYSIS_SCHEMA_VERSION",
    "IdentityResolution",
    "NetworkAnalysisResult",
    "NetworkAPIEffect",
    "NetworkAnalyzer",
    "NetworkCallsite",
    "NetworkDisposition",
    "NetworkResourceAgentResult",
    "NetworkIdentity",
    "NetworkInteractionAnalysis",
    "NetworkInteractionDraft",
    "NetworkInteractionKind",
    "NetworkInteractionReport",
    "lookup_network_api",
    "normalize_api_name",
]
