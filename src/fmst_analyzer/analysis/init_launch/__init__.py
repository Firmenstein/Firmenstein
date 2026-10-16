"""Single-Agent rootfs launch-command discovery."""

from .analyzer_schema import (
    AnalysisGap,
    InitLaunchAnalysisResult,
    LaunchRecipe,
    LaunchRecipeAgentOutput,
    LaunchRecipeDraft,
    LaunchRecipeAnalysis,
    SourceSnippet,
    TargetIdentity,
)
from .target_identity import enumerate_target_identity


def __getattr__(name):
    if name == "InitLaunchAnalyzer":
        from .analyzer import InitLaunchAnalyzer
        return InitLaunchAnalyzer
    raise AttributeError(name)

__all__ = [
    "AnalysisGap",
    "InitLaunchAnalysisResult",
    "InitLaunchAnalyzer",
    "LaunchRecipe",
    "LaunchRecipeAgentOutput",
    "LaunchRecipeDraft",
    "LaunchRecipeAnalysis",
    "SourceSnippet",
    "TargetIdentity",
    "enumerate_target_identity",
]
