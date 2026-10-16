"""Shared source identity for API calls observed by an Analyzer.

Flattened coverage flows provide overlap hints to consumers. Observing a
callsite does not prove all of its contexts complete or give exclusive
behavior ownership; independent Analyzers still inspect their own scope.
"""
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field


class CoveredAPICall(BaseModel):
    """A single callsite attributed to a specific analyzer's coverage."""

    binary_name: str = Field(
        description="The ELF filename that contains this callsite."
    )
    function_name: str = Field(
        description="Enclosing caller's function identifier in the persisted "
        "decompiled artifact, not the callee/import stub."
    )
    api_name: str = Field(
        description="Verbatim callee name from the decompiled call "
        "expression (pread != read, fread != read — do not normalise). "
        "Must be an actual call; branch and return statements are not API calls."
    )
    line_number: int = Field(
        description="1-indexed line number in the complete persisted decompiled C artifact."
    )
    column_number: int | None = Field(
        default=None,
        description=(
            "Zero-based column in the persisted decompiled C artifact. "
            "None is accepted for agent-authored or legacy evidence that "
            "has only display-line coordinates."
        ),
    )
    function_ea: int | None = Field(
        default=None,
        description="Function entry EA in the owning IDA database, when known.",
    )
    snapshot_hash: str | None = Field(
        default=None,
        description="Immutable FunctionSemanticSnapshot identity, when known.",
    )
    ctree_index: int | None = Field(
        default=None,
        description="CTree object identity within snapshot_hash, when known.",
    )
    source_ea: int | None = Field(
        default=None,
        description=(
            "Guest instruction EA associated with the CTree call, or None "
            "for BADADDR and legacy evidence."
        ),
    )
    reason: str = Field(
        description="One-phrase reason why this callsite is claimed. "
        "Example: 'setup: open AF_UNIX socket fd', 'termination: exit "
        "on fopen(L65) NULL'."
    )

    @property
    def identity_key(self) -> tuple:
        """Immutable CTree identity with a coordinate-only legacy fallback."""
        if (
            self.function_ea is not None
            and self.snapshot_hash is not None
            and self.ctree_index is not None
        ):
            return (
                "ctree",
                self.binary_name,
                self.function_ea,
                self.snapshot_hash,
                self.ctree_index,
            )
        return (
            "display",
            *self.display_key,
            self.column_number,
        )

    @property
    def display_key(self) -> tuple[str, str, str, int]:
        """Legacy coordinate used only to fold unlocated evidence into facts."""
        return (
            self.binary_name,
            self.function_name,
            self.api_name,
            self.line_number,
        )


def _normalize_api_name(api_name: str) -> str:
    return api_name.removeprefix("__imp_")


def _display_api_aliases(api_name: str) -> tuple[str, ...]:
    """Return only aliases introduced by the persisted C renderer."""
    normalized = _normalize_api_name(api_name)
    if normalized in {"exit", "_exit"}:
        return ("exit", "_exit")
    return (normalized,)


class CoveredAPICallResolver:
    """Resolve Agent display citations to immutable CTree identities.

    A display citation remains valid human evidence when it is ambiguous, but
    only a unique CTree match is safe for cross-analyzer deduplication.
    """

    def __init__(self, view: Any) -> None:
        self._index: dict[tuple[str, str, int, str], list[Any]] = defaultdict(list)
        for binary, callgraph in view.adg.get_binary_callgraphs().items():
            for function in callgraph.get_node_for_analysis():
                is_reachable = getattr(view.adg, "is_reachable", None)
                if callable(is_reachable) and not is_reachable(function):
                    continue
                function_names = {
                    function.decompiled_name,
                    function.artifact_stem,
                }
                for callsite in function.get_callsites().values():
                    if not callsite.is_populated or callsite.line_number <= 0:
                        continue
                    if (
                        callsite.snapshot_hash is None
                        or callsite.ctree_index is None
                    ):
                        continue
                    function_names.add(callsite.caller_name)
                    for function_name in function_names:
                        for api_alias in _display_api_aliases(
                            callsite.callee_name,
                        ):
                            self._index[(
                                binary.name,
                                function_name,
                                callsite.line_number,
                                api_alias,
                            )].append(callsite)

    def resolve(self, item: CoveredAPICall) -> CoveredAPICall:
        matches: list[Any] = []
        for api_alias in _display_api_aliases(item.api_name):
            matches.extend(self._index.get((
                item.binary_name,
                item.function_name,
                item.line_number,
                api_alias,
            ), []))
        if item.column_number is not None:
            matches = [
                callsite for callsite in matches
                if callsite.column_number == item.column_number
            ]
        if item.function_ea is not None:
            matches = [
                callsite for callsite in matches
                if callsite.caller_ea == item.function_ea
            ]
        if item.snapshot_hash is not None:
            matches = [
                callsite for callsite in matches
                if callsite.snapshot_hash == item.snapshot_hash
            ]
        if item.ctree_index is not None:
            matches = [
                callsite for callsite in matches
                if callsite.ctree_index == item.ctree_index
            ]

        by_identity = {
            (
                callsite.caller_ea,
                callsite.snapshot_hash,
                callsite.ctree_index,
            ): callsite
            for callsite in matches
        }
        if len(by_identity) != 1:
            return item

        callsite = next(iter(by_identity.values()))
        return item.model_copy(update={
            "api_name": _normalize_api_name(callsite.callee_name),
            "column_number": callsite.column_number,
            "function_ea": callsite.caller_ea,
            "snapshot_hash": callsite.snapshot_hash,
            "ctree_index": callsite.ctree_index,
            "source_ea": callsite.source_ea,
        })

    def resolve_many(
        self, items: list[CoveredAPICall],
    ) -> list[CoveredAPICall]:
        return [self.resolve(item) for item in items]
