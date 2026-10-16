"""Deterministic validation and identity assignment for launch candidates."""
from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError

from fmst_analyzer.analysis.base.execution import execution_snapshot

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Optional
from fmst_analyzer.analysis.base.analysis_finding import FindingAnchor, InitLaunchFindingDomain
from fmst_analyzer.analysis.base.finding_binding import bind_finding, pointer
from fmst_basic.utils.guest_paths import resolve_guest_path

from .analyzer_schema import (
    INIT_LAUNCH_EVIDENCE_ROOTS,
    INIT_LAUNCH_SCHEMA_VERSION,
    AnalysisGap,
    InitLaunchAnalysisResult,
    LaunchRecipe,
    LaunchRecipeAgentOutput,
    LaunchRecipeDraft,
    SourceSnippet,
    TargetIdentity,
)
from .target_identity import (
    enumerate_initialization_roots,
    finding_target_for_identity,
    resolve_symlink_chain_in_rootfs,
)

_LINE_RE = re.compile(r"(?:^|\b)(?:line\s*|L)(\d+)$", re.IGNORECASE)
_TRAILING_LINE_RE = re.compile(r":(\d+)$")
def _normalise_relative_path(rootfs: Path, value: str) -> str:
    raw = value.strip()
    if not raw:
        raise OutputValidationError("empty rootfs path")
    root = rootfs.resolve()
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            relative = Path(raw.lstrip("/"))
    else:
        relative = candidate
    pure = PurePosixPath(relative.as_posix())
    # Parent components must be resolved after any preceding guest symlink;
    # their presence alone does not prove a path escapes the rootfs.
    if pure.is_absolute():
        raise OutputValidationError(f"rootfs path escapes the root: {value!r}")
    normalised = pure.as_posix()
    if normalised in {"", "."}:
        raise OutputValidationError(f"invalid rootfs path: {value!r}")
    return normalised


def _line_number(location: str) -> Optional[int]:
    text = location.strip()
    match = _LINE_RE.search(text) or _TRAILING_LINE_RE.search(text)
    return int(match.group(1)) if match else None


def _validate_text_snippet(path: Path, snippet: SourceSnippet) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeError as exc:
        raise OutputValidationError(f"source is not a readable text file: {snippet.path}") from exc
    needle = snippet.text
    if not needle or needle not in text:
        raise OutputValidationError(
            f"source excerpt is not present in {snippet.path}: {snippet.text!r}"
        )
    line_number = _line_number(snippet.location)
    if line_number is None:
        raise OutputValidationError(
            f"text source location must contain a line number: {snippet.location!r}"
        )
    lines = text.splitlines()
    if not 1 <= line_number <= len(lines):
        raise OutputValidationError(
            f"source line {line_number} is outside {snippet.path} "
            f"(1..{len(lines)})"
        )
    matching_spans = []
    offset = 0
    while True:
        index = text.find(needle, offset)
        if index < 0:
            break
        first = text[:index].count("\n") + 1
        matching_spans.append((first, first + needle.count("\n")))
        offset = index + 1
    if not any(first <= line_number <= last for first, last in matching_spans):
        spans = ", ".join(
            f"{first}..{last}" for first, last in matching_spans
        )
        raise OutputValidationError(
            f"source excerpt in {snippet.path} is at lines {spans}, not "
            f"{line_number}"
        )


def _validate_elf_snippet(
    path: Path,
    snippet: SourceSnippet,
    elf_cache: dict[Path, object],
) -> None:
    try:
        import lief

        binary = elf_cache.get(path)
        if binary is None:
            binary = lief.parse(str(path))
            if binary is not None:
                elf_cache[path] = binary
    except Exception as exc:
        raise RuntimeError(f"failed to parse ELF source {snippet.path}: {exc}") from exc
    if binary is None:
        raise RuntimeError(f"failed to parse ELF source {snippet.path}")

    from .elf_evidence import validate_excerpt
    try:
        validate_excerpt(binary, snippet.location.strip(), snippet.text)
    except ValueError as error:
        raise OutputValidationError(f"{snippet.path} at {snippet.location}: {error}") from error


def _validate_snippet(
    rootfs: Path,
    snippet: SourceSnippet,
    elf_cache: dict[Path, object],
) -> SourceSnippet:
    normalised_path = _normalise_relative_path(rootfs, snippet.path)
    resolved = resolve_guest_path(
        rootfs.resolve(), normalised_path, follow_final_symlink=False,
    )
    if resolved is None:
        raise OutputValidationError(f"rootfs path is missing or escapes: {snippet.path!r}")
    path = rootfs.resolve() / resolved[0][-1]
    normalised = snippet.model_copy(update={"path": normalised_path})
    if path.is_symlink():
        if snippet.location.strip().lower() != "symlink":
            raise OutputValidationError(
                f"symlink source location must be 'symlink': "
                f"{snippet.location!r}"
            )
        target = os.readlink(path)
        if snippet.text != target:
            raise OutputValidationError(
                f"symlink excerpt for {snippet.path} must equal raw target "
                f"{target!r}"
            )
        return normalised
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
    except OSError as exc:
        raise RuntimeError(f"source is not readable: {snippet.path}") from exc
    if magic == b"\x7fELF":
        _validate_elf_snippet(path, normalised, elf_cache)
    else:
        _validate_text_snippet(path, normalised)
    return normalised






def _normalise_executable(
    rootfs: Path,
    identity: TargetIdentity,
    executable_path: str,
) -> str:
    normalised = _normalise_relative_path(rootfs, executable_path)
    if resolve_symlink_chain_in_rootfs(rootfs.resolve(), normalised) is None:
        raise OutputValidationError(f"rootfs executable is missing or escapes: {executable_path!r}")
    allowed = {
        identity.selected_rootfs_path,
        *identity.target_aliases,
    }
    if normalised not in allowed:
        raise OutputValidationError(
            f"launch executable {executable_path!r} does not name selected "
            f"target {identity.selected_rootfs_path!r} or an alias"
        )
    return "/" + normalised




def _recipe_key(recipe: LaunchRecipeDraft) -> tuple[str, ...]:
    return (
        *recipe.launch_site.position_key(),
        *recipe.context_anchor.position_key(),
        recipe.executable_path,
        json.dumps(
            recipe.command_template,
            ensure_ascii=False,
            separators=(",", ":"),
        ),
    )


def _recipe_id(key: tuple[str, ...]) -> str:
    encoded = json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode()
    return "launch-" + hashlib.sha256(encoded).hexdigest()[:16]


def _validate_recipe(
    rootfs: Path,
    identity: TargetIdentity,
    draft: LaunchRecipeDraft,
    elf_cache: dict[Path, object],
) -> LaunchRecipeDraft:
    launch_site = _validate_snippet(rootfs, draft.launch_site, elf_cache)
    context_anchor = _validate_snippet(rootfs, draft.context_anchor, elf_cache)
    executable = _normalise_executable(
        rootfs, identity, draft.executable_path
    )
    actions = [
        _validate_snippet(rootfs, action, elf_cache)
        for action in draft.preparation_actions
    ]
    chain = [
        _validate_snippet(rootfs, item, elf_cache)
        for item in draft.initialization_chain
    ]
    if chain[-1] != launch_site:
        raise OutputValidationError(
            "initialization_chain must end with the exact launch_site"
        )
    if context_anchor.position_key() not in {item.position_key() for item in chain}:
        raise OutputValidationError("context_anchor must identify a source position in initialization_chain")
    # The same dispatcher/helper can be invoked repeatedly with different
    # service arguments. Repeated source positions do not prove a runtime
    # cycle and must not force removal or rebinding of its evidence.
    return draft.model_copy(
        update={
            "launch_site": launch_site,
            "context_anchor": context_anchor,
            "executable_path": executable,
            "command_template": list(draft.command_template),
            "initialization_chain": chain,
            "preparation_actions": actions,
        }
    )


def _gap_key(gap: AnalysisGap) -> tuple[str, ...]:
    if gap.source is None:
        return (gap.kind, "", "", "", gap.reason.strip())
    return (
        gap.kind,
        gap.source.path,
        gap.source.location.strip(),
        gap.source.text.strip(),
        gap.reason.strip(),
    )


def finalise_agent_output(
    rootfs: Path,
    identity: TargetIdentity,
    output: LaunchRecipeAgentOutput,
) -> InitLaunchAnalysisResult:
    """Validate Agent facts and construct the authoritative result."""
    rootfs = rootfs.resolve()
    elf_cache: dict[Path, object] = {}
    recipes: dict[str, LaunchRecipe] = {}
    findings = {}
    target = finding_target_for_identity(rootfs, identity)
    validated = []
    for index, item in enumerate(output.launch_recipes):
        try:
            validated.append(_validate_recipe(rootfs, identity, item, elf_cache))
        except OutputValidationError as error:
            raise OutputValidationError(f"/launch_recipes/{index}: {error}") from error
    from collections import Counter
    from uuid import uuid4

    validated = list({draft.model_dump_json(): draft for draft in validated}.values())
    keys = [_recipe_key(draft) for draft in validated]
    counts = Counter(keys)
    for draft, key in zip(validated, keys, strict=True):
        recipe_id = _recipe_id(key)
        if counts[key] > 1:
            # Shared source and argv do not establish that observations conflict.
            # Keep each observation and persist its controller-assigned identity.
            recipe_id += "-" + uuid4().hex
        recipe = LaunchRecipe(recipe_id=recipe_id, **draft.model_dump(exclude={"finding"}))
        if recipe_id in recipes and recipes[recipe_id] != recipe:
            raise OutputValidationError(f"launch recipe ID collision: {recipe_id}")
        recipes[recipe_id] = recipe
        draft.finding.validate_references(
            recipe.model_dump(mode="json"),
            allowed_roots=INIT_LAUNCH_EVIDENCE_ROOTS,
        )
        record_ref = pointer("launch_recipes", recipe_id)
        finding = bind_finding(
            target=target, source="init_launch", source_id=recipe_id,
            semantics=draft.finding, record_ref=record_ref,
            boundary_kind="environment",
            anchors=[FindingAnchor(kind="environment", ref=record_ref + "/launch_site"),
                     FindingAnchor(kind="environment", ref=record_ref + "/context_anchor")],
            domain=InitLaunchFindingDomain(
                kind="init_launch", recipe_id=recipe_id,
                preparation_refs=[pointer("launch_recipes", recipe_id, "preparation_actions", i)
                                  for i in range(len(recipe.preparation_actions))],
            ),
        )
        findings[finding.finding_ref] = finding

    gaps_by_key: dict[tuple[str, ...], AnalysisGap] = {}
    for gap in output.analysis_gaps:
        source = (
            _validate_snippet(rootfs, gap.source, elf_cache)
            if gap.source is not None
            else None
        )
        normalised = gap.model_copy(
            update={"source": source, "reason": gap.reason.strip()}
        )
        gaps_by_key.setdefault(_gap_key(normalised), normalised)

    return InitLaunchAnalysisResult(execution=execution_snapshot(),
        schema_version=INIT_LAUNCH_SCHEMA_VERSION, phase="full", finding_target=target,
        initialization_roots=enumerate_initialization_roots(rootfs),
        planning_findings=findings,
        target_identity=identity,
        launch_recipes=recipes,
        analysis_gaps=[gaps_by_key[key] for key in sorted(gaps_by_key)],
    )


__all__ = ["finalise_agent_output"]
