"""Attempt-local references to exact source excerpts already returned by tools."""
from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError

import hashlib
import json
from pathlib import Path

from fmst_basic.agent.tool import tool
from .analyzer_schema import LaunchRecipeAgentOutput, SourceSnippet
from .target_identity import resolve_symlink_chain_in_rootfs


SOURCE_PREFIX = "@source:"


class SourceEvidence:
    def __init__(self):
        self.sources: dict[str, SourceSnippet] = {}

    def reference(self, snippet: dict) -> dict:
        source = SourceSnippet.model_validate(snippet)
        # A short tool handle is not a persisted identity. Check the full object
        # before reuse so even a digest collision cannot redirect a citation.
        token = SOURCE_PREFIX + hashlib.sha256(source.model_dump_json().encode()).hexdigest()[:16]
        if token in self.sources and self.sources[token] != source:
            raise OutputValidationError("Source evidence handle collision; registered evidence was retained")
        self.sources[token] = source
        return {**snippet, "text": token}

    def materialize(self, output: LaunchRecipeAgentOutput) -> LaunchRecipeAgentOutput:
        errors: dict[tuple[str, str, str], dict] = {}

        def position(source):
            return source.path.lstrip("/"), source.position_key()[1]

        def choice(token, source):
            return {"source_snippet": {**source.model_dump(mode="json"), "text": token},
                    "content": source.text}

        def resolve(value, pointer=""):
            if isinstance(value, list):
                return [resolve(item, f"{pointer}/{index}") for index, item in enumerate(value)]
            if not isinstance(value, dict):
                return value
            if {"path", "location", "text"} <= value.keys() and value["text"].startswith(SOURCE_PREFIX):
                token = value["text"]
                source = self.sources.get(token)
                requested = SourceSnippet.model_validate(value)
                if source is None or position(requested) != position(source):
                    key = (token, *position(requested))
                    if key not in errors:
                        errors[key] = {
                            "error": ("Unknown source evidence identifier" if source is None else
                                      "Source evidence identifier belongs to a different path or location"),
                            "reference": token,
                            "requested_path": requested.path,
                            "requested_location": requested.location,
                            "output_paths": [],
                            "bound_source": None if source is None else choice(token, source),
                            "available_sources": [choice(ref, item) for ref, item in self.sources.items()
                                                  if position(item) == position(requested)],
                        }
                    errors[key]["output_paths"].append(f"{pointer}/text")
                    return value
                return source.model_dump(mode="json")
            return {key: resolve(item, f"{pointer}/{key.replace('~', '~0').replace('/', '~1')}")
                    for key, item in value.items()}

        expanded = resolve(output.model_dump(mode="json"))
        if errors:
            raise OutputValidationError(
                "Rejected source references; select exact tool-returned evidence supporting each claim. "
                "Candidates at the same position may quote different ranges; none was substituted.\n"
                + json.dumps(list(errors.values()), ensure_ascii=False, indent=2)
            )
        return LaunchRecipeAgentOutput.model_validate(expanded)


def make_source_tool(rootfs: Path, sources: SourceEvidence):
    rootfs = rootfs.resolve()

    @tool
    def read_source(path: str, start_line: int = 1, end_line: int = 200) -> dict:
        """Read UTF-8 initialization source and return an exact citation reference.

        source_snippet is ready for output: its text is a source identifier, so
        tabs/spacing need not be transcribed. The Controller materializes the
        original text and revalidates the file before publication. Select a
        narrow source range to distinguish branch/caller context. General file
        search can locate other relevant ranges. ELF evidence uses the ELF tools.

        Args:
            path: Guest rootfs-relative text file; symlink targets resolve within rootfs.
            start_line: First line, one-based and inclusive.
            end_line: Last line, inclusive; at most 200 lines per request.
        """
        if start_line < 1 or end_line < start_line or end_line - start_line >= 200:
            raise OutputValidationError("Specify a positive inclusive range of at most 200 lines")
        chain = resolve_symlink_chain_in_rootfs(rootfs, path.lstrip("/"))
        if chain is None:
            raise OutputValidationError("Source path is missing or escapes rootfs")
        relative = chain[-1]
        lines = (rootfs / relative).read_text(encoding="utf-8").splitlines()
        if start_line > len(lines):
            raise OutputValidationError(f"Source has {len(lines)} lines; start_line is out of range")
        last = min(end_line, len(lines))
        content = "\n".join(lines[start_line - 1:last])
        if not content:
            raise OutputValidationError("Selected range is empty; select the relevant source statement")
        source = dict(path=relative, location=f"line {start_line}", text=content)
        return {"source_snippet": sources.reference(source), "content": content,
                "showing_lines": f"{start_line}-{last} of {len(lines)}"}

    return read_source
