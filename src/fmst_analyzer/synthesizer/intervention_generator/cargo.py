"""Cargo output parsing and deterministic Unit attribution."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class BuildError:
    unit_id: str
    file_path: str
    snippet: str


@dataclass
class TestFailure:
    unit_id: str
    test_name: str
    message: str


def _unit_id(module: str) -> str:
    return "unit-" + module.removeprefix("unit_")


def classify_file_path(path: str, owner_modules: dict[str, str] | None = None) -> str | None:
    match = re.search(
        r"(?:^|/)tests/(unit_[a-z0-9_]+)_test/(?:main\.rs)", path
    )
    if match:
        return owner_modules.get(match.group(1)) if owner_modules is not None else _unit_id(match.group(1))
    match = re.search(r"(?:^|/)src/(unit_[a-z0-9_]+)/", path)
    if match:
        return owner_modules.get(match.group(1)) if owner_modules is not None else _unit_id(match.group(1))
    return None


def parse_build_errors(stderr: str, *, owner_modules: dict[str, str] | None = None) -> list[BuildError]:
    out: list[BuildError] = []
    lines = stderr.splitlines()
    index = 0
    while index < len(lines):
        if not (lines[index].startswith("error[") or lines[index].startswith("error:")):
            index += 1
            continue
        block: list[str] = []
        end = index
        while end < len(lines) and not (
            end > index
            and (lines[end].startswith("error[") or lines[end].startswith("error:"))
        ):
            block.append(lines[end])
            end += 1
            if (
                end < len(lines)
                and lines[end - 1].strip() == ""
                and lines[end][:1] not in " =|"
                and not lines[end].startswith("error")
            ):
                break
        snippet = "\n".join(block)
        marker = re.search(r"-->\s+(\S+):(\d+):(\d+)", snippet)
        if marker:
            file_path = marker.group(1)
            unit_id = classify_file_path(file_path, owner_modules)
            if unit_id is not None:
                out.append(BuildError(
                    unit_id=unit_id,
                    file_path=file_path,
                    snippet=snippet.strip(),
                ))
        index = end
    return out


_TEST_PANIC_RE = re.compile(
    r"----\s+(?P<name>\S+)\s+stdout\s+----\s*\n"
    r"(?P<body>.+?)"
    r"(?=\n----\s+\S+\s+stdout\s+----|\Z|\nfailures:\n(?!\s))",
    re.DOTALL,
)


def parse_test_failures(stdout_stderr: str, *, owner_modules: dict[str, str] | None = None) -> list[TestFailure]:
    out: list[TestFailure] = []
    for match in _TEST_PANIC_RE.finditer(stdout_stderr):
        name = match.group("name").strip()
        body = match.group("body").strip()
        file_match = re.search(
            r"tests/(unit_[a-z0-9_]+)_test/(?:main\.rs)", body
        )
        if file_match:
            unit_id = (owner_modules.get(file_match.group(1), "unknown")
                       if owner_modules is not None else _unit_id(file_match.group(1)))
        else:
            name_match = re.search(r"(unit_[a-z0-9_]+)", name)
            unit_id = ((owner_modules.get(name_match.group(1), "unknown")
                        if owner_modules is not None else _unit_id(name_match.group(1)))
                       if name_match else "unknown")
        out.append(TestFailure(unit_id=unit_id, test_name=name, message=body))
    return out


__all__ = [
    "BuildError",
    "TestFailure",
    "classify_file_path",
    "parse_build_errors",
    "parse_test_failures",
]
