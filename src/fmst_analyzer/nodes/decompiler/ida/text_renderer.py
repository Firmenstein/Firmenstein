"""Line-preserving pseudocode rendering with raw-to-rendered offsets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Pattern, Sequence


@dataclass(frozen=True)
class RenderedLine:
    text: str
    # Boundary map: raw_offset -> rendered_offset.  Length is raw + 1.
    offsets: tuple[int, ...]

    def rendered_column(self, raw_column: int) -> int:
        if raw_column < 0 or raw_column >= len(self.offsets):
            raise ValueError(
                f"Raw column {raw_column} outside line boundary map "
                f"0..{len(self.offsets) - 1}"
            )
        return self.offsets[raw_column]


Replacement = tuple[Pattern[str], str]


def compile_replacements(
    pairs: Iterable[tuple[str, str]],
) -> list[Replacement]:
    return [(re.compile(pattern), replacement) for pattern, replacement in pairs]


def render_line(text: str, replacements: Sequence[Replacement]) -> RenderedLine:
    """Apply replacements while retaining a map from original boundaries.

    If an original boundary lies inside a replaced token it maps to the start
    of the replacement; the token's final boundary maps to the replacement's
    final boundary.  This is the useful behavior for CTree item start columns.
    """
    current = text
    offsets = list(range(len(text) + 1))

    for pattern, replacement in replacements:
        matches = list(pattern.finditer(current))
        for match in reversed(matches):
            start, end = match.span()
            rendered = match.expand(replacement)
            delta = len(rendered) - (end - start)
            for index, position in enumerate(offsets):
                if position < start:
                    continue
                if position == end:
                    offsets[index] = start + len(rendered)
                elif position > end:
                    offsets[index] = position + delta
                else:
                    offsets[index] = start
            current = current[:start] + rendered + current[end:]

    return RenderedLine(current, tuple(offsets))


def render_lines(
    lines: Sequence[str], replacements: Sequence[Replacement]
) -> list[RenderedLine]:
    return [render_line(line, replacements) for line in lines]
