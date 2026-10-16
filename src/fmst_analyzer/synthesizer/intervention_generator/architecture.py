"""Authoritative Generator architecture detection from the target ELF."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, TypeAlias

import lief


GeneratorArch: TypeAlias = Literal["arm", "x86_64", "mipsel", "mipsbe"]


def detect_generator_arch(binary_path: Path) -> GeneratorArch:
    """Return the architecture encoded by the selected target ELF."""
    parsed = lief.parse(str(Path(binary_path)))
    if not isinstance(parsed, lief.ELF.Binary):
        raise RuntimeError(f"Cannot parse target ELF architecture: {binary_path}")
    machine = parsed.header.machine_type
    if machine == lief.ELF.ARCH.ARM:
        return "arm"
    if machine == lief.ELF.ARCH.X86_64:
        return "x86_64"
    if machine == lief.ELF.ARCH.MIPS:
        if parsed.header.identity_data == lief.ELF.Header.ELF_DATA.LSB:
            return "mipsel"
        if parsed.header.identity_data == lief.ELF.Header.ELF_DATA.MSB:
            return "mipsbe"
    raise RuntimeError(
        f"Unsupported target ELF architecture {machine} "
        f"({parsed.header.identity_data}) for {binary_path}"
    )


def manifest_arch(arch: GeneratorArch) -> str:
    """Map a concrete architecture to the IIB manifest family."""
    return "mips" if arch in {"mipsel", "mipsbe"} else arch


__all__ = [
    "GeneratorArch",
    "detect_generator_arch",
    "manifest_arch",
]
