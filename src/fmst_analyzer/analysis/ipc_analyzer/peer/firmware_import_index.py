"""Firmware-wide ELF facts used by deterministic IPC peer indexing.

Scans every ELF in the firmware rootfs with LIEF and records only the facts
used by per-channel candidate discovery:

* symbol_to_elfs      : undef dynsym name -> ELFs that import it
* dt_needed_per_elf   : each ELF's ordered DT_NEEDED list (order matters for
                        dynamic linker first-hit resolution)

Plus executable/shared-library classification and a loader-name-to-provider
candidate map. Numeric identifier byte searches are intentionally absent, so
architecture and endianness do not belong in this index.

Building this index does not mutate LibDepGraph.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional, Set

import lief
from loguru import logger

from ._lief_lock import LIEF_PARSE_LOCK


ElfKind = Literal["exec", "so"]


@dataclass(frozen=True)
class _ParsedELF:
    kind: ElfKind | None
    soname: str | None = None
    needed: tuple[str, ...] = ()
    undefined_symbols: frozenset[str] = frozenset()
    defined_function_symbols: frozenset[str] = frozenset()


@dataclass
class FirmwareImportIndex:
    """Raw reverse-import data over all ELFs in a firmware rootfs."""

    # Classification of every reachable ELF.
    elf_kind: Dict[Path, ElfKind] = field(default_factory=dict)

    # Loader name -> every physical .so claiming that SONAME/basename.
    # Callers must require a unique candidate before extending a closure.
    soname_candidates: Dict[str, Set[Path]] = field(default_factory=dict)

    # Undefined dynsym name -> ELFs that import it (binary or .so).
    symbol_to_elfs: Dict[str, Set[Path]] = field(default_factory=dict)

    # Per-ELF undefined dynamic symbols.  Keeping both directions avoids
    # repeatedly inverting the firmware-wide index when computing which
    # executable closures actually call a provider export.
    undefined_functions_per_elf: Dict[Path, Set[str]] = field(
        default_factory=dict,
    )

    # Per-ELF ordered DT_NEEDED list. Order matters — the dynamic linker walks
    # this list in declaration order for first-hit symbol resolution.
    dt_needed_per_elf: Dict[Path, List[str]] = field(default_factory=dict)

    # Defined dynamic function symbols for provider-entry/caller matching.
    defined_functions_per_elf: Dict[Path, Set[str]] = field(default_factory=dict)

    # Valid ELF objects that cannot be a user-space process/provider (for
    # example ET_REL kernel modules). They are intentionally not unresolved items.
    ignored_elfs: Set[Path] = field(default_factory=set)

    # ELF files whose contents could not be parsed by LIEF.  Candidate
    # discovery reports these as an explicit coverage boundary instead of
    # silently treating them as non-IPC executables.
    unparseable_elfs: Set[Path] = field(default_factory=set)

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------


def _normalize_symbol(name: str) -> str:
    """Strip GNU symbol versioning suffixes (`foo@@GLIBC_2.17` -> `foo`).

    Firmware binaries rarely use versioning, but we normalize defensively so
    that versioned and unversioned forms don't split into separate dict keys.
    """
    if "@" in name:
        return name.split("@", 1)[0]
    return name


def _iter_rootfs_elfs(rootfs: Path) -> Iterable[Path]:
    """Yield ELF files and kernel-module candidates under ``rootfs``.

    Symlinks are not followed — we want to index unique physical ELFs only;
    the SONAME index already collapses library versions via DT_SONAME names.
    ``.ko`` files are included even when their bytes are not ELF (for example,
    a host-built test fixture on macOS); the classifier then records them as
    ignored rather than silently dropping a kernel-module candidate.
    """
    magic = b"\x7fELF"
    for path in rootfs.rglob("*"):
        try:
            if not path.is_file() or path.is_symlink():
                continue
            if path.suffix == ".ko":
                yield path
                continue
            with open(path, "rb") as f:
                if f.read(4) == magic:
                    yield path
        except (OSError, PermissionError):
            continue


def _classify_and_parse(
    path: Path,
) -> Optional[_ParsedELF]:
    """Parse a single ELF with lief.

    Returns a parsed record, with ``kind=None`` for a valid non-user-space ELF,
    or None only when parsing/indexing genuinely failed.

    Classification rules (in order):
      1. ET_EXEC                              -> 'exec'
      2. ET_DYN + has DT_SONAME               -> 'so'
      3. ET_DYN + no PT_INTERP                -> 'so'   (unversioned firmware .so)
      4. ET_DYN + has PT_INTERP               -> 'exec' (PIE binary)

    Undef/defined symbol detection uses `sym.shndx == SHN_UNDEF (0)` rather
    than lief's `sym.imported`/`sym.exported` properties. Those properties are
    unreliable on ET_EXEC binaries for ARM/MIPS firmware (lief reports
    imported=False for everything). `shndx == 0` is the ground truth.
    """
    try:
        with LIEF_PARSE_LOCK:
            binary = lief.ELF.parse(str(path))
    except Exception as exc:
        logger.debug(f"[ipc-peer] lief failed to parse {path}: {exc}")
        return None
    if binary is None:
        return None

    file_type = binary.header.file_type
    soname: Optional[str] = None
    needed: List[str] = []

    try:
        dyn_entries = list(binary.dynamic_entries)
    except Exception as exc:
        logger.debug(f"[ipc-peer] no dynamic entries for {path}: {exc}")
        return None

    for entry in dyn_entries:
        if isinstance(entry, lief.ELF.DynamicEntryLibrary):
            needed.append(entry.name)
        elif isinstance(entry, lief.ELF.DynamicSharedObject):
            soname = entry.name

    # Classify via (file_type, soname, PT_INTERP). PT_INTERP presence is the
    # ground truth for "is this a directly-invocable binary" on stripped
    # firmware .so's where DT_SONAME is often absent.
    if file_type == lief.ELF.Header.FILE_TYPE.EXEC:
        kind: ElfKind = "exec"
    elif file_type == lief.ELF.Header.FILE_TYPE.DYN:
        if soname:
            kind = "so"
        else:
            has_interp = False
            try:
                for seg in binary.segments:
                    if seg.type == lief.ELF.Segment.TYPE.INTERP:
                        has_interp = True
                        break
            except Exception:
                has_interp = False
            kind = "exec" if has_interp else "so"
    else:
        # REL / CORE / NONE are valid ELF objects but cannot represent a
        # user-space executable/provider in this analysis. In particular,
        # kernel modules are ET_REL and must not pollute unresolved coverage items.
        return _ParsedELF(kind=None)

    undef: Set[str] = set()
    defined_functions: Set[str] = set()
    try:
        for sym in binary.dynamic_symbols:
            name = _normalize_symbol(sym.name) if sym.name else ""
            if not name:
                continue
            # `shndx == 0` (SHN_UNDEF) is the universal "imported" test,
            # working on both ET_EXEC and ET_DYN across all architectures.
            if int(sym.shndx) == 0:
                undef.add(name)
            elif (
                sym.type in {
                    lief.ELF.Symbol.TYPE.FUNC,
                    lief.ELF.Symbol.TYPE.GNU_IFUNC,
                }
                and sym.binding in {
                    lief.ELF.Symbol.BINDING.GLOBAL,
                    lief.ELF.Symbol.BINDING.WEAK,
                }
                and sym.visibility in {
                    lief.ELF.Symbol.VISIBILITY.DEFAULT,
                    lief.ELF.Symbol.VISIBILITY.PROTECTED,
                }
            ):
                defined_functions.add(name)
    except Exception as exc:
        logger.debug(f"[ipc-peer] dynsym iteration failed for {path}: {exc}")

    return _ParsedELF(
        kind=kind,
        soname=soname,
        needed=tuple(needed),
        undefined_symbols=frozenset(undef),
        defined_function_symbols=frozenset(defined_functions),
    )


def build_firmware_import_index(rootfs: Path) -> FirmwareImportIndex:
    """Build a FirmwareImportIndex by scanning every ELF under rootfs.

    This walks the rootfs once, reads each ELF via lief, and accumulates the
    reverse indices. Cost is O(n ELFs * dynsym size); on a typical firmware
    with a few hundred ELFs it completes in seconds.
    """
    index = FirmwareImportIndex()
    symbol_to_elfs: Dict[str, Set[Path]] = defaultdict(set)
    soname_candidates: Dict[str, Set[Path]] = defaultdict(set)

    elf_count = 0
    failed_count = 0
    for elf_path in _iter_rootfs_elfs(rootfs):
        parsed = _classify_and_parse(elf_path)
        if parsed is None:
            # A damaged/truncated kernel module is still outside the
            # user-space process/provider universe.  LIEF cannot expose its
            # ET_REL header reliably, so retain the filesystem classification
            # instead of turning it into a Channel unresolved item.
            if elf_path.suffix == ".ko" or "lib/modules" in elf_path.parts:
                index.ignored_elfs.add(elf_path)
                continue
            failed_count += 1
            index.unparseable_elfs.add(elf_path)
            continue
        if parsed.kind is None:
            index.ignored_elfs.add(elf_path)
            continue
        elf_count += 1
        kind = parsed.kind

        index.elf_kind[elf_path] = kind
        index.dt_needed_per_elf[elf_path] = list(parsed.needed)
        index.defined_functions_per_elf[elf_path] = set(
            parsed.defined_function_symbols
        )
        index.undefined_functions_per_elf[elf_path] = set(
            parsed.undefined_symbols
        )
        for sym in parsed.undefined_symbols:
            symbol_to_elfs[sym].add(elf_path)

        if kind == "so":
            # Some .so's ship without an explicit SONAME; fall back to file
            # basename so that DT_NEEDED -> path lookups can still resolve.
            key = parsed.soname if parsed.soname else elf_path.name
            soname_candidates[key].add(elf_path)

    index.symbol_to_elfs = dict(symbol_to_elfs)
    index.soname_candidates = {
        name: set(paths) for name, paths in soname_candidates.items()
    }

    logger.info(
        f"[ipc-peer] FirmwareImportIndex built: {elf_count} ELFs "
        f"({len([k for k in index.elf_kind.values() if k == 'exec'])} exec, "
        f"{len([k for k in index.elf_kind.values() if k == 'so'])} so), "
        f"{failed_count} unparseable, "
        f"{len(index.symbol_to_elfs)} unique symbols"
    )
    return index
