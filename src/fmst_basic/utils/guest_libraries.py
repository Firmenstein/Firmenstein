"""Resolve DT_NEEDED in a guest loader namespace, without executing the guest.

The static launch baseline has no LD_LIBRARY_PATH override or working directory.
Unsupported cache formats, relative paths and dynamic tokens remain explicit
gaps instead of selecting an arbitrary recursive basename match.
"""
from pathlib import Path, PurePosixPath
import struct
import re

import lief

from .file_utils import (
    AmbiguousBinaryError, _has_elf_magic, _resolve_guest_symlink, _sha256,
    find_binary_in_rootfs,
)


class GuestLibraryResolver:
    def __init__(self, rootfs: Path, executable: Path):
        self.rootfs = rootfs.absolute().resolve()
        self._metadata = {}
        self._unique_candidates = {}
        binary = self._elf(executable)
        # ET_DYN plugins and shared objects normally have no PT_INTERP. They
        # still participate in the same guest loader namespace as the target;
        # use their ELF class/data to select the standard directories instead
        # of rejecting an otherwise valid dependency root.
        interpreter = PurePosixPath(binary.interpreter).name if binary.interpreter else ""
        self._musl = bool(re.fullmatch(r"ld-musl-[A-Za-z0-9_-]+\.so\.1", interpreter))
        if self._musl:
            self.default_dirs = self._musl_directories(binary.interpreter)
        elif "uClibc" in interpreter or not interpreter:
            self.default_dirs = ("/lib", "/usr/lib", "/usr/X11R6/lib")
        elif interpreter.startswith("ld-linux"):
            self.default_dirs = ("/lib64", "/usr/lib64") if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else ("/lib", "/usr/lib")
        else:
            raise ValueError(f"Unsupported guest loader {binary.interpreter!r} for {executable}")
        self.cached_paths = {} if self._musl else self._read_cache(binary.header.identity_data)

    def _musl_directories(self, interpreter: str) -> tuple[str, ...]:
        """Read musl's colon/newline path file, relative to the loader prefix.

        An existing empty file disables the default search. musl does not use
        glibc's ld.so.cache. Guest links are resolved only inside the rootfs.
        """
        loader = PurePosixPath(interpreter)
        config = loader.parent.parent / "etc" / (loader.name.removesuffix(".so.1") + ".path")
        path = _resolve_guest_symlink(self.rootfs / config.relative_to("/"), self.rootfs)
        if path is None:
            return ("/lib", "/usr/local/lib", "/usr/lib")
        content = path.read_text(encoding="utf-8")
        if "\x00" in content:
            raise ValueError(f"Invalid musl library search path file: {config}")
        return tuple(value for value in re.split(r"[:\n]", content) if value)

    def _elf(self, path):
        path = Path(path).absolute()
        if path not in self._metadata:
            binary = lief.parse(str(path))
            if not isinstance(binary, lief.ELF.Binary):
                raise ValueError(f"Cannot read guest ELF loader metadata: {path}")
            self._metadata[path] = binary
        return self._metadata[path]

    def _paths(self, importer, tag):
        for entry in self._elf(importer).dynamic_entries:
            if entry.tag == tag:
                return entry.paths
        return None

    def _expand(self, value, importer):
        origin = "/" + Path(importer).absolute().relative_to(self.rootfs).parent.as_posix()
        value = value.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
        if "$" in value or not PurePosixPath(value).is_absolute():
            raise ValueError(f"Guest library path requires unknown launch context: {value!r} in {importer}")
        return PurePosixPath(value)

    def _candidate(self, path):
        resolved = _resolve_guest_symlink(self.rootfs / path.relative_to("/"), self.rootfs)
        return resolved if resolved is not None and _has_elf_magic(resolved) else None

    def _read_cache(self, byte_order):
        path = _resolve_guest_symlink(self.rootfs / "etc/ld.so.cache", self.rootfs)
        if path is None:
            return {}
        data = path.read_bytes()
        if not data.startswith(b"ld.so-1.7.0\0") or len(data) < 16:
            raise ValueError(f"Unsupported guest ld.so.cache format: {path}")
        order = "<" if byte_order == lief.ELF.Header.ELF_DATA.LSB else ">"
        count = struct.unpack_from(order + "I", data, 12)[0]
        strings = 16 + 12 * count
        if strings > len(data):
            raise ValueError(f"Invalid guest ld.so.cache table: {path}")

        def string(offset):
            start = strings + offset
            if start >= len(data):
                raise ValueError(f"Invalid guest ld.so.cache string: {path}")
            end = data.find(b"\0", start)
            if end < 0:
                raise ValueError(f"Unterminated guest ld.so.cache string: {path}")
            return data[start:end].decode("utf-8")

        result = {}
        for i in range(count):
            _, key, value = struct.unpack_from(order + "III", data, 16 + i * 12)
            result.setdefault(string(key), []).append(string(value))
        return result

    def resolve(self, needed: str, importer: Path, loader_chain: tuple[Path, ...] = ()) -> Path | None:
        if "/" in needed:
            return self._candidate(self._expand(needed, importer))
        runpath = self._paths(importer, lief.ELF.DynamicEntry.TAG.RUNPATH)
        directories = []
        # RPATH is inherited down the loading chain. RUNPATH applies only to
        # direct dependencies and suppresses that importer's RPATH search.
        if self._musl:
            # musl follows needed_by for both RUNPATH and RPATH, preferring
            # RUNPATH in each importing image. glibc only inherits RPATH.
            for owner in (importer, *loader_chain):
                paths = self._paths(owner, lief.ELF.DynamicEntry.TAG.RUNPATH)
                if paths is None:
                    paths = self._paths(owner, lief.ELF.DynamicEntry.TAG.RPATH)
                directories.extend((p, owner) for p in (paths or []))
        elif runpath is None:
            for owner in (importer, *loader_chain):
                if self._paths(owner, lief.ELF.DynamicEntry.TAG.RUNPATH) is None:
                    directories.extend((p, owner) for p in (self._paths(owner, lief.ELF.DynamicEntry.TAG.RPATH) or []))
        if not self._musl:
            directories.extend((p, importer) for p in (runpath or []))
        unknown_paths = []

        def accept(candidate):
            if unknown_paths:
                # An unknown cwd/token may change precedence, but it cannot
                # select different code if every in-rootfs copy is identical.
                # This does not claim that a library absent from known search
                # locations can actually be loaded.
                if needed not in self._unique_candidates:
                    try:
                        self._unique_candidates[needed] = find_binary_in_rootfs(needed, self.rootfs)
                    except AmbiguousBinaryError as error:
                        raise AmbiguousBinaryError(f"Unknown guest search paths {unknown_paths}: {error}") from error
                unique = self._unique_candidates[needed]
                if unique is None or _sha256(unique) != _sha256(candidate):
                    raise AmbiguousBinaryError(f"Unresolved guest library search order for {needed!r}: {unknown_paths}")
            return candidate

        for value, owner in directories:
            try:
                directory = self._expand(value, owner)
            except ValueError:
                unknown_paths.append((str(owner), value))
                continue
            candidate = self._candidate(directory / needed)
            if candidate is not None:
                return accept(candidate)
        cached = {
            candidate for p in self.cached_paths.get(needed, [])
            if (candidate := self._candidate(self._expand(p, importer))) is not None
        }
        if len(cached) > 1:
            raise AmbiguousBinaryError(f"Guest loader cache has multiple candidates for {needed!r}: {sorted(map(str, cached))}")
        if cached:
            return accept(cached.pop())
        for directory in self.default_dirs:
            try:
                guest_directory = self._expand(directory, importer)
            except ValueError:
                unknown_paths.append((str(importer), directory))
                continue
            candidate = self._candidate(guest_directory / needed)
            if candidate is not None:
                return accept(candidate)
        if unknown_paths:
            raise ValueError(f"Guest library search requires unknown launch context for {needed!r}: {unknown_paths}")
        return None
