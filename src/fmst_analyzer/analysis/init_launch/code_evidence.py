"""On-demand native code evidence for initialization launchers and helpers.

The portable ELF tools remain available without IDA. This explicitly native
tool reuses the normal LibDepGraph/CTree path; it never runs another Analyzer.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from fmst_basic.agent.tool import tool
from .target_identity import resolve_symlink_chain_in_rootfs


def _canonical_chunks(path: Path, relative: str, listing: str) -> list[dict]:
    import lief
    from .elf_evidence import read_excerpt
    binary = lief.parse(str(path))
    ranges = re.findall(r"^; chunk: (0x[0-9a-f]+)-(0x[0-9a-f]+)$", listing, re.MULTILINE)
    if binary is None or not ranges:
        raise ValueError("Native function evidence has no verifiable ELF/chunk boundaries")
    snippets = []
    for start, end in ranges:
        cursor, stop = int(start, 16), int(end, 16)
        lines = []
        while cursor < stop:
            excerpt = read_excerpt(binary, hex(cursor), min(4096, stop - cursor))
            if not excerpt["decoded_bytes"]:
                raise ValueError(f"Function evidence decoding stops at {relative}:{hex(cursor)}")
            lines.append(excerpt["assembly"])
            cursor += excerpt["decoded_bytes"]
        snippets.append({"path": relative, "location": start, "text": "\n".join(lines)})
    return snippets


class LauncherCodeEvidence:
    def __init__(self, rootfs: Path, global_config, phase: str):
        self.rootfs = rootfs.resolve()
        self.global_config = global_config
        self.phase = phase
        self.views = {}

    async def _view(self, path: Path):
        if self.phase != "full":
            raise ValueError("Native initialization code evidence requires full phase")
        # Native SDK imports and initialization are confined to this boundary.
        from fmst_analyzer.graphs.lib_dep_graph import LibDepGraph
        from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
        graph = LibDepGraph(self.rootfs, self.global_config,
                            cache_label="init-launch-" + hashlib.sha256(path.relative_to(self.rootfs).as_posix().encode()).hexdigest())
        binary = graph.add_binary(path, expand_dependencies=False, build_structural_adg=False)
        await graph.decompile_analysis(binary)
        return AnalysisView(graph.get_decompiled_adg(binary))

    async def _get_view(self, path: str):
        if self.phase != "full":
            raise ValueError("Native initialization code evidence requires full phase")
        if self.global_config.workdir is None:
            raise ValueError("Native initialization code evidence requires a configured local workdir and IDA")
        chain = resolve_symlink_chain_in_rootfs(self.rootfs, path.lstrip("/"))
        if chain is None:
            raise ValueError("Initialization ELF path is missing or escapes rootfs")
        relative = chain[-1]
        if relative not in self.views:
            self.views[relative] = await self._view(self.rootfs / relative)
        return relative, self.views[relative]

    async def references(self, path: str, string_query: str, function_name: str | None):
        if self.phase != "full":
            raise ValueError("Native initialization code evidence requires full phase")
        if not string_query and not function_name:
            raise ValueError("Supply a nonempty string query or exact function name")
        relative, view = await self._get_view(path)
        result = {"path": relative, "string_references": {}, "direct_callers": [],
                  "limitations": ["References locate candidate source; they do not prove initialization reachability.",
                                  "Direct callers omit unresolved indirect/data-table dispatch; inspect source before drawing an edge."]}
        if string_query:
            index_path = self.global_config.decompiled_code_dir / view.root.name / "string_xrefs.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            result["string_references"] = {text: refs for text, refs in sorted(index.items())
                                           if string_query in text}
        if function_name:
            if view.get_function_ea(view.root.name, function_name) is None:
                raise ValueError("Initialization function name was not found")
            result["direct_callers"] = [{"function_name": caller.artifact_stem, "function_ea": caller.ea}
                                        for caller in sorted(view.get_function_caller_nodes(view.root.name, function_name),
                                                             key=lambda node: node.ea)]
        return result

    async def read(self, path: str, function_ea: int | None, function_name: str | None):
        if self.phase != "full":
            raise ValueError("Native initialization code evidence requires full phase")
        if function_ea is None and not function_name:
            raise ValueError("Supply an exact function entry address or name")
        relative, view = await self._get_view(path)
        if function_ea is None:
            function_ea = view.get_function_ea(view.root.name, function_name)
            if function_ea is None:
                raise ValueError("Initialization function name was not found")
        name = view.get_decompiled_name(view.root.name, function_ea)
        callgraph = view.lib_dep_graph.get_callgraph_by_name(view.root.name)
        function = callgraph.get_node_by_ea(function_ea)
        listing = view.get_disassembly_path(view.root.name, function_ea).read_text(encoding="utf-8")
        sources = _canonical_chunks(self.rootfs / relative, relative, listing)
        return {
            "path": relative, "binary_sha256": hashlib.sha256((self.rootfs / relative).read_bytes()).hexdigest(),
            "elf_identity": view.get_binary_elf_identity(view.root.name),
            "function_ea": function_ea, "function_name": name,
            "ctree_snapshot_hash": function.semantic_snapshot.snapshot_hash,
            "decompiled_code": view.get_full_code(view.root.name, name),
            "source_snippets": sources,
        }


def make_launcher_code_tools(rootfs, global_config, *, phase, sources=None):
    evidence = LauncherCodeEvidence(rootfs, global_config, phase)

    @tool
    async def find_elf_references(path: str, string_query: str = "",
                                  function_name: str | None = None) -> dict:
        """Locate launcher strings and direct callers through the existing native indexes.

        Use to find an exact function entry for a launch string or to trace a
        known helper's callers without scanning machine-code ranges. Returns all
        substring matches and direct callers. An empty caller list does not rule
        out indirect/data-table dispatch and a string hit does not prove a launch
        edge. inspect_elf_function provides source evidence for the located code.
        The first query for an ELF may require local IDA/Hex-Rays; subsequent
        queries reuse the same single-binary view, without another Analyzer.

        Args:
            path: Guest rootfs-relative launcher/helper ELF, including aliases.
            string_query: Case-sensitive nonempty substring, or empty to omit string search.
            function_name: Exact decompiled name whose direct callers are requested, or null.
        """
        return await evidence.references(path, string_query, function_name)

    @tool
    async def inspect_elf_function(path: str, function_ea: int | None = None,
                                   function_name: str | None = None) -> dict:
        """Read a launcher's complete decompiled function and canonical ELF evidence.

        Use for call dispatch, branch polarity, argument origins or preparation
        helpers that are difficult to establish from raw ELF instructions. The
        first request for a binary can run local IDA/Hex-Rays and cache its CTree;
        later requests reuse that view. IDA and a configured workdir are required.
        This inspects only the requested binary, not its dependency closure.

        Decompiled C is semantic guidance. source_snippets contains canonical
        assembly ready for exact SourceSnippet citations; read_elf also exposes
        data-table bytes and inspect_elf locates strings. Report native-backend unavailability as a
        concrete evidence gap; never invent decompilation or execute guest code.

        Args:
            path: Guest rootfs-relative launcher/helper ELF, including symlink aliases.
            function_ea: Exact function entry virtual address, not a callsite address.
            function_name: Exact symbol or decompiled function name when EA is unknown.
        """
        result = await evidence.read(path, function_ea, function_name)
        if sources is not None:
            result["assembly"] = "\n".join(source["text"] for source in result["source_snippets"])
            result["source_snippets"] = [sources.reference(source) for source in result["source_snippets"]]
        return result

    return [find_elf_references, inspect_elf_function]
