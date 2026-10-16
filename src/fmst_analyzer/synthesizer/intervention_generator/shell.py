"""Deterministic Rust shell and IIB manifest generation for Units."""

from __future__ import annotations

import json
import os
import re
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionUnit,
    ResolvedCallsiteAnchor,
    ResolvedFunctionAnchor,
    ResourceAnchor,
)
from .architecture import GeneratorArch, manifest_arch


_TEMPLATE_DIR = Path(__file__).parent / "templates"
def _api_abi_version(crate_root: Path) -> int:
    """Read the API actually linked by this crate, including retained releases."""
    cargo = tomllib.loads((crate_root / "Cargo.toml").read_text())
    api = (crate_root / cargo["dependencies"]["fmst-iib-api"]["path"]).resolve()
    source = (api / "src/manifest.rs").read_text()
    match = re.search(r"pub const CURRENT_ABI_VERSION: u32 = ([0-9]+);", source)
    if match is None:
        raise ValueError(f"Selected GuestWeave API has no declared ABI version: {api}")
    return int(match[1])


@dataclass
class ResolvedManifestEntry:
    unit_id: str
    strategy: Literal["function_stub", "pseudo_file", "callsite_hook"]
    binary: str | None = None
    offset: int | None = None
    symbol_hint: str | None = None
    entry_slug: str | None = None
    callsite_id: str | None = None
    resume_offset: int | None = None
    pseudo_file_paths: list[str] = field(default_factory=list)


@dataclass
class ResolvedManifest:
    entries: list[ResolvedManifestEntry] = field(default_factory=list)


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", value.lower())


def unit_module_name(unit_id: str) -> str:
    return "unit_" + slugify(unit_id.removeprefix("unit-"))


def unit_test_target(unit_id: str) -> str:
    return f"{unit_module_name(unit_id)}_test"


def unit_test_relative_path(unit_id: str) -> Path:
    return Path("tests") / unit_test_target(unit_id) / "main.rs"


def callsite_short_slug(callsite_id: str) -> str:
    return slugify(callsite_id.replace("::", "_"))


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _render(env: Environment, template_name: str, **context) -> str:
    return env.get_template(template_name).render(**context)


def generate_shell(
    *,
    target_binary: str,
    image_name: str,
    arch: GeneratorArch,
    units: list[InterventionUnit],
    resolved_manifest: ResolvedManifest,
    interventions_root: Path,
    test_harnesses_root: Path,
    iib_api_abspath: Path,
) -> None:
    env = _env()
    crate_name = f"intervention_{slugify(target_binary)}"
    test_crate_name = f"tests_{slugify(target_binary)}"
    crate_root = interventions_root / target_binary
    test_root = test_harnesses_root / target_binary
    crate_root.mkdir(parents=True, exist_ok=True)
    test_root.mkdir(parents=True, exist_ok=True)

    _write(
        crate_root / "Cargo.toml",
        _render(
            env,
            "intervention_Cargo.toml.j2",
            crate_name=crate_name,
            iib_api_relpath=os.path.relpath(iib_api_abspath, start=crate_root),
        ),
    )
    shutil.copyfile(_TEMPLATE_DIR / "build.rs", crate_root / "build.rs")
    configure_active_units(
        target_binary=target_binary,
        image_name=image_name,
        arch=arch,
        units=units,
        resolved_manifest=resolved_manifest,
        crate_root=crate_root,
    )
    for unit in units:
        _generate_unit_shell(env, unit, crate_root / "src" / unit_module_name(unit.unit_id))

    _write(
        test_root / "Cargo.toml",
        _render(
            env,
            "test_harnesses_Cargo.toml.j2",
            test_crate_name=test_crate_name,
            crate_name=crate_name,
            intervention_relpath=os.path.relpath(crate_root, start=test_root),
            iib_api_relpath=os.path.relpath(iib_api_abspath, start=test_root),
            mock_features=json.dumps(
                (["mock", "mock-big-endian"]
                 if arch == "mipsbe"
                 else ["mock", "mock-32-bit"]
                 if arch in {"arm", "mips"}
                 else ["mock"]),
            ),
            test_targets=[
                {
                    "name": unit_test_target(unit.unit_id),
                    "path": unit_test_relative_path(unit.unit_id).as_posix(),
                }
                for unit in units
            ],
        ),
    )
    _write(test_root / "src" / "lib.rs", _render(env, "tests_lib.rs.j2"))
    for unit in units:
        module = unit_module_name(unit.unit_id)
        _write(
            test_root / unit_test_relative_path(unit.unit_id),
            _render(env, "placeholder_test.rs.j2", module=module, unit_id=unit.unit_id),
        )


def generate_unit_shell(
    *,
    unit: InterventionUnit,
    crate_root: Path,
) -> None:
    """Add one Controller-validated runtime Unit to an existing crate.

    Runtime-discovered Units are validated by a real sandbox attempt. Emitting
    a passing placeholder test here would falsely claim Generator coverage.
    """
    env = _env()
    module = unit_module_name(unit.unit_id)
    _generate_unit_shell(env, unit, crate_root / "src" / module)


def configure_active_units(
    *,
    target_binary: str,
    image_name: str,
    arch: GeneratorArch,
    units: list[InterventionUnit],
    resolved_manifest: ResolvedManifest,
    crate_root: Path,
) -> None:
    """Register only Units that remain eligible for the shared final build.

    Unit source directories are intentionally retained for reports and
    debugging.  The Controller owns these three index files so a not-ready Unit
    cannot make otherwise valid Units fail the shared crate build.
    """
    env = _env()
    # Runner may reconfigure a crate restored from an immutable Generator
    # baseline. Refresh this Controller-owned translation layer together with
    # manifest.json so both always implement the current manifest ABI.
    shutil.copyfile(_TEMPLATE_DIR / "build.rs", crate_root / "build.rs")
    manifest = _build_manifest(
        target_image=image_name,
        target_binary=target_binary,
        arch=manifest_arch(arch),
        resolved=resolved_manifest,
        abi_version=_api_abi_version(crate_root),
    )
    _write(crate_root / "manifest.json", json.dumps(manifest, indent=2))
    modules = [unit_module_name(unit.unit_id) for unit in units]
    _write(
        crate_root / "src" / "lib.rs",
        _render(env, "lib.rs.j2", target_binary=target_binary, modules=modules),
    )
    _write(
        crate_root / "src" / "state.rs",
        _render(env, "state.rs.j2", modules=modules),
    )


def _generate_unit_shell(
    env: Environment,
    unit: InterventionUnit,
    unit_dir: Path,
) -> None:
    kind_subdir = {
        "function_stub": "function_stubs",
        "pseudo_file": "pseudo_files",
        "callsite_hook": "callsite_hooks",
    }[unit.strategy]
    _write(unit_dir / "mod.rs", _render(env, "unit_mod.rs.j2", kind_subdir=kind_subdir))
    _write(unit_dir / "state.rs", _render(env, "unit_state.rs.j2"))
    _write(unit_dir / "logic.rs", _render(env, "unit_logic.rs.j2"))

    if unit.strategy == "function_stub":
        entries: list[str] = []
        for anchor in unit.anchors:
            assert isinstance(anchor, ResolvedFunctionAnchor)
            module = f"stub_{slugify(anchor.function_name)}"
            entries.append(module)
            _write(
                unit_dir / "function_stubs" / f"{module}.rs",
                _render(env, "function_stub_shell.rs.j2", function_name=anchor.function_name),
            )
        _write(
            unit_dir / "function_stubs" / "mod.rs",
            _render(env, "kind_subdir_mod.rs.j2", entries=entries),
        )
    elif unit.strategy == "pseudo_file":
        paths = [
            anchor.value for anchor in unit.anchors
            if isinstance(anchor, ResourceAnchor)
        ]
        _write(
            unit_dir / "pseudo_files" / "mod.rs",
            _render(
                env,
                "pseudo_file_shell.rs.j2",
                pseudo_file_paths=paths,
            ),
        )
    else:
        entries = []
        for anchor in unit.anchors:
            assert isinstance(anchor, ResolvedCallsiteAnchor)
            module = f"hook_{callsite_short_slug(anchor.callsite_id)}"
            entries.append(module)
            _write(
                unit_dir / "callsite_hooks" / f"{module}.rs",
                _render(env, "callsite_hook_shell.rs.j2", callsite_id=anchor.callsite_id),
            )
        _write(
            unit_dir / "callsite_hooks" / "mod.rs",
            _render(env, "kind_subdir_mod.rs.j2", entries=entries),
        )


def _build_manifest(
    *,
    target_image: str,
    target_binary: str,
    arch: str,
    resolved: ResolvedManifest,
    abi_version: int,
) -> dict:
    callsite_hooks: list[dict] = []
    function_stubs: list[dict] = []
    pseudo_files: list[dict] = []
    for entry in resolved.entries:
        module = unit_module_name(entry.unit_id)
        if entry.strategy == "function_stub":
            function_stubs.append({
                "id": f"stub_{entry.unit_id}_{entry.entry_slug}",
                "target": {
                    "binary": entry.binary,
                    "offset": f"0x{entry.offset:08x}",
                    "_symbol_hint": entry.symbol_hint,
                },
                "flavor": "Call",
                "entry_fn_path": f"crate::{module}::function_stubs::stub_{entry.entry_slug}::intercept",
                "source_file": f"src/{module}/function_stubs/stub_{entry.entry_slug}.rs",
            })
        elif entry.strategy == "callsite_hook":
            if entry.resume_offset is None:
                raise ValueError(
                    f"{entry.unit_id}: callsite hook is missing resume_offset"
                )
            callsite_hooks.append({
                "id": f"hook_{entry.unit_id}_{entry.entry_slug}",
                "target": {
                    "binary": entry.binary,
                    "offset": f"0x{entry.offset:08x}",
                    "_symbol_hint": entry.symbol_hint,
                },
                "resume_offset": f"0x{entry.resume_offset:08x}",
                "flavor": "Call",
                "entry_fn_path": f"crate::{module}::callsite_hooks::hook_{entry.entry_slug}::intercept",
                "source_file": f"src/{module}/callsite_hooks/hook_{entry.entry_slug}.rs",
            })
        else:
            pseudo_files.append({
                "id": f"pf_{entry.unit_id}",
                "paths": entry.pseudo_file_paths,
                "impl_type_path": f"crate::{module}::pseudo_files::PseudoFileImpl",
                "factory_path": f"crate::{module}::pseudo_files::factory",
                "source_file": f"src/{module}/pseudo_files/mod.rs",
            })
    return {
        "manifest_abi_version": abi_version,
        "target_image": target_image,
        "target_binary": target_binary,
        "arch": arch,
        "global_state": {
            "type_path": "crate::state::GlobalState",
            "init_path": "crate::state::GlobalState::default",
        },
        "callsite_hooks": callsite_hooks,
        "function_stubs": function_stubs,
        "pseudo_files": pseudo_files,
    }


__all__ = [
    "ResolvedManifest",
    "ResolvedManifestEntry",
    "callsite_short_slug",
    "configure_active_units",
    "generate_unit_shell",
    "generate_shell",
    "slugify",
    "unit_module_name",
    "unit_test_relative_path",
    "unit_test_target",
]
