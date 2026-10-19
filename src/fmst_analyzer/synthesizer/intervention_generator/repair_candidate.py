"""Publish an explicit diagnostic starting point when no bound candidate exists.

The executable runs GuestWeave without asserting that no intervention is needed.
Any unfinished Generator code is retained separately as unvalidated repair material.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from fmst_analyzer.analysis.base.report_io import write_text
from fmst_analyzer.runner.identity import tree_sha256


TRACE_WORKER = '''use guestweave::{run, ExecLauncher, RunConfig};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let binary = args.next().ok_or("expected guest ELF")?;
    let rootfs = args.next().ok_or("expected guest rootfs")?;
    let trace = args.next().ok_or("expected trace output path")?;
    let mut config = RunConfig::new(binary, rootfs);
    config.trace_output = Some(PathBuf::from(trace));
    config.syscall_trace = true;
    config.args = args.collect();
    config.exec = Some(ExecLauncher::current_process()?);
    run(config)?;
    Ok(())
}
'''


def publish_repair_candidate(destination: Path, *, config, repair_input, arch: str) -> dict:
    """Create fresh source material, bound to the admitted input and failure."""
    destination.mkdir(parents=True, exist_ok=False)
    feature = "mips" if arch == "mipsel" else arch
    cargo = ('[package]\nname = "fmst-upstream-diagnostic"\nversion = "0.1.0"\nedition = "2021"\n'
             '[workspace]\n[dependencies]\n'
             'guestweave = { path = "/task/work/framework/GuestWeave", features = [' + json.dumps(feature) + '] }\n'
             'fmst-iib-api = { path = "/task/work/framework/GuestWeave/fmst-iib-api" }\n')
    write_text(destination / "intervention/Cargo.toml", cargo)
    write_text(destination / "intervention/src/main.rs", TRACE_WORKER)
    write_text(destination / "README.md",
               "# Upstream repair candidate\n\n"
               "Upstream analysis did not produce a consumable Generator publication.\n"
               "This diagnostic executable runs the real guest through GuestWeave without an intervention.\n"
               "Usage: fmst-upstream-diagnostic <guest ELF> <rootfs> <trace output> [guest arguments].\n"
               "It does not prove that intervention is unnecessary or that the firmware works.\n"
               "Review upstream_repair_input.json and available analysis reports, investigate native failures, "
               "and implement/rebuild/load interventions where the observed behavior requires them.\n"
               "Any upstream-generator files are unvalidated repair material; verify their input identity, "
               "ABI and bindings before reusing them.\n")
    sources = []
    # Only an attempt that entered Generation can contribute unfinished code.
    # Earlier stages must not silently inherit an older candidate in this workdir.
    if repair_input.failed_stage == "generation" and repair_input.generator_materials_current:
        from .baseline import _authored_files
        for kind, name in (("intervention", "interventions"), ("test_harness", "test_harnesses")):
            source = Path(config.workdir) / name / config.current_target
            if not source.is_dir():
                continue
            if source.is_symlink() or not source.resolve().is_relative_to(Path(config.workdir).resolve()):
                sources.append({"source": str(source), "status": "unavailable", "reason": "Source is outside the task workdir"})
                continue
            try:
                files = _authored_files(source)
            except RuntimeError:
                sources.append({"source": str(source), "status": "unavailable", "reason": "Authored source contains symlinks"})
                continue
            for path in files:
                target = destination / "upstream-generator" / kind / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
            sources.append({"source": str(source), "status": "unvalidated", "files": len(files)})
    record = {"schema_version": 1, "origin": "diagnostic_scaffold", "generation_status": "not_completed",
              "target_path": repair_input.target_path, "target_sha256": repair_input.target_sha256,
              "rootfs_sha256": repair_input.rootfs_sha256, "arch": arch, "upstream_generator_materials": sources}
    write_text(destination / "repair-candidate.json", json.dumps(record, indent=2) + "\n")
    return {"root": destination, "baseline_id": "upstream-repair:" + tree_sha256(destination), "record": record}
