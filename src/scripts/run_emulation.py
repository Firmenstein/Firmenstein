#!/usr/bin/env python3
"""Standalone Firmenstein emulation launcher.

Given firmware metadata, a workdir, and a target binary, stages the environment
intervention script against a throwaway rootfs copy and launches the
IIB harness so it dlopen-loads the synthesized intervention cdylib and
emulates the target under libafl_qemu.

Usage:
    python src/scripts/run_emulation.py \\
        --workdir ./workdir \\
        --firmware-metadata /path/to/artifact/metadata.json \\
        --target-binary httpd

Assumes the full analyze pipeline has already produced:
    <workdir>/<image>/interventions/<target>/target/release/lib*.so
    <workdir>/<image>/env_scripts/<target>/setup_rootfs.py   (optional)
and that the harness binary has been built:
    ../GuestWeave/target/release/fmst-harness-<arch>

This launcher intentionally has NO dependency on fmst_analyzer — it
operates purely on the on-disk artefacts the pipeline leaves behind,
so you can iterate on one step (e.g. hand-edit the cdylib or the env
script) and re-emulate without running the full analyze loop.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from fmst_basic.FirmProbe.metadata import load_firmware_metadata

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = PROJECT_ROOT.parent
HARNESS_DIR = WORKSPACE_ROOT / "GuestWeave" / "target" / "release"

ARCH_ALIASES = {
    "arm": "arm", "armv7": "arm", "armhf": "arm", "armel": "arm",
    "x86_64": "x86_64", "amd64": "x86_64", "x86-64": "x86_64", "x86": "x86_64",
    "mips": "mips", "mipsel": "mips",
}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Launch IIB emulation for a synthesized target",
    )
    ap.add_argument("--workdir", type=Path, required=True,
                    help="Project-level workdir (without <image> suffix)")
    ap.add_argument("--firmware-metadata", type=Path, required=True,
                    help="FirmProbe metadata.json path")
    ap.add_argument("--target-binary", required=True)
    ap.add_argument("--rootfs", type=Path, default=None,
                    help="Override the rootfs path from metadata.json")
    ap.add_argument("--arch", default=None,
                    help="Target arch: arm / x86_64 / mips. Default: FMST_ARCH env or 'arm'")
    ap.add_argument("--intervention-so", type=Path, default=None,
                    help="Override cdylib path. Default: auto-pick under interventions/<target>/target/")
    ap.add_argument("--env-script", type=Path, default=None,
                    help="Override env setup script. Default: env_scripts/<target>/setup_rootfs.py")
    ap.add_argument("--timeout", type=float, default=None,
                    help="Wall-clock timeout in seconds for the harness")
    ap.add_argument("--guest-arg", action="append", default=[],
                    help="Trailing argument forwarded to the guest binary (repeatable)")
    return ap.parse_args()


def resolve_rootfs(metadata: dict, override: Optional[Path]) -> Path:
    if override is not None:
        return override.resolve()
    return Path(metadata["rootfs_path"])


def detect_arch(explicit: Optional[str]) -> str:
    raw = explicit or os.environ.get("FMST_ARCH") or "arm"
    arch = ARCH_ALIASES.get(raw.lower())
    if arch is None:
        raise RuntimeError(f"unrecognized arch {raw!r}")
    return arch


def find_cdylib(interventions_dir: Path) -> Optional[Path]:
    """First ``release/lib*.so`` under the crate's target tree."""
    target = interventions_dir / "target"
    if not target.exists():
        return None
    for so in target.rglob("release/lib*.so"):
        return so
    return None


def stage_rootfs(src_rootfs: Path, dest_parent: Path) -> Path:
    """Duplicate the rootfs so preparation can never mutate the source tree."""
    dest = dest_parent / f"rootfs_stage_{int(time.time())}"
    print(f"[launcher] copying rootfs -> {dest}")
    shutil.copytree(src_rootfs, dest, symlinks=True)
    return dest


def run_env_script(script: Path, rootfs: Path) -> None:
    print(f"[launcher] running env setup: {script} {rootfs}")
    r = subprocess.run(
        [sys.executable, str(script), str(rootfs)],
        capture_output=True, text=True,
    )
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise RuntimeError(f"env setup script failed with exit {r.returncode}")


def run_harness(
    harness_bin: Path,
    intervention_so: Optional[Path],
    target_binary_path: Path,
    rootfs: Path,
    guest_args: list[str],
    timeout: Optional[float],
    log_path: Path,
) -> int:
    intervention_arguments = (
        ["--intervention-so", str(intervention_so)]
        if intervention_so is not None
        else ["--trace-only"]
    )
    argv = [
        str(harness_bin),
        *intervention_arguments,
        "--binary", str(target_binary_path),
        "--rootfs", str(rootfs),
        *guest_args,
    ]
    print(f"[launcher] launching: {' '.join(argv)}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as logf:
        proc = subprocess.Popen(argv, stdout=logf, stderr=subprocess.STDOUT)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            print(f"[launcher] harness timed out after {timeout}s", file=sys.stderr)
            rc = -1
    print(f"[launcher] harness exited {rc}; log at {log_path}")
    return rc


def main() -> int:
    args = parse_args()
    metadata = load_firmware_metadata(args.firmware_metadata)
    image_name = metadata["image_name"]
    image_workdir = args.workdir.resolve() / image_name
    if not image_workdir.is_dir():
        print(f"[launcher] workdir missing: {image_workdir}", file=sys.stderr)
        return 2

    arch = detect_arch(args.arch)
    harness_bin = HARNESS_DIR / f"fmst-harness-{arch}"
    if not harness_bin.exists():
        print(
            f"[launcher] harness binary missing: {harness_bin}\n"
            f"  build it with: cargo build --release -p fmst-harness-{arch}",
            file=sys.stderr,
        )
        return 2

    intervention_so = args.intervention_so or find_cdylib(
        image_workdir / "interventions" / args.target_binary
    )
    if intervention_so is not None and not intervention_so.exists():
        print(f"[launcher] intervention cdylib is missing: {intervention_so}", file=sys.stderr)
        return 2
    if intervention_so is None:
        print("[launcher] no intervention cdylib found; using trace-only harness")

    src_rootfs = resolve_rootfs(metadata, args.rootfs)
    if not src_rootfs.is_dir():
        print(f"[launcher] rootfs missing: {src_rootfs}", file=sys.stderr)
        return 2

    target_binary_path = src_rootfs / "bin" / args.target_binary
    # Fallback: let the user just point --binary at anywhere under the
    # rootfs. We scan a few common locations.
    if not target_binary_path.exists():
        for sub in ("usr/sbin", "sbin", "usr/bin", "bin"):
            cand = src_rootfs / sub / args.target_binary
            if cand.exists():
                target_binary_path = cand
                break
    if not target_binary_path.exists():
        print(
            f"[launcher] target binary {args.target_binary} not found under "
            f"{src_rootfs} (checked bin/, sbin/, usr/bin/, usr/sbin/)",
            file=sys.stderr,
        )
        return 2

    stage_parent = image_workdir / "emulation_stage"
    stage_parent.mkdir(parents=True, exist_ok=True)
    rootfs = stage_rootfs(src_rootfs, stage_parent)
    staged_target_binary_path = rootfs / target_binary_path.relative_to(src_rootfs)

    env_script = args.env_script or (
        image_workdir / "env_scripts" / args.target_binary / "setup_rootfs.py"
    )
    if env_script.exists():
        run_env_script(env_script, rootfs)
    else:
        print(f"[launcher] no env setup script at {env_script} — skipping")

    log_path = image_workdir / "logs" / f"iib_{args.target_binary}.log"
    rc = run_harness(
        harness_bin=harness_bin,
        intervention_so=intervention_so,
        target_binary_path=staged_target_binary_path,
        rootfs=rootfs,
        guest_args=args.guest_arg,
        timeout=args.timeout,
        log_path=log_path,
    )
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
