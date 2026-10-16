"""Build a delivered service in a fresh native volume with no network access."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


def main() -> None:
    package, work, evidence = Path("/package"), Path("/build"), Path("/evidence")
    if any(work.iterdir()):
        raise ValueError("build volume must start empty")
    manifest = json.loads((package / "PACKAGE.json").read_text())
    delivery = Path("/delivery")
    framework = delivery / "workspace/GuestWeave"
    sys.path.insert(0, str(framework / "tools"))
    import offline

    offline.verify(delivery)
    env = os.environ.copy()
    env.update(CARGO_HOME=str(work / "cargo-home"), CARGO_TARGET_DIR=str(work / "target"),
        CARGO_NET_OFFLINE="true", RUSTUP_TOOLCHAIN="1.98.0", PIP_NO_INDEX="1",
        LIBAFL_QEMU_DIR=str(work / "qemu"), VHARNESS_DIR=str(work / "libvharness"))
    for name in ("LIBAFL_QEMU_CLONE_DIR", "LIBAFL_QEMU_GIT_URL", "LIBAFL_QEMU_GIT_REV", "LIBAFL_QEMU_NO_BUILD"):
        env.pop(name, None)
    Path(env["CARGO_HOME"]).mkdir()
    for name in ("qemu", "libvharness"):
        offline.extract(delivery / "sources" / (name + ".tar.gz"), work / name)
    arch = manifest["guest_arch"]
    harness_name = {"arm": "fmst-harness-arm", "mipsel": "fmst-harness-mips",
        "mipsbe": "fmst-harness-mips", "x86_64": "fmst-harness-x86"}[arch]
    command = ["cargo", "build", "--frozen", "--release", "--jobs", "4", "-p", harness_name]
    if arch == "mipsbe":
        command += ["--no-default-features", "--features", "big-endian"]
    record = {"command": command, "initial_target_absent": not Path(env["CARGO_TARGET_DIR"]).exists(),
        "initial_cargo_home_empty": not any(Path(env["CARGO_HOME"]).iterdir()),
        "native_qemu_build_absent": not (work / "qemu/build").exists(),
        "environment": {k: env[k] for k in ("CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE",
            "RUSTUP_TOOLCHAIN", "LIBAFL_QEMU_DIR", "VHARNESS_DIR", "PIP_NO_INDEX")}}
    (evidence / "build-inputs.json").write_text(json.dumps(record, indent=2) + "\n")
    subprocess.run(command, cwd=framework, env=env, check=True)
    bundle = evidence / "runtime"
    from build_runtime_bundle import build_bundle

    build_bundle(work / "target/release" / harness_name, bundle,
        binaries={"nc": Path("/usr/bin/nc"), "sh": Path("/bin/sh"),
                  "sleep": Path("/bin/sleep"), "cp": Path("/bin/cp")})
    authored = package / "authored"
    intervention = authored / "interventions" / manifest["target_binary"]
    intervention_present = (intervention / "Cargo.toml").is_file()
    if intervention_present:
        command = ["cargo", "build", "--frozen", "--release", "--manifest-path", str(intervention / "Cargo.toml")]
        subprocess.run(command, cwd=intervention, env=env, check=True)
        name = tomllib.loads((intervention / "Cargo.toml").read_text())["lib"]["name"]
        shutil.copy2(work / "target/release" / ("lib" + name.replace("-", "_") + ".so"), bundle / "intervention.so")
    (evidence / "build-complete.json").write_text(json.dumps({"harness": harness_name,
        "intervention_built": intervention_present, "self_tests_run": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
