"""Freeze exact authored Cargo dependencies in a task-owned container volume."""
from pathlib import Path
import os
import shutil
import subprocess


def main():
    package = Path("/package")
    env = os.environ.copy()
    env.update(CARGO_HOME="/build/cargo-home", RUSTUP_TOOLCHAIN="1.98.0",
               CARGO_NET_OFFLINE="true" if Path("/registry-seed").exists() else "false")
    Path(env["CARGO_HOME"]).mkdir()
    if Path("/registry-seed").exists():
        shutil.copytree("/registry-seed", Path(env["CARGO_HOME"]) / "registry")
    manifests = sorted((package / "authored").rglob("Cargo.toml"))
    for manifest in manifests:
        if not manifest.with_name("Cargo.lock").is_file():
            raise ValueError(f"authored manifest lacks its frozen lockfile: {manifest}")
    command = ["cargo", "vendor", "--locked", "--versioned-dirs", "--manifest-path", str(manifests[0])]
    for manifest in manifests[1:]:
        command += ["--sync", str(manifest)]
    command.append(str(package / "dependencies/authored-vendor"))
    config = subprocess.check_output(command, cwd=package, env=env, text=True)
    directory = package / ".cargo"
    directory.mkdir()
    (directory / "config.toml").write_text(config + "\n[net]\noffline = true\n")


if __name__ == "__main__":
    main()
