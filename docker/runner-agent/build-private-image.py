"""Build the locally configured IDA/license into a private Runner image.

Only the selected installation and IDA user files enter the streamed context.
No project directory, model configuration, temporary context or image tar is used.
"""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tarfile
import time


def select_user_files(ida: Path, user_directories: list[Path]) -> dict[str, Path]:
    files = {}
    for directory in [ida, *user_directories]:
        for path in sorted(directory.glob('*.hexlic')):
            files.setdefault(path.name, path)
    registry = next((path / 'ida.reg' for path in user_directories
                     if (path / 'ida.reg').is_file()), None)
    if not files:
        raise ValueError('No IDA .hexlic file found in the selected installation or IDAUSR directories')
    if registry is None:
        raise ValueError('No existing ida.reg found in the IDAUSR search path')
    files['ida.reg'] = registry
    return files


def stream_context(stream, ida: Path, user_files: dict[str, Path]) -> None:
    def select(info):
        path = Path(info.name)
        if '__pycache__' in path.parts or path.suffix == '.hexlic':
            return None
        # Set read/traversal permissions in the COPY layer itself; chmod -R in
        # a later RUN would copy up the entire IDA installation into a new layer.
        info.mode |= 0o444
        if info.isdir() or info.mode & 0o111:
            info.mode |= 0o111
        return info

    # Docker's stdin context detection needs a regular tar header first;
    # a Python PAX extended header can be mistaken for a plain Dockerfile.
    with tarfile.open(fileobj=stream, mode='w|', format=tarfile.GNU_FORMAT) as archive:
        archive.add(Path(__file__).with_name('Dockerfile.private-ida'), arcname='Dockerfile')
        archive.add(ida, arcname='ida', filter=select)
        for name, source in user_files.items():
            # Materialize only explicitly selected user files, including symlinked profiles.
            archive.add(source.resolve(strict=True), arcname='ida-user/' + name)


def transfer_image(source_cli, destination_cli, tag, log):
    """Stream engine-to-engine without a second on-disk image archive."""
    with subprocess.Popen(source_cli + ['image', 'save', tag], stdout=subprocess.PIPE, stderr=log) as source:
        with subprocess.Popen(destination_cli + ['image', 'load', '--quiet'], stdin=source.stdout,
                              stdout=log, stderr=log) as destination:
            source.stdout.close()
            loaded = destination.wait()
        saved = source.wait()
    if saved or loaded:
        raise RuntimeError(f'Local image transfer failed (save={saved}, load={loaded})')


def main():
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / '.env')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', default='firmenstein/runner-agent:py312-ida-private')
    parser.add_argument('--base-image', default='firmenstein/runner-agent:py312-tools')
    parser.add_argument('--engine', default=os.getenv('FMST_RUNNER_DOCKER_HOST', os.getenv('DOCKER_HOST', 'unix:///var/run/docker.sock')))
    parser.add_argument('--build-engine', default=os.getenv('DOCKER_HOST', 'unix:///var/run/docker.sock'))
    parser.add_argument('--ida-dir', type=Path, default=os.getenv('IDADIR'))
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--min-free-gib', type=float, help='Optional free-space requirement on the receipt filesystem')
    args = parser.parse_args()
    if args.min_free_gib is not None and args.min_free_gib < 0:
        parser.error('--min-free-gib must be non-negative')
    if args.ida_dir is None or not args.ida_dir.is_dir():
        parser.error('Configure IDADIR or pass --ida-dir with the local installation')
    ida = args.ida_dir.resolve(strict=True)
    profiles = [Path(p).expanduser() for p in os.getenv('IDAUSR', str(Path.home() / '.idapro')).split(os.pathsep) if p]
    user_files = select_user_files(ida, profiles)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    cli = ['docker', '--host', args.engine]
    builder = ['docker', '--host', args.build_engine]
    security = json.loads(subprocess.run(builder + ['info', '--format', '{{json .SecurityOptions}}'],
                                        capture_output=True, text=True, check=True).stdout)
    if 'name=userns' in security:
        raise RuntimeError('Build on a local Docker engine without userns-remap, then load into the isolated task engine; direct remapped builds can shift image ownership')
    base = subprocess.run(cli + ['image', 'inspect', args.base_image, '--format', '{{.Id}}'],
                          capture_output=True, text=True, check=True).stdout.strip()
    required_disk = None if args.min_free_gib is None else args.min_free_gib * 1024**3
    if required_disk is not None and shutil.disk_usage(args.receipt.parent).free < required_disk:
        raise RuntimeError(f'Private image build needs the requested {args.min_free_gib:g} GiB free on the receipt filesystem')
    log_path = args.receipt.with_suffix('.build.log')
    began = time.time()
    with log_path.open('wb') as log:
        os.chmod(log_path, 0o600)
        current_base = subprocess.run(builder + ['image', 'inspect', args.base_image, '--format', '{{.Id}}'],
                                      capture_output=True, text=True)
        if current_base.returncode or current_base.stdout.strip() != base:
            transfer_image(cli, builder, args.base_image, log)
        command = builder + ['build', '--quiet', '--network=none', '--build-arg',
                         'RUNNER_BASE_IMAGE=' + args.base_image, '--tag', args.tag, '-']
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT) as process:
            try:
                stream_context(process.stdin, ida, user_files)
            finally:
                process.stdin.close()
            code = process.wait()
        if code == 0 and args.build_engine != args.engine:
            transfer_image(builder, cli, args.tag, log)
    receipt = {'status': 'built' if code == 0 else 'build_failed', 'tag': args.tag,
               'engine': args.engine, 'build_engine': args.build_engine,
               'required_disk_free_bytes': required_disk,
               'base_image_id': base, 'elapsed_seconds': round(time.time()-began, 3),
               'exit_code': code, 'build_log': str(log_path), 'license_in_build_context': True,
               'license_baked_into_private_image': code == 0,
               'project_or_model_configuration_in_context': False, 'pushed': False}
    if code == 0:
        receipt['image_id'] = subprocess.run(cli + ['image', 'inspect', args.tag, '--format', '{{.Id}}'],
                                            capture_output=True, text=True, check=True).stdout.strip()
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
    if code:
        raise SystemExit(code)


if __name__ == '__main__':
    main()
