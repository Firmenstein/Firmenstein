"""Extend verified offline inputs with the exact union of consumer lockfiles.

Never update a consumer lock or modify an existing delivery. New registry crates
must match their lockfile checksums before becoming Cargo vendor sources.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tarfile
import tomllib

import httpx


def registry_packages(locks):
    packages = {}
    for lock in locks:
        for item in tomllib.loads(lock.read_text())['package']:
            source = item.get('source', '')
            if not source:
                continue
            if source != 'registry+https://github.com/rust-lang/crates.io-index':
                raise ValueError(f'Offline extension needs an explicit source for {source}')
            key = (item['name'], item['version'])
            if key in packages and packages[key] != item['checksum']:
                raise ValueError(f'Conflicting lockfile checksum for {key}')
            packages[key] = item['checksum']
    return packages


def add_crate(client, vendor, name, version, checksum):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not re.fullmatch(r'[A-Za-z0-9.+_-]+', version):
        raise ValueError('Invalid registry package name or version')
    url = f'https://static.crates.io/crates/{name}/{name}-{version}.crate'
    archive = vendor / f'.{name}-{version}.crate'
    digest = hashlib.sha256()
    try:
        with client.stream('GET', url) as response, archive.open('wb') as out:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest() != checksum:
            raise ValueError(f'Registry archive does not match lockfile: {name} {version}')
        root = vendor / f'{name}-{version}'
        root.mkdir(exist_ok=False)
        prefix = f'{name}-{version}'
        with tarfile.open(archive) as stream:
            for member in stream:
                parts = PurePosixPath(member.name).parts
                if not parts or parts[0] != prefix or '..' in parts:
                    raise ValueError('Unsafe registry archive path')
                path = root.joinpath(*parts[1:])
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with stream.extractfile(member) as src, path.open('xb') as dst:
                        import shutil
                        shutil.copyfileobj(src, dst)
                    path.chmod(member.mode & 0o777)
                else:
                    raise ValueError('Unsupported registry archive entry')
        files = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in root.rglob('*') if p.is_file()}
        (root / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': checksum}) + '\n')
        return {'name': name, 'version': version, 'checksum': checksum, 'url': url,
                'directory': root.name}
    finally:
        archive.unlink(missing_ok=True)


def main():
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--delivery', type=Path, required=True)
    parser.add_argument('--lock-list', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tools = args.delivery / 'workspace/GuestWeave/tools'
    sys.path.insert(0, str(tools))
    spec = importlib.util.spec_from_file_location('offline_verifier', tools / 'offline.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.verify(args.delivery)
    locks = [Path(p).resolve(strict=True) for p in json.loads(args.lock_list.read_text())]
    required = registry_packages(locks)
    available = {}
    for root in (args.delivery / 'vendor').iterdir():
        item = tomllib.loads((root / 'Cargo.toml').read_text())['package']
        available[(item['name'], item['version'])] = json.loads((root / '.cargo-checksum.json').read_text())['package']
    for key in required.keys() & available.keys():
        if required[key] != available[key]:
            raise ValueError(f'Existing vendor checksum differs from consumer lock: {key}')
    args.output.mkdir(parents=True, exist_ok=False)
    subprocess.run(['cp', '--reflink=auto', '-r', '--preserve=mode,timestamps',
                    str(args.delivery) + '/.', str(args.output)], check=True)
    added = []
    with httpx.Client(trust_env=False, timeout=60, follow_redirects=True) as client:
        for (name, version), checksum in sorted(required.items()):
            if (name, version) not in available:
                added.append(add_crate(client, args.output / 'vendor', name, version, checksum))
    receipt = {k: v for k, v in original.items() if k not in {'files', 'delivery_id'}}
    receipt.update(parent_delivery_id=original['delivery_id'], files=module.inventory(args.output),
                   consumer_locks=[{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in locks],
                   registry_additions=added)
    receipt['delivery_id'] = module.identity(receipt)
    (args.output / 'DELIVERY.json').write_text(json.dumps(receipt, indent=2) + '\n')
    module.verify(args.output)
    print(json.dumps({'status': 'verified', 'delivery_id': receipt['delivery_id'], 'added': added}))


if __name__ == '__main__':
    main()
