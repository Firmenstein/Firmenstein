"""Explicit Docker integration test; run from repo root after activating src/.venv.

Creates a fresh output directory, builds a freestanding guest + ABI v3 fixture,
and tests the real x86_64 harness on the configured local Linux builder.
No Analyzer, Plan, Generator, Agent, firmware, or network scenario is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from dotenv import load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    workspace_root = Path(__file__).resolve().parents[4]
    project_root = workspace_root / 'Firmenstein'
    fixture_root = project_root / 'tests/runtime_fixtures/guestweave'
    load_dotenv(project_root / '.env')
    from fmst_analyzer.runner.runtime_builder import create_runtime_builder
    from fmst_analyzer.runner.budget import ExecutionBudget

    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    workspace = workspace_root / 'GuestWeave'
    assets = fixture_root / 'assets/image_resource_contract'
    builder = create_runtime_builder(
        runtime_workspace=workspace, workdir=out,
        image=os.environ.get('FMST_RUNTIME_BUILDER_IMAGE'),
        platform_name=os.environ.get('FMST_RUNTIME_BUILDER_PLATFORM'),
        budget=ExecutionBudget(900, cleanup_seconds=60),
    )
    cp = builder._container_path
    results = []
    source_paths = list((workspace/'fmst-iib-runtime/src').glob('*.rs')) + list(assets.glob('*')) + [Path(__file__).resolve()]
    source_hashes = {str(p.relative_to(workspace_root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    artifacts = {}

    def run(label: str, command: list[str], timeout: int = 120, expected: int = 0):
        result = builder._run(command, timeout=timeout)
        (out / f'{label}.stdout').write_text(result.stdout)
        (out / f'{label}.stderr').write_text(result.stderr)
        results.append({'label': label, 'command': command, 'returncode': result.returncode,
                        'expected': expected})
        (out / 'commands.json').write_text(json.dumps(results, indent=2))
        assert result.returncode == expected, f'{label}: exit {result.returncode}; see {out}'
        return result

    try:
        target = builder.cargo_target_dir(workspace) / 'x86_64'
        run('build-harness', ['cargo', 'build', '--locked', '--release', '--manifest-path', cp(workspace/'Cargo.toml'),
                             '--target-dir', cp(target), '-p', 'fmst-harness-x86'], 900)
        harness = target/'release/fmst-harness-x86'
        lld = run('linker', ['sh', '-c', 'printf "%s" "$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n \'s/^host: //p\')/bin/rust-lld"']).stdout
        for case in ['direct', 'fork']:
            case_dir = out / case
            case_dir.mkdir()
            parent, child = case_dir/'parent', case_dir/'child'
            for binary, defs in [(parent, ['-DFORK_CHILD'] if case == 'fork' else []), (child, ['-DCHILD'])]:
                obj = binary.with_suffix('.o')
                run(f'{case}-{binary.name}-compile', ['clang', '--target=x86_64-linux-gnu', '-O0', '-c',
                    '-nostdlib', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pic',
                    f'-DCHILD_PATH="{cp(child)}"', f'-DFILE_PATH="{cp(case_dir/"ordinary-file")}"',
                    *defs, cp(assets/'guest.c'), '-o', cp(obj)])
                run(f'{case}-{binary.name}-link', [lld, '-flavor', 'gnu', '-m', 'elf_x86_64',
                    '-static', '--entry=_start', '-o', cp(binary), cp(obj)])
            symbols = run(f'{case}-symbols', ['nm', '-n', cp(parent)]).stdout
            sym = {name: int(addr,16) for addr, _, name in (line.split() for line in symbols.splitlines() if len(line.split()) == 3)}
            loads = run(f'{case}-elf', ['readelf', '-lW', cp(parent)]).stdout
            base = min(int(x,16) for x in re.findall(r'LOAD\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)', loads))
            crate = case_dir/'intervention'
            crate.mkdir()
            shutil.copyfile(assets/'intervention.rs', crate/'lib.rs')
            (crate/'layout.rs').write_text(
                f'const HOOK_OFFSET: u64 = {sym["probe_hook"]-base};\n'
                f'const NATIVE_DELTA: i64 = {sym["native_answer"]-sym["probe_hook"]};\n'
                f'const DATA_DELTA: i64 = {sym["data_marker"]-sym["probe_hook"]};\n')
            (crate/'Cargo.toml').write_text(
                '[package]\nname="image-resource-contract"\nversion="0.1.0"\nedition="2021"\n'
                '[workspace]\n[lib]\ncrate-type=["cdylib"]\npath="lib.rs"\n'
                '[features]\nno-snapshot=[]\n[dependencies]\n'
                f'fmst-iib-api={{path={json.dumps(cp(workspace/"fmst-iib-api"))}}}\n')
            run(f'{case}-intervention', ['cargo','build','--release','--manifest-path',cp(crate/'Cargo.toml')], 300)
            built_so = crate/'target/release/libimage_resource_contract.so'
            so = case_dir/'intervention.so'
            shutil.copyfile(built_so, so)
            for p in [harness, parent, child, so]:
                artifacts[str(p.relative_to(workspace_root))] = hashlib.sha256(p.read_bytes()).hexdigest()
            common = [cp(harness), '--intervention-so', cp(so), '--rootfs', '/']
            # Initial mismatch must fail before executing any child instruction.
            run(f'{case}-initial-mismatch', [*common, '--binary', cp(child), '--trace-output', cp(case_dir/'mismatch.json')], expected=2)
            mismatch = json.loads((case_dir/'mismatch.json').read_text())
            assert 'IIB-MISSING-BINARY' in json.dumps(mismatch)
            result = run(f'{case}-guest', [*common, '--binary', cp(parent), '--trace-output', cp(case_dir/'trace.json')])
            assert result.stdout == 'contract-child-ok\n'
            traces = [json.loads(p.read_text()) for p in case_dir.glob('trace*.json')]
            assert any('iib_hook_skipped_missing_binary' in json.dumps(t) for t in traces)
            assert any('native_call_resolution_failed' in json.dumps(t) for t in traces)
            handoffs = [t for t in traces if t.get('scope') == 'non_cloexec_open_file_descriptions']
            assert len(handoffs) == 1
            handoff = handoffs[0]
            assert handoff['schema_version'] == 2
            assert len(handoff['descriptions']) == 1
            assert handoff['descriptions'][0]['resource_id'] == 'shared-state'
            assert handoff['descriptions'][0]['state'] == [1,1,88,89,90]
            assert {d['fd'] for d in handoff['descriptors']} == {7,8}
            assert (case_dir/'ordinary-file').read_bytes() == b'F'
            if case == 'direct':
                run('no-snapshot-build', ['cargo','build','--release','--manifest-path',cp(crate/'Cargo.toml'), '--features','no-snapshot'], 300)
                no_snapshot = case_dir/'intervention-no-snapshot.so'
                shutil.copyfile(built_so, no_snapshot)
                artifacts[str(no_snapshot.relative_to(workspace_root))] = hashlib.sha256(no_snapshot.read_bytes()).hexdigest()
                no_snapshot_common = [cp(no_snapshot) if v == cp(so) else v for v in common]
                run('no-snapshot-guest', [*no_snapshot_common, '--binary', cp(parent), '--trace-output', cp(case_dir/'no-snapshot.json')], expected=21)
                failed = [p.read_text() for p in case_dir.glob('no-snapshot*.json')]
                assert any('has no exec handoff snapshot' in s for s in failed)
        evidence_paths = [p for p in out.rglob('*') if p.is_file() and 'target' not in p.parts]
        receipt = {'status': 'passed', 'guest_arch': 'x86_64', 'builder_platform': builder.platform_name,
                   'baseline': subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                   'source_hashes': source_hashes, 'artifact_hashes': artifacts,
                   'evidence_hashes': {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence_paths}}
        assert all(hashlib.sha256((workspace_root/p).read_bytes()).hexdigest() == digest for p, digest in source_hashes.items()), 'source changed during validation'
        assert all(hashlib.sha256((workspace_root/p).read_bytes()).hexdigest() == digest for p, digest in artifacts.items()), 'artifact changed during validation'
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2))
        print(json.dumps({'status':'passed','receipt':str(out/'receipt.json')}))
    finally:
        (out/'cleanup.json').write_text(json.dumps(builder.cleanup_records, indent=2))


if __name__ == '__main__':
    main()
