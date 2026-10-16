"""Real x86_64 guest / local Docker regression for host diagnostic isolation.

Uses no firmware or intervention. A fresh directory retains commands, original
stdout/stderr, trace and diagnostics even when an assertion fails.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from dotenv import load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--offline', action='store_true', help='Use a builder image containing the Cargo registry cache.')
    args = parser.parse_args()
    workspace_root = Path(__file__).resolve().parents[4]
    project_root = workspace_root / 'Firmenstein'
    fixture_root = project_root / 'tests/runtime_fixtures/guestweave'
    load_dotenv(project_root / '.env')
    from fmst_analyzer.runner.budget import ExecutionBudget
    from fmst_analyzer.runner.runtime_builder import create_runtime_builder

    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    workspace = workspace_root / 'GuestWeave'
    guest = fixture_root / 'assets/diagnostic_isolation/guest.c'
    budget = ExecutionBudget(3600, cleanup_seconds=60)
    builder = create_runtime_builder(runtime_workspace=workspace, workdir=out,
        image=os.environ.get('FMST_RUNTIME_BUILDER_IMAGE'),
        platform_name=os.environ.get('FMST_RUNTIME_BUILDER_PLATFORM'), budget=budget)
    cp = builder._container_path
    commands, checks = [], []
    sources = [guest, Path(__file__).resolve(), workspace/'fmst-iib-runtime/src/diagnostic_sink.c',
               workspace/'fmst-iib-runtime/Cargo.toml', workspace/'fmst-iib-runtime/build.rs',
               *list((workspace/'fmst-iib-runtime/src').glob('*.rs')),
               *list((workspace/'harness-x86/src').glob('*.rs'))]
    hashes = {str(p.relative_to(workspace_root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    artifacts = {}
    def run(label, command, timeout=120):
        result = builder._run(command, timeout=timeout)
        (out/f'{label}.stdout').write_text(result.stdout)
        (out/f'{label}.stderr').write_text(result.stderr)
        commands.append(dict(label=label, command=command, returncode=result.returncode))
        (out/'commands.json').write_text(json.dumps(commands, indent=2))
        assert result.returncode == 0, f'{label} failed; see {out}'
        return result.stdout
    status = 'incomplete'
    try:
        target = builder.cargo_target_dir(workspace)/'x86_64'
        if not args.skip_build:
            run('build', ['env','CARGO_HTTP_TIMEOUT=20','CARGO_NET_RETRY=1',
                'cargo','build',*(['--offline'] if args.offline else []),'--release','--manifest-path',cp(workspace/'Cargo.toml'),
                '--target-dir',cp(target),'-p','fmst-harness-x86'],900)
        harness = target/'release/fmst-harness-x86'
        lld = run('linker',['sh','-c','printf "%s" "$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n \'s/^host: //p\')/bin/rust-lld"'])
        for case in ['normal', 'crash', 'log-failure', 'drop-uid', 'guest-log-variable']:
            directory = out/case
            directory.mkdir()
            directory.chmod(0o777)  # Same writable output contract as Runner.
            child = directory/'child'
            for name in ['parent','child']:
                binary = directory/name
                defs = (['-DCHILD'] if name=='child' else []) + (['-DCRASH'] if case=='crash' else []) + (['-DLOG_FAILURE'] if case=='log-failure' else [])
                if case == 'drop-uid':
                    defs.append('-DDROP_UID')
                if case == 'guest-log-variable' and name == 'parent':
                    defs.append(f'-DEXPECT_QEMU_LOG_FILENAME="QEMU_LOG_FILENAME={cp(directory/"unsafe-persistent-fd.log")}"')
                run(f'{case}-{name}-compile',['clang','--target=x86_64-linux-gnu','-O0','-c',
                    '-nostdlib','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic',
                    f'-DCHILD_PATH="{cp(child)}"',f'-DSTATUS_PATH="{cp(directory/"wait-status.bin")}"',
                    f'-DTRACE_DIR="{cp(directory)}"', f'-DMOVED_DIR="{cp(directory)}.moved"',
                    *defs,cp(guest),'-o',cp(binary.with_suffix('.o'))])
                run(f'{case}-{name}-link',[lld,'-flavor','gnu','-m','elf_x86_64','-static',
                    '--entry=_start','-o',cp(binary),cp(binary.with_suffix('.o'))])
                artifacts[str(binary.relative_to(workspace_root))] = hashlib.sha256(binary.read_bytes()).hexdigest()
            stdout = run(case,['env','RUST_LOG=info','QEMU_LOG=in_asm',
                f'QEMU_LOG_FILENAME={cp(directory/"unsafe-persistent-fd.log")}',
                cp(harness),'--trace-only','--rootfs','/',
                '--binary',cp(directory/'parent'),'--trace-output',cp(directory/'runtime_trace.json'),
                *(['--guest-env',f'QEMU_LOG_FILENAME={cp(directory/"unsafe-persistent-fd.log")}'] if case=='guest-log-variable' else [])])
            expected = 'guest-stderr\nafter-exec-fallback\nguest-stderr\nchild-body\nparent-complete\n'
            if case == 'log-failure':
                expected = expected.replace('after-exec-fallback', 'during-log-failure\nafter-exec-fallback')
            logs = list(directory.glob('diagnostics-*.log'))
            identities = [json.loads(p.read_text()) for p in directory.glob('diagnostics-*.json')]
            assert logs and identities and all(m['process_start_ticks'] is not None for m in identities)
            assert not (directory/'unsafe-persistent-fd.log').exists(), 'QEMU bypassed the diagnostic sink'
            assert any('IN:' in p.read_text() for p in logs), 'requested QEMU diagnostics were lost'
            assert any('uncaught target signal 11' in p.read_text() for p in logs) == (case=='crash')
            assert any(m['write_failures_including_fork_prefix'] for m in identities) == (case=='log-failure')
            checks.append(dict(case=case, stdout_exact=stdout==expected, expected_stdout=expected,
                wait_status=int.from_bytes((directory/'wait-status.bin').read_bytes(),'little')))
        artifacts[str(harness.relative_to(workspace_root))] = hashlib.sha256(harness.read_bytes()).hexdigest()
        assert all(hashlib.sha256((workspace_root/p).read_bytes()).hexdigest()==h for p,h in hashes.items()), 'source changed'
        assert all(c['stdout_exact'] for c in checks), 'host diagnostic contamination; see original stdout and receipt'
        status = 'passed'
    finally:
        (out/'receipt.json').write_text(json.dumps(dict(status=status, checks=checks, source_hashes=hashes,
            artifact_hashes=artifacts, budget_remaining=budget.remaining(cleanup=True),
            baseline=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()),indent=2))
        (out/'cleanup.json').write_text(json.dumps(builder.cleanup_records,indent=2))
    print(json.dumps(dict(status=status, receipt=str(out/'receipt.json'))))


if __name__ == '__main__':
    main()
