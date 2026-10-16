"""Build a private image with vendored dependencies and four native harnesses.

Only framework/dependency inputs enter the context. Build in one native
container, stream image transfer between local engines, and keep receipts.
Resource limits are optional settings supplied by the caller.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / 'src'))
from fmst_analyzer.runner.task.runtime_inputs import source_identity


def context(stream, payload=None):
    with tarfile.open(fileobj=stream, mode='w|', format=tarfile.GNU_FORMAT) as archive:
        dockerfile = 'Dockerfile.runtime-payload' if payload else 'Dockerfile.runtime'
        archive.add(Path(__file__).with_name(dockerfile), arcname='Dockerfile')
        if payload:
            archive.add(payload, arcname='payload')


def copy(cli, container, source, destination, *, exclude=()):
    with subprocess.Popen(cli + ['cp', '-a', '-', container + ':/'], stdin=subprocess.PIPE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as p:
        def select(info):
            if any(x in exclude for x in Path(info.name).parts):
                return None
            return info
        with tarfile.open(fileobj=p.stdin, mode='w|') as archive:
            archive.add(source, arcname=destination.lstrip('/'), filter=select)
        p.stdin.close()
        error = p.stderr.read().decode(errors='replace')
        if p.wait():
            raise RuntimeError('Runtime input copy failed: ' + error)


BUILD = r'''
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys
base=Path('/opt/guestweave');fw=base/'workspace/GuestWeave'
sys.path.insert(0,str(fw/'tools'))
from offline import extract
from build_runtime_bundle import build_bundle
config=base/'workspace/.cargo/config.toml';config.parent.mkdir(exist_ok=True)
config.write_text('[source.crates-io]\nreplace-with="runner-vendor"\n[source.runner-vendor]\ndirectory="/opt/guestweave/vendor"\n')
env=os.environ.copy()
for k in list(env):
 if k.lower() in {'http_proxy','https_proxy','all_proxy'}:env.pop(k)
env.pop('CARGO_BUILD_JOBS',None)
if len(sys.argv)>1:env['CARGO_BUILD_JOBS']=sys.argv[1]
env.update(RUSTUP_TOOLCHAIN='1.98.0',CARGO_NET_OFFLINE='true',PIP_NO_INDEX='1')
metadata=json.loads((base/'runtime.json').read_text());metadata['harnesses']={}
for arch,package,features in [('arm','fmst-harness-arm',[]),('mipsel','fmst-harness-mips',[]),('mipsbe','fmst-harness-mips',['--no-default-features','--features','big-endian']),('x86_64','fmst-harness-x86',[])]:
 print('BUILD '+arch,flush=True)
 work=Path('/build')/arch;work.mkdir(parents=True)
 for n in ('qemu','libvharness'):extract(base/'sources'/(n+'.tar.gz'),work/n)
 env.update(LIBAFL_QEMU_DIR=str(work/'qemu'),VHARNESS_DIR=str(work/'libvharness'))
 command=['cargo','build','--offline','--locked','--release','--target-dir',str(work/'target'),'-p',package,*features]
 subprocess.run(command,cwd=fw,env=env,check=True)
 harness=work/'target/release'/package;bundle=base/'runtime'/arch
 build_bundle(harness,bundle,binaries={})
 metadata['harnesses'][arch]={'path':str(bundle/package),'sha256':hashlib.sha256((bundle/package).read_bytes()).hexdigest()}
 subprocess.run([str(bundle/package),'--help'],env=env,stdout=subprocess.DEVNULL,check=True)
 shutil.rmtree(work)
 print('READY '+arch,flush=True)
(base/'runtime.json').write_text(json.dumps(metadata,indent=2)+'\n')
'''


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tag', default='firmenstein/runner-agent:py312-runtime')
    parser.add_argument('--base-image', default='firmenstein/runner-agent:py312-ida-private')
    parser.add_argument('--build-engine', default=os.getenv('DOCKER_HOST') or 'unix:///var/run/docker.sock')
    parser.add_argument('--engine', default=os.getenv('FMST_RUNNER_DOCKER_HOST'))
    parser.add_argument('--delivery', type=Path, default=os.getenv('FMST_RUNNER_RUNTIME_INPUTS'))
    parser.add_argument('--memory', help='Optional Docker memory limit, e.g. 8g; disables swap when set')
    parser.add_argument('--cpus', type=float, help='Optional Docker CPU limit')
    parser.add_argument('--pids-limit', type=int, help='Optional Docker process limit')
    parser.add_argument('--jobs', type=int, help='Optional Cargo build parallelism')
    parser.add_argument('--min-free-gib', type=float, help='Optional free-space requirement on the output filesystem')
    args = parser.parse_args(argv)
    if not args.engine or not args.engine.strip():
        parser.error('Configure FMST_RUNNER_DOCKER_HOST or pass --engine for the task engine')
    if args.delivery is None:
        parser.error('Configure FMST_RUNNER_RUNTIME_INPUTS or pass --delivery with a verified offline delivery; see docker/runner-agent/README.md')
    try:
        args.delivery = args.delivery.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        parser.error('--delivery must name an existing offline delivery directory')
    if not args.delivery.is_dir() or not (args.delivery / 'DELIVERY.json').is_file():
        parser.error('--delivery must contain DELIVERY.json; prepare the offline inputs first')
    for name in ('cpus', 'pids_limit', 'jobs'):
        value = getattr(args, name)
        if value is not None and value <= 0:
            parser.error('--' + name.replace('_', '-') + ' must be positive')
    if args.min_free_gib is not None and args.min_free_gib < 0:
        parser.error('--min-free-gib must be non-negative')
    return args


def build_container_command(cli, container, tooling, args):
    command = cli + ['create', '--name', container]
    if args.memory is not None:
        command += ['--memory', args.memory, '--memory-swap', args.memory]
    if args.cpus is not None:
        command += ['--cpus', str(args.cpus)]
    if args.pids_limit is not None:
        command += ['--pids-limit', str(args.pids_limit)]
    return command + ['--network', 'none', '--entrypoint', '/bin/sleep', tooling, 'infinity']


def main():
    sys.dont_write_bytecode = True
    from dotenv import load_dotenv
    load_dotenv(PROJECT / '.env')
    args = parse_args()
    from fmst_analyzer.global_config import GlobalConfig
    from fmst_analyzer.framework import runtime_workspace
    framework = runtime_workspace(GlobalConfig())
    delivery = args.delivery
    # Verify the complete vendored delivery before using its source archives.
    sys.path.insert(0, str(framework / 'tools'))
    spec = importlib.util.spec_from_file_location('runtime_offline', framework / 'tools/offline.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    delivery_receipt = module.verify(delivery)
    pins = json.loads((framework / 'dependencies/linux-runtime.json').read_text())['sources']
    records = delivery_receipt['sources']
    for n in ('qemu','libvharness'):
        if any(pins[n][k] != records[n][k] for k in ('repository','commit')):
            raise ValueError('Native source pin mismatch: '+n)
    args.output.mkdir(parents=True, exist_ok=False)
    if args.min_free_gib is not None and shutil.disk_usage(args.output).free < args.min_free_gib * 1024**3:
        raise RuntimeError(f'Runtime preparation needs the requested {args.min_free_gib:g} GiB free on the output filesystem')
    helper_spec=importlib.util.spec_from_file_location('private_builder',Path(__file__).with_name('build-private-image.py'))
    helper=importlib.util.module_from_spec(helper_spec);helper_spec.loader.exec_module(helper)
    cli=['docker','--host',args.build_engine];destination=['docker','--host',args.engine]
    container='fmst-runtime-dependencies-'+str(os.getpid());began=time.time()
    log=args.output/'build.log'
    with log.open('wb') as out:
        os.chmod(log,0o600)
        base_id=subprocess.check_output(destination+['image','inspect',args.base_image,'--format','{{.Id}}'],text=True).strip()
        present=subprocess.run(cli+['image','inspect',args.base_image,'--format','{{.Id}}'],capture_output=True,text=True)
        if present.returncode or present.stdout.strip()!=base_id:helper.transfer_image(destination,cli,args.base_image,out)
        tooling=args.tag+'-tooling'
        with subprocess.Popen(cli+['build','--target','tooling','--build-arg','RUNNER_BASE_IMAGE='+args.base_image,'-t',tooling,'-'],stdin=subprocess.PIPE,stdout=out,stderr=out) as p:
            context(p.stdin);p.stdin.close()
            if p.wait():raise RuntimeError('Tooling image build failed; see '+str(log))
        subprocess.run(build_container_command(cli,container,tooling,args),check=True,stdout=out,stderr=out)
        try:
            subprocess.run(cli+['start',container],check=True,stdout=out,stderr=out)
            copy(cli,container,framework,'/opt/guestweave/workspace/GuestWeave',exclude=('.git','target','__pycache__'))
            copy(cli,container,framework.parent/'lib/LibAFL','/opt/guestweave/workspace/lib/LibAFL',exclude=('.git','target','__pycache__'))
            copy(cli,container,delivery/'vendor','/opt/guestweave/vendor')
            for n in ('qemu','libvharness'):copy(cli,container,delivery/'sources'/(n+'.tar.gz'),'/opt/guestweave/sources/'+n+'.tar.gz')
            metadata={'schema_version':1,'framework_source_id':source_identity(framework),'libafl_source_id':source_identity(framework.parent/'lib/LibAFL'),'sources':{n:records[n] for n in ('qemu','libvharness')},'build_network':'none','base_image_id':base_id,'offline_delivery_id':delivery_receipt['delivery_id']}
            subprocess.run(cli+['exec','-i',container,'python','-c',"import sys,pathlib;p=pathlib.Path('/opt/guestweave/runtime.json');p.write_text(sys.stdin.read())"],input=json.dumps(metadata).encode(),check=True,stdout=out,stderr=out)
            build_command = cli+['exec',container,'python','-c',BUILD]
            if args.jobs is not None:build_command.append(str(args.jobs))
            subprocess.run(build_command,check=True,stdout=out,stderr=out)
            payload=args.output/'payload';payload.mkdir()
            subprocess.run(cli+['cp',container+':/opt/guestweave/.',str(payload)],check=True,stdout=out,stderr=out)
            with subprocess.Popen(cli+['build','--network','none','--build-arg','RUNNER_TOOLING_IMAGE='+tooling,'-t',args.tag,'-'],stdin=subprocess.PIPE,stdout=out,stderr=out) as p:
                context(p.stdin,payload);p.stdin.close()
                if p.wait():raise RuntimeError('Runtime image assembly failed; see '+str(log))
            if args.engine != args.build_engine:helper.transfer_image(cli,destination,args.tag,out)
            image_id=subprocess.check_output(destination+['image','inspect',args.tag,'--format','{{.Id}}'],text=True).strip()
            receipt={'status':'built','tag':args.tag,'image_id':image_id,'elapsed_seconds':time.time()-began,'runtime':json.loads((payload/'runtime.json').read_text()),'build_log':str(log),'private_ida_base_preserved':True,'pushed':False,
                     'build_options':{key:getattr(args,key) for key in ('memory','cpus','pids_limit','jobs','min_free_gib')}}
            (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
            # Payload is in the private image; avoid keeping a second source/vendor copy.
            shutil.rmtree(payload)
        finally:
            subprocess.run(cli+['rm','-f',container],stdout=out,stderr=out)
    print(json.dumps(receipt))


if __name__=='__main__':
    main()
