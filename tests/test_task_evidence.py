"""Regressions for container evidence routing and optional native analysis."""
import asyncio
import json
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.task.execution import create_execution, update_execution, select_execution, finish_execution
from fmst_analyzer.runner.task.tools import make_evidence_tools
from fmst_analyzer.runner.task.trace_query import query_trace
from fmst_analyzer.runner.trace_files import trace_inventory


class UnavailableAnalysis:
    async def call(self, *args):
        raise RuntimeError('IDA fixture unavailable')


def task_tools(root):
    (root / 'work/rootfs').mkdir(parents=True, exist_ok=True)
    (root / 'evidence').mkdir(exist_ok=True)
    return {item.name: item for item in make_evidence_tools({'target':'httpd'}, UnavailableAnalysis(), task_root=root)}


def process_trace(path, text='openat(path=/dev/config) -> -2', pid=17):
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {'schema_version': 6, 'host_pid': pid, 'origin_pid': 1,
        'image_loads': [{'kind':'image_load','detail':'httpd@0x4000'}],
        'dropped_events': 3, 'events': [{'sequence':1,'last_sequence':4,'repeat_count':4,
            'kind':'syscall_result','detail':text,'pc':123,'elapsed_ns':10,'last_elapsed_ns':40}]}
    path.write_text(json.dumps(value))
    return value


def test_nested_process_traces_remain_scoped_to_execution_and_exclude_derived(tmp_path):
    tools = task_tools(tmp_path)
    first = create_execution({'rootfs':str(tmp_path/'work/rootfs')}, task_root=tmp_path)
    first_trace = first.parent/'runtime/child/runtime_trace.json'
    process_trace(first_trace)
    process_trace(first.parent/'runtime/runtime-trace-views/runtime_trace-copy.json')
    result = json.loads(tools['view_runtime_trace_files'].invoke({}))
    assert result['total'] == 1 and result['traces'][0]['path'] == str(first_trace)
    second = create_execution({'rootfs':str(tmp_path/'work/rootfs')}, task_root=tmp_path)
    assert json.loads(tools['view_runtime_trace_files'].invoke({}))['total'] == 0
    assert json.loads(tools['view_runtime_trace_files'].invoke({'execution_path':str(first)}))['total'] == 1
    assert select_execution(tmp_path)[0] == second


def test_raw_events_and_exported_code_work_when_ida_fails(tmp_path):
    tools = task_tools(tmp_path)
    path = tmp_path/'custom/runtime_trace.json'
    original = process_trace(path)
    query = json.loads(tools['query_runtime_events'].invoke({'trace_path':str(path),'syscall_name':'openat','sequence_start':3}))
    assert query['total'] == 1 and query['capture']['dropped_events'] == 3
    assert json.loads(Path(query['query_path']).read_text())['events'] == original['events']
    assert 'events' not in query
    with pytest.raises(RuntimeError, match='IDA fixture'):
        tools['query_runtime_events'].invoke({'trace_path':str(path),'static_ea':123})
    assert json.loads(tools['query_runtime_events'].invoke({'trace_path':str(path)}))['total'] == 1
    code = tmp_path/'export.c';code.write_text('int main() { return 0; }\n')
    assert json.loads(tools['read_analysis_artifact'].invoke({'path':str(code)}))['lines'] == [code.read_text().strip()]
    assert json.loads(tools['inspect_runtime_core'].invoke({}))['collection']['status'] == 'not_collected'


def test_checkpoint_change_cannot_mix_query_pages(tmp_path):
    path = tmp_path/'runtime_trace.json';original = process_trace(path)
    result = query_trace(path, tmp_path/'queries')
    path.write_text('{"events":[]}')
    with pytest.raises(ValueError, match='source_changed'):
        query_trace(path,tmp_path/'queries', source_sha256=result['source_sha256'])
    assert json.loads(Path(result['checkpoint_path']).read_text()) == original


def test_same_trace_basename_in_child_directories_retains_own_diagnostics(tmp_path):
    for name in ['a','b']:
        p=tmp_path/name/'runtime_trace.json';process_trace(p)
        (p.parent/'diagnostics-test.json').write_text(json.dumps({'trace_path':str(p)}))
    result=trace_inventory(tmp_path,recursive=True)
    assert len(result['traces']) == 2
    for record in result['traces']:
        assert Path(record['diagnostic_paths'][0]).parent == Path(record['path']).parent


def test_log_default_changes_with_firmware_and_explicit_paths_work(tmp_path):
    tools=task_tools(tmp_path)
    old=create_execution({'rootfs':str(tmp_path/'work/rootfs')},task_root=tmp_path)
    old_log=old.parent/'service.log';old_log.write_text('old firmware\n')
    update_execution(old,log_paths=[{'path':str(old_log),'role':'firmware'}])
    assert 'old firmware' in tools['view_container_log'].invoke({})
    new=create_execution({'rootfs':str(tmp_path/'work/rootfs')},task_root=tmp_path)
    new_log=new.parent/'service.log';new_log.write_text('new firmware\n')
    proxy=new.parent/'proxy.log';proxy.write_text('proxy\n')
    update_execution(new,log_paths=[{'path':str(new_log),'role':'firmware'},{'path':str(proxy),'role':'proxy'}])
    assert 'new firmware' in tools['view_container_log'].invoke({})
    assert 'old firmware' not in tools['view_container_log'].invoke({})
    assert 'proxy' in tools['view_container_log'].invoke({'path':str(proxy)})


def test_unregistered_log_does_not_claim_no_execution(tmp_path):
    tools=task_tools(tmp_path)
    result=json.loads(tools['view_container_log'].invoke({}))
    assert result['status']=='log_selection_required'
    assert 'does not mean' in result['notice']


def test_semantic_tool_catalog_does_not_start_native_runtime(tmp_path, monkeypatch):
    from fmst_analyzer.runner.task.analysis_rpc import semantic_tools
    from fmst_analyzer.runner.task import analysis
    monkeypatch.setattr(analysis,'load_view',lambda *a,**k:pytest.fail('Catalog must not initialize IDA'))
    tools={item.name:item for item in semantic_tools(UnavailableAnalysis())}
    assert 'view_function' in tools and 'onboard_binary' in tools
    assert tools['view_function'].args_schema.model_json_schema()['properties']['binary_name']
    with pytest.raises(RuntimeError,match='IDA fixture'):
        tools['view_function'].invoke({'binary_name':'httpd','function_name':'main'})


def test_runtime_core_accepts_explicit_file_without_fake_execution_identity(tmp_path, monkeypatch):
    from fmst_analyzer.runner.core_inspection import inspect_core
    core=tmp_path/'x.core'
    core.write_bytes(b'\x7fELF\x01\x01\x01'+bytes(9)+struct.pack('<HHIIIIIHHHHHH',4,40,1,0,52,0,0,52,32,0,0,0,0))
    monkeypatch.setattr('fmst_analyzer.runner.core_inspection.shutil.which',lambda _: '/fixture/gdb')
    monkeypatch.setattr('fmst_analyzer.runner.core_inspection.subprocess.run',lambda cmd,**kw: subprocess.CompletedProcess(cmd,0,'registers',''))
    result=inspect_core(None,core_path=core,output_root=tmp_path)
    assert result['target_pid'] is None and 'not inferred' in result['association']
    assert result['stdout']=='registers'


def test_finished_core_collection_does_not_adopt_later_execution_files(tmp_path):
    task_tools(tmp_path)
    path=create_execution({'rootfs':str(tmp_path/'work/rootfs')},task_root=tmp_path)
    finish_execution(path,0)
    (tmp_path/'work/rootfs/later.core').write_bytes(b'not a core')
    finish_execution(path,0)
    result=json.loads((path.parent/'core-collection.json').read_text())
    assert result['terminal'] and result['status']=='no_core_found' and not result['errors']


@pytest.mark.parametrize('core_pid,expected', [(7,'process_trace'),(8,'unverified')])
def test_primary_crash_before_first_trace_events_uses_launch_and_pid(tmp_path,monkeypatch,core_pid,expected):
    from fmst_analyzer.runner.task.cores import collect_cores
    task_tools(tmp_path)
    path=create_execution({'rootfs':str(tmp_path/'work/rootfs'),'executable':'/server'},task_root=tmp_path)
    (path.parent/'runtime/runtime_trace.json').write_text(json.dumps({'host_pid':7,'events':[],
        'guest_arch':'arm','byte_order':'little','word_bits':32}))
    (tmp_path/'work/rootfs/crash.core').write_bytes(b'\x7fELF\x01\x01\x01'+bytes(9)+struct.pack('<HH',4,40))
    monkeypatch.setattr('fmst_analyzer.runner.runtime_dump._core_identity',lambda p:{'pid':core_pid,'executable':'/server','tids':[core_pid],'errors':[]})
    monkeypatch.setattr('fmst_analyzer.runner.task.cores.shutil.disk_usage',lambda p:SimpleNamespace(free=128*1024**3))
    result=collect_cores(path)
    assert result['cores'][0]['association']==expected


def test_materials_follow_live_analysis_and_include_peer_reports(tmp_path,monkeypatch):
    from fmst_analyzer.runner.task import materials
    rootfs=tmp_path/'rootfs';rootfs.mkdir()
    actual=tmp_path/'actual';selected=tmp_path/'selected/httpd';selected.mkdir(parents=True)
    for name in ['graph_cache','decompiled_code','disassembled_code','decompiler_db','diagnostic_reports/cgi']:
        p=actual/name;p.mkdir(parents=True);(p/'fixture').write_text('retained')
    copies=[];published=[]
    monkeypatch.setattr(materials,'copy_tree',lambda container,source,dest,**kw:copies.append((source,dest)))
    monkeypatch.setattr(materials,'docker',lambda *a,**k:None)
    config=SimpleNamespace(current_target='httpd',workdir=tmp_path/'wrong')
    source=SimpleNamespace(workdir=actual,fw_rootfs_path=rootfs,decompiler_db_dir=actual/'decompiler_db')
    view=SimpleNamespace(global_config=source,lib_dep_graph=SimpleNamespace(get_nodes=lambda:[]))
    task=SimpleNamespace(name='fixture',output=tmp_path,put_json=lambda p,v:published.append(v))
    result=materials.package_analysis(task,config=config,view=view,reports=selected,rootfs=rootfs,rootfs_sha256='identity')
    assert (actual/'graph_cache','/task/analysis/graph_cache') in copies
    assert result['report_paths']['cgi']=='/task/input/firmware-reports/cgi'
    assert result['report_paths']['httpd']=='/task/input/reports'
    assert all('wrong' not in str(source) for source,_ in copies)


def test_early_exec_crash_uses_transition_and_not_fork_prefix(tmp_path,monkeypatch):
    from fmst_analyzer.runner.task.cores import collect_cores
    task_tools(tmp_path)
    path=create_execution({'rootfs':str(tmp_path/'work/rootfs'),'executable':'/server'},task_root=tmp_path)
    runtime=path.parent/'runtime'
    process_trace(runtime/'runtime_trace.pid-7.json',pid=7)
    child=runtime/'runtime_trace.exec-1.pid-7.json'
    child.write_text(json.dumps({'host_pid':7,'events':[]}))
    (runtime/'runtime_trace.exec-1.pid-7.transition.json').write_text(json.dumps({
        'child_trace':'/fmst-output/'+child.name,'status':'started','host_pid':7,'request':{'pathname':'/child'}}))
    (tmp_path/'work/rootfs/crash.core').write_bytes(b'\x7fELF\x01\x01\x01'+bytes(9)+struct.pack('<HH',4,40))
    monkeypatch.setattr('fmst_analyzer.runner.runtime_dump._core_identity',lambda p:{'pid':7,'executable':'/child','tids':[7],'errors':[]})
    monkeypatch.setattr('fmst_analyzer.runner.task.cores.shutil.disk_usage',lambda p:SimpleNamespace(free=128*1024**3))
    result=collect_cores(path)
    assert result['cores'][0]['association']=='process_trace'
    assert result['cores'][0]['trace_path']==str(child)


def test_cross_arch_core_does_not_launch_native_only_gdb(tmp_path,monkeypatch):
    from fmst_analyzer.runner.core_inspection import inspect_core
    core=tmp_path/'arm.core'
    core.write_bytes(b'\x7fELF\x01\x01\x01'+bytes(9)+struct.pack('<HHIIIIIHHHHHH',4,40,1,0,52,0,0,52,32,0,0,0,0))
    monkeypatch.setattr('platform.machine',lambda:'x86_64')
    monkeypatch.setattr('fmst_analyzer.runner.core_inspection.shutil.which',lambda name:None if name=='gdb-multiarch' else '/fixture/gdb')
    monkeypatch.setattr('fmst_analyzer.runner.core_inspection.subprocess.run',lambda *a,**k:pytest.fail('Wrong-architecture GDB must not be launched'))
    result=inspect_core(None,core_path=core,output_root=tmp_path)
    assert result['status']=='unavailable' and 'gdb-multiarch' in result['error']


def test_material_path_resolution_preserves_input_and_working_paths(tmp_path):
    from fmst_analyzer.runner.task.materials import resolve_material_path
    index=tmp_path/'materials.json';index.write_text(json.dumps({'materials':[
        {'source_path':'/old/root','container_path':'/task/input/rootfs','working_path':'/task/work/rootfs','status':'included'},
        {'source_path':'/old/root/code','container_path':'/task/analysis/decompiled_code','status':'included'}]}))
    assert resolve_material_path('/old/root/etc/config',index)['working_path']=='/task/work/rootfs/etc/config'
    assert resolve_material_path('/old/root/code/main.c',index)['container_path']=='/task/analysis/decompiled_code/main.c'
