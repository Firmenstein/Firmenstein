"""Lazy, restartable native analysis process; IDA cannot exit the Agent worker."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from .common import TASK, clean_environment


class AnalysisClient:
    def __init__(self, task_root: Path = TASK):
        self.root = task_root
        self.process = None
        self.lock = asyncio.Lock()
        self.log_path = None

    async def call(self, name: str, arguments: dict):
        async with self.lock:
            if self.process is None or self.process.returncode is not None:
                self.log_path = self.root / 'evidence' / f'analysis-backend-{time.time_ns()}.log'
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self.process = await asyncio.create_subprocess_exec(
                    sys.executable, '-m', __name__, str(self.root), str(self.log_path),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, env=clean_environment())
            process = self.process
            try:
                process.stdin.write((json.dumps({'name': name, 'arguments': arguments}) + '\n').encode())
                await process.stdin.drain()
                line = await process.stdout.readline()
                if not line:
                    code = await process.wait()
                    raise RuntimeError(f'Analysis backend exited {code}; log: {self.log_path}. Other evidence tools remain usable; repair and retry.')
                reply = json.loads(line)
                if 'error' in reply:
                    raise RuntimeError(f"{reply['error']}; analysis log: {self.log_path}. Repair and retry in this session.")
                return json.loads(Path(reply['result_path']).read_text())
            except (BrokenPipeError, ConnectionResetError):
                await process.wait()
                raise RuntimeError(f'Analysis backend disconnected; log: {self.log_path}. Retry after repair.')

    async def close(self):
        if self.process is not None and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()


def semantic_tools(client: AnalysisClient):
    from fmst_basic.agent.tool import AgentTool, tool
    from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import make_analyzer_tools
    # Tool definitions do not access the view; only the child owns its instance.
    definitions = make_analyzer_tools(None)
    result = []
    for definition in definitions:
        if definition.name == 'evaluate_integer_cases':
            result.append(definition)
            continue
        def bind(name):
            async def invoke(**arguments):
                return await client.call(name, arguments)
            return invoke
        result.append(AgentTool(name=definition.name, description=definition.description,
            args_schema=definition.args_schema, coroutine=bind(definition.name)))

    @tool
    async def onboard_binary(path: str) -> str:
        """Analyze a firmware ELF or library with IDA in the private analysis process.

        Extends the analysis graph and exports semantic C/assembly when available.
        Can start from a missing topology. Failures affect this operation only;
        repair dependencies and retry without restarting the Agent.
        Args:
            path: Firmware-absolute ELF path, such as /usr/bin/service.cgi.
        """
        return await client.call('onboard_binary', {'path': path})
    return result + [onboard_binary]


async def serve(task_root: Path, log_path: Path):
    # C/native stdout as well as Python logs must not corrupt the RPC stream.
    reply_stream = os.fdopen(os.dup(sys.stdout.fileno()), 'w', buffering=1)
    with log_path.open('a') as log:
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
    view = None
    task = json.loads((task_root / 'task.json').read_text())
    for line in sys.stdin:
        try:
            request = json.loads(line)
            name, args = request['name'], request['arguments']
            from .analysis import load_view
            if view is None:
                view = load_view(task, task_root=task_root, bootstrap_path=args.get('path') if name == 'onboard_binary' else None)
            if name == 'onboard_binary':
                from ..rootfs_actions import _guest_host_path
                binary = view.lib_dep_graph.add_binary(_guest_host_path(task_root / 'work/rootfs', args['path'], follow_final_symlink=True))
                await view.lib_dep_graph.decompile_analysis(binary)
                result = json.dumps({'binary': binary.name, 'semantic_ready': binary.semantic_ready,
                    'analysis_root': str(task_root / 'analysis')})
            elif name == 'map_trace':
                from ..trace_context import persist_runtime_trace_context
                context, _ = persist_runtime_trace_context(Path(args['trace_path']), Path(args['output']), view,
                    executed_binary_hashes=args.get('executed_binary_hashes'))
                result = str(context)
            else:
                from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import make_analyzer_tools
                tools = {item.name: item for item in make_analyzer_tools(view)}
                result = await tools[name].ainvoke(args)
            from .common import write_json
            import uuid
            result_path = task_root / 'evidence/analysis-results' / (uuid.uuid4().hex + '.json')
            write_json(result_path, result)
            reply = {'result_path': str(result_path)}
        except Exception as error:
            import traceback
            traceback.print_exc()
            reply = {'error': f'{type(error).__name__}: {error}'}
        reply_stream.write(json.dumps(reply) + '\n')


if __name__ == '__main__':
    asyncio.run(serve(Path(sys.argv[1]), Path(sys.argv[2])))
