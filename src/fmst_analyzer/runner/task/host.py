"""Host lifecycle for one private task container; no firmware repair decisions."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tarfile
import time
import uuid
import gzip
import shutil
import socket
from pathlib import Path

from .common import write_json
from .schema import TaskResult, TaskResultV1, ServiceCompletion, read_result
from .options import ContainerResources, RunnerOptions

LABEL = "org.firmenstein.runner-task"


def docker_argv(*args):
    endpoint = os.getenv("FMST_RUNNER_DOCKER_HOST", os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock"))
    return ["docker", "--host", endpoint, *args]


def render_result(result: TaskResult, *, engine_endpoint: str = "unix:///var/run/docker.sock") -> str:
    report = Path(result.report_dir) / "result.json"
    lines = ["# Runner task", "", f"- backend: {result.backend}", f"- task_id: {result.task_id}",
             f"- target: {result.target}", f"- status: {result.status}", f"- reason: {result.reason}",
             f"- container_id: {result.container_id}", "- independent_replay: false"]
    lines += [f"- docker_engine: {engine_endpoint}",
              f"- container_shell: docker --host {engine_endpoint} exec -it {result.container_id} bash"]
    if isinstance(result, TaskResult):
        lines += [f"- agent_phase: {result.agent_phase}", f"- handoff_status: {result.handoff_status}",
                  f"- package_status: {result.package_status}", f"- package_path: {result.package_path}",
                  f"- runner_options: {Path(result.report_dir) / 'runner-options.json'}"]
    if result.completion:
        lines += ["", result.completion.summary, "", result.completion.access, "", "## Native interactions", ""]
        lines += [f"- {item.operation}: {item.observed}" for item in result.completion.interactions]
        lines += ["", "## Limitations", "", *[f"- {x}" for x in result.completion.limitations]]
    if result.socks_proxy:
        lines += ["", f"Native-origin SOCKS proxy: `{result.socks_proxy}` (enable remote DNS)."]
    lines += ["", "Lifecycle commands:", "", "```sh", *[
        f"python -m fmst_analyzer.runner.task.host {action} {report}" for action in ("status", "logs", "stop")], "```"]
    return "\n".join(lines) + "\n"


def docker(*args: str, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(docker_argv(*args), capture_output=True, **kwargs)
    if result.returncode:
        stderr = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        error = RuntimeError(f"Docker {args[0]} exited {result.returncode}: {stderr}")
        error.process_result = result
        raise error
    return result


def copy_tree(container: str, source: Path, destination: str, *, exclude=()) -> None:
    """Stream a private copy; do not mount host input or follow firmware symlinks."""
    with subprocess.Popen(docker_argv("cp", "-a", "-", f"{container}:/"), stdin=subprocess.PIPE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as process:
        try:
            with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                def select(info):
                    parts = Path(info.name).parts
                    if any(part in exclude for part in parts):
                        return None
                    return info
                archive.add(source, arcname=destination.lstrip("/"), filter=select)
        finally:
            process.stdin.close()
        error = process.stderr.read().decode(errors="replace")
        if process.wait() != 0:
            raise RuntimeError(f"Container copy failed: {error}")


class ContainerTask:
    def __init__(self, *, output: Path, target: str, image: str,
                 budget_seconds: float = 7200, capability_probe: bool = False,
                 delivery_mode: str = "full", resources: ContainerResources | None = None):
        if budget_seconds <= 0:
            raise ValueError("budget_seconds must be positive")
        options = RunnerOptions(delivery_mode=delivery_mode, resources=resources)
        self.delivery_mode = options.delivery_mode
        self.resource_limits = options.resources
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.task_id = uuid.uuid4().hex
        self.name = f"fmst-task-{self.task_id}"
        self.image = image
        self.budget_seconds = budget_seconds
        self.capability_probe = capability_probe
        self.relays = []
        write_json(self.output / "docker-engine.json", {"endpoint": docker_argv()[2]})
        write_json(self.output / "runner-options.json", options.model_dump(mode="json"))
        self.result = TaskResult(task_id=self.task_id, target=target, status="preparing",
                                 started_at=time.time(), report_dir=str(self.output))
        self.persist()

    def persist(self):
        write_json(self.output / "result.json", self.result.model_dump(mode="json"))
        (self.output / "index.md").write_text(render_result(self.result, engine_endpoint=docker_argv()[2]))

    def create(self):
        import fcntl
        # Serialize container creation; batch concurrency and host admission
        # are selected and enforced by the caller.
        lock = Path(__file__).resolve().parents[4] / ".fmst/runner-task-launch.lock"
        lock.parent.mkdir(parents=True, exist_ok=True)
        with lock.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            self._create()

    def _create(self):
        info = json.loads(docker("info", "--format", "{{json .}}", text=True).stdout)
        security = info["SecurityOptions"]
        if "name=userns" not in security:
            raise RuntimeError("Runner requires Docker userns-remap for a private task user namespace; configure FMST_RUNNER_DOCKER_HOST")
        limits = self.resource_limits.docker_arguments(info) if self.resource_limits else []
        self.result.session_volume = "fmst-sessions-" + self.task_id
        docker("volume", "create", "--label", f"{LABEL}={self.task_id}", self.result.session_volume)
        self.persist()
        created = docker("create", "--name", self.name, "--label", f"{LABEL}={self.task_id}",
            *limits, "--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE",
            "--cap-add", "NET_ADMIN", "--tmpfs", "/run:rw,nosuid,size=128m",
            "--mount", f"type=volume,source={self.result.session_volume},destination=/task/sessions",
            "--publish", "127.0.0.1::1080",
            "--log-driver", "local", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
            "--env", "PYTHONPATH=/opt/fmst/src", self.image, text=True).stdout.strip()
        self.result.container_id = created
        self.persist()
        src = Path(__file__).resolve().parents[3]
        for package in ("fmst_basic", "fmst_analyzer"):
            copy_tree(created, src / package, f"/opt/fmst/src/{package}",
                      exclude=("__pycache__", ".git", ".venv", "node_modules"))
        self.archive_source("execution-source.tar.gz")
        docker("start", created)
        docker("exec", created, "chmod", "-R", "a+rX", "/opt/fmst/src")
        docker("exec", created, "chown", "-R", "runner:runner", "/opt/fmst")
        # A small wait is only readiness, not a new Agent budget.
        for _ in range(100):
            ready = subprocess.run(docker_argv("exec", created, "test", "-d", "/task/control/replies"),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError("Runner init did not become ready")
        self.put_json("/run/fmst/lifecycle.json", {"status": "repairing", "agent_phase": "repairing",
                      "deadline": self.result.started_at + self.budget_seconds})

    def put_json(self, destination: str, data):
        self.put_file(destination, json.dumps(data).encode())

    def put_file(self, destination: str, data: bytes):
        # JSON is sent only on stdin. Secret values never enter argv, Docker
        # Config.Env, image layers, host receipts or logs.
        script = "import sys,pathlib,os;p=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.'+str(os.getpid())+'.tmp');f=t.open('wb');os.fchmod(f.fileno(),0o600);f.write(sys.stdin.buffer.read());f.close();t.replace(p)"
        docker("exec", "-i", self.name, "python", "-c", script, destination,
               input=data)

    def archive_source(self, filename):
        output = self.output / filename
        temporary = output.with_suffix(output.suffix + ".partial")
        with subprocess.Popen(docker_argv("cp", f"{self.name}:/opt/fmst/src", "-"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            with gzip.open(temporary, "wb", compresslevel=1) as archive:
                shutil.copyfileobj(process.stdout, archive)
            error = process.stderr.read().decode(errors="replace")
            if process.wait() != 0:
                raise RuntimeError(f"Execution source archive failed: {error}")
        temporary.replace(output)

    def configure(self, task: dict):
        self.put_json("/task/task.json", {**task, "task_id": self.task_id,
                                        "delivery_mode": self.delivery_mode,
                                        "resources": self.resource_limits.model_dump(mode="json") if self.resource_limits else None})
        self.configure_model()
        self.put_json("/run/fmst/lifecycle.json", {"status": "repairing", "agent_phase": "repairing",
                      "deadline": self.result.started_at + self.budget_seconds})
        docker("exec", self.name, "mkdir", "-p", "/task/sessions")
        docker("exec", self.name, "chown", "-R", "runner:runner", "/run/fmst",
               "/task/evidence", "/task/delivery", "/task/control", "/task/sessions")
        docker("exec", self.name, "chown", "runner:runner", "/task/task.json")
        # Model proxy/credentials stay out of native shell processes.
        docker("exec", self.name, "sh", "-c",
               "printf '%s\\n' 'unset ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY FMST_CLAUDE_AUTH_TOKEN FMST_CODEX_AUTH_TOKEN OPENAI_API_KEY HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy' > /opt/fmst/bash-env")
        self.result.status = "repairing"
        self.persist()

    def configure_model(self):
        """Supply current credentials on tmpfs, without changing the task Goal/state."""
        from fmst_basic.agent.config import (configured_claude_base_url, configured_claude_auth_token,
                                             configured_claude_model, configured_claude_reasoning_effort)
        token = configured_claude_auth_token()
        if not token:
            raise RuntimeError("Current pipeline model credential is missing")
        model_settings = {
            "FMST_CLAUDE_BASE_URL": configured_claude_base_url(),
            "FMST_CLAUDE_AUTH_TOKEN": token, "FMST_CLAUDE_MODEL": configured_claude_model(),
            "FMST_CLAUDE_REASONING_EFFORT": configured_claude_reasoning_effort(),
        }
        from .network import ProxyRelay, loopback_proxy
        info = json.loads(docker("inspect", self.name, text=True).stdout)[0]
        network = info["NetworkSettings"]["Networks"]["bridge"]
        security = json.loads(docker("info", "--format", "{{json .SecurityOptions}}", text=True).stdout)
        relayed = {}
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
            value = os.getenv(name)
            if not value:
                continue
            if name.lower() != "no_proxy" and loopback_proxy(value):
                if "name=rootless" in security:
                    from .network import rootless_proxy
                    model_settings[name] = rootless_proxy(value)
                    continue
                if value not in relayed:
                    relay = ProxyRelay(value, gateway=network["Gateway"], container_ip=network["IPAddress"])
                    self.relays.append(relay)
                    relayed[value] = relay.url
                value = relayed[value]
            model_settings[name] = value
        self.put_json("/run/fmst/model.json", model_settings)
        docker("exec", self.name, "chown", "runner:runner", "/run/fmst/model.json")

    def archive_session(self):
        """Save native history privately; the retained container stays intact."""
        import hashlib
        private = self.output / "private"
        private.mkdir(mode=0o700, exist_ok=True)
        private.chmod(0o700)
        output = private / "agent-sessions.tar.gz"
        temporary = private / "agent-sessions.partial.tar.gz"
        with subprocess.Popen(docker_argv("cp", f"{self.name}:/task/sessions", "-"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            with temporary.open("wb") as raw:
                os.fchmod(raw.fileno(), 0o600)
                with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1) as archive:
                    shutil.copyfileobj(process.stdout, archive)
            error = process.stderr.read().decode(errors="replace")
            if process.wait() != 0:
                raise RuntimeError(f"Native session archive failed: {error}")
        temporary.replace(output)
        with output.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        write_json(private / "session-retention.json", {
            "schema_version": 1, "container_session_dir": "/task/sessions/runner",
            "archive": str(output), "sha256": digest, "captured_at": time.time(),
            "scope": "private native history; no /run model credentials; not a user delivery package"})

    @classmethod
    async def resume_retained(cls, result_path: Path, message: str, timeout_seconds: float = 300):
        """Run an explicit follow-up in a retained session, preserving the original Goal result."""
        import fcntl
        if not message.strip() or not 0 < timeout_seconds <= 7200:
            raise ValueError("Resume needs a message and a timeout in (0, 7200] seconds")
        result_path = result_path.resolve()
        result = read_result(result_path.read_text())
        if result.container_removed or result.status != "serving":
            raise ValueError("Resume requires a retained serving task; archived tasks need environment restoration first")
        # Attach without creating a container or rewriting the original result.
        task = cls.__new__(cls)
        task.output, task.result = result_path.parent, result
        task.task_id, task.name, task.relays = result.task_id, result.container_id, []
        lock_path = Path(__file__).resolve().parents[4] / ".fmst/runner-task-launch.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a") as lock:
            # A short follow-up holds admission; existing tasks keep running.
            # This also prevents new launches from overlooking its model slot.
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = json.loads(docker("inspect", task.name, text=True).stdout)[0]
            if info["Config"]["Labels"].get(LABEL) != task.task_id or not info["State"]["Running"]:
                raise ValueError("Retained container identity is invalid or the container is stopped")
            live_worker = (
                "from pathlib import Path;import json;"
                "from fmst_analyzer.runner.task.common import process_identity;"
                "p=Path('/run/fmst/worker.json');w=json.loads(p.read_text()) if p.exists() else {};"
                "print(bool(w) and process_identity(w['pid'])==w['start_ticks'])")
            busy = docker("exec", task.name, "python", "-c", live_worker, text=True).stdout.strip() == "True"
            if busy:
                raise ValueError("The task already has a live Agent")
            docker("exec", task.name, "test", "-f", "/task/sessions/runner/session.json")
            followup = task.output / "private/resumes" / uuid.uuid4().hex
            followup.mkdir(mode=0o700, parents=True)
            request_path = "/task/sessions/followups/" + followup.name + ".txt"
            process = None
            status = "error"
            try:
                task.configure_model()
                task.put_file(request_path, message.encode())
                docker("exec", task.name, "chown", "runner:runner", request_path)
                with (followup / "worker.log").open("wb") as log:
                    process = await asyncio.create_subprocess_exec(*docker_argv(
                        "exec", "--user", "runner", "--env", "BASH_ENV=/opt/fmst/bash-env", task.name,
                        "python", "-m", "fmst_analyzer.runner.task.worker", "--resume-message", request_path),
                        stdout=log, stderr=asyncio.subprocess.STDOUT)
                    await asyncio.wait_for(process.wait(), timeout_seconds)
                    status = "completed" if process.returncode == 0 else "error"
            except asyncio.TimeoutError:
                status = "timeout"
            except asyncio.CancelledError:
                status = "cancelled"
                raise
            finally:
                try:
                    if process is not None:
                        task.stop_worker()
                        if process.returncode is None:
                            await asyncio.wait_for(process.wait(), 10)
                    subprocess.run(docker_argv("exec", task.name, "rm", "-f", "/run/fmst/model.json"),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    task.archive_session()
                    subprocess.run(docker_argv("cp", f"{task.name}:/task/evidence/resumes", str(followup)),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                finally:
                    for relay in task.relays:
                        relay.close()
                    write_json(followup / "result.json", {"status": status, "timeout_seconds": timeout_seconds,
                               "original_result": str(result_path), "finished_at": time.time()})
            return {"status": status, "report": str(followup / "result.json")}

    def collect(self):
        # Large traces remain in the retained task. Only completion, events and
        # path inventories are copied here; no recursive full-rootfs snapshots.
        for name in ("delivery", "evidence/worker-events.jsonl", "evidence/tool-events.jsonl"):
            destination = self.output / Path(name).name
            if name == "delivery":
                destination.mkdir(exist_ok=True)
                name += "/."
            subprocess.run(docker_argv("cp", f"{self.name}:/task/{name}", str(destination)),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if isinstance(self.result, TaskResult):
            path = self.output / "delivery/handoff-status.json"
            if path.exists():
                try:
                    status = json.loads(path.read_text())["status"]
                    if status not in {"not_started", "collecting", "ready", "invalid", "timeout", "error", "interrupted"}:
                        raise ValueError("Invalid handoff status")
                    self.result.handoff_status = status
                except (ValueError, KeyError, TypeError):
                    self.result.handoff_status = "error"
                    self.result.package_error = "Invalid handoff status record; original file retained"

    def reconcile_completion(self):
        """Check service identity even if the SDK exit raced the host deadline."""
        self.collect()
        stopped = self.output / "delivery/host-stop.json"
        if stopped.exists():
            self.result.status = json.loads(stopped.read_text())["status"]
            return False
        completed = self.output / "delivery/completion.json"
        if not completed.exists():
            return False
        completion = ServiceCompletion.model_validate_json(completed.read_text())
        check = docker("exec", self.name, "python", "-c",
            "from fmst_analyzer.runner.task.common import process_identity;import sys;print(process_identity(int(sys.argv[1])))",
            str(completion.service_pid), text=True).stdout.strip()
        if check != str(completion.service_start_ticks):
            raise RuntimeError("Declared service did not survive Agent exit")
        self.result.completion = completion
        self.result.status = "serving"
        self.result.socks_proxy = self.native_proxy()
        return True

    def native_proxy(self):
        ports = docker("port", self.name, "1080/tcp", text=True).stdout.strip()
        if not ports:
            return None
        address, port = ports.rsplit(":", 1)
        try:
            with socket.create_connection((address, int(port)), timeout=2) as stream:
                stream.sendall(b"\x05\x01\x00")
                if stream.recv(2) == b"\x05\x00":
                    return "socks5h://" + ports
        except OSError:
            pass
        return None

    def stop_worker(self):
        # Only the SDK worker and its children; init-owned service jobs are
        # siblings and survive. PID identities protect against reuse.
        docker("exec", self.name, "python", "-m", "fmst_analyzer.runner.task.worker_control")

    async def run(self):
        self.result.agent_phase = "repairing"
        self.persist()
        with (self.output / "worker.log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(*docker_argv("exec", "--user", "runner",
                "--env", "BASH_ENV=/opt/fmst/bash-env", self.name, "python", "-m",
                "fmst_analyzer.runner.task.worker"), stdout=log, stderr=asyncio.subprocess.STDOUT)
            try:
                remaining = max(.01, self.result.started_at + self.budget_seconds - time.time())
                await asyncio.wait_for(process.wait(), remaining + 5)
                if not self.reconcile_completion() and self.result.status == "repairing":
                    self.result.status = "error"
                    self.result.reason = f"Worker exited {process.returncode}; inspect worker.log and container evidence"
            except asyncio.TimeoutError:
                self.result.status = "budget_exhausted"
            except asyncio.CancelledError:
                self.result.status = "cancelled"
                raise
            except Exception as error:
                self.result.status = "error"
                self.result.reason = str(error)
            finally:
                # The success transition belongs to the worker before SDK exit,
                # then is checked here. A host timeout cannot kill a serving demo.
                try:
                    self.reconcile_completion()
                except Exception as error:
                    self.result.status = "error"
                    self.result.reason = str(error)
                if self.result.status != "serving":
                    self.stop(self.result.status)
                else:
                    try:
                        self.stop_worker()
                        self.reconcile_completion()
                    except Exception as error:
                        self.result.reason = str(error)
                        self.collect()
                        marker = self.output / "delivery/host-stop.json"
                        reason = json.loads(marker.read_text())["status"] if marker.exists() else "error"
                        self.stop(reason)
                    if not self.result.container_removed:
                        subprocess.run(docker_argv("exec", self.name, "rm", "-f", "/run/fmst/model.json"),
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if process.returncode is None:
                    await process.wait()
                if self.result.status == "serving" and not self.result.container_removed:
                    try:
                        self.apply_delivery_resource_limits()
                    except Exception as error:
                        message = "Post-Goal core resource limits failed: " + str(error)
                        if self.delivery_mode == "full":
                            self.result.package_status = "error"
                            self.result.package_error = message
                        else:
                            self.result.cleanup_error = message
                    try:
                        self.archive_session()
                    except Exception as error:
                        # History remains in the service container if backup fails.
                        self.result.cleanup_error = str(error)
                self.result.finished_at = time.time()
                self.result.agent_phase = "exited"
                for relay in self.relays:
                    relay.close()
                self.persist()
                if self.result.status == "serving":
                    if self.delivery_mode == "rehosting_only":
                        # Intentional omission, not an incomplete delivery.
                        # Completion, live service and private session retention
                        # have already been reconciled above.
                        self.result.package_status = "not_started"
                    elif self.result.package_error:
                        self.result.package_status = "error"
                    elif self.result.handoff_status == "ready":
                        self.result.package_status = "capturing"
                        self.persist()
                        try:
                            from .delivery_capture import capture
                            path = await asyncio.to_thread(capture, self)
                            manifest = json.loads((path / "delivery.json").read_text())
                            self.result.package_path = str(path)
                            self.result.package_status = manifest["capture"]["status"]
                        except Exception as error:
                            self.result.package_status = "error"
                            self.result.package_error = str(error)
                    else:
                        self.result.package_status = "incomplete"
                    self.persist()
        return self.result

    def apply_delivery_resource_limits(self):
        """Bound diagnostic dumps after the model exits; preserve service and old cores."""
        info = json.loads(docker("inspect", self.name, text=True).stdout)[0]
        if info["Config"]["Labels"].get(LABEL) != self.task_id or not info["State"]["Running"]:
            raise ValueError("Post-Goal resource limits require the owned live task container")
        docker("exec", self.name, "test", "!", "-e", "/run/fmst/model.json")
        self.put_file("/opt/fmst-delivery/bootstrap.py", Path(__file__).with_name("delivery_bootstrap.py").read_bytes())
        docker("exec", self.name, "chmod", "0644", "/opt/fmst-delivery/bootstrap.py")
        for user in ("0", "runner"):
            docker("exec", "--user", user, self.name, "python", "/opt/fmst-delivery/bootstrap.py", "--limit-cores-only", timeout=60)

    def stop(self, reason="stopped"):
        if self.result.container_id and not self.result.container_removed:
            # Address immutable ID and verify ownership before any mutation.
            stop_container(self.result.container_id, self.task_id)
            self.collect()
            if reason != "stopped":
                try:
                    self.archive_failure()
                except Exception as error:
                    # An incomplete archive is never a reason to discard its
                    # sole source. The stopped container remains inspectable.
                    self.result.cleanup_error = str(error)
        self.result.status = reason
        for relay in self.relays:
            relay.close()
        self.persist()

    def archive_failure(self):
        if self.result.container_removed:
            return
        self.archive_source("execution-source-final.tar.gz")
        output = self.output / "task.tar.gz"
        temporary = self.output / "task.partial.tar.gz"
        temporary.touch(mode=0o600, exist_ok=True)
        temporary.chmod(0o600)
        excluded = ("task/input/rootfs", "task/work/framework/GuestWeave/target",
                    "task/work/candidate/intervention/target", "task/work/candidate/test_harness/target")
        # Source inputs remain at their recorded host locations. Retain final
        # rootfs/source/analysis and every evidence file; skip build caches.
        with subprocess.Popen(docker_argv("cp", f"{self.name}:/task", "-"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            with tarfile.open(fileobj=process.stdout, mode="r|") as source, \
                    tarfile.open(temporary, mode="w:gz", compresslevel=1) as archive:
                for item in source:
                    if any(item.name == path or item.name.startswith(path + "/") for path in excluded):
                        continue
                    archive.addfile(item, source.extractfile(item) if item.isfile() else None)
            error = process.stderr.read().decode(errors="replace")
            if process.wait() != 0:
                raise RuntimeError(f"Task archive failed: {error}")
        temporary.replace(output)
        output.chmod(0o600)  # Includes private native session transcripts.
        self.result.archive = str(output)
        # Stop was ownership-checked above; use the immutable ID for removal.
        docker("rm", self.result.container_id)
        self.result.container_removed = True


def stop_container(container_id: str, task_id: str):
    info = json.loads(docker("inspect", container_id, text=True).stdout)[0]
    if info["Config"]["Labels"].get(LABEL) != task_id:
        raise ValueError("Container ownership mismatch")
    docker("stop", "--time", "10", container_id)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Inspect, stop or resume a retained Runner task")
    parser.add_argument("action", choices=["status", "stop", "logs", "resume"])
    parser.add_argument("result", type=Path)
    parser.add_argument("--message-file", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=300)
    args = parser.parse_args()
    result = read_result(args.result.read_text())
    engine = args.result.with_name("docker-engine.json")
    # Old rootful receipts remain addressable even after the default changes.
    os.environ["FMST_RUNNER_DOCKER_HOST"] = json.loads(engine.read_text())["endpoint"] if engine.exists() else "unix:///var/run/docker.sock"
    if args.action == "resume":
        if args.message_file is None:
            parser.error("resume requires --message-file")
        from dotenv import load_dotenv
        load_dotenv(Path.cwd() / ".env")
        outcome = asyncio.run(ContainerTask.resume_retained(
            args.result, args.message_file.read_text(), args.timeout_seconds))
        print(json.dumps(outcome))
        if outcome["status"] != "completed":
            raise SystemExit(1)
    elif args.action == "stop":
        stop_container(result.container_id, result.task_id)
        result.status = "stopped"
        write_json(args.result, result.model_dump(mode="json"))
        args.result.with_name("index.md").write_text(render_result(result, engine_endpoint=docker_argv()[2]))
    elif args.action == "status":
        state = None if result.container_removed else json.loads(docker("inspect", result.container_id, text=True).stdout)[0]["State"]
        print(json.dumps({"task_id": result.task_id, "status": result.status, "container": state,
                          "archive": result.archive}))
    else:
        if result.container_removed:
            print(json.dumps({"archive": result.archive, "logs": "task/evidence inside the archive"}))
            return
        subprocess.run(docker_argv("logs", "--tail", "100", result.container_id), check=True)
        state = json.loads(docker("inspect", result.container_id, text=True).stdout)[0]["State"]
        if state["Running"]:
            subprocess.run(docker_argv("exec", result.container_id, "python", "-c",
                "from pathlib import Path;import json;print(json.dumps({'service_logs':[str(p) for p in Path('/task/evidence').rglob('*.log')],'read':'Use the recorded Docker endpoint, then docker exec CONTAINER tail -n 100 PATH'},indent=2))"), check=True)


if __name__ == "__main__":
    main()
