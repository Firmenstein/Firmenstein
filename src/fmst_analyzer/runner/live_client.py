"""Persistent native browser interaction for a Runner's current candidate.

The proxy maps explicitly selected firmware origins to one local service port.
It preserves Host, request bodies and raw responses, including redirects.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

from .browser_access import (start_browser, stop_browser, find_browser,
    _process_identity, _pidfd_open, _pidfd_signal)
from .budget import ExecutionBudget, run_process


class NativeOriginProxy:
    def __init__(self, host_port: int, origin: str, evidence: Path):
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("use a native http(s) service URL without credentials")
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.host_port = host_port
        self.evidence = evidence
        self.lock = threading.Lock()
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def read(self, size):
                result = b""
                while len(result) < size:
                    chunk = self.request.recv(size - len(result))
                    if not chunk:
                        raise ConnectionError("proxy handshake ended")
                    result += chunk
                return result

            def handle(self):
                self.request.settimeout(30)
                try:
                    version, count = self.read(2)
                    methods = self.read(count)
                    if version != 5 or 0 not in methods:
                        return
                    self.request.sendall(b"\x05\x00")
                    version, command, _, address_type = self.read(4)
                    if address_type == 3:
                        hostname = self.read(self.read(1)[0]).decode("ascii")
                    elif address_type == 1:
                        hostname = socket.inet_ntop(socket.AF_INET, self.read(4))
                    elif address_type == 4:
                        hostname = socket.inet_ntop(socket.AF_INET6, self.read(16))
                    else:
                        return
                    port = int.from_bytes(self.read(2), "big")
                    allowed = version == 5 and command == 1 and hostname == owner.hostname and port == owner.port
                    with owner.lock, owner.evidence.open("a") as log:
                        log.write(json.dumps({"hostname": hostname, "port": port,
                            "allowed": allowed, "unix_ns": time.time_ns()}) + "\n")
                    if not allowed:
                        self.request.sendall(b"\x05\x02\x00\x01" + bytes(6))
                        return
                    with socket.create_connection(("127.0.0.1", owner.host_port), timeout=30) as upstream:
                        self.request.sendall(b"\x05\x00\x00\x01" + bytes(6))
                        # SOCKS forwards the original byte stream: native Host,
                        # TLS, framing and keep-alive are completely unchanged.
                        sockets = [self.request, upstream]
                        while True:
                            readable, _, _ = select.select(sockets, [], [], 30)
                            if not readable:
                                return
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (upstream if source is self.request else self.request).sendall(data)
                except (ConnectionError, OSError, ValueError):
                    return

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            block_on_close = False

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"socks5://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def start_delivery_proxy(root: Path, package_id: str, service: dict):
    """Keep native authority available after the package CLI exits."""
    pointer = root / "state/native-proxy.json"
    if pointer.exists():
        raise ValueError("this package already has a native proxy receipt; use down first")
    output = root / "state/proxies" / uuid.uuid4().hex
    output.mkdir(parents=True)
    path = output / "receipt.json"
    record = {"schema_version": 1, "package_id": package_id,
        "sandbox_session_id": service["sandbox_session_id"], "state": "starting",
        "origin": service["url"], "host_port": service["published_port"]}
    path.write_text(json.dumps(record, indent=2) + "\n")
    command = [sys.executable, "-m", "fmst_analyzer.runner.live_client", "--proxy", str(path)]
    with (output / "proxy.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"native proxy exited ({process.returncode}); log: {output / 'proxy.log'}")
            record = json.loads(path.read_text())
            if record["state"] == "running":
                pointer.write_text(json.dumps({**record, "receipt": str(path)}, indent=2) + "\n")
                return record
            time.sleep(0.05)
        raise RuntimeError("native proxy did not become ready")
    except BaseException as error:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        path.write_text(json.dumps({**record, "state": "failed", "error": str(error)}, indent=2) + "\n")
        raise


def stop_delivery_proxy(root: Path, package_id: str):
    """Stop only the package-owned proxy, retaining its connection ledger."""
    pointer = root / "state/native-proxy.json"
    if not pointer.exists():
        return {"state": "absent"}
    record = json.loads(pointer.read_text())
    path = Path(record["receipt"]).resolve()
    if (record["package_id"] != package_id or path.parent.parent != (root / "state/proxies").resolve()
            or path.name != "receipt.json" or len(path.parent.name) != 32):
        raise ValueError("native proxy receipt belongs to another package")
    try:
        descriptor = _pidfd_open(record["pid"])
    except ProcessLookupError:
        descriptor = None
    try:
        identity = _process_identity(record["pid"]) if descriptor is not None else None
        if identity and identity["state"] != "Z":
            command = [sys.executable, "-m", "fmst_analyzer.runner.live_client", "--proxy", str(path)]
            if (identity["start_ticks"] != record["process_start_ticks"]
                    or identity["executable"] != record["executable"]
                    or [value for value in identity["argv"] if value] != [value.encode() for value in command]):
                raise ValueError("native proxy process identity changed; no signal sent")
            import signal
            poll = select.poll()
            poll.register(descriptor, select.POLLIN)
            _pidfd_signal(descriptor, signal.SIGTERM)
            if not poll.poll(3000):
                _pidfd_signal(descriptor, signal.SIGKILL)
                if not poll.poll(3000):
                    raise RuntimeError("native proxy exit was not observed")
        record.update(state="stopped", stopped_unix_ns=time.time_ns())
        path.with_name("stopped.json").write_text(json.dumps(record, indent=2) + "\n")
        pointer.unlink()
        return {"state": "stopped", "receipt": str(path.with_name("stopped.json"))}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _serve_delivery_proxy(path: Path):
    record = json.loads(path.read_text())
    proxy = NativeOriginProxy(record["host_port"], record["origin"], path.parent / "connections.jsonl")
    identity = _process_identity(os.getpid())
    record.update(state="running", pid=os.getpid(), process_start_ticks=identity["start_ticks"],
        executable=identity["executable"], proxy_url=proxy.url)
    # Readers see a complete record while startup is polling.
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(record, indent=2) + "\n")
    temporary.replace(path)
    try:
        proxy.thread.join()
    finally:
        proxy.close()


class RunnerLiveClient:
    def __init__(self, *, root: Path, budget: ExecutionBudget, runtime_builder):
        self.root, self.budget, self.runtime_builder = root, budget, runtime_builder
        self.sandbox = None
        self.browser = None
        self.proxy = None
        self.current = None
        self.start_candidate = None  # Supplied by the executor once an attempt exists.
        self.cleanup_records = []
        self.pending_service = None
        self.session = "runner-" + uuid.uuid4().hex
        self.lock = threading.RLock()

    def _process(self, command, *, input=None, cleanup=False):
        env = {k: v for k, v in os.environ.items()
            if k.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
            and not k.startswith("AGENT_BROWSER_")}
        return run_process(["agent-browser", "--session", self.session,
            "--cdp", str(self.browser["debug_port"]), *command], budget=self.budget,
            timeout=35, capture_output=True, text=True, input=input, env=env, cleanup=cleanup)

    def start(self, origin: str):
        """Every start is a fresh service overlay and private browser session."""
        with self.lock:
            self.budget.check()
            self.stop()
            if self.start_candidate is None:
                raise ValueError("run the initial candidate before starting native interaction")
            candidate = self.start_candidate()
            attempt = candidate["attempt"]
            parsed = urlsplit(origin)
            service_port = (urlsplit(attempt.browser_origin).port or (443 if urlsplit(attempt.browser_origin).scheme == "https" else 80)) if attempt.browser_origin else attempt.scenario.port
            if parsed.scheme not in {"http", "https"} or (parsed.port or (443 if parsed.scheme == "https" else 80)) != service_port:
                raise ValueError("native origin port must match the current service port")
            output = self.root / uuid.uuid4().hex
            output.mkdir(parents=True)
            self.current = {"schema_version": 1, "instance_id": output.name,
                "attempt_number": attempt.attempt_number,
                "attempt_sha256": candidate["attempt_sha256"],
                "workspace_sha256": candidate["workspace_sha256"],
                "origin": origin, "path": str(output), "state": "starting",
                "started_unix_ns": time.time_ns(), "commands": []}
            try:
                sandbox = candidate["sandbox"]
                self.sandbox = sandbox
                if self.pending_service is not None:
                    ready, port, number = self.pending_service
                    self.pending_service = None
                else:
                    number = 100000 + len(list(self.root.iterdir()))
                    self.current["container"] = f"{sandbox.network_name}-a{number}"
                    self.current["service_attempt_number"] = number
                    self.current["runtime_source_root"] = str(sandbox.output_root / f"attempt-{number:02d}")
                    self.current["runtime_artifact_root"] = str(output / "runtime")
                    with socket.socket() as sock:
                        sock.bind(("127.0.0.1", 0))
                        port = sock.getsockname()[1]
                    ready = sandbox.start_service(intervention_so=candidate["intervention_so"], attempt_number=number,
                        executable_path=candidate["executable_path"], guest_args=attempt.guest_args,
                        guest_working_directory=attempt.guest_working_directory,
                        guest_environment=attempt.guest_environment, companion_processes=attempt.companion_processes,
                        port=service_port, host_port=port, timeout_seconds=min(120, self.budget.remaining()))
                self.current["service_attempt_number"] = number
                self.current["runtime_source_root"] = str(sandbox.output_root / f"attempt-{number:02d}")
                self.current["runtime_artifact_root"] = str(output / "runtime")
                self.current.update(container=ready.container_name, readiness=ready.readiness)
                self.proxy = NativeOriginProxy(port, origin, output / "proxy.jsonl")
                explicit = os.environ.get("FMST_RUNNER_BROWSER")
                if not explicit and not any(shutil.which(n) for n in ("chromium", "google-chrome", "google-chrome-stable", "chromium-browser")):
                    installed = sorted((Path.home() / ".agent-browser/browsers").glob("chrome-*/chrome"))
                    explicit = str(installed[-1]) if installed else None
                service = {"url": origin, "transport_url": f"http://127.0.0.1:{port}/", "sandbox_session_id": sandbox.session_id}
                self.browser = start_browser(output, output.name, service, None,
                    find_browser(explicit), headless=True, proxy_url=self.proxy.url)
                self.current.update(state="running", browser_session=self.session)
                self._save()
                self.command(["network", "har", "start"])
                self.command(["open", origin])
                return self.command(["snapshot", "-i"])
            except BaseException as error:
                self.current.update(state="failed", error=f"{type(error).__name__}: {error}")
                self._save()
                self.stop()
                raise

    def _save(self):
        if self.current:
            (Path(self.current["path"]) / "receipt.json").write_text(json.dumps(self.current, indent=2) + "\n")

    def command(self, arguments: list[str], stdin: str | None = None):
        with self.lock:
            return self._command(arguments, stdin)

    def _command(self, arguments: list[str], stdin: str | None = None):
        """Run native page actions and retain full outputs, even on failure."""
        if not self.browser or not self.current:
            raise ValueError("start a native client instance first")
        # This is a scoped browser capability, not access to CLI-wide sessions,
        # response mocks, cookie fabrication or another browser's CDP endpoint.
        allowed = {"--help", "cookies", "open", "snapshot", "click", "dblclick", "fill", "type", "press", "select", "check", "uncheck", "hover", "focus", "get", "is", "find", "wait", "back", "forward", "reload", "scroll", "scrollintoview", "frame", "tab", "dialog", "eval", "console", "errors", "network", "screenshot", "set", "keyboard"}
        if not arguments or arguments[0] not in allowed or any(a in {"--cdp", "--session", "--auto-connect", "--profile", "--state"} or a.startswith(("--cdp=", "--session=")) for a in arguments):
            raise ValueError("use page interaction commands in this owned browser")
        help_only = arguments == ["--help"] or (len(arguments) == 2 and arguments[1] == "--help")
        if arguments[0] == "--help" and arguments != ["--help"]:
            raise ValueError("use --help alone or <command> --help")
        if arguments[0] == "cookies" and not help_only and arguments not in (["cookies"], ["cookies", "get"]):
            raise ValueError("cookies are read-only; authenticate through the native interface")
        if arguments[0] == "network" and not help_only and (len(arguments) < 2 or arguments[1] not in {"requests", "har"}):
            raise ValueError("network inspection only; native responses must remain unchanged")
        if arguments[0] == "set" and not help_only and (len(arguments) < 2 or arguments[1] not in {"credentials", "viewport"}):
            raise ValueError("only native HTTP credentials and viewport settings are supported")
        args = list(arguments)
        output = Path(self.current["path"])
        index = len(self.current["commands"])
        if args[0] == "screenshot" and not help_only:
            args = ["screenshot", str(output / f"screen-{index:04d}.png")]
        if args[:3] == ["network", "har", "stop"]:
            args = args[:3] + [str(output / "network.har")]
        record = {"arguments": args, "stdin": stdin, "unix_ns": time.time_ns()}
        path = output / f"command-{index:04d}.json"
        try:
            result = self._process(args, input=stdin)
            record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except BaseException as error:
            record.update(error=f"{type(error).__name__}: {error}")
            for name in ("stdout", "stderr"):
                value = getattr(error, name, None)
                if value is not None:
                    record[name] = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
            raise
        finally:
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
            self.current["commands"].append(path.name)
            self._save()
        text = result.stdout + result.stderr
        return json.dumps({"instance_receipt": str(output / "receipt.json"),
            "command_receipt": str(path), "returncode": result.returncode,
            "runtime_evidence_root": self.current.get("runtime_source_root"),
            "output": text if len(text) <= 24000 else None,
            "notice": "Full output retained in command_receipt" if len(text) > 24000 else None})

    def stop(self):
        with self.lock:
            return self._stop()

    def _stop(self):
        if self.browser is None and self.proxy is None and self.sandbox is None:
            return
        errors = []
        if self.browser:
            try:
                self._process(["network", "har", "stop", str(Path(self.current["path"]) / "network.har")], cleanup=True)
                self._process(["close"], cleanup=True)
            except Exception as error:
                errors.append(str(error))
            try:
                stop_browser(Path(self.current["path"]), self.current["instance_id"])
            except Exception as error:
                errors.append(str(error))
            self.browser = None
        if self.proxy:
            self.proxy.close()
            self.proxy = None
        if self.sandbox:
            try:
                if self.current.get("container"):
                    self.sandbox.stop_service(self.current["container"], self.current["service_attempt_number"])
                    source = self.sandbox.output_root / f"attempt-{self.current['service_attempt_number']:02d}"
                    shutil.copytree(source, Path(self.current["path"]) / "runtime", symlinks=True,
                        dirs_exist_ok=True)
            except Exception as error:
                errors.append(str(error))
            finally:
                self.sandbox = None
        if self.current:
            self.current.update(state="cleanup_failed" if errors else "stopped", cleanup_errors=errors)
            self._save()
        if errors:
            raise RuntimeError("Native client cleanup: " + "; ".join(errors))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--proxy":
        raise SystemExit("Use the package browse command to start a native origin proxy")
    _serve_delivery_proxy(Path(sys.argv[2]))
