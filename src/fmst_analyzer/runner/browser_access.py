"""Source-bound browser origin and a private Chromium process for a package."""
from __future__ import annotations

import hashlib
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import time
import uuid

from pydantic import Field, field_validator

from .schema import StrictModel


class AccessEvidence(StrictModel):
    path: str = Field(description="Source file path on export; package-relative frozen copy in the delivered contract.")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the complete source file.")
    excerpt: str = Field(min_length=1, description="Exact UTF-8 source excerpt; identity binding does not prove its interpretation.")


class BrowserAccess(StrictModel):
    configuration_id: str = Field(description="SuccessfulConfiguration whose native service and browser access were examined.")
    hostname: str = Field(description="Native HTTP DNS hostname or 127.0.0.1, without a scheme, port or path. Browser-local DNS mapping does not redirect literal IP addresses. The user's published port is retained.")
    rationale: str = Field(min_length=1, description="Why this origin is needed by the native service, and the observed validation boundary.")
    evidence: list[AccessEvidence] = Field(min_length=1, description="Source and/or real interaction evidence supporting the origin; frozen with the engineering package.")

    @field_validator("hostname")
    @classmethod
    def valid_hostname(cls, value):
        if len(value) > 253 or value != value.lower():
            raise ValueError("use a lowercase DNS hostname or IPv4 address")
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            pass
        else:
            if value != "127.0.0.1":
                raise ValueError("browser-local DNS mapping cannot redirect a literal IPv4 origin")
            return value
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
            raise ValueError("invalid browser origin hostname")
        return value


def freeze_access(access: BrowserAccess | None, destination: Path, configuration_id: str):
    """Copy complete cited files; validate identity/excerpts, not native semantics."""
    if access is None:
        return None
    if access.configuration_id != configuration_id:
        raise ValueError("browser access belongs to another successful configuration")
    evidence = []
    for item in access.evidence:
        content = Path(item.path).read_bytes()
        if hashlib.sha256(content).hexdigest() != item.sha256 or item.excerpt.encode() not in content:
            raise ValueError("browser access evidence hash/excerpt differs: " + item.path)
        relative = "access_evidence/" + item.sha256
        target = destination / relative
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(content)
        evidence.append(item.model_copy(update={"path": relative}))
    return access.model_copy(update={"evidence": evidence})


def validate_access(access: BrowserAccess | None, root: Path, configuration_id: str):
    if access is None:
        return
    if access.configuration_id != configuration_id:
        raise ValueError("browser access configuration differs")
    for item in access.evidence:
        if item.path != "access_evidence/" + item.sha256:
            raise ValueError("browser access evidence must use its package-relative content identity")
        path = (root / item.path).resolve(strict=True)
        if not path.is_relative_to((root / "access_evidence").resolve()):
            raise ValueError("browser access evidence is outside the frozen evidence directory")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != item.sha256 or item.excerpt.encode() not in content:
            raise ValueError("browser access evidence changed: " + item.path)


def access_urls(access: BrowserAccess | None, port: int):
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    transport = f"http://127.0.0.1:{port}/"
    return {"url": f"http://{access.hostname}:{port}/" if access else transport,
            "transport_url": transport,
            "browser_required": bool(access and access.hostname != "127.0.0.1")}


def find_browser(explicit: str | None):
    if explicit:
        path = shutil.which(explicit)
        if path is None:
            raise ValueError("browser executable is unavailable: " + explicit)
        return str(Path(path).resolve())
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if path := shutil.which(name):
            return str(Path(path).resolve())
    raise ValueError("install Chrome/Chromium or provide --browser /path/to/executable")


def _process_identity(pid: int):
    """Linux start ticks and argv protect against signalling a reused PID."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"start_ticks": int(fields[19]), "state": fields[0],
                "executable": str(Path(f"/proc/{pid}/exe").resolve(strict=True)),
                "argv": Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")}
    except (FileNotFoundError, ProcessLookupError):
        return None


def _pidfd_open(pid):
    # The bundled CPython does not expose these Linux APIs. Use libc without
    # architecture-specific syscall numbers or a PID-only signal fallback.
    function = ctypes.CDLL(None, use_errno=True).pidfd_open
    function.argtypes = [ctypes.c_int, ctypes.c_uint]
    function.restype = ctypes.c_int
    descriptor = function(pid, 0)
    if descriptor < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    return descriptor


def _pidfd_signal(descriptor, value):
    function = ctypes.CDLL(None, use_errno=True).pidfd_send_signal
    function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(descriptor, value, None, 0) < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _session_alive(session):
    """Chrome children can outlive the main process while flushing a profile."""
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[3]) == session and fields[0] != 'Z':
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def start_browser(root: Path, package_id: str, service: dict, access: BrowserAccess | None,
                  executable: str, *, headless=False, proxy_url: str | None = None):
    """Launch a separate profile and process; DNS/proxy changes are browser-local."""
    pointer = root / "state/browser.json"
    if pointer.exists():
        raise ValueError("this package already has a browser receipt; use down first")
    output = root / "state/browsers" / uuid.uuid4().hex
    profile = output / "profile"
    profile.mkdir(parents=True, mode=0o700)
    command = [executable, f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
               "--disable-extensions"]
    if proxy_url:
        command += [f"--proxy-server={proxy_url}", "--proxy-bypass-list=<-loopback>"]
    else:
        command.append("--no-proxy-server")
    hostname = access.hostname if access else "127.0.0.1"
    if hostname != "127.0.0.1" and not proxy_url:
        command.append(f"--host-resolver-rules=MAP {hostname} 127.0.0.1")
    if headless:
        command += ["--headless=new", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0"]
    command.append(service["url"])
    record = {"schema_version": 1, "package_id": package_id, "sandbox_session_id": service["sandbox_session_id"],
              "url": service["url"], "transport_url": service["transport_url"], "state": "starting",
              "command": command, "profile": str(profile), "log": str(output / "browser.log"),
              "executable": executable,
              "headless": headless, "started_unix_ns": time.time_ns()}
    process = None
    try:
        with (output / "browser.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        identity = _process_identity(process.pid)
        if identity is None:
            raise RuntimeError("browser exited before process identity could be captured")
        record.update(pid=process.pid, process_start_ticks=identity["start_ticks"])
        # Publish ownership before checking startup so failure cleanup has the
        # same identity-bound stop path as normal down.
        pointer.write_text(json.dumps(record, indent=2) + "\n")
        started = time.monotonic()
        deadline = started + 10
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"browser exited ({process.returncode}); log: {record['log']}")
            active = profile / "DevToolsActivePort"
            if (not headless and time.monotonic() - started >= 0.5) or (headless and active.exists()):
                if headless:
                    record["debug_port"] = int(active.read_text().splitlines()[0])
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("browser debug endpoint did not become ready; log: " + record["log"])
            time.sleep(0.05)
        identity = _process_identity(process.pid)
        if identity is None or identity["start_ticks"] != record["process_start_ticks"]:
            raise RuntimeError("browser process changed during startup")
        # Installed browser commands can be launcher scripts. Bind the actual
        # observed executable after startup, rather than the command's wrapper.
        record["executable"] = identity["executable"]
        record["state"] = "running"
        record["startup_observation"] = "debug_port_file" if headless else "process_alive_after_startup"
        pointer.write_text(json.dumps(record, indent=2) + "\n")
        return record
    except BaseException as error:
        record.update(state="failed", error=f"{type(error).__name__}: {error}")
        if pointer.exists():
            try:
                record["cleanup"] = stop_browser(root, package_id)
            except (OSError, ValueError, RuntimeError) as cleanup:
                record["cleanup_error"] = str(cleanup)
        else:
            try:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                shutil.rmtree(profile)
            except (OSError, subprocess.SubprocessError) as cleanup:
                record["cleanup_error"] = str(cleanup)
        raise
    finally:
        (output / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")


def stop_browser(root: Path, package_id: str):
    pointer = root / "state/browser.json"
    if not pointer.exists():
        return {"state": "absent"}
    record = json.loads(pointer.read_text())
    if record["package_id"] != package_id:
        raise ValueError("browser belongs to another package")
    profile = Path(record["profile"]).resolve()
    if (profile.parent.parent != (root / "state/browsers").resolve() or profile.name != "profile"
            or not re.fullmatch(r"[0-9a-f]{32}", profile.parent.name)):
        raise ValueError("browser profile is outside this package")
    pid = record["pid"]
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError("invalid browser PID")
    # The pidfd closes the PID-reuse race between identity checking and signal.
    try:
        descriptor = _pidfd_open(pid)
    except ProcessLookupError:
        descriptor = None
    try:
        identity = _process_identity(pid) if descriptor is not None else None
        if identity and identity["state"] != "Z":
            expected = f"--user-data-dir={profile}".encode()
            # Chromium may rewrite cmdline into one space-separated argv entry
            # after startup. Check bounded flag text plus executable/start ticks.
            argv = [value for value in identity["argv"] if value]
            profile_matches = expected in argv or (len(argv) == 1 and
                re.search(rb"(?:^| )" + re.escape(expected) + rb"(?: |$)", argv[0]) is not None)
            if (identity["start_ticks"] != record["process_start_ticks"] or not profile_matches
                    or identity["executable"] != record["executable"]):
                raise ValueError("browser process identity changed; no signal sent")
            poll = select.poll()
            poll.register(descriptor, select.POLLIN)
            try:
                _pidfd_signal(descriptor, signal.SIGTERM)
                if not poll.poll(3000):
                    _pidfd_signal(descriptor, signal.SIGKILL)
                    if not poll.poll(3000):
                        raise RuntimeError("browser exit was not observed; profile retained")
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while _session_alive(pid):
            if time.monotonic() >= deadline:
                raise RuntimeError("browser child exit was not observed; profile retained")
            time.sleep(0.05)
        record.update(state="stopped", stopped_unix_ns=time.time_ns())
        # Profiles can contain passwords/session tokens. Retain logs and
        # lifecycle receipts; remove this disposable profile after shutdown.
        if profile.exists():
            shutil.rmtree(profile)
        (profile.parent / "stopped.json").write_text(json.dumps(record, indent=2) + "\n")
        pointer.unlink()
        return {"state": "stopped", "receipt": str(profile.parent / "stopped.json")}
    except (OSError, ValueError, RuntimeError) as error:
        record.update(state="cleanup_failed", cleanup_error=f"{type(error).__name__}: {error}")
        (profile.parent / "cleanup-failed.json").write_text(json.dumps(record, indent=2) + "\n")
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
