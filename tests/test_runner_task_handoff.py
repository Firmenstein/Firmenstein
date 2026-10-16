"""Delivery is post-Goal, bounded, local-validated and independent of service success."""
import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from fmst_analyzer.runner.task.handoff import HandoffDraftV1, collect_handoff, validate_references


def draft(root):
    evidence = root / "read.json"
    evidence.write_text('{}')
    return dict(schema_version=1, summary="Local firmware test environment", analysis=[],
                startup=dict(availability="unavailable", unavailable_reason="Retained startup information is incomplete"),
                access=dict(native_url="http://device/", transport="socks5", instructions="Use the native proxy"),
                state=[], key_artifacts=[], evidence=[dict(path=str(evidence), purpose="native readback")],
                limitations=["WAN unavailable"], restart_verification=dict(status="not_tested", details="Same service retained"))


def test_legacy_receipts_do_not_gain_delivery_claims():
    from fmst_analyzer.runner.task.schema import read_result, TaskResultV1
    value = dict(schema_version=1, task_id="old", target="httpd", status="serving", started_at=1, report_dir="old")
    result = read_result(json.dumps(value))
    assert type(result) is TaskResultV1
    assert not hasattr(result, "handoff_status")


def test_capture_after_restart_preserves_original_completion():
    from fmst_analyzer.runner.task.delivery_capture import capture_service_identity
    original = {"service_pid": 42, "service_start_ticks": 100, "summary": "original observed business"}
    restarted = {"status": "running", "service_pid": 64, "service_start_ticks": 200, "init_start_ticks": 150}
    identity = {1:150, 42:None, 64:200}.get
    captured = capture_service_identity(original, restarted, identity)
    assert captured == {"source":"delivery_startup", "service_pid":64, "service_start_ticks":200, "init_start_ticks":150}
    assert original == {"service_pid":42, "service_start_ticks":100, "summary":"original observed business"}


@pytest.mark.parametrize("changes", [
    {"service_pid": 0}, {"service_pid": True}, {"service_start_ticks": 0},
    {"service_start_ticks": 201}, {"init_start_ticks": 149}, {"init_start_ticks": True},
    {"status":"starting"}, {"status":"startup_error"},
])
def test_capture_rejects_stale_or_invalid_restart_receipt(changes):
    from fmst_analyzer.runner.task.delivery_capture import capture_service_identity
    restarted = {"status":"running", "service_pid":64, "service_start_ticks":200, "init_start_ticks":150, **changes}
    with pytest.raises(ValueError, match="Neither"):
        capture_service_identity({"service_pid":42,"service_start_ticks":100}, restarted, {1:150,42:None,64:200}.get)


def test_capture_prefers_still_live_original_service():
    from fmst_analyzer.runner.task.delivery_capture import capture_service_identity
    captured = capture_service_identity({"service_pid":42,"service_start_ticks":100}, None, {1:150,42:100}.get)
    assert captured["source"] == "original_completion" and captured["service_pid"] == 42


def test_concurrent_capture_waits_for_the_real_os_lock(tmp_path):
    import fcntl
    import threading
    from fmst_analyzer.runner.task.delivery_capture import acquire_capture_lock
    with (tmp_path / 'capture.lock').open('a') as first, (tmp_path / 'capture.lock').open('a') as second:
        fcntl.flock(first, fcntl.LOCK_EX)
        released = threading.Event()
        def release():
            time.sleep(0.02)
            fcntl.flock(first, fcntl.LOCK_UN)
            released.set()
        thread = threading.Thread(target=release)
        thread.start()
        acquire_capture_lock(second, time.monotonic() + 2)
        thread.join()
        assert released.is_set()


def test_capture_queue_deadline_does_not_break_the_existing_lock(tmp_path):
    import fcntl
    from fmst_analyzer.runner.task.delivery_capture import acquire_capture_lock
    with (tmp_path / 'capture.lock').open('a') as first, (tmp_path / 'capture.lock').open('a') as second:
        fcntl.flock(first, fcntl.LOCK_EX)
        with pytest.raises(TimeoutError, match='queue deadline'):
            acquire_capture_lock(second, time.monotonic() - 1)
        with pytest.raises(BlockingIOError):
            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_image_timeout_blocks_another_capture_and_retains_original_operation(tmp_path):
    import subprocess
    from fmst_analyzer.runner.task.delivery_capture import commit_image
    stage = tmp_path / "stage"
    (stage / "evidence").mkdir(parents=True)
    pending = tmp_path / "capture.pending.json"
    calls = []

    def timed_out(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired("docker commit", 600)

    arguments = dict(container="retained-service", task_id="task", engine="local-engine",
                     stage=stage, pending=pending, timeout=600)
    with pytest.raises(subprocess.TimeoutExpired):
        commit_image(timed_out, **arguments)
    original = pending.read_bytes()
    operation = json.loads(original)
    assert operation["status"] == "outcome_unknown"
    assert operation["container"] == "retained-service"
    assert (stage / "evidence/image-operation.json").read_bytes() == original
    with pytest.raises(RuntimeError, match="unknown outcome"):
        commit_image(timed_out, **arguments)
    assert len(calls) == 1 and pending.read_bytes() == original


def test_confirmed_image_completion_clears_pending_but_keeps_exact_receipt(tmp_path):
    from fmst_analyzer.runner.task.delivery_capture import commit_image
    stage = tmp_path / "stage"
    (stage / "evidence").mkdir(parents=True)
    pending = tmp_path / "capture.pending.json"
    image = "sha256:" + "1" * 64

    def finished(*args, **kwargs):
        assert pending.is_file()
        return SimpleNamespace(stdout=image + "\n")

    assert commit_image(finished, container="service", task_id="task", engine="engine",
                        stage=stage, pending=pending, timeout=600) == image
    receipt = json.loads((stage / "evidence/image-operation.json").read_text())
    assert not pending.exists() and receipt["status"] == "complete" and receipt["image"] == image


def test_confirmed_docker_failure_does_not_block_unrelated_next_capture(tmp_path):
    from fmst_analyzer.runner.task.delivery_capture import commit_image
    stage = tmp_path / "stage"
    (stage / "evidence").mkdir(parents=True)
    pending = tmp_path / "capture.pending.json"

    def failed(*args, **kwargs):
        error = RuntimeError("Docker explicitly refused the request")
        error.process_result = SimpleNamespace(returncode=1)
        raise error

    with pytest.raises(RuntimeError, match="explicitly refused"):
        commit_image(failed, container="service", task_id="task", engine="engine",
                     stage=stage, pending=pending, timeout=600)
    assert not pending.exists()
    assert json.loads((stage / "evidence/image-operation.json").read_text())["status"] == "failed"


def test_archived_hardlink_identity_records_content_size_not_empty_tar_header(tmp_path):
    import hashlib
    import io
    import tarfile
    from fmst_analyzer.runner.task.delivery_capture import apply_archived_artifacts
    from fmst_analyzer.runner.task.delivery_manifest import StateArchive
    payload = b"delivered configuration"
    path = tmp_path / "state.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("data")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
        link = tarfile.TarInfo("alias")
        link.type, link.linkname = tarfile.LNKTYPE, "data"
        link.uid, link.gid, link.mode = 123, 456, 0o640
        archive.addfile(link)
    external = StateArchive(destination="/config", file=path.name,
                            sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size, excluded_mounts=[])
    records = [{"path":"/config/alias", "kind":"missing"}]
    apply_archived_artifacts(records, external, tmp_path)
    assert records == [{"path":"/config/alias", "kind":"file", "mode":0o640,
                        "uid":123, "gid":456, "storage":path.name,
                        "sha256":hashlib.sha256(payload).hexdigest(), "size":len(payload)}]


@pytest.mark.parametrize("bad", ["relative", "/task/../secret", "/task/sessions/runner/session.json"])
def test_artifact_paths_are_absolute_and_not_native_history(tmp_path, bad):
    value = draft(tmp_path)
    value["key_artifacts"] = [dict(path=bad, purpose="bad reference")]
    with pytest.raises(ValueError):
        validate_references(HandoffDraftV1.model_validate(value))


def test_missing_restart_cannot_be_reported_as_available(tmp_path):
    value = draft(tmp_path)
    value["startup"] = dict(availability="available")
    with pytest.raises(ValidationError):
        HandoffDraftV1.model_validate(value)


def test_local_validation_corrects_format_without_creating_a_new_agent(tmp_path):
    (tmp_path / "delivery").mkdir()
    value = draft(tmp_path)
    calls = []

    class Agent:
        async def ainvoke(self, message, trace):
            calls.append(message)
            output = dict(value)
            if len(calls) == 1:
                output["unexpected"] = True
            (tmp_path / "delivery/handoff.json").write_text(json.dumps(output))

    result = asyncio.run(collect_handoff(Agent(), None, task_root=tmp_path, deadline=time.time()+10))
    assert result["status"] == "ready" and result["attempts"] == 2
    assert len(calls) == 2 and "Correct only" in calls[1]
    assert json.loads((tmp_path / "delivery/handoff-attempts/1.json").read_text())["unexpected"]


def test_exhausted_deadline_does_not_call_model_or_change_completion(tmp_path):
    (tmp_path / "delivery").mkdir()
    original = tmp_path / "delivery/completion.json"
    original.write_text('{"retained":true}')

    class Agent:
        async def ainvoke(self, *args, **kwargs):
            pytest.fail("No budget remains")

    result = asyncio.run(collect_handoff(Agent(), None, task_root=tmp_path, deadline=0))
    assert result["status"] == "timeout"
    assert original.read_text() == '{"retained":true}'


def test_invalid_handoff_is_bounded_to_three_turns(tmp_path):
    (tmp_path / "delivery").mkdir()
    calls = []

    class Agent:
        async def ainvoke(self, *args, **kwargs):
            calls.append(1)

    result = asyncio.run(collect_handoff(Agent(), None, task_root=tmp_path, deadline=time.time()+10))
    assert result["status"] == "invalid" and len(calls) == 3


@pytest.mark.parametrize("delivery_mode", ["full", "rehosting_only"])
def test_complete_then_handoff_uses_same_client_and_closes_last(monkeypatch, tmp_path, delivery_mode):
    import fmst_basic.agent as agents
    from fmst_analyzer.runner.task import worker, common, analysis_rpc
    for module in (worker, common):
        monkeypatch.setattr(module, "TASK", tmp_path)
        monkeypatch.setattr(module, "CONTROL", tmp_path / "control")
    monkeypatch.setattr(worker, "process_identity", lambda pid: 123)
    monkeypatch.setattr(common, "process_identity", lambda pid: 123)
    for name in ("evidence", "control", "delivery"):
        (tmp_path / name).mkdir()
    common.write_json(tmp_path / "control/lifecycle.json", {"status":"repairing", "deadline":time.time()+30})
    common.write_json(tmp_path / "task.json", {"task_id":"fixture", "goal":"native service", "capability_probe":True,
                                             "delivery_mode":delivery_mode})
    evidence = tmp_path / "evidence/read.json"
    evidence.write_text('{}')
    completion = dict(summary="local service", native_url="http://device/", service_pid=42,
                      service_start_ticks=123, access="local", interactions=[dict(operation="read", observed="value", evidence=[str(evidence)])])
    order = []
    factories = []
    value = draft(tmp_path)

    class Analysis:
        def __init__(self, *_): pass
        async def close(self): order.append("analysis_close")

    class Agent:
        session_receipt = tmp_path / "session.json"

        async def ainvoke(self, message, trace):
            order.append("invoke")
            if order.count("invoke") == 1:
                assert "handoff-schema.json" not in message
                assert not (tmp_path / "delivery/handoff-schema.json").exists()
                await factories[0]["tools"][0].ainvoke({"completion":completion})
                order.append("completed")
            else:
                assert "handoff-schema.json" in message
                assert (tmp_path / "delivery/completion.json").exists()
                common.write_json(tmp_path / "delivery/handoff.json", value)
            return SimpleNamespace(status="completed", text="saved")

        async def aclose(self): order.append("agent_close")

    def create(**kwargs):
        factories.append(kwargs)
        assert "output_schema" not in kwargs
        return Agent()

    monkeypatch.setattr(agents, "create_analysis_agent", create)
    monkeypatch.setattr(analysis_rpc, "AnalysisClient", Analysis)
    asyncio.run(worker.run_session({"FMST_CLAUDE_MODEL":"test", "FMST_CLAUDE_REASONING_EFFORT":"high"}))
    assert len(factories) == 1
    expected = ["invoke", "completed"] + (["invoke"] if delivery_mode == "full" else [])
    assert order == expected + ["agent_close", "analysis_close"]
    assert json.loads((tmp_path / "delivery/handoff-status.json").read_text())["status"] == (
        "ready" if delivery_mode == "full" else "not_started")
    if delivery_mode == "rehosting_only":
        assert not (tmp_path / "delivery/handoff-schema.json").exists()
    assert json.loads((tmp_path / "control/lifecycle.json").read_text())["status"] == "serving"


def test_mount_capture_gaps_are_explicit(tmp_path):
    from fmst_analyzer.runner.task.delivery_capture import mount_gaps
    h = HandoffDraftV1.model_validate(draft(tmp_path))
    mounts = [dict(path="/task/work/state", fstype="tmpfs")]
    assert mount_gaps(mounts, h)
    from fmst_analyzer.runner.task.handoff import State
    h.state = [State(path="/task/work/state", role="peer socket", persistence="recreate", initialization="Startup creates peer")]
    assert mount_gaps(mounts, h) == []


def test_kernel_mounts_use_actual_guest_root_mapping(tmp_path):
    from fmst_analyzer.runner.task.delivery_capture import mount_gaps
    h = HandoffDraftV1.model_validate(draft(tmp_path))
    mounts = [dict(path="/task/work/rootfs/dev", visible_path="/task/work/rootfs/dev", fstype="tmpfs"),
              dict(path="/task/work/rootfs/dev", visible_path="/dev", process_root="/task/work/rootfs", fstype="tmpfs"),
              dict(path="/task/work/rootfs/data", visible_path="/data", fstype="tmpfs")]
    gaps = mount_gaps(mounts,h)
    assert len(gaps)==1 and "/task/work/rootfs/data" in gaps[0]


def test_external_files_below_tmpfs_share_a_selected_restore_directory():
    from fmst_analyzer.runner.task.delivery_capture import state_archive_plan
    from fmst_analyzer.runner.task.handoff import State
    states = [State(path=p, role="flash", persistence="external_mount", initialization="preserve data")
              for p in ("/dev/mtdblock/2", "/dev/mtdblock/3")]
    mounts = [{"path":"/", "fstype":"overlay"}, {"path":"/dev", "fstype":"tmpfs"}]
    plans, gaps = state_archive_plan(mounts, states, [{"path":s.path,"kind":"file"} for s in states])
    assert not gaps
    assert plans == [{"destination":"/dev/mtdblock", "members":["./2", "./3"], "excluded_mounts":[]}]


def test_external_state_respects_nested_mount_boundaries():
    from fmst_analyzer.runner.task.delivery_capture import state_archive_plan
    from fmst_analyzer.runner.task.handoff import State
    states = [State(path=p, role="state", persistence="external_mount", initialization="preserve data")
              for p in ("/data", "/data/peer")]
    mounts = [{"path":"/data", "fstype":"tmpfs"}, {"path":"/data/peer", "fstype":"ext4"}]
    plans, gaps = state_archive_plan(mounts, states, [{"path":s.path,"kind":"directory"} for s in states])
    assert not gaps
    assert [p["destination"] for p in plans] == ["/data", "/data/peer"]
    assert plans[0]["excluded_mounts"] == ["/data/peer"]


def test_sibling_file_mounts_do_not_create_duplicate_volumes_or_exclude_their_data():
    from fmst_analyzer.runner.task.delivery_capture import state_archive_plan
    from fmst_analyzer.runner.task.handoff import State
    states = [State(path=p, role="state", persistence="external_mount", initialization="preserve")
              for p in ("/data/2", "/data/3")]
    mounts = [{"path":s.path, "fstype":"ext4"} for s in states]
    plans, gaps = state_archive_plan(mounts, states, [{"path":s.path,"kind":"file"} for s in states])
    assert not gaps
    assert plans == [{"destination":"/data", "members":["./2", "./3"], "excluded_mounts":[]}]


@pytest.mark.parametrize("kind,mounts", [
    ("missing", [{"path":"/dev", "fstype":"tmpfs"}]),
    ("file", [{"path":"/", "fstype":"overlay"}]),
])
def test_invalid_external_state_is_a_capture_gap(kind, mounts):
    from fmst_analyzer.runner.task.delivery_capture import state_archive_plan
    from fmst_analyzer.runner.task.handoff import State
    state = State(path="/dev/flash/data", role="flash", persistence="external_mount", initialization="preserve")
    plans, gaps = state_archive_plan(mounts, [state], [{"path":state.path,"kind":kind}])
    assert not plans and len(gaps) == 1


def test_down_snapshot_failure_preserves_the_running_container(monkeypatch):
    from fmst_analyzer.runner.task.delivery_cli import Delivery
    launcher = Delivery.__new__(Delivery)
    launcher.info = lambda name: ({"id":"fixture"}, {"State":{"Running":True}})
    def unavailable(*args):
        raise OSError("snapshot disk full")
    monkeypatch.setattr(launcher, "snapshot_ephemeral", unavailable)
    launcher.docker = lambda *args: pytest.fail("must not stop when the snapshot fails")
    with pytest.raises(OSError, match="disk full"):
        launcher.down("retained")


def test_new_volume_does_not_reset_to_initial_state_on_down():
    from fmst_analyzer.runner.task.delivery_cli import Delivery
    launcher = Delivery.__new__(Delivery)
    launcher.manifest = {"state_archives":[{"destination":"/dev/flash"}]}
    assert launcher.ephemeral_archives({"original":False}, {}) == []


@pytest.mark.parametrize("wait_status,expected", [(0,0), (42 << 8,42), (15,143), (134,134)])
def test_guest_entry_exit_reaches_the_caller_with_original_raw_evidence(monkeypatch, tmp_path, wait_status, expected):
    from fmst_analyzer.runner.task import guest
    events = iter([(2,wait_status)])
    def wait():
        try: return next(events)
        except StopIteration: raise ChildProcessError from None
    monkeypatch.setattr(guest.os, "wait", wait)
    assert guest.reap_guest_children(2, tmp_path) == expected
    assert json.loads((tmp_path / "entry-exit.json").read_text()) == {"pid":2,"status":wait_status}
    assert json.loads((tmp_path / "process-exits.jsonl").read_text())["wait_status"] == wait_status


def test_daemonized_entry_and_helper_exits_remain_distinct(monkeypatch, tmp_path):
    from fmst_analyzer.runner.task import guest
    events = iter([(3, 1 << 8), (2,0), (4,15)])
    def wait():
        try: return next(events)
        except StopIteration: raise ChildProcessError from None
    monkeypatch.setattr(guest.os, "wait", wait)
    assert guest.reap_guest_children(2, tmp_path) == 0
    assert [json.loads(line)["wait_status"] for line in (tmp_path / "process-exits.jsonl").read_text().splitlines()] == [256,0,15]


def test_missing_native_entry_exit_is_unknown_instead_of_success(monkeypatch, tmp_path):
    from fmst_analyzer.runner.task import guest
    def no_children(): raise ChildProcessError
    monkeypatch.setattr(guest.os, "wait", no_children)
    with pytest.raises(RuntimeError, match="not collected"):
        guest.reap_guest_children(2, tmp_path)


@pytest.mark.parametrize("before,expected", [
    ((0,-1),(0,-1)), ((1024*1024,-1),(1024*1024,-1)),
    ((-1,-1),(64*1024**2,-1)), ((8*1024**2,8*1024**2),(8*1024**2,8*1024**2)),
])
def test_guest_launcher_preserves_disabled_and_smaller_core_limits(monkeypatch, before, expected):
    from fmst_analyzer.runner.task import guest
    observed = []
    monkeypatch.setattr(guest.resource, "getrlimit", lambda kind: before)
    monkeypatch.setattr(guest.resource, "setrlimit", lambda kind, limits: observed.append(limits))
    guest.limit_guest_core_dumps()
    assert observed == [expected]


def test_completion_is_frozen_and_handoff_deadline_preserves_original(monkeypatch, tmp_path):
    from fmst_analyzer.runner.task import common
    from fmst_analyzer.runner.task.schema import ServiceCompletion
    from fmst_analyzer.runner.task.init import handoff_expired, stop_reason
    monkeypatch.setattr(common, "TASK", tmp_path)
    monkeypatch.setattr(common, "CONTROL", tmp_path / "control")
    monkeypatch.setattr(common, "process_identity", lambda pid: 123)
    monkeypatch.setattr(common.time, "time", lambda: 100)
    common.write_json(tmp_path / "control/lifecycle.json", {"status":"repairing", "deadline":250})
    c = ServiceCompletion(summary="local service", native_url="http://device/", service_pid=42, service_start_ticks=123,
        access="proxy", interactions=[dict(operation="read", observed="value", evidence=["/task/evidence/read.json"])])
    common.retain_service(c, {})
    state = json.loads((tmp_path / "control/lifecycle.json").read_text())
    assert state["deadline"] == 250 and state["handoff_deadline"] == 250
    assert handoff_expired(state, 250)
    assert stop_reason(state, now=999) is None
    with pytest.raises(RuntimeError, match="frozen"):
        common.retain_service(c, {})


def test_metadata_restore_handles_overlay_copyup_and_preserves_later_user_changes(monkeypatch, tmp_path):
    import os
    import base64
    from fmst_analyzer.runner.task.delivery_bootstrap import restore_metadata
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("snapshot")
    os.link(a, b)
    source = tmp_path / "xattrs.json"
    source.write_text(json.dumps({"entries":[{"path":str(p), "attributes":{"user.fixture":base64.b64encode(b"value").decode()}} for p in (a,b)],
                                 "hardlinks":[{"paths":[str(a),str(b)], "count":2}]}))
    real_setxattr = os.setxattr

    def copyup(path, key, value, **kwargs):
        # A lower-layer hardlink can split on each first metadata write.
        path = Path(path)
        temp = path.with_suffix('.copyup')
        temp.write_bytes(path.read_bytes())
        temp.replace(path)
        real_setxattr(path, key, value, **kwargs)

    monkeypatch.setattr(os, "setxattr", copyup)
    restore_metadata(tmp_path)
    assert os.path.samefile(a,b)
    assert os.getxattr(a,"user.fixture") == b"value"
    b.unlink()
    b.write_text("user deliberately split the file")
    restore_metadata(tmp_path)
    assert not os.path.samefile(a,b)
    assert b.read_text() == "user deliberately split the file"


def test_bad_handoff_status_does_not_corrupt_service_state(monkeypatch, tmp_path):
    from fmst_analyzer.runner.task import host
    task = host.ContainerTask(output=tmp_path / "task", target="fixture", image="fixture")
    task.result.status = "serving"
    (task.output / "delivery").mkdir()
    (task.output / "delivery/handoff-status.json").write_text('{broken')
    monkeypatch.setattr(host.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    task.collect()
    assert task.result.status == "serving" and task.result.handoff_status == "error"


@pytest.mark.parametrize("delivery_mode", ["full", "rehosting_only"])
def test_package_failure_keeps_successful_service(monkeypatch, tmp_path, delivery_mode):
    from fmst_analyzer.runner.task import host, delivery_capture
    task = host.ContainerTask(output=tmp_path / "task", target="fixture", image="fixture", delivery_mode=delivery_mode)
    task.result.container_id = "fixture-container"
    task.result.handoff_status = "ready"

    class Process:
        returncode = 0
        async def wait(self): return 0

    async def create(*args, **kwargs): return Process()
    def reconcile():
        task.result.status = "serving"
        return True
    def broken_capture(*args, **kwargs):
        if delivery_mode == "rehosting_only":
            pytest.fail("Rehosting-only must never capture an image, even if a handoff exists")
        raise RuntimeError("capture fixture error")
    def unexpected_stop(*args, **kwargs): pytest.fail("Package failure must not stop the service")
    monkeypatch.setattr(host.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(host.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    monkeypatch.setattr(task, "reconcile_completion", reconcile)
    monkeypatch.setattr(task, "stop_worker", lambda: None)
    retained = []
    monkeypatch.setattr(task, "archive_session", lambda: retained.append("session"))
    monkeypatch.setattr(task, "apply_delivery_resource_limits", lambda: retained.append("resources"))
    monkeypatch.setattr(task, "stop", unexpected_stop)
    monkeypatch.setattr(delivery_capture, "capture", broken_capture)
    result = asyncio.run(task.run())
    assert result.status == "serving" and result.package_status == ("error" if delivery_mode == "full" else "not_started")
    assert retained == ["resources", "session"]
    assert not result.container_removed


def test_unlimited_snapshot_does_not_launch_with_invalid_zero_resource_flags():
    from fmst_analyzer.runner.task.delivery_cli import container_limits
    config = {"Memory":0, "MemorySwap":0, "NanoCpus":0, "PidsLimit":None, "ShmSize":64*1024**2}
    assert container_limits(config, {}) == ["--shm-size", str(64*1024**2)]
    config.update(Memory=1024, MemorySwap=1024, NanoCpus=500000000, PidsLimit=64)
    engine = {key:True for key in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")}
    args = container_limits(config, engine)
    assert args[args.index("--cpus")+1] == "0.5"
    assert args[args.index("--memory-swap")+1] == "1024"


@pytest.mark.parametrize("ticks", [None, 0, True, 123])
def test_startup_receipt_cannot_claim_an_absent_process(monkeypatch, ticks):
    from fmst_analyzer.runner.task import delivery_bootstrap as bootstrap
    monkeypatch.setattr(bootstrap, "identity", lambda pid: None)
    with pytest.raises(ValueError):
        bootstrap.validate_receipt({"service_pid":42,"service_start_ticks":ticks,"log_paths":[],"execution_path":None})


def test_retained_startup_failure_replaces_starting_receipt(monkeypatch):
    from fmst_analyzer.runner.task import delivery_bootstrap as bootstrap
    receipts = []
    def failed_startup():
        raise RuntimeError("fixture startup failed")
    monkeypatch.setattr(bootstrap.sys, "argv", ["bootstrap.py", "--startup-only"])
    monkeypatch.setattr(bootstrap, "identity", lambda pid: 123)
    monkeypatch.setattr(bootstrap, "save", lambda path, value: receipts.append(value))
    monkeypatch.setattr(bootstrap, "limit_automatic_core_dumps", lambda: None)
    monkeypatch.setattr(bootstrap, "startup", failed_startup)
    with pytest.raises(RuntimeError, match="fixture startup failed"):
        bootstrap.main()
    assert receipts == [{"status":"starting", "init_start_ticks":123},
                        {"status":"startup_error", "error":"fixture startup failed", "init_start_ticks":123}]


def test_core_limit_failure_records_startup_error_before_any_service_launch(monkeypatch):
    from fmst_analyzer.runner.task import delivery_bootstrap as bootstrap
    receipts = []
    def unavailable():
        raise PermissionError("fixture process limit denied")
    monkeypatch.setattr(bootstrap, "save", lambda path, value: receipts.append(value))
    monkeypatch.setattr(bootstrap, "identity", lambda pid: 123)
    monkeypatch.setattr(bootstrap, "limit_automatic_core_dumps", unavailable)
    monkeypatch.setattr(bootstrap, "startup", lambda: pytest.fail("Must not launch after a limit error"))
    with pytest.raises(PermissionError, match="limit denied"):
        bootstrap.main()
    assert receipts[-1]["status"] == "startup_error"
    assert receipts[-1]["error"] == "fixture process limit denied"


@pytest.mark.parametrize("receipt,observed_ticks,init_ticks,expected", [
    ({"status":"running","service_pid":42,"service_start_ticks":123}, None, 100, "not_running"),
    ({"status":"running","service_pid":42,"service_start_ticks":123}, 456, 100, "not_running"),
    ({"status":"running","service_pid":42,"service_start_ticks":None}, None, 100, "not_running"),
    ({"status":"running","service_pid":42,"service_start_ticks":True}, 1, 100, "not_running"),
    ({"status":"running","service_pid":42,"service_start_ticks":123,"init_start_ticks":100}, 123, 200, "not_running"),
    ({"status":"starting"}, None, 100, "starting"),
    ({"status":"startup_error"}, None, 100, "startup_error"),
    ({"status":"running","service_pid":42,"service_start_ticks":123,"init_start_ticks":100}, 123, 100, "running"),
])
def test_launcher_checks_live_identity_instead_of_trusting_running_receipt(receipt, observed_ticks, init_ticks, expected):
    from fmst_analyzer.runner.task.delivery_cli import Delivery
    delivery = Delivery.__new__(Delivery)
    delivery.info = lambda name: ({"id":"fixture"}, {"State":{"Running":True}})
    delivery.docker = lambda *args: json.dumps({"receipt":receipt,"service_identity":observed_ticks,"init_identity":init_ticks}).encode()
    assert delivery.service("retained")["service"] == expected
