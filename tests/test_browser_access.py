"""Source identity, native origins and owned browser cleanup counterexamples."""
import hashlib
import json
import signal
import subprocess
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from fmst_analyzer.runner import browser_access as browser
from fmst_analyzer.runner import delivery
from fmst_analyzer.runner.schema import InteractionScenario


def access_fixture(tmp_path):
    source = tmp_path / "native-source.txt"
    source.write_text('complete source\nnative origin: router.example\nother evidence\n')
    return browser.BrowserAccess(configuration_id="success", hostname="router.example",
        rationale="Native Referer check observed in source and browser flow.", evidence=[dict(
            path=str(source), sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            excerpt="native origin: router.example")])


@pytest.mark.parametrize("hostname", ["https://router.example", "router.example:80", "router.example/path",
                                     "router.example, MAP * 127.0.0.1", "-router", "", "Router.example", "192.168.1.1"])
def test_hostname_cannot_inject_url_or_resolver_syntax(tmp_path, hostname):
    with pytest.raises(ValidationError):
        browser.BrowserAccess.model_validate(access_fixture(tmp_path).model_dump() | {"hostname": hostname})


def test_evidence_is_complete_portable_and_bound_to_configuration(tmp_path):
    access = access_fixture(tmp_path)
    root = tmp_path / "package"
    root.mkdir()
    with pytest.raises(ValueError, match="another successful configuration"):
        browser.freeze_access(access, root, "another")
    frozen = browser.freeze_access(access, root, "success")
    assert (root / frozen.evidence[0].path).read_bytes() == (tmp_path / "native-source.txt").read_bytes()
    (tmp_path / "native-source.txt").unlink()
    browser.validate_access(frozen, root, "success")
    assert browser.access_urls(frozen, 19080) == dict(url="http://router.example:19080/",
        transport_url="http://127.0.0.1:19080/", browser_required=True)
    (root / frozen.evidence[0].path).write_text("changed")
    with pytest.raises(ValueError, match="evidence changed"):
        browser.validate_access(frozen, root, "success")


@pytest.mark.parametrize("changed", ["sha256", "excerpt", "path"])
def test_evidence_mismatch_and_outside_path_are_rejected(tmp_path, changed):
    access = access_fixture(tmp_path)
    root = tmp_path / "package"
    root.mkdir()
    if changed == "path":
        frozen = browser.freeze_access(access, root, "success")
        frozen.evidence[0].path = str(tmp_path / "native-source.txt")
        with pytest.raises(ValueError, match="package-relative"):
            browser.validate_access(frozen, root, "success")
    else:
        setattr(access.evidence[0], changed, "0" * 64 if changed == "sha256" else "unobserved")
        with pytest.raises(ValueError, match="hash/excerpt"):
            browser.freeze_access(access, root, "success")


@pytest.mark.parametrize("native_origin", [False, True])
@pytest.mark.parametrize("direct_ui", [False, True])
def test_export_reader_renderer_and_inventory_share_schema2(tmp_path, monkeypatch, native_origin, direct_ui):
    access = access_fixture(tmp_path) if native_origin else None
    provenance = tmp_path / "success"
    provenance.mkdir()
    manifest = provenance / "manifest.json"
    manifest.write_text('{}')
    dependency = tmp_path / "offline"
    dependency.mkdir()
    original = SimpleNamespace(configuration_id="success", target_binary="httpd", guest_arch="mipsbe",
        host_platform="linux/amd64", input_trees={"rootfs": "tree"}, attempt=SimpleNamespace(browser_origin=None,
            scenario=InteractionScenario(protocol="http", port=80, evidence_refs=["source"],
                steps=[dict(request_text="GET / HTTP/1.0\r\n\r\n", expected_status_code=200)])))
    if direct_ui:
        original.attempt.browser_origin = 'http://192.0.2.10/ui/'
        original.attempt.scenario = None
    monkeypatch.setattr(delivery, "load_frozen_inputs", lambda *args: original)
    receipt = dict(delivery_id="offline", builder=dict(image_id="image"))
    monkeypatch.setattr(delivery, "_offline_module", lambda *args: SimpleNamespace(verify=lambda *args: receipt))
    monkeypatch.setattr(delivery, "_copy_python", lambda *args: {})
    root = tmp_path / "package"
    exported = delivery.export_package(manifest, dependency, root, browser_access=access)
    loaded, _ = delivery.load_package(root)
    assert loaded == exported and loaded.schema_version == 2
    assert (root / "controller/fmst_analyzer/runner/browser_access.py").is_file()
    assert (root / "controller/fmst_analyzer/runner/live_client.py").is_file()
    readme = (root / "README.md").read_text()
    assert "./fmst browse" in readme
    assert ('verify checks fresh startup readiness' in readme) == direct_ui
    assert ("Native browser hostname: router.example" in readme) == native_origin
    assert browser.access_urls(loaded.browser_access, 8080)["browser_required"] == native_origin
    value = json.loads((root / "PACKAGE.json").read_text())
    value["schema_version"] = 1
    (root / "PACKAGE.json").write_text(json.dumps(value))
    with pytest.raises(ValueError, match="schema_version"):
        delivery.load_package(root)
    value["schema_version"] = 2
    value["browser_access"] = None if native_origin else access_fixture(tmp_path).model_dump()
    (root / "PACKAGE.json").write_text(json.dumps(value))
    with pytest.raises(ValueError, match="identity differs"):
        delivery.load_package(root)


def owned_browser(tmp_path):
    profile = tmp_path / "state/browsers" / ("a" * 32) / "profile"
    profile.mkdir(parents=True)
    (profile / "private-cookie").write_text("disposable fixture")
    record = dict(package_id="package", pid=12345, process_start_ticks=99, profile=str(profile), state="running",
                  command=["/fixture/chrome-wrapper", f"--user-data-dir={profile}"], executable="/fixture/chrome")
    (tmp_path / "state/browser.json").write_text(json.dumps(record))
    return profile, record


@pytest.fixture(autouse=True)
def no_real_browser_process_scan(monkeypatch):
    monkeypatch.setattr(browser, "_session_alive", lambda pid: False)


@pytest.mark.parametrize("identity_changed", [False, True])
@pytest.mark.parametrize("rewritten", [False, True])
def test_cleanup_never_signals_reused_pid_and_waits_before_profile_removal(tmp_path, monkeypatch, identity_changed, rewritten):
    profile, record = owned_browser(tmp_path)
    monkeypatch.setattr(browser, "_pidfd_open", lambda pid: 77)
    monkeypatch.setattr(browser.os, "close", lambda fd: None)
    monkeypatch.setattr(browser, "_process_identity", lambda pid: dict(start_ticks=98 if identity_changed else 99,
        state="S", executable="/fixture/chrome", argv=[
            f"/fixture/chrome --user-data-dir={profile} --headless=new".encode() if rewritten
            else f"--user-data-dir={profile}".encode()]))
    signals = []
    def send(fd, value):
        assert profile.exists()
        signals.append(value)
    monkeypatch.setattr(browser, "_pidfd_signal", send)
    polls = iter([[], [(77, 1)]])
    class Poll:
        def register(self, *args):
            pass
        def poll(self, *args):
            assert profile.exists()
            return next(polls)
    monkeypatch.setattr(browser.select, "poll", Poll)
    if identity_changed:
        with pytest.raises(ValueError, match="identity changed"):
            browser.stop_browser(tmp_path, "package")
        assert signals == [] and profile.exists()
        assert (profile.parent / "cleanup-failed.json").is_file()
    else:
        assert browser.stop_browser(tmp_path, "package")["state"] == "stopped"
        assert signals == [signal.SIGTERM, signal.SIGKILL]
        assert not profile.exists() and not (tmp_path / "state/browser.json").exists()


def test_missing_process_profile_and_exit_timeout_keep_honest_cleanup(tmp_path, monkeypatch):
    profile, _ = owned_browser(tmp_path)
    monkeypatch.setattr(browser, "_pidfd_open", lambda pid: 77)
    monkeypatch.setattr(browser.os, "close", lambda fd: None)
    monkeypatch.setattr(browser, "_process_identity", lambda pid: dict(start_ticks=99, state="S", executable="/fixture/chrome",
        argv=[f"--user-data-dir={profile}".encode()]))
    monkeypatch.setattr(browser, "_pidfd_signal", lambda *args: None)
    monkeypatch.setattr(browser.select, "poll", lambda: SimpleNamespace(register=lambda *args: None, poll=lambda *args: []))
    with pytest.raises(RuntimeError, match="exit was not observed"):
        browser.stop_browser(tmp_path, "package")
    assert profile.exists() and (tmp_path / "state/browser.json").exists()
    monkeypatch.setattr(browser, "_process_identity", lambda pid: None)
    import shutil
    shutil.rmtree(profile)
    assert browser.stop_browser(tmp_path, "package")["state"] == "stopped"


def test_profile_is_retained_until_browser_children_exit(tmp_path, monkeypatch):
    profile, _ = owned_browser(tmp_path)
    monkeypatch.setattr(browser, "_pidfd_open", lambda pid: 77)
    monkeypatch.setattr(browser.os, "close", lambda fd: None)
    monkeypatch.setattr(browser, "_process_identity", lambda pid: None)
    observations=iter([True, True, False])
    def alive(pid):
        assert profile.exists()
        return next(observations)
    monkeypatch.setattr(browser, "_session_alive", alive)
    monkeypatch.setattr(browser.time, "sleep", lambda delay: None)
    assert browser.stop_browser(tmp_path, "package")["state"] == "stopped"
    assert not profile.exists()


def test_browser_cleanup_failure_does_not_skip_firmware_cleanup(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    def fail(*args):
        raise RuntimeError("browser identity mismatch")
    monkeypatch.setattr(delivery, "stop_browser", fail)
    cleaned = []
    monkeypatch.setattr(delivery, "_down_service", lambda *args: cleaned.append(True) or {"state": "stopped"})
    with pytest.raises(RuntimeError, match="cleanup incomplete"):
        delivery.down_service(tmp_path, SimpleNamespace(package_id="package"))
    assert cleaned == [True]
    assert json.loads((tmp_path / "state/down-failed.json").read_text())["browser_cleanup"]["state"] == "cleanup_failed"


def test_headed_browser_immediate_exit_is_failure_with_cleanup_receipt(tmp_path, monkeypatch):
    process = SimpleNamespace(pid=12345, returncode=1, poll=lambda: 1, terminate=lambda: None, wait=lambda **kw: None)
    monkeypatch.setattr(browser.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(browser, "_process_identity", lambda pid: dict(start_ticks=99))
    def stop(root, package_id):
        pointer = root / "state/browser.json"
        import shutil
        shutil.rmtree(json.loads(pointer.read_text())["profile"])
        pointer.unlink()
        return {"state": "stopped"}
    monkeypatch.setattr(browser, "stop_browser", stop)
    service = dict(url="http://router.example:19080/", transport_url="http://127.0.0.1:19080/", sandbox_session_id="session")
    with pytest.raises(RuntimeError, match="browser exited"):
        browser.start_browser(tmp_path, "package", service, access_fixture(tmp_path), "/fixture/browser")
    receipt = json.loads(next((tmp_path / "state/browsers").glob('*/receipt.json')).read_text())
    assert receipt["state"] == "failed" and receipt["cleanup"]["state"] == "stopped"
    assert "--host-resolver-rules=MAP router.example 127.0.0.1" in receipt["command"]
    assert "--no-proxy-server" in receipt["command"]


@pytest.mark.parametrize("changed", ["url", "service_identity", "service_stopped"])
def test_browse_refuses_changed_origin_or_stale_service(tmp_path, monkeypatch, changed):
    monkeypatch.setattr(delivery, "load_model_json", lambda *args: SimpleNamespace(attempt=SimpleNamespace(browser_origin=None)))
    (tmp_path / "state").mkdir()
    record=dict(package_id="package", state="running", published_port=8080, container_name="container",
        sandbox_session_id="owned", target_slug="httpd", **browser.access_urls(None, 8080))
    if changed == "url":
        record["url"] = "http://different.example:8080/"
    (tmp_path / "state/service.json").write_text(json.dumps(record))
    inspect=dict(State=dict(Running=changed != "service_stopped"), Config=dict(Labels={
        "fmst.runner.managed":"true", "fmst.runner.target":"httpd",
        "fmst.runner.session":"another" if changed == "service_identity" else "owned"}))
    monkeypatch.setattr(delivery, "_process", lambda *args: subprocess.CompletedProcess([],0,json.dumps([inspect])))
    def launch(*args, **kwargs):
        pytest.fail("browser must not launch against changed or stopped service")
    monkeypatch.setattr(delivery, "start_browser", launch)
    with pytest.raises(ValueError, match="URLs differ" if changed == "url" else "identity differs"):
        delivery.browse_service(tmp_path, SimpleNamespace(package_id="package", browser_access=None))


def test_native_browse_keeps_authority_and_cleans_proxy_on_browser_failure(tmp_path, monkeypatch):
    (tmp_path / 'state').mkdir()
    origin = 'http://192.0.2.10:80/manage/'
    record = dict(package_id='package', state='running', published_port=19080,
        sandbox_session_id='owned', target_slug='guest', container_name='container',
        **delivery._service_urls(SimpleNamespace(browser_access=None), 19080, origin))
    (tmp_path / 'state/service.json').write_text(json.dumps(record))
    monkeypatch.setattr(delivery, 'load_model_json', lambda *args: SimpleNamespace(attempt=SimpleNamespace(browser_origin=origin)))
    inspect = dict(State=dict(Running=True), Config=dict(Labels={
        'fmst.runner.managed':'true', 'fmst.runner.target':'guest', 'fmst.runner.session':'owned'}))
    monkeypatch.setattr(delivery, '_process', lambda *args: subprocess.CompletedProcess([], 0, json.dumps([inspect])))
    monkeypatch.setattr(delivery, 'find_browser', lambda *args: '/fixture/chrome')
    events = []
    def proxy(*args):
        events.append('proxy'); return {'proxy_url':'socks5://127.0.0.1:12345'}
    def launch(root, package_id, service, access, executable, **kwargs):
        assert service['url'] == origin and kwargs['proxy_url'] == 'socks5://127.0.0.1:12345'
        events.append('browser'); raise RuntimeError('browser failed')
    monkeypatch.setattr(delivery, 'start_delivery_proxy', proxy)
    monkeypatch.setattr(delivery, 'start_browser', launch)
    monkeypatch.setattr(delivery, 'stop_delivery_proxy', lambda *args: events.append('proxy-stop'))
    with pytest.raises(RuntimeError, match='browser failed'):
        delivery.browse_service(tmp_path, SimpleNamespace(package_id='package', browser_access=None))
    assert events == ['proxy', 'browser', 'proxy-stop']
