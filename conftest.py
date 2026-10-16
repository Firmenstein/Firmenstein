"""Repository test bootstrap and opt-in G0 offline boundary."""

from pathlib import Path
import importlib.util
import os
import sys

from dotenv import load_dotenv
import pytest


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT / "src"))


class G0ExternalOperation(BaseException):
    """Stop external work even when production code catches Exception."""


@pytest.fixture
def g0_external_operation(request):
    if not request.config.getoption("--g0"):
        pytest.skip("requires the opt-in offline guard")
    return G0ExternalOperation


def _offline_audit(event, args):
    if event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork",
        "socket.connect", "socket.bind", "socket.getaddrinfo", "socket.sendto",
    }:
        raise G0ExternalOperation(f"G0 forbids external operation: {event}")


def _forbid_ida(*args, **kwargs):
    raise G0ExternalOperation("G0 forbids opening an IDA database")


def pytest_addoption(parser):
    parser.addoption(
        "--g0", action="store_true", help="Run offline with external operations blocked."
    )


def pytest_configure(config):
    if not config.getoption("--g0"):
        return
    # Install before collection: imports must not start external work either.
    sys.addaudithook(_offline_audit)
    if not os.environ.get("IDADIR") or importlib.util.find_spec("idapro") is None:
        return
    try:
        import idapro
        from ida_domain import Database
    except ImportError:
        # The Python package may be installed without a usable native SDK.
        return

    patch = pytest.MonkeyPatch()
    patch.setattr(idapro, "open_database", _forbid_ida)
    patch.setattr(Database, "open", _forbid_ida)
    config._g0_patch = patch


def pytest_collection_modifyitems(config, items):
    if config.getoption("--g0"):
        for item in items:
            if item.get_closest_marker("external"):
                item.add_marker(pytest.mark.skip(reason="G0 excludes real external integration"))


def pytest_unconfigure(config):
    patch = getattr(config, "_g0_patch", None)
    if patch is not None:
        patch.undo()
