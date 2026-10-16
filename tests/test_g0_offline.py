"""The offline guard fails before a real process or network operation starts."""

import socket
import subprocess
import sys

import pytest

def test_g0_blocks_process_before_execution(g0_external_operation, tmp_path):
    sentinel = tmp_path / "unexpected-child-output"
    with pytest.raises(g0_external_operation, match="subprocess.Popen"):
        subprocess.run([
            sys.executable, "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
            str(sentinel),
        ], check=True)
    assert not sentinel.exists()


def test_g0_blocks_network_before_connection(g0_external_operation):
    with socket.socket() as connection:
        with pytest.raises(g0_external_operation, match="socket.connect"):
            connection.connect(("127.0.0.1", 9))
    with pytest.raises(g0_external_operation, match="socket.getaddrinfo"):
        socket.getaddrinfo("g0.invalid", 80)
