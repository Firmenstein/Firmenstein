"""Make an existing loopback-only host proxy reachable by its task container.

The proxy configuration is reused, never rebound or modified. The relay listens
only on the Docker bridge gateway and accepts only this container's source IP.
It forwards bytes without recording them and lives for the repair session.
"""
import ipaddress
import select
import socket
import socketserver
import threading
from urllib.parse import urlsplit, urlunsplit


class ProxyRelay:
    def __init__(self, url: str, *, gateway: str, container_ip: str):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.port:
            raise ValueError("Configured proxy needs a supported URL scheme and explicit port")
        destination = (parsed.hostname, parsed.port)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if self.client_address[0] != container_ip:
                    return
                try:
                    with socket.create_connection(destination, timeout=10) as remote:
                        remote.settimeout(None)
                        while True:
                            readable, _, _ = select.select([remote, self.request], [], [], 180)
                            if not readable:
                                return
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (remote if source is self.request else self.request).sendall(data)
                except OSError:
                    return

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server((gateway, 0), Handler)
        self.closed = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        authentication = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
        self.url = urlunsplit((parsed.scheme, authentication + gateway + ":" + str(self.server.server_address[1]),
                              parsed.path, parsed.query, parsed.fragment))

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def loopback_proxy(url: str) -> bool:
    host = urlsplit(url).hostname
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def rootless_proxy(url: str) -> str:
    """Reach the existing host proxy through RootlessKit's slirp gateway."""
    import os
    parsed = urlsplit(url)
    authentication = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    gateway = os.getenv("FMST_RUNNER_HOST_GATEWAY", "10.0.2.2")
    return urlunsplit((parsed.scheme, authentication + gateway + ":" + str(parsed.port),
                      parsed.path, parsed.query, parsed.fragment))
