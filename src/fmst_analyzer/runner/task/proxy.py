"""SOCKS5 native-origin access; forwards bytes without rewriting firmware HTTP."""
import select
import socket
import socketserver
import struct


def receive(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError
        data += part
    return data


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.request
        peer.settimeout(30)
        try:
            version, count = receive(peer, 2)
            methods = receive(peer, count)
            if version != 5 or 0 not in methods:
                peer.sendall(b"\x05\xff")
                return
            peer.sendall(b"\x05\x00")
            version, action, _, kind = receive(peer, 4)
            if version != 5 or action != 1:
                return
            if kind == 1:
                host = socket.inet_ntoa(receive(peer, 4))
            elif kind == 3:
                host = receive(peer, receive(peer, 1)[0]).decode("idna")
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, receive(peer, 16))
            else:
                return
            port = struct.unpack("!H", receive(peer, 2))[0]
            with socket.create_connection((host, port), timeout=15) as upstream:
                peer.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                peer.settimeout(None)
                upstream.settimeout(None)
                while True:
                    ready, _, _ = select.select([peer, upstream], [], [], 120)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is peer else peer).sendall(data)
        except (OSError, EOFError, UnicodeError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("169.254.241.2", 1080), Proxy) as server:
        server.serve_forever()
