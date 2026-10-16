"""Route model HTTP separately from shell, package and browser networking."""
from __future__ import annotations

import threading
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from urllib.request import proxy_bypass_environment

import httpx

PROXY_KEYS = {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}
HOP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
               'te', 'trailer', 'transfer-encoding', 'upgrade', 'host'}


def upstream_proxy(settings: dict, url: str) -> str | None:
    parts = urlsplit(url)
    values = {k.lower(): v for k, v in settings.items() if k.lower() in PROXY_KEYS}
    if proxy_bypass_environment(parts.netloc, {'no': values.get('no_proxy', '')}):
        return None
    return values.get(parts.scheme + '_proxy') or values.get('all_proxy')


class ModelRoute:
    def __init__(self, settings: dict):
        self.upstream = settings['FMST_CLAUDE_BASE_URL'].rstrip('/')
        self.auth = settings.get('FMST_CLAUDE_AUTH_TOKEN')
        self.local_token = secrets.token_urlsafe(32)
        self.proxy = upstream_proxy(settings, self.upstream)
        self.client = httpx.Client(proxy=self.proxy, trust_env=False, timeout=1800)
        route = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass  # Request headers and payloads can contain model credentials.

            def forward(self):
                sent_headers = False
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
                if route.auth:
                    # The SDK/shell snapshot gets a task-local token, never the
                    # upstream credential. Only this relay supplies it upstream.
                    for key in list(headers):
                        if key.lower() in {'authorization', 'x-api-key'}:
                            del headers[key]
                    headers['Authorization'] = 'Bearer ' + route.auth
                try:
                    with route.client.stream(self.command, route.upstream + self.path,
                                             content=body, headers=headers) as response:
                        self.send_response(response.status_code)
                        for k, v in response.headers.items():
                            if k.lower() not in HOP_HEADERS | {'content-length'}:
                                self.send_header(k, v)
                        has_body = self.command != 'HEAD' and response.status_code not in {204, 304}
                        if has_body:
                            self.send_header('Transfer-Encoding', 'chunked')
                        self.end_headers()
                        sent_headers = True
                        if not has_body:
                            return
                        for chunk in response.iter_raw():
                            if chunk:
                                self.wfile.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                                self.wfile.flush()
                        self.wfile.write(b'0\r\n\r\n');self.wfile.flush()
                except (httpx.HTTPError, OSError):
                    # Avoid logging proxy URLs, headers or reflected upstream errors.
                    if not sent_headers:
                        self.send_response(502)
                        self.send_header('Content-Length', '0')
                        self.send_header('Connection', 'close')
                        self.end_headers()
                    self.close_connection = True

            do_POST = do_GET = do_HEAD = do_PUT = do_DELETE = forward

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f'http://127.0.0.1:{self.server.server_port}'

    def environment(self, settings: dict) -> dict:
        result = {k: v for k, v in settings.items() if k.lower() not in PROXY_KEYS}
        result['FMST_CLAUDE_BASE_URL'] = self.base_url
        if self.auth:
            result['FMST_CLAUDE_AUTH_TOKEN'] = self.local_token
        return result

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
        self.client.close()
