"""Model routing must preserve streaming without leaking into tool egress."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from fmst_analyzer.runner.task.model_route import ModelRoute, upstream_proxy


def test_model_proxy_selection_respects_destination_and_no_proxy():
    settings = {'HTTPS_PROXY': 'http://model-proxy.invalid:1234', 'NO_PROXY': 'localhost,.internal'}
    assert upstream_proxy(settings, 'https://api.example/v1') == settings['HTTPS_PROXY']
    assert upstream_proxy(settings, 'https://node.internal/v1') is None
    assert upstream_proxy(settings, 'http://example.com') is None


@pytest.mark.external
def test_route_streams_auth_and_keeps_shell_environment_separate():
    observed = {}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            observed['path'] = self.path
            observed['auth'] = self.headers['Authorization']
            observed['body'] = self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            self.wfile.write(b'data: first\n\ndata: second\n\n')

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-Length', '123')
            self.end_headers()

    server = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = {'FMST_CLAUDE_BASE_URL': f'http://127.0.0.1:{server.server_port}/api',
                'FMST_CLAUDE_AUTH_TOKEN': 'upstream-fixture-only',
                'HTTP_PROXY': 'http://unused.invalid:1234', 'NO_PROXY': '127.0.0.1'}
    route = ModelRoute(settings)
    try:
        env = route.environment(settings)
        assert not any(k.lower().endswith('_proxy') for k in env)
        assert env['FMST_CLAUDE_BASE_URL'] == route.base_url
        assert env['FMST_CLAUDE_AUTH_TOKEN'] != settings['FMST_CLAUDE_AUTH_TOKEN']
        with httpx.Client(trust_env=False) as client:
            response = client.post(route.base_url + '/v1/messages', content=b'fixture',
                                   headers={'Authorization': 'Bearer ' + env['FMST_CLAUDE_AUTH_TOKEN']})
            assert response.status_code == 200
            assert response.content == b'data: first\n\ndata: second\n\n'
            assert observed == {'path': '/api/v1/messages', 'auth': 'Bearer upstream-fixture-only', 'body': b'fixture'}
            response = client.head(route.base_url + '/health')
            assert response.status_code == 200 and response.content == b''
            assert 'transfer-encoding' not in response.headers
    finally:
        route.close()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.external
def test_unreachable_upstream_returns_sanitized_error():
    server = ThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
    port = server.server_port
    server.server_close()
    route = ModelRoute({'FMST_CLAUDE_BASE_URL': f'http://127.0.0.1:{port}/private'})
    try:
        with httpx.Client(trust_env=False) as client:
            response = client.get(route.base_url + '/v1/messages')
        assert response.status_code == 502
        assert response.content == b''
    finally:
        route.close()
