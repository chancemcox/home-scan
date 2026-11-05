"""HTTP API coverage for the HomeScan dashboard and scanner ingest."""
import base64
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import storage
from cloudflare_sync import Manager
from ha import Cluster
from ws import Hub, OP_CLOSE, OP_PING, OP_TEXT, accept_key


INGEST = 'ingest-token-for-homescan-tests-32b'


class ListingAPI:
    def __init__(self):
        self.zone = {'id': 'zone', 'name': 'chancecox.com', 'account': {'id': 'account'}}
        self.tunnel = {
            'id': '11111111-2222-3333-4444-555555555555',
            'name': 'homescan',
            'config_src': 'cloudflare',
            'status': 'healthy',
            'created_at': '2026-01-01T00:00:00Z',
            'connections': [{'id': 'c1'}],
        }
        self.config = {'ingress': [{'hostname': 'nas.house.chancecox.com', 'service': 'http://192.168.2.5:80'},
                                   {'service': 'http_status:404'}]}

    def call(self, method, path, body=None):
        if method == 'GET' and path.startswith('/zones?'):
            if 'name=' in path:
                return [dict(self.zone)] if 'chancecox.com' in path or 'house.chancecox.com' in path else []
            return [dict(self.zone)]
        if method == 'GET' and path.endswith('/configurations'):
            return {'config': json.loads(json.dumps(self.config))}
        if method == 'GET' and path.endswith('/' + self.tunnel['id']):
            return dict(self.tunnel)
        if method == 'GET' and 'cfd_tunnel' in path:
            return [dict(self.tunnel)]
        if method == 'GET' and path.endswith('/token'):
            return 'connector-token'
        if method == 'GET' and path.endswith('/d1/database'):
            return [{'uuid': 'd1-homescan-id', 'name': 'homescan'}]
        if method == 'POST' and path.endswith('/d1/database'):
            return {'uuid': 'd1-homescan-id', 'name': body['name']}
        raise AssertionError((method, path, body))


class AppServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.db = str(Path(cls.temp.name) / 'homescan.db')
        cls.cfg = Path(cls.temp.name) / 'cloudflare.json'
        cls.cfg.write_text(json.dumps({
            'api_token': 'dashboard-secret-token',
            'zone_id': 'zone',
            'zone_name': 'chancecox.com',
            'account_id': 'account',
            'tunnel_id': '11111111-2222-3333-4444-555555555555',
        }))
        os.environ['DB_PATH'] = cls.db
        os.environ['SCAN_MODE'] = 'agent'
        os.environ['INGEST_TOKEN'] = INGEST
        os.environ['USERS_PATH'] = str(Path(cls.temp.name) / 'users.json')
        import auth
        import app as app_module
        cls.auth = auth
        auth.USERS_PATH = Path(os.environ['USERS_PATH'])
        auth.BOOTSTRAP_PASSWORD_PATH = Path(cls.temp.name) / 'initial-admin-password.txt'
        auth._sessions.clear()
        auth._bootstrap_password = None
        auth.init()
        cls.app = app_module
        cls.app.DB = cls.db
        cls.app.MODE = 'agent'
        cls.app.TOKEN = INGEST
        cls.app.HUB = Hub()
        storage.init(cls.db)
        cls.api = ListingAPI()
        cls.app.CLOUDFLARE = Manager(cls.db, cls.cfg, lambda token: cls.api)
        cls.app.CLOUDFLARE.init()
        cls.app.CLUSTER = Cluster(cls.app.CLOUDFLARE, enabled=False, local_ip='192.168.2.100', node_id='test-node')
        storage.record_batches(cls.db, [dict(source='network', hosts=[dict(
            ip='192.168.2.5', mac='02:11:22:33:44:55', hostname='NAS')])])
        cls.app.Handler.log_message = lambda *args, **kwargs: None
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), cls.app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_address[1]}'
        password = auth.bootstrap_password() or os.environ.get('HOMESCAN_ADMIN_PASSWORD')
        if not password:
            # auth.init may have run before USERS_PATH was set; seed explicitly.
            auth.init()
            password = auth.bootstrap_password()
        session = auth.login(auth.DEFAULT_USER, password, remember=False)
        cls.cookie = f'{auth.SESSION_COOKIE}={session["token"]}'
        cls.password = password

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp.cleanup()

    def auth_headers(self, extra=None):
        headers = {'Cookie': self.cookie}
        if extra:
            headers.update(extra)
        return headers

    def get(self, path, headers=None, auth=True):
        hdrs = self.auth_headers(headers) if auth else dict(headers or {})
        req = urllib.request.Request(self.base + path, headers=hdrs)
        # Preserve 302 Location checks for login redirects.
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=5) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def post(self, path, body, headers=None, origin=True, auth=True):
        data = json.dumps(body).encode()
        hdrs = {'Content-Type': 'application/json', 'Content-Length': str(len(data))}
        if auth:
            hdrs['Cookie'] = self.cookie
        if origin:
            host = self.base.removeprefix('http://')
            hdrs.update({'Origin': self.base, 'Host': host, 'Sec-Fetch-Site': 'same-origin'})
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self.base + path, data=data, headers=hdrs, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read().decode()), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode()), dict(exc.headers)

    def test_health_and_static_assets(self):
        code, body, headers = self.get('/health', auth=False)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {'ok': True})
        self.assertIn("default-src 'self'", headers.get('Content-Security-Policy', ''))
        code, body, _ = self.get('/login', auth=False)
        self.assertEqual(code, 200)
        self.assertIn(b'Sign in', body)
        code, body, _ = self.get('/login.js', auth=False)
        self.assertEqual(code, 200)
        self.assertIn(b'/api/login', body)
        for path, needle in (('/', b'HomeScan'), ('/app.js', b'schedulePoll'), ('/style.css', b'--mint')):
            code, body, _ = self.get(path)
            self.assertEqual(code, 200)
            self.assertIn(needle, body)
        code, _, headers = self.get('/', auth=False)
        self.assertEqual(code, 302)
        self.assertEqual(headers.get('Location'), '/login')

    def test_login_remember_me_and_logout(self):
        code, payload, headers = self.post('/api/login', {
            'username': 'admin', 'password': self.password, 'remember': True
        }, auth=False, origin=False)
        self.assertEqual(code, 200)
        self.assertTrue(payload['ok'])
        cookie = headers.get('Set-Cookie', '')
        self.assertIn(self.auth.SESSION_COOKIE + '=', cookie)
        self.assertIn('Max-Age=', cookie)
        code, body, _ = self.get('/api/me', headers={'Cookie': cookie.split(';', 1)[0]})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['username'], 'admin')
        code, payload, headers = self.post('/api/logout', {}, headers={'Cookie': cookie.split(';', 1)[0]}, origin=False)
        self.assertEqual(code, 200)
        self.assertIn('Max-Age=0', headers.get('Set-Cookie', ''))
        code, body, _ = self.get('/api/devices', auth=False)
        self.assertEqual(code, 401)

    def test_devices_payload_hides_token(self):
        code, body, _ = self.get('/api/devices')
        self.assertEqual(code, 200)
        payload = json.loads(body)
        self.assertTrue(payload['cloudflare']['configured'])
        self.assertNotIn('dashboard-secret-token', body.decode())
        self.assertTrue(any(d['ip'] == '192.168.2.5' for d in payload['devices']))

    def test_cloudflare_list_endpoints(self):
        code, body, _ = self.get('/api/cloudflare/tunnels')
        self.assertEqual(code, 200)
        tunnels = json.loads(body)
        self.assertTrue(tunnels['configured'])
        self.assertEqual(tunnels['tunnels'][0]['name'], 'homescan')
        code, body, _ = self.get('/api/cloudflare/zones')
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['zones'][0]['name'], 'chancecox.com')

    def test_same_origin_required_for_settings(self):
        code, payload, _ = self.post('/api/cloudflare/sync', {}, origin=False)
        self.assertEqual(code, 403)
        self.assertIn('dashboard', payload['error'])

    def test_connect_endpoint_rotates_token(self):
        setup_api = ListingAPI()
        with mock.patch.object(self.app.CLOUDFLARE, 'api_factory', lambda token: setup_api):
            # Keep path writes on the temp config via connect_cloudflare through Manager.connect
            with mock.patch('cloudflare_sync.TOKEN_FILE', Path(self.temp.name) / 'connector.token'):
                code, payload, _ = self.post('/api/cloudflare/connect', {
                    'api_token': 'rotated-cloudflare-api-token',
                    'tunnel': False,
                    'd1': False,
                })
        self.assertEqual(code, 200)
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['zone'], 'chancecox.com')
        saved = json.loads(self.cfg.read_text())
        self.assertEqual(saved['api_token'], 'rotated-cloudflare-api-token')
        self.assertNotIn('d1_database_id', saved)
        self.assertNotIn('rotated-cloudflare-api-token', json.dumps(self.app.CLOUDFLARE.public_state()))
        storage.use_sqlite()

    def test_scan_ingest_requires_bearer_and_records(self):
        code, payload, _ = self.post('/api/scan', {'hosts': [{'ip': '192.168.2.9', 'mac': '02:AA:BB:CC:DD:EE', 'hostname': 'Phone'}]},
                                  headers={'Authorization': 'Bearer wrong'}, origin=False, auth=False)
        self.assertEqual(code, 401)
        code, payload, _ = self.post('/api/scan', {
            'sources': [{'source': 'network', 'hosts': [{'ip': '192.168.2.9', 'mac': '02:AA:BB:CC:DD:EE', 'hostname': 'Phone'}]}]
        }, headers={'Authorization': 'Bearer ' + INGEST}, origin=False, auth=False)
        self.assertEqual(code, 200)
        self.assertTrue(payload['ok'])
        devices = storage.inventory(self.db)['devices']
        self.assertTrue(any(d['ip'] == '192.168.2.9' for d in devices))

    def test_scan_drops_empty_deco_error_batch(self):
        before = len(storage.inventory(self.db)['devices'])
        code, payload, _ = self.post('/api/scan', {
            'sources': [{'source': 'deco', 'hosts': [], 'error': 'timeout'}]
        }, headers={'Authorization': 'Bearer ' + INGEST}, origin=False, auth=False)
        self.assertEqual(code, 400)
        self.assertEqual(len(storage.inventory(self.db)['devices']), before)

    def test_websocket_upgrade_sends_snapshot(self):
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f'GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n'
            f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
            f'Cookie: {self.cookie}\r\n\r\n'
        ).encode()
        with socket.create_connection(('127.0.0.1', self.server.server_address[1]), timeout=5) as sock:
            sock.sendall(req)
            buf = b''
            while b'\r\n\r\n' not in buf:
                chunk = sock.recv(4096)
                self.assertTrue(chunk)
                buf += chunk
            head, rest = buf.split(b'\r\n\r\n', 1)
            self.assertIn(b'101', head.split(b'\r\n', 1)[0])
            self.assertIn(accept_key(key).encode(), head)
            pending = rest

            def read(n):
                nonlocal pending
                while len(pending) < n:
                    chunk = sock.recv(4096)
                    self.assertTrue(chunk)
                    pending += chunk
                out, pending = pending[:n], pending[n:]
                return out

            header = read(2)
            opcode, length = header[0] & 0x0F, header[1] & 0x7F
            if length == 126:
                length = struct.unpack('!H', read(2))[0]
            elif length == 127:
                length = struct.unpack('!Q', read(8))[0]
            payload = read(length)
            self.assertEqual(opcode, OP_TEXT)
            self.assertIn('devices', json.loads(payload))
            # Ask the server to close cleanly.
            mask = os.urandom(4)
            sock.sendall(bytes([0x80 | OP_CLOSE, 0x80]) + mask)


class FrontendAssetTests(unittest.TestCase):
    def read(self, name):
        return Path(__file__).with_name(name).read_text(encoding='utf-8')

    def test_connection_form_supports_token_edit(self):
        html = self.read('index.html')
        js = self.read('app.js')
        self.assertIn('id="connection-form"', html)
        self.assertIn('id="cf-token"', html)
        self.assertIn('id="cf-tunnel"', html)
        self.assertIn('id="ha-state"', html)
        self.assertIn('id="dns-suffix"', html)
        self.assertIn('id="logout-button"', html)
        self.assertIn('id="cf-d1"', html)
        self.assertIn('/api/cloudflare/connect', js)
        self.assertIn('/api/cloudflare/domain', js)
        self.assertIn('d1:$(\'cf-d1\').checked', js)
        self.assertIn('Leave blank to keep the current token', js)
        self.assertIn('haState', js)

    def test_tunnel_delete_and_multi_hostname_ui(self):
        html = self.read('index.html')
        js = self.read('app.js')
        self.assertIn('id="tunnel-add-hostname"', html)
        self.assertIn('origin host and port', html)
        self.assertIn('url.hostname=host.value.trim()', js)
        self.assertIn('/api/cloudflare/tunnels/delete-hostname', js)
        self.assertIn('/api/cloudflare/tunnels/delete', js)
        self.assertIn('schedulePoll', js)
        self.assertIn('Reconnecting…', js)
        self.assertNotIn("Cannot reach HomeScan. Retrying…';setTimeout(connect,2000)", js)


if __name__ == '__main__':
    unittest.main()
