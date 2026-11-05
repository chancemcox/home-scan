"""Cluster failover: DNS claim, leader heartbeats, follower takeover."""
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import storage
from cloudflare_sync import Manager, CloudflareError
import ha
from ha import Cluster
from ws import Hub
import ws


class HaDNSAPI:
    def __init__(self):
        self.records = {}
        self.writes = []

    def call(self, method, path, body=None):
        if method == 'GET' and 'dns_records' in path:
            name = parse_qs(urlsplit(path).query).get('name', [''])[0]
            return [dict(r) for r in self.records.values() if r.get('name') == name]
        if method == 'POST' and path.endswith('/dns_records'):
            rid = 'dns-' + str(len(self.records) + 1)
            record = dict(body, id=rid)
            self.records[rid] = record
            self.writes.append((method, path, dict(body)))
            return dict(record)
        if method == 'PUT' and '/dns_records/' in path:
            rid = path.rsplit('/', 1)[-1]
            record = dict(body, id=rid)
            self.records[rid] = record
            self.writes.append((method, path, dict(body)))
            return dict(record)
        raise AssertionError((method, path, body))


class EnsureHaDnsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / 'db.sqlite')
        self.cfg = Path(self.temp.name) / 'cf.json'
        self.cfg.write_text(json.dumps(dict(
            api_token='token-value-for-ha-tests', zone_id='zone', account_id='account',
            zone_name='example.com', suffix='house.example.com', tunnel_id='tunnel')))
        storage.init(self.db)
        self.api = HaDNSAPI()
        self.m = Manager(self.db, self.cfg, lambda token: self.api)
        self.m.init()

    def test_creates_and_updates_ha_record(self):
        first = self.m.ensure_ha_dns('192.168.2.100')
        self.assertEqual(first['hostname'], 'homescan.house.example.com')
        self.assertEqual(list(self.api.records.values())[0]['content'], '192.168.2.100')
        self.assertEqual(list(self.api.records.values())[0]['comment'], 'homescan:ha')
        self.m.ensure_ha_dns('192.168.2.101')
        self.assertEqual(list(self.api.records.values())[0]['content'], '192.168.2.101')

    def test_refuses_foreign_record(self):
        self.api.records['x'] = dict(id='x', name='homescan.house.example.com', type='A',
                                     content='10.0.0.1', comment='manual')
        with self.assertRaisesRegex(CloudflareError, 'owned by another'):
            self.m.ensure_ha_dns('192.168.2.100')


class ClusterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / 'db.sqlite')
        self.cfg = Path(self.temp.name) / 'cf.json'
        self.cfg.write_text(json.dumps(dict(
            api_token='token-value-for-ha-tests', zone_id='zone', account_id='account',
            zone_name='example.com', suffix='house.example.com')))
        storage.init(self.db)
        self.api = HaDNSAPI()
        self.m = Manager(self.db, self.cfg, lambda token: self.api)
        self.m.init()

    def test_disabled_cluster_always_accepts_scans(self):
        cluster = Cluster(self.m, enabled=False, local_ip='192.168.2.100', node_id='n1')
        self.assertTrue(cluster.is_leader())
        self.assertEqual(cluster.public_state()['role'], 'disabled')

    def test_missing_dns_claims_leadership(self):
        cluster = Cluster(self.m, enabled=True, local_ip='192.168.2.100', node_id='node-a',
                          hostname='homescan.house.example.com', port=8080)
        with mock.patch('ha.resolve_ipv4', return_value=[]):
            cluster.claim = mock.Mock(wraps=cluster.claim)
            with mock.patch.object(cluster, '_lead_until_step_down'):
                cluster.tick()
        cluster.claim.assert_called()
        self.assertEqual(cluster.role, 'leader')
        self.assertEqual(list(self.api.records.values())[0]['content'], '192.168.2.100')

    def test_dns_pointing_here_becomes_leader(self):
        cluster = Cluster(self.m, enabled=True, local_ip='192.168.2.100', node_id='node-a',
                          hostname='homescan.house.example.com')
        with mock.patch('ha.resolve_ipv4', return_value=['192.168.2.100']):
            with mock.patch.object(cluster, '_lead_until_step_down'):
                cluster.tick()
        self.assertEqual(cluster.role, 'leader')
        self.assertTrue(cluster.public_state()['scanning'])

    def test_follower_times_out_and_claims(self):
        cluster = Cluster(self.m, enabled=True, local_ip='192.168.2.101', node_id='node-b',
                          hostname='homescan.house.example.com')
        with mock.patch('ha.TIMEOUT', 0.2), mock.patch('ha.HEARTBEAT', 0.05):
            with mock.patch('ha.connect_ha', side_effect=ConnectionError('down')):
                with mock.patch('ha.resolve_ipv4', return_value=['192.168.2.100']):
                    cluster.tick()
        self.assertEqual(cluster.role, 'leader')
        self.assertEqual(list(self.api.records.values())[0]['content'], '192.168.2.101')

    def test_non_leader_ha_endpoint_returns_503(self):
        cluster = Cluster(self.m, enabled=True, local_ip='192.168.2.101', node_id='node-b',
                          hostname='homescan.house.example.com')
        cluster.role = 'follower'
        sent = {}

        class Handler:
            def send(self, code, body):
                sent['code'] = code
                sent['body'] = json.loads(body.decode())

        cluster.serve(Handler())
        self.assertEqual(sent['code'], 503)
        self.assertFalse(sent['body']['ha']['scanning'])


class HaServerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / 'db.sqlite')
        self.cfg = Path(self.temp.name) / 'cf.json'
        self.cfg.write_text(json.dumps(dict(
            api_token='token-value-for-ha-tests', zone_id='zone', account_id='account',
            zone_name='chancecox.com', installation_id='install-1')))
        storage.init(self.db)
        self.api = HaDNSAPI()
        self.cloudflare = Manager(self.db, self.cfg, lambda token: self.api)
        self.cloudflare.init()
        self.cluster = Cluster(self.cloudflare, enabled=True, local_ip='127.0.0.1',
                               node_id='leader-node', hostname='127.0.0.1', port=0)
        self.cluster.role = 'leader'
        self.cluster.claim = lambda reason='x': '127.0.0.1'
        self.hub = Hub()

        import app as app_module
        self.app = app_module
        self.app.DB = self.db
        self.app.MODE = 'agent'
        self.app.TOKEN = 't' * 32
        self.app.CLOUDFLARE = self.cloudflare
        self.app.CLUSTER = self.cluster
        self.app.HUB = self.hub
        self.app.Handler.log_message = lambda *a, **k: None
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.app.Handler)
        self.cluster.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_leader_websocket_sends_heartbeat_snapshot(self):
        client = ha.connect_ha('127.0.0.1', self.cluster.port)
        self.addCleanup(client.close)
        client.sock.settimeout(2)
        opcode, payload = client.recv()
        self.assertEqual(opcode, ws.OP_TEXT)
        message = json.loads(payload.decode())
        self.assertEqual(message['type'], 'heartbeat')
        self.assertEqual(message['node_id'], 'leader-node')

    def test_scan_rejected_on_standby(self):
        self.cluster.role = 'follower'
        import urllib.request
        body = json.dumps({'hosts': [{'ip': '192.168.2.9', 'mac': '02:11:22:33:44:55', 'hostname': 'x'}]}).encode()
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.cluster.port}/api/scan', data=body, method='POST',
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.app.TOKEN,
                     'Content-Length': str(len(body))})
        try:
            urllib.request.urlopen(req, timeout=3)
            self.fail('expected 503')
        except Exception as exc:
            self.assertEqual(getattr(exc, 'code', None), 503)


if __name__ == '__main__':
    unittest.main()
