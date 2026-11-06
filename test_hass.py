"""Home Assistant app packaging and option loading."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ADDON = ROOT / 'homescan'
PAYLOAD = (
    'app.py', 'storage.py', 'cloudflare_sync.py', 'ws.py', 'ha.py', 'auth.py',
    'd1.py', 'do_db.py', 'cluster_state.py', 'applog.py', 'index.html',
    'login.html', 'login.js', 'app.js', 'style.css', 'deco.py',
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class HassAddonTests(unittest.TestCase):
    def test_addon_payload_matches_repository(self):
        for name in PAYLOAD:
            self.assertEqual(digest(ADDON / name), digest(ROOT / name), name)
        config = (ADDON / 'config.yaml').read_text(encoding='utf-8')
        self.assertIn('ingress: true', config)
        self.assertIn('ingress_port: 8099', config)
        self.assertIn('host_network: true', config)
        self.assertIn('NET_RAW', config)
        self.assertIn('slug: homescan', config)
        repo = (ROOT / 'repository.yaml').read_text(encoding='utf-8')
        self.assertIn('name: HomeScan', repo)
        dockerfile = (ADDON / 'Dockerfile').read_text(encoding='utf-8')
        for name in PAYLOAD:
            self.assertIn(name, dockerfile)

    def test_addon_options_overlay(self):
        import app
        old = (app.MODE, app.TOKEN, app.NETWORK, os.environ.get('HA_LOCAL_IP'))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'options.json'
            path.write_text(json.dumps({
                'scan_network': '10.1.0.0/24',
                'scan_mode': 'nmap',
                'ha_local_ip': '10.1.0.8',
                'ingest_token': '',
            }), encoding='utf-8')
            os.environ['HASS_OPTIONS'] = str(path)
            try:
                app.apply_addon_options()
                self.assertEqual(app.NETWORK, '10.1.0.0/24')
                self.assertEqual(app.MODE, 'nmap')
                self.assertEqual(app.TOKEN, old[1])
                self.assertEqual(os.environ['HA_LOCAL_IP'], '10.1.0.8')
            finally:
                app.MODE, app.TOKEN, app.NETWORK = old[:3]
                os.environ.pop('HASS_OPTIONS', None)
                if old[3] is None:
                    os.environ.pop('HA_LOCAL_IP', None)
                else:
                    os.environ['HA_LOCAL_IP'] = old[3]
