"""Direct coverage for inventory helpers and MAC identity rules."""
import tempfile
import unittest
from pathlib import Path

import storage


MAC = '02:11:22:33:44:55'


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / 'storage.db')
        storage.init(self.db)

    def test_mac_normalization_and_identity(self):
        self.assertEqual(storage.mac_address('aa-bb-cc-dd-ee-ff'), 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(storage.identity('192.168.2.5', MAC), 'mac:' + MAC)
        self.assertEqual(storage.identity('192.168.2.5', ''), 'ip:192.168.2.5')
        self.assertEqual(storage.mac_address('not-a-mac'), '')
        self.assertEqual(storage.mac_address('00:00:00:00:00:00'), '')

    def test_normalize_dedupes_and_rejects_invalid_ip(self):
        rows = storage.normalize([
            dict(ip='192.168.2.5', mac='', hostname='anon'),
            dict(ip='192.168.2.5', mac=MAC, hostname='NAS'),
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], dict(ip='192.168.2.5', mac=MAC, hostname='NAS', device_id='mac:' + MAC))
        with self.assertRaises(ValueError):
            storage.normalize([dict(ip='not-an-ip', mac=MAC, hostname='bad')])
        self.assertEqual(storage.mac_address('01:11:22:33:44:55'), '')

    def test_inventory_marks_fresh_and_stale(self):
        storage.record_batches(self.db, [dict(source='network', hosts=[dict(ip='192.168.2.5', mac=MAC, hostname='NAS')])])
        inv = storage.inventory(self.db)
        self.assertFalse(inv['stale'])
        self.assertEqual(inv['devices'][0]['status'], 'seen')
        self.assertEqual(inv['devices'][0]['device_id'], 'mac:' + MAC)

    def test_ip_only_promotes_to_mac(self):
        storage.record_batches(self.db, [dict(source='network', hosts=[dict(ip='192.168.2.5', mac='', hostname='anon')])])
        storage.record_batches(self.db, [dict(source='network', hosts=[dict(ip='192.168.2.5', mac=MAC, hostname='NAS')])])
        devices = storage.inventory(self.db)['devices']
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['device_id'], 'mac:' + MAC)
        self.assertEqual(devices[0]['hostname'], 'NAS')

    def test_app_settings_round_trip(self):
        storage.set_settings(self.db, {'suffix': 'house.example.com', 'zone_name': 'example.com'})
        self.assertEqual(storage.get_settings(self.db, ('suffix',)), {'suffix': 'house.example.com'})
        storage.set_settings(self.db, {'suffix': 'lan.example.com'})
        self.assertEqual(storage.get_settings(self.db)['suffix'], 'lan.example.com')
        self.assertEqual(storage.get_settings(self.db)['zone_name'], 'example.com')


if __name__ == '__main__':
    unittest.main()
