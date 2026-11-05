"""Durable Object SQL storage backend."""
import json
import unittest
from io import BytesIO
from urllib.error import HTTPError

import storage
from do_db import DoConnection, DoDbError


class FakeResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self.headers = {'Content-Type': 'application/json'}
        self._raw = json.dumps(payload).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class DoDbTests(unittest.TestCase):
    def tearDown(self):
        storage.use_sqlite()

    def test_execute_and_backend_switch(self):
        calls = []

        def opener(req, timeout=0):
            body = json.loads(req.data.decode())
            merged = {}
            merged.update(getattr(req, 'unredirected_hdrs', {}) or {})
            merged.update(dict(req.headers))
            headers = {str(k).lower(): v for k, v in merged.items()}
            calls.append((req.full_url, req.get_method(), body, headers.get('x-homescan-cluster')))
            return FakeResponse({
                'success': True,
                'results': [{'device_id': 'mac:AA'}],
                'meta': {'last_row_id': 3, 'changes': 1},
            })

        storage.use_do('https://homescan-cluster.example.workers.dev', 'secret', opener=opener)
        self.assertEqual(storage.backend_state(), dict(kind='durable-object', database_id='', shared=True))
        with storage.connect('/unused.db') as db:
            cursor = db.execute('SELECT device_id FROM devices WHERE device_id=?', ('mac:AA',))
            row = cursor.fetchone()
            self.assertEqual(row['device_id'], 'mac:AA')
            self.assertEqual(cursor.lastrowid, 3)
        self.assertEqual(calls[0][0], 'https://homescan-cluster.example.workers.dev/v1/sql')
        self.assertEqual(calls[0][2]['params'], ['mac:AA'])
        self.assertEqual(calls[0][3], 'secret')

    def test_error_surface(self):
        def opener(req, timeout=0):
            raise HTTPError(req.full_url, 400, 'Bad', {}, BytesIO(b'{"success":false,"error":"nope"}'))

        conn = DoConnection('https://example.workers.dev', 'secret', opener=opener)
        with self.assertRaisesRegex(DoDbError, 'nope'):
            conn.execute('SELECT 1')


if __name__ == '__main__':
    unittest.main()
