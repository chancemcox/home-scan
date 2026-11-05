"""Shared Cloudflare D1 adapter and ensure_database helpers."""
import unittest

import storage
from d1 import D1Connection, ensure_database


class FakeD1API:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.writes = []

    def call(self, method, path, body=None):
        if method == 'GET' and path.endswith('/d1/database'):
            return list(self.rows)
        if method == 'POST' and path.endswith('/d1/database'):
            row = dict(uuid='created-d1', name=body['name'])
            self.rows.append(row)
            self.writes.append(body)
            return dict(row)
        raise AssertionError((method, path, body))


class D1HelperTests(unittest.TestCase):
    def tearDown(self):
        storage.use_sqlite()

    def test_ensure_database_reuses_shared_homescan(self):
        api = FakeD1API([{'uuid': 'existing', 'name': 'homescan'}])
        self.assertEqual(ensure_database(api, 'account'), 'existing')
        self.assertEqual(api.writes, [])

    def test_ensure_database_creates_when_missing(self):
        api = FakeD1API()
        self.assertEqual(ensure_database(api, 'account'), 'created-d1')
        self.assertEqual(api.writes[0]['name'], 'homescan')

    def test_connection_execute_and_backend_switch(self):
        calls = []

        def caller(sql, params):
            calls.append((sql, params))
            return [{'results': [{'username': 'admin'}], 'meta': {'last_row_id': 7, 'changes': 1}}]

        storage.use_d1('account', 'db-id', 'token-value-with-enough-length', caller=caller)
        self.assertEqual(storage.backend_state(), dict(kind='d1', database_id='db-id', shared=True))
        with storage.connect('/unused.db') as db:
            cursor = db.execute('SELECT username FROM users WHERE id=?', (1,))
            row = cursor.fetchone()
            self.assertEqual(row['username'], 'admin')
            self.assertEqual(cursor.lastrowid, 7)
        self.assertEqual(calls[0][0], 'SELECT username FROM users WHERE id=?')
        self.assertEqual(calls[0][1], [1])
        storage.use_sqlite()
        self.assertEqual(storage.backend_state()['kind'], 'sqlite')


if __name__ == '__main__':
    unittest.main()
