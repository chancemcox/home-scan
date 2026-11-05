"""Structured logging with push id and one-month retention."""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import applog
import storage


class AppLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / 'logs.db')
        storage.use_sqlite()
        storage.init(self.db)
        self._prev_db = applog._DB_PATH
        self._prev_push = applog.PUSH
        applog.configure(self.db)
        self._push = mock.patch.dict(os.environ, {'HOMESCAN_PUSH': 'abc1234'})
        self._push.start()
        self.addCleanup(self._push.stop)
        applog.PUSH = applog.push_id()
        self.addCleanup(self._restore)

    def _restore(self):
        applog.configure(self._prev_db)
        applog.PUSH = self._prev_push

    def test_write_includes_push_and_persists(self):
        applog.error('sync blew up', source='cloudflare', detail='zone missing')
        rows = storage.recent_logs(self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['push'], 'abc1234')
        self.assertEqual(rows[0]['level'], 'error')
        self.assertEqual(rows[0]['source'], 'cloudflare')
        self.assertIn('sync blew up', rows[0]['message'])
        self.assertIn('zone missing', rows[0]['detail'])

    def test_expire_removes_rows_older_than_one_month(self):
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        fresh = datetime.now(timezone.utc).isoformat()
        storage.append_log(self.db, 'error', 'oldpush', 'app', 'ancient', created_at=old)
        storage.append_log(self.db, 'error', 'abc1234', 'app', 'recent', created_at=fresh)
        removed = storage.expire_logs(self.db, older_than_days=30)
        self.assertGreaterEqual(removed, 1)
        rows = storage.recent_logs(self.db)
        self.assertEqual([r['message'] for r in rows], ['recent'])

    def test_push_id_reads_env(self):
        self.assertEqual(applog.push_id(), 'abc1234')


if __name__ == '__main__':
    unittest.main()
