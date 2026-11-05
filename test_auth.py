"""Dashboard authentication, sessions, and remember-me cookies."""
import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import auth


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.users = Path(self.temp.name) / 'users.json'
        self.bootstrap = Path(self.temp.name) / 'initial-admin-password.txt'
        auth._sessions.clear()
        auth._bootstrap_password = None
        self.addCleanup(lambda: os.environ.pop('HOMESCAN_ADMIN_PASSWORD', None))
        os.environ.pop('HOMESCAN_ADMIN_PASSWORD', None)
        self._users_patch = mock.patch.object(auth, 'USERS_PATH', self.users)
        self._boot_patch = mock.patch.object(auth, 'BOOTSTRAP_PASSWORD_PATH', self.bootstrap)
        self._users_patch.start(); self._boot_patch.start()
        self.addCleanup(self._users_patch.stop)
        self.addCleanup(self._boot_patch.stop)
        auth.init()
        self.password = auth.bootstrap_password()

    def test_admin_seeded_without_hardcoded_password(self):
        users = json.loads(self.users.read_text())['users']
        self.assertIn('admin', users)
        self.assertTrue(self.bootstrap.exists())
        self.assertEqual(self.bootstrap.read_text().strip(), self.password)
        self.assertNotIn(self.password, self.users.read_text())
        result = auth.login('admin', self.password, remember=False)
        self.assertEqual(result['username'], 'admin')
        self.assertIsNone(result['max_age'])
        self.assertEqual(auth.session_user(result['token']), 'admin')

    def test_env_password_used_when_provided(self):
        auth._sessions.clear()
        self.users.unlink(missing_ok=True)
        self.bootstrap.unlink(missing_ok=True)
        os.environ['HOMESCAN_ADMIN_PASSWORD'] = 'EnvPassword!!99'
        auth.init()
        self.assertEqual(auth.bootstrap_password(), 'EnvPassword!!99')
        self.assertFalse(self.bootstrap.exists())
        auth.login('admin', 'EnvPassword!!99', False)

    def test_invalid_login_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Invalid'):
            auth.login('admin', 'wrong-password', False)
        with self.assertRaisesRegex(ValueError, 'username and password'):
            auth.login('', '', False)

    def test_username_is_case_insensitive(self):
        for name in ('Admin', 'ADMIN', 'aDmIn'):
            result = auth.login(name, self.password, remember=False)
            self.assertEqual(result['username'], 'admin')
            self.assertEqual(auth.session_user(result['token']), 'admin')
            auth.logout(result['token'])

    def test_remember_me_sets_longer_cookie_lifetime(self):
        session = auth.login('admin', self.password, remember=False)
        remembered = auth.login('admin', self.password, remember=True)
        self.assertIsNone(session['max_age'])
        self.assertGreater(remembered['max_age'], 0)
        self.assertIn('Max-Age=', auth.cookie_header(remembered['token'], True, remembered['max_age']))
        self.assertNotIn('Max-Age=', auth.cookie_header(session['token'], False, None))

    def test_logout_and_expiry(self):
        result = auth.login('admin', self.password, remember=True)
        auth.logout(result['token'])
        self.assertIsNone(auth.session_user(result['token']))
        again = auth.login('admin', self.password, remember=False)
        auth._sessions[again['token']]['expires'] = auth.now() - timedelta(seconds=1)
        self.assertIsNone(auth.session_user(again['token']))

    def test_parse_cookie(self):
        token = 'abc.def_ghi'
        header = f'other=1; {auth.SESSION_COOKIE}={token}; path=/'
        self.assertEqual(auth.parse_cookie(header), token)
        self.assertEqual(auth.parse_cookie(''), '')


if __name__ == '__main__':
    unittest.main()
