"""Dashboard authentication, sessions, and remember-me cookies."""
import json
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
        auth._sessions.clear()
        self._users_patch = mock.patch.object(auth, 'USERS_PATH', self.users)
        self._users_patch.start()
        self.addCleanup(self._users_patch.stop)
        auth.init()

    def test_default_admin_seeded(self):
        users = json.loads(self.users.read_text())['users']
        self.assertIn('admin', users)
        self.assertNotIn(auth.DEFAULT_PASSWORD, self.users.read_text())
        result = auth.login('admin', auth.DEFAULT_PASSWORD, remember=False)
        self.assertEqual(result['username'], 'admin')
        self.assertIsNone(result['max_age'])
        self.assertEqual(auth.session_user(result['token']), 'admin')

    def test_invalid_login_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Invalid'):
            auth.login('admin', 'wrong-password', False)
        with self.assertRaisesRegex(ValueError, 'username and password'):
            auth.login('', '', False)

    def test_remember_me_sets_longer_cookie_lifetime(self):
        session = auth.login('admin', auth.DEFAULT_PASSWORD, remember=False)
        remembered = auth.login('admin', auth.DEFAULT_PASSWORD, remember=True)
        self.assertIsNone(session['max_age'])
        self.assertGreater(remembered['max_age'], 0)
        self.assertIn('Max-Age=', auth.cookie_header(remembered['token'], True, remembered['max_age']))
        self.assertNotIn('Max-Age=', auth.cookie_header(session['token'], False, None))

    def test_logout_and_expiry(self):
        result = auth.login('admin', auth.DEFAULT_PASSWORD, remember=True)
        auth.logout(result['token'])
        self.assertIsNone(auth.session_user(result['token']))
        again = auth.login('admin', auth.DEFAULT_PASSWORD, remember=False)
        auth._sessions[again['token']]['expires'] = auth.now() - timedelta(seconds=1)
        self.assertIsNone(auth.session_user(again['token']))

    def test_parse_cookie(self):
        token = 'abc.def_ghi'
        header = f'other=1; {auth.SESSION_COOKIE}={token}; path=/'
        self.assertEqual(auth.parse_cookie(header), token)
        self.assertEqual(auth.parse_cookie(''), '')


if __name__ == '__main__':
    unittest.main()
