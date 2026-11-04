import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as Client
from unittest.mock import patch
import deco

class DecoTests(unittest.TestCase):
    def test_online_valid_clients_only(self):
        rows = [Client(ip='192.168.86.5', name='Phone', mac='aa-bb-cc-dd-ee-ff', online=True),
                Client(ip='192.168.86.6', name='Sleeping', mac='', online=False),
                Client(ip='0.0.0.0', name='No lease', mac='', online=True),
                Client(ip='invalid', name='Invalid', mac='', online=True)]
        self.assertEqual(deco.normalize(rows), [dict(ip='192.168.86.5',hostname='Phone',mac='AA:BB:CC:DD:EE:FF')])

    def test_unconfigured_never_logs_in(self):
        with tempfile.TemporaryDirectory() as t, patch.object(deco,'CONFIG',Path(t)/'missing'), patch.object(deco,'LEGACY',Path(t)/'legacy-missing'):
            with patch.object(deco,'sdk', side_effect=AssertionError('should not login')):
                self.assertFalse(deco.collect()['configured'])

    def test_disabled_never_logs_in(self):
        with tempfile.TemporaryDirectory() as t:
            config=Path(t)/'config.json'; config.write_text(json.dumps(dict(enabled=False,host='192.168.86.233',password='test-secret')))
            with patch.object(deco,'CONFIG',config), patch.object(deco,'LEGACY',Path(t)/'missing'), patch.object(deco,'COOLDOWN',Path(t)/'cooldown'):
                with patch.object(deco,'sdk', side_effect=AssertionError('should not login')):
                    result=deco.collect()
                self.assertEqual(result,dict(enabled=False,configured=True,available=False,hosts=[]))

    def test_failure_redacts_secret_and_limits_retries(self):
        with tempfile.TemporaryDirectory() as t:
            config=Path(t)/'config.json'; config.write_text(json.dumps(dict(enabled=True,host='192.168.86.233',password='test-secret')))
            calls={'n':0}
            def boom(*a,**k):
                calls['n']+=1
                raise deco.AuthenticationError('test-secret')
            with patch.object(deco,'CONFIG',config), patch.object(deco,'LEGACY',Path(t)/'missing'), patch.object(deco,'COOLDOWN',Path(t)/'cooldown'):
                with patch.object(deco,'sdk', return_value=(boom, deco.AuthenticationError)):
                    result=deco.collect()
                    self.assertFalse(result['available'])
                    self.assertNotIn('error',result)
                    self.assertNotIn('test-secret',json.dumps(result))
                    deco.collect()
                    self.assertEqual(calls['n'],1)

    def test_complete_json_with_missing_http_chunk(self):
        from http.client import IncompleteRead
        transport = Client(_post=lambda: None)
        def incomplete(): raise IncompleteRead(b'{"result": {"client_list": []}}')
        transport._post = incomplete
        deco.tolerate_complete_json(transport)
        self.assertEqual(transport._post(), {'result': {'client_list': []}})
        def truncated(): raise IncompleteRead(b'{"result":')
        transport._post = truncated
        deco.tolerate_complete_json(transport)
        with self.assertRaises(ValueError): transport._post()

    def test_connection_failure_is_silent(self):
        with tempfile.TemporaryDirectory() as t:
            config=Path(t)/'config.json'; config.write_text(json.dumps(dict(enabled=True,host='192.168.86.233',password='test-secret')))
            calls={'n':0}
            def boom(*a,**k):
                calls['n']+=1
                raise TimeoutError('test-secret')
            with patch.object(deco,'CONFIG',config), patch.object(deco,'LEGACY',Path(t)/'missing'), patch.object(deco,'COOLDOWN',Path(t)/'cooldown'):
                with patch.object(deco,'sdk', return_value=(boom, deco.AuthenticationError)):
                    for _ in range(2):
                        result=deco.collect()
                        self.assertEqual(result,dict(enabled=True,configured=True,available=False,hosts=[]))
                    self.assertEqual(calls['n'],2)

    def test_save_settings_toggle_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as t:
            config=Path(t)/'deco.json'
            with patch.object(deco,'CONFIG',config), patch.object(deco,'LEGACY',Path(t)/'missing'), patch.object(deco,'COOLDOWN',Path(t)/'cooldown'):
                state=deco.save_settings(dict(enabled=True,host='192.168.86.233',username='admin',password='test-secret'))
                self.assertTrue(state['enabled']); self.assertTrue(state['password_set'])
                self.assertNotIn('test-secret',json.dumps(state))
                saved=json.loads(config.read_text())
                self.assertEqual(saved['password'],'test-secret')
                off=deco.save_settings(dict(enabled=False,host='192.168.86.233'))
                self.assertFalse(off['enabled']); self.assertTrue(off['password_set'])
                self.assertEqual(json.loads(config.read_text())['password'],'test-secret')

if __name__ == '__main__': unittest.main()
