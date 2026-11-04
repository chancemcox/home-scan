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
        with tempfile.TemporaryDirectory() as t, patch.object(deco,'CONFIG',Path(t)/'missing'), patch.object(deco,'DecoClient') as sdk:
            self.assertFalse(deco.collect()['configured'])
            sdk.assert_not_called()

    def test_failure_redacts_secret_and_limits_retries(self):
        with tempfile.TemporaryDirectory() as t:
            config=Path(t)/'config.json'; config.write_text(json.dumps(dict(host='192.168.86.233',password='test-secret')))
            with patch.object(deco,'CONFIG',config), patch.object(deco,'COOLDOWN',Path(t)/'cooldown'), patch.object(deco,'DecoClient',side_effect=deco.AuthenticationError('test-secret')) as sdk:
                result=deco.collect()
                self.assertFalse(result['available'])
                self.assertNotIn('error',result)
                self.assertNotIn('test-secret',json.dumps(result))
                deco.collect()
                self.assertEqual(sdk.call_count,1)

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
            config=Path(t)/'config.json'; config.write_text(json.dumps(dict(host='192.168.86.233',password='test-secret')))
            with patch.object(deco,'CONFIG',config), patch.object(deco,'COOLDOWN',Path(t)/'cooldown'), patch.object(deco,'DecoClient',side_effect=TimeoutError('test-secret')) as sdk:
                for _ in range(2):
                    result=deco.collect()
                    self.assertEqual(result,dict(configured=True,available=False,hosts=[]))
                self.assertEqual(sdk.call_count,2)

if __name__ == '__main__': unittest.main()



