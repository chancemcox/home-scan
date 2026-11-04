import unittest
from datetime import datetime,timezone,timedelta
from storage import device_states
class StatusTests(unittest.TestCase):
 def state(self, scans, obs):
  devices=[{'ip':'192.168.86.5'}]
  device_states(devices,obs,scans,datetime(2026,11,3,20,0,tzinfo=timezone.utc))
  return devices[0]['status']
 def scan(self,i,source,error=None,age=0):
  return dict(id=i,source=source,error=error,finished=(datetime(2026,11,3,20,0,tzinfo=timezone.utc)-timedelta(seconds=age)).isoformat())
 def test_network_scan_cannot_remove_deco_device(self):
  self.assertEqual(self.state([self.scan(1,'deco'),self.scan(2,'network')],[dict(ip='192.168.86.5',source='deco',scan_id=1)]),'seen')
 def test_deco_failure_keeps_fresh_success(self):
  # A Deco timeout must not invalidate a still-fresh successful observation.
  self.assertEqual(self.state([self.scan(1,'deco'),self.scan(2,'deco','timeout'),self.scan(3,'network')],[dict(ip='192.168.86.5',source='deco',scan_id=1)]),'seen')
 def test_confirmed_absence(self):
  self.assertEqual(self.state([self.scan(2,'deco')],[dict(ip='192.168.86.5',source='deco',scan_id=1)]),'not_seen')
 def test_stale_is_unknown(self):
  self.assertEqual(self.state([self.scan(1,'deco',age=200)],[dict(ip='192.168.86.5',source='deco',scan_id=1)]),'unknown')
 def test_other_source_can_confirm_presence(self):
  self.assertEqual(self.state([self.scan(1,'deco','timeout'),self.scan(2,'network')],[dict(ip='192.168.86.5',source='deco',scan_id=1),dict(ip='192.168.86.5',source='network',scan_id=2)]),'seen')
if __name__=='__main__':unittest.main()
