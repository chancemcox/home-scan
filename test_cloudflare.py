import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit,parse_qs
import storage
from cloudflare_sync import Manager, CloudflareError, hostname

MAC='02:11:22:33:44:55'
OTHER='02:66:77:88:99:AA'

class FakeAPI:
    def __init__(self):
        self.records={}
        self.config={'ingress':[{'hostname':'unrelated.chancecox.com','service':'http://10.0.0.9:8000'},{'service':'http_status:404'}]}
        self.writes=[]
        self.fail=False
        self.fail_dns_once=False
        self.next_id=1
    def call(self,method,path,body=None):
        if self.fail: raise CloudflareError('Cloudflare could not be reached.')
        if 'configurations' in path:
            if method=='GET': return {'config':copy.deepcopy(self.config)}
            self.writes.append((method,path,copy.deepcopy(body)))
            self.config=copy.deepcopy(body['config'])
            return {'config':copy.deepcopy(self.config)}
        if method=='GET':
            name=parse_qs(urlsplit(path).query)['name'][0]
            return [copy.deepcopy(r) for r in self.records.values() if r['name']==name]
        if self.fail_dns_once:
            self.fail_dns_once=False
            raise CloudflareError('Temporary DNS failure')
        self.writes.append((method,path,copy.deepcopy(body)))
        if method=='POST':
            rid=str(self.next_id);self.next_id+=1
            self.records[rid]=dict(body,id=rid)
            return copy.deepcopy(self.records[rid])
        rid=path.rsplit('/',1)[-1]
        if method=='DELETE': self.records.pop(rid,None);return {'id':rid}
        self.records[rid]=dict(body,id=rid)
        return copy.deepcopy(self.records[rid])

class TunnelEditingAPI:
    TID='11111111-2222-3333-4444-555555555555'
    OTHER='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    def __init__(self, config_src='cloudflare'):
        self.tunnel=dict(id=self.TID,name='paperless',config_src=config_src)
        self.other=dict(id=self.OTHER,name='home assistant',config_src='cloudflare')
        self.config={'ingress':[{'hostname':'docs.example.com','service':'http://192.168.2.10:8000'},
                                {'service':'http_status:404'}]}
        self.other_config={'ingress':[{'hostname':'ha.other.example','service':'http://192.168.2.101:8123'},
                                      {'hostname':'n8n.other.example','service':'http://192.168.2.101:5678'},
                                      {'service':'http_status:404'}]}
        self.writes=[];self.deleted=False
    def call(self,method,path,body=None):
        if path.endswith('/'+self.OTHER+'/configurations'):
            if method=='GET': return {'config':copy.deepcopy(self.other_config)}
            self.writes.append((method,path,copy.deepcopy(body)))
            self.other_config=copy.deepcopy(body['config']);return {'config':copy.deepcopy(self.other_config)}
        if path.endswith('/configurations'):
            if method=='GET': return {'config':copy.deepcopy(self.config)}
            self.writes.append((method,path,copy.deepcopy(body)))
            self.config=copy.deepcopy(body['config']);return {'config':copy.deepcopy(self.config)}
        if path.endswith('/'+self.OTHER):
            if method=='GET': return copy.deepcopy(self.other)
            if method=='DELETE': self.writes.append((method,path,body));self.deleted=True;return copy.deepcopy(self.other)
            raise AssertionError((method,path,body))
        if path.endswith('/'+self.TID):
            if method=='GET': return copy.deepcopy(self.tunnel)
            if method=='DELETE': self.writes.append((method,path,body));self.deleted=True;return copy.deepcopy(self.tunnel)
            self.writes.append((method,path,copy.deepcopy(body)))
            self.tunnel['name']=body['name'];return copy.deepcopy(self.tunnel)
        if method=='GET' and path.startswith('/zones?'): return []
        if method=='GET': return [copy.deepcopy(self.tunnel)]
        raise AssertionError((method,path,body))

class RouteCreationAPI(TunnelEditingAPI):
    def __init__(self):
        super().__init__();self.records=[]
        self.zones={'zone':{'id':'zone','name':'chancecox.com','account':{'id':'account'}},
                    'zone2':{'id':'zone2','name':'other.example','account':{'id':'account'}}}
    def call(self,method,path,body=None):
        if path in ('/zones/zone','/zones/zone2'): return copy.deepcopy(self.zones[path.rsplit('/',1)[-1]])
        if method=='GET' and path.startswith('/zones?'):
            name=parse_qs(urlsplit(path).query).get('name',[''])[0]
            return [copy.deepcopy(z) for z in self.zones.values() if z['name']==name]
        for zone_id in self.zones:
            prefix=f'/zones/{zone_id}/dns_records'
            if path.startswith(prefix):
                if method=='GET':
                    name=parse_qs(urlsplit(path).query).get('name',[None])[0]
                    rows=copy.deepcopy(self.records)
                    return [r for r in rows if name is None or r.get('name')==name]
                if method=='DELETE':
                    rid=path.rsplit('/',1)[-1];self.records=[r for r in self.records if r.get('id')!=rid]
                    self.writes.append((method,path,body));return {'id':rid}
                record=dict(body,id='dns'+str(len(self.records)+1));self.records.append(record)
                self.writes.append((method,path,copy.deepcopy(body)));return record
        return super().call(method,path,body)

class SetupAPI:
    def __init__(self):
        self.token=None;self.writes=[];self.tunnels=[];self.tokens={};self.d1=[]
        self.zone={'id':'zone','name':'chancecox.com','account':{'id':'account'}}
    def call(self,method,path,body=None):
        if method=='GET' and path.startswith('/zones?'):
            name=parse_qs(urlsplit(path).query).get('name',[''])[0]
            if not name or name in ('chancecox.com','house.chancecox.com', self.zone['name']):
                return [copy.deepcopy(self.zone)]
            return []
        if method=='GET' and path.endswith('/d1/database'):
            return copy.deepcopy(self.d1)
        if method=='POST' and path.endswith('/d1/database'):
            row=dict(uuid='d1-homescan-id',name=body['name']);self.d1.append(row)
            self.writes.append((method,path,copy.deepcopy(body)));return copy.deepcopy(row)
        if method=='GET' and 'cfd_tunnel' in path and path.endswith('/token'):
            tid=path.rsplit('/',2)[-2];return self.tokens.setdefault(tid,'connector-token-'+tid[:8])
        if method=='GET' and 'cfd_tunnel' in path and 'configurations' not in path and '?' in path:
            name=parse_qs(urlsplit(path).query).get('name',[''])[0]
            return [copy.deepcopy(t) for t in self.tunnels if t.get('name')==name]
        if method=='POST' and path.endswith('/cfd_tunnel'):
            tunnel=dict(id='new-tunnel-id',name=body['name'],config_src='cloudflare')
            self.tunnels.append(tunnel);self.writes.append((method,path,copy.deepcopy(body)));return copy.deepcopy(tunnel)
        if method=='PUT' and path.endswith('/configurations'):
            self.writes.append((method,path,copy.deepcopy(body)));return {'config':body['config']}
        raise AssertionError((method,path,body))

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db=str(Path(self.temp.name)/'test.db')
        self.cfg=Path(self.temp.name)/'cloudflare.json'
        self.cfg.write_text(json.dumps(dict(api_token='test-secret',zone_id='zone',account_id='account',tunnel_id='tunnel',zone_name='chancecox.com',suffix='house.chancecox.com')))
        storage.init(self.db)
        self.api=FakeAPI()
        self.m=Manager(self.db,self.cfg,lambda token:self.api);self.m.init()
        self.see('192.168.2.5')
        self.did='mac:'+MAC
    def see(self,ip,mac=MAC,source='network',name='NAS'):
        storage.record_batches(self.db,[dict(source=source,hosts=[dict(ip=ip,mac=mac,hostname=name)])])
    def save(self,local=True,tunnel=True,localname='nas',tunnelname='nas-web',port=8080):
        self.m.save(dict(device_id=self.did,local=dict(enabled=local,hostname=localname),
                         tunnel=dict(enabled=tunnel,hostname=tunnelname,port=port,protocol='http')))
    def test_connect_saves_token_and_keeps_existing_on_blank(self):
        from cloudflare_sync import connect_cloudflare
        api=SetupAPI();token_file=Path(self.temp.name)/'tunnel-token'
        result=connect_cloudflare(dict(api_token='brand-new-cloudflare-token',tunnel=False),self.cfg,lambda token:api,token_file)
        self.assertEqual(result['configured'],True)
        self.assertEqual(result['zone'],'chancecox.com')
        self.assertTrue(result['database_shared'])
        self.assertEqual(result['d1_database_id'],'d1-homescan-id')
        saved=json.loads(self.cfg.read_text())
        self.assertEqual(saved['api_token'],'brand-new-cloudflare-token')
        self.assertEqual(saved['d1_database_id'],'d1-homescan-id')
        self.assertFalse(token_file.exists())
        api2=SetupAPI();api2.d1=[{'uuid':'d1-homescan-id','name':'homescan'}]
        kept=connect_cloudflare(dict(api_token='',tunnel=False),self.cfg,lambda token:api2,token_file)
        self.assertEqual(kept['zone'],'chancecox.com')
        self.assertEqual(json.loads(self.cfg.read_text())['api_token'],'brand-new-cloudflare-token')
    def test_connect_creates_tunnel_and_connector_token(self):
        from cloudflare_sync import connect_cloudflare
        cfg=Path(self.temp.name)/'fresh.json';token_file=Path(self.temp.name)/'tunnel-token'
        api=SetupAPI()
        result=connect_cloudflare(dict(api_token='brand-new-cloudflare-token',tunnel=True),cfg,lambda token:api,token_file)
        self.assertTrue(result['tunnel_configured'])
        saved=json.loads(cfg.read_text())
        self.assertEqual(saved['tunnel_id'],'new-tunnel-id')
        self.assertEqual(token_file.read_text(),'connector-token-new-tunn')
    def test_connect_validation_errors(self):
        from cloudflare_sync import connect_cloudflare, CloudflareError
        cfg=Path(self.temp.name)/'validate.json';token_file=Path(self.temp.name)/'tunnel-token'
        with self.assertRaisesRegex(ValueError,'API token'):
            connect_cloudflare(dict(api_token='short',tunnel=False),cfg,lambda token:SetupAPI(),token_file)
        class NoZone(SetupAPI):
            def call(self,method,path,body=None):
                if method=='GET' and path.startswith('/zones?'): return []
                return super().call(method,path,body)
        with self.assertRaisesRegex(CloudflareError,'active Cloudflare zone'):
            connect_cloudflare(dict(api_token='brand-new-cloudflare-token',tunnel=False),cfg,lambda token:NoZone(),token_file)
        cfg.write_text(json.dumps(dict(api_token='old-token-value-here',zone_id='other-zone',zone_name='chancecox.com',account_id='account')))
        with self.assertRaisesRegex(CloudflareError,'Zone changed'):
            connect_cloudflare(dict(api_token='brand-new-cloudflare-token',tunnel=False),cfg,lambda token:SetupAPI(),token_file)
    def test_manager_connect_queues_sync(self):
        from cloudflare_sync import connect_cloudflare
        api=SetupAPI();token_file=Path(self.temp.name)/'mgr-token'
        self.m.api_factory=lambda token:api
        with mock.patch('cloudflare_sync.TOKEN_FILE',token_file):
            self.m.wake.clear()
            result=self.m.connect(dict(api_token='brand-new-cloudflare-token',tunnel=False))
        self.assertTrue(result['configured'])
        self.assertTrue(self.m.wake.is_set())
    def test_mac_follows_ip_and_cloudflare_is_idempotent(self):
        self.save();self.m.sync_once()
        count=len(self.api.writes)
        self.m.sync_once();self.assertEqual(len(self.api.writes),count)
        self.see('192.168.1.80');self.m.sync_once()
        records=list(self.api.records.values())
        self.assertEqual(next(r for r in records if r['type']=='A')['content'],'192.168.1.80')
        self.assertFalse(next(r for r in records if r['type']=='A')['proxied'])
        self.assertEqual(next(r for r in records if r['type']=='CNAME')['content'],'tunnel.cfargotunnel.com')
        self.assertEqual(next(r for r in self.api.config['ingress'] if r.get('hostname')=='nas-web.house.chancecox.com')['service'],'http://192.168.1.80:8080')
        devices=storage.inventory(self.db)['devices'];self.assertEqual(len(devices),1)
        self.assertEqual(devices[0]['device_id'],self.did)
        self.assertEqual(len(self.m.public_state()['routes']),2)
    def test_same_ip_different_mac_never_inherits_settings(self):
        self.save();self.m.sync_once()
        self.see('192.168.2.5',OTHER);self.m.sync_once()
        self.assertEqual(self.api.records,{})
        self.assertTrue(all(r['device_id']==self.did and r['state']=='waiting' for r in self.m.public_state()['routes']))
        self.see('192.168.2.9');self.m.sync_once()
        self.assertEqual(len(self.api.records),2)
    def test_manual_dns_drift_is_corrected(self):
        self.save(tunnel=False);self.m.sync_once()
        r=next(iter(self.api.records.values()));r['content']='192.168.2.99';r['proxied']=True
        self.m.sync_once();r=next(iter(self.api.records.values()))
        self.assertEqual(r['content'],'192.168.2.5');self.assertFalse(r['proxied'])
    def test_foreign_dns_is_not_overwritten(self):
        self.api.records['foreign']=dict(id='foreign',name='nas.house.chancecox.com',type='A',content='10.0.0.5')
        self.save(tunnel=False);self.m.sync_once()
        self.assertEqual(self.api.writes,[])
        self.assertEqual(next(r for r in self.m.public_state()['routes'] if r['kind']=='local')['state'],'error')
    def test_rename_disable_preserve_unrelated_ingress(self):
        self.save();self.m.sync_once();self.save(localname='storage',tunnelname='storage-web');self.m.sync_once()
        self.assertEqual({r['name'] for r in self.api.records.values()},{'storage.house.chancecox.com','storage-web.house.chancecox.com'})
        self.save(False,False);self.m.sync_once()
        self.assertEqual(self.api.records,{})
        self.assertEqual(self.api.config['ingress'],[{'hostname':'unrelated.chancecox.com','service':'http://10.0.0.9:8000'},{'service':'http_status:404'}])
    def test_failed_cloudflare_does_not_block_scans(self):
        self.save();self.api.fail=True;self.m.sync_once()
        self.see('192.168.2.8')
        self.assertEqual(storage.inventory(self.db)['devices'][0]['ip'],'192.168.2.8')
        self.api.fail=False;self.m.sync_once()
        self.assertTrue(all(r['state']=='synced' for r in self.m.public_state()['routes']))
    def test_partial_tunnel_creation_recovers(self):
        self.save(local=False);self.api.fail_dns_once=True;self.m.sync_once();self.m.sync_once()
        self.assertEqual(len(self.api.records),1)
        self.assertEqual(len([r for r in self.api.config['ingress'] if r.get('hostname')=='nas-web.house.chancecox.com']),1)
    def test_deco_skip_keeps_timestamps_and_target(self):
        self.see('192.168.86.20',source='deco');self.save();self.m.sync_once()
        prior=storage.inventory(self.db)['devices'][0]['last_seen']
        storage.record_batches(self.db,[dict(source='network',hosts=[])])
        self.m.sync_once()
        d=storage.inventory(self.db)['devices'][0]
        self.assertEqual(d['last_seen'],prior);self.assertEqual(d['ip'],'192.168.86.20')
    def test_no_token_exposed(self):
        self.assertNotIn('test-secret',json.dumps(self.m.public_state()))
    def test_save_domain_updates_suffix(self):
        result=self.m.save_domain(dict(suffix='lan.example.org'))
        self.assertEqual(result['suffix'],'lan.example.org')
        self.assertEqual(self.m.suffix(),'lan.example.org')
        self.assertEqual(self.m.public_state()['suffix'],'lan.example.org')
        self.assertEqual(storage.get_settings(self.db,('suffix',))['suffix'],'lan.example.org')
        self.save(local=True,tunnel=False,localname='nas')
        with storage.connect(self.db) as db:
            row=db.execute("SELECT hostname FROM cf_routes WHERE kind='local'").fetchone()
        self.assertEqual(row['hostname'],'nas.lan.example.org')
        self.m.save(dict(device_id=self.did,local=dict(enabled=False,hostname=''),
                         tunnel=dict(enabled=True,hostname='app.cdn.example.com',port=443,protocol='https')))
        with storage.connect(self.db) as db:
            row=db.execute("SELECT hostname FROM cf_routes WHERE kind='tunnel'").fetchone()
        self.assertEqual(row['hostname'],'app.cdn.example.com')
    def test_shared_settings_sync_and_suffix_backfill(self):
        from cloudflare_sync import infer_suffix_from_hostnames
        self.assertEqual(
            infer_suffix_from_hostnames(
                ['cmcwin.house.chancecox.com','cam.house.chancecox.com'],
                'chancecox.com'),
            'house.chancecox.com')
        payload=self.m.sync_shared_settings()
        self.assertEqual(payload['suffix'],'house.chancecox.com')
        self.assertEqual(storage.get_settings(self.db)['suffix'],'house.chancecox.com')
        self.assertEqual(storage.get_settings(self.db)['zone_name'],'chancecox.com')
        raw=json.loads(self.cfg.read_text()); raw.pop('suffix',None); self.cfg.write_text(json.dumps(raw))
        self.assertEqual(self.m.suffix(),'house.chancecox.com')
        self.save(local=True,tunnel=False,localname='nas')
        with storage.connect(self.db) as db:
            db.execute('DELETE FROM app_settings')
        raw=json.loads(self.cfg.read_text()); raw.pop('suffix',None); self.cfg.write_text(json.dumps(raw))
        self.m.init()
        self.assertEqual(self.m.suffix(),'house.chancecox.com')
        self.assertEqual(json.loads(self.cfg.read_text())['suffix'],'house.chancecox.com')
        self.assertEqual(storage.get_settings(self.db)['suffix'],'house.chancecox.com')
    def test_validation_and_hostname_collision(self):
        for value in ('*.house.chancecox.com','nas.evil.com','a.b.house.chancecox.com','https://nas.house.chancecox.com/path'):
            with self.assertRaises(ValueError): hostname(value, suffix='house.chancecox.com')
        with self.assertRaises(ValueError): self.save(localname='same',tunnelname='same')
        with self.assertRaises(ValueError): self.save(port=65536)
        self.save(tunnel=False)
        self.see('192.168.2.6',OTHER)
        with self.assertRaises(ValueError):
            self.m.save(dict(device_id='mac:'+OTHER,local=dict(enabled=True,hostname='nas')))
    def test_missing_mac_cannot_sync(self):
        self.see('192.168.2.10',mac='')
        with self.assertRaises(ValueError): self.m.save(dict(device_id='ip:192.168.2.10',local=dict(enabled=True,hostname='unknown')))
    def test_unknown_mac_promoted_without_duplicates(self):
        self.see('192.168.2.10',mac='');self.see('192.168.2.10',mac=OTHER)
        rows=storage.inventory(self.db)['devices']
        self.assertEqual(len(rows),2);self.assertFalse(any(d['device_id'].startswith('ip:') for d in rows))
    def test_invalid_batch_rolls_back_whole_scan(self):
        with storage.connect(self.db) as db: before=db.execute('SELECT count(*) FROM scans').fetchone()[0]
        with self.assertRaises(ValueError): storage.record_batches(self.db,[dict(source='network',hosts=[dict(ip='invalid')])])
        with storage.connect(self.db) as db: self.assertEqual(db.execute('SELECT count(*) FROM scans').fetchone()[0],before)

class TunnelEditingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=str(Path(self.temp.name)/'test.db');storage.init(self.db)
        self.cfg=Path(self.temp.name)/'cloudflare.json'
        self.cfg.write_text(json.dumps(dict(api_token='test-secret',account_id='account',zone_id='zone',
                                            zone_name='example.com',tunnel_id=TunnelEditingAPI.TID)))
        self.api=TunnelEditingAPI();self.m=Manager(self.db,self.cfg,lambda token:self.api);self.m.init()
        storage.record_batches(self.db,[dict(source='network',hosts=[dict(ip='192.168.2.5',mac=MAC,hostname='NAS')])])
        self.did='mac:'+MAC

    def test_load_and_update_existing_tunnel(self):
        detail=self.m.get_tunnel(TunnelEditingAPI.TID)
        self.assertEqual(detail['name'],'paperless')
        desired={'ingress':[{'hostname':'files.example.com','service':'http://192.168.2.20:8080'},
                            {'service':'http_status:404'}]}
        result=self.m.update_tunnel(dict(tunnel_id=TunnelEditingAPI.TID,name='files',config=desired))
        self.assertEqual(result['name'],'files');self.assertEqual(result['config'],desired)
        self.assertEqual([write[0] for write in self.api.writes],['PATCH','PUT'])

    def test_tunnel_editor_validation_and_local_config(self):
        bad=[{}, {'ingress':[]}, {'ingress':[{'hostname':'x','service':'http://x'}]},
             {'ingress':[{'service':''}]}, {'ingress':[{'service':'http_status:404','originRequest':'bad'}]}]
        for config in bad:
            with self.subTest(config=config), self.assertRaises(ValueError):
                self.m.update_tunnel(dict(tunnel_id=TunnelEditingAPI.TID,name='x',config=config))
        self.api.tunnel['config_src']='local'
        with self.assertRaises(ValueError): self.m.get_tunnel(TunnelEditingAPI.TID)

    def test_protects_homescan_owned_ingress(self):
        with storage.connect(self.db) as db:
            db.execute("INSERT INTO cf_resources VALUES('route','docs.example.com','tunnel',NULL)")
        desired={'ingress':[{'hostname':'docs.example.com','service':'http://192.168.2.99:8000'},
                            {'service':'http_status:404'}]}
        with self.assertRaisesRegex(ValueError,'device settings'):
            self.m.update_tunnel(dict(tunnel_id=TunnelEditingAPI.TID,name='paperless',config=desired))
        self.assertEqual(self.api.writes,[])

    def test_link_existing_rule_follows_mac_ip_and_unlinks(self):
        self.api.config['ingress'][0]['service']='http://192.168.2.10:8000/base?q=1#part'
        result=self.m.save_tunnel_link(dict(tunnel_id=TunnelEditingAPI.TID,hostname='docs.example.com',
                                            path='',device_id=self.did))
        self.m.sync_once()
        self.assertEqual(self.api.config['ingress'][0]['service'],'http://192.168.2.5:8000/base?q=1#part')
        storage.record_batches(self.db,[dict(source='network',hosts=[dict(ip='192.168.1.77',mac=MAC,hostname='NAS')])])
        self.m.sync_once()
        self.assertEqual(self.api.config['ingress'][0]['service'],'http://192.168.1.77:8000/base?q=1#part')
        link=self.m.public_state()['tunnel_links'][0]
        self.assertEqual((link['state'],link['synced_ip']),('synced','192.168.1.77'))
        self.m.save_tunnel_link(dict(action='delete',link_id=result['id']))
        self.assertEqual(self.m.public_state()['tunnel_links'],[])

    def test_link_validation_and_waiting_mac(self):
        with self.assertRaisesRegex(ValueError,'unique'):
            self.m.save_tunnel_link(dict(tunnel_id=TunnelEditingAPI.TID,hostname='missing.example.com',
                                         path='',device_id=self.did))
        self.api.config['ingress'][0]['service']='http_status:404'
        with self.assertRaisesRegex(ValueError,'URL-based'):
            self.m.save_tunnel_link(dict(tunnel_id=TunnelEditingAPI.TID,hostname='docs.example.com',
                                         path='',device_id=self.did))

    def test_create_hostname_on_different_domain_with_port_and_mac_link(self):
        self.api=RouteCreationAPI();self.m=Manager(self.db,self.cfg,lambda token:self.api);self.m.init()
        result=self.m.create_tunnel_route(dict(tunnel_id=TunnelEditingAPI.TID,zone_id='zone2',hostname='files',
                                                device_id=self.did,protocol='https',port=8443))
        self.assertEqual(result['hostname'],'files.other.example')
        rule=next(r for r in self.api.config['ingress'] if r.get('hostname')=='files.other.example')
        self.assertEqual(rule['service'],'https://192.168.2.5:8443')
        self.assertEqual(self.api.records[0]['content'],TunnelEditingAPI.TID+'.cfargotunnel.com')
        link=self.m.public_state()['tunnel_links'][0]
        self.assertEqual((link['hostname'],link['device_id']),('files.other.example',self.did))

    def test_create_multiple_hostnames_on_same_computer(self):
        self.api=RouteCreationAPI();self.m=Manager(self.db,self.cfg,lambda token:self.api);self.m.init()
        first=self.m.create_tunnel_route(dict(tunnel_id=TunnelEditingAPI.TID,zone_id='zone2',hostname='files',
                                               device_id=self.did,protocol='http',port=80))
        second=self.m.create_tunnel_route(dict(tunnel_id=TunnelEditingAPI.TID,zone_id='zone2',hostname='photos',
                                                device_id=self.did,protocol='http',port=8080))
        links=self.m.public_state()['tunnel_links']
        self.assertEqual({first['hostname'],second['hostname']},{'files.other.example','photos.other.example'})
        self.assertEqual({link['device_id'] for link in links},{self.did})
        self.assertEqual(len(links),2)

    def test_create_nested_hostname_under_selected_zone(self):
        self.api=RouteCreationAPI();self.m=Manager(self.db,self.cfg,lambda token:self.api);self.m.init()
        result=self.m.create_tunnel_route(dict(tunnel_id=TunnelEditingAPI.TID,zone_id='zone',hostname='files.house',
                                                device_id=self.did,protocol='http',port=80))
        self.assertEqual(result['hostname'],'files.house.chancecox.com')  # zone name from fixture

    def test_delete_public_hostname_and_dns(self):
        self.api=RouteCreationAPI();self.m=Manager(self.db,self.cfg,lambda token:self.api);self.m.init()
        created=self.m.create_tunnel_route(dict(tunnel_id=TunnelEditingAPI.TID,zone_id='zone2',hostname='files',
                                                 device_id=self.did,protocol='http',port=80))
        detail=self.m.delete_tunnel_hostname(dict(tunnel_id=TunnelEditingAPI.TID,hostname=created['hostname'],path=''))
        self.assertFalse(any(r.get('hostname')==created['hostname'] for r in detail['config']['ingress']))
        self.assertEqual(self.api.records,[])
        self.assertEqual(self.m.public_state()['tunnel_links'],[])

    def test_delete_tunnel_refuses_homescan_and_removes_other(self):
        with self.assertRaisesRegex(ValueError,'HomeScan tunnel'):
            self.m.delete_tunnel(dict(tunnel_id=TunnelEditingAPI.TID))
        self.m.save_tunnel_link(dict(tunnel_id=TunnelEditingAPI.OTHER,hostname='ha.other.example',path='',device_id=self.did))
        self.assertEqual(len(self.m.public_state()['tunnel_links']),1)
        self.assertEqual(self.m.delete_tunnel(dict(tunnel_id=TunnelEditingAPI.OTHER)),{'ok':True})
        self.assertTrue(self.api.deleted)
        self.assertEqual(self.m.public_state()['tunnel_links'],[])

    def test_delete_hostname_protects_homescan_owned_ingress(self):
        with storage.connect(self.db) as db:
            db.execute("INSERT INTO cf_resources VALUES('route','docs.example.com','tunnel',NULL)")
        with self.assertRaisesRegex(ValueError,'device settings'):
            self.m.delete_tunnel_hostname(dict(tunnel_id=TunnelEditingAPI.TID,hostname='docs.example.com',path=''))
        self.assertEqual(self.api.config['ingress'][0]['hostname'],'docs.example.com')

    def test_delete_tunnel_rejects_local_config(self):
        self.api.other['config_src']='local'
        with self.assertRaisesRegex(ValueError,'local configuration'):
            self.m.delete_tunnel(dict(tunnel_id=TunnelEditingAPI.OTHER))

    def test_list_tunnels_marks_homescan_tunnel(self):
        listed=self.m.list_tunnels()
        self.assertTrue(listed['configured'])
        self.assertEqual(listed['tunnels'][0]['id'],TunnelEditingAPI.TID)
        self.assertTrue(listed['tunnels'][0]['homescan'])
        self.assertTrue(listed['tunnels'][0]['editable'])
        self.assertEqual(listed['tunnels'][0]['hostnames'][0]['hostname'],'docs.example.com')

class HelperTests(unittest.TestCase):
    def test_hostname_and_private_ip_helpers(self):
        from cloudflare_sync import hostname, hostname_under_zone, normalize_suffix, private_ip
        s='house.example.com'
        self.assertEqual(hostname('nas', suffix=s),'nas.house.example.com')
        self.assertEqual(hostname('https://nas.house.example.com', suffix=s),'nas.house.example.com')
        self.assertEqual(hostname('nas-web', suffix=s, kind='tunnel'),'nas-web.house.example.com')
        self.assertEqual(hostname('app.other.example.com', kind='tunnel'),'app.other.example.com')
        self.assertEqual(hostname('nas', suffix='lan.example.org'),'nas.lan.example.org')
        self.assertEqual(hostname_under_zone('files','example.com'),'files.example.com')
        self.assertEqual(hostname_under_zone('files.house','example.com'),'files.house.example.com')
        self.assertEqual(hostname_under_zone('files.house.example.com','example.com'),'files.house.example.com')
        self.assertEqual(normalize_suffix('Lan.Example.COM'),'lan.example.com')
        self.assertEqual(private_ip('10.1.2.3'),'10.1.2.3')
        with self.assertRaises(ValueError): private_ip('8.8.8.8')
        with self.assertRaises(ValueError): hostname('nas')
        with self.assertRaises(ValueError): hostname('app.other.example.com', suffix=s)
        with self.assertRaises(ValueError): hostname_under_zone('example.com','example.com')
        with self.assertRaises(ValueError): hostname_under_zone('','example.com')

class MigrationTests(unittest.TestCase):
    def test_legacy_rows_merge_by_mac_with_history_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            path=str(Path(t)/'legacy.db')
            with sqlite3.connect(path) as db:
                db.executescript('''CREATE TABLE devices(ip TEXT PRIMARY KEY, hostname TEXT, mac TEXT, first_seen TEXT, last_seen TEXT, scan_id INTEGER);
                CREATE TABLE device_sources(ip TEXT, source TEXT, last_seen TEXT, scan_id INTEGER, PRIMARY KEY(ip,source));
                CREATE TABLE sightings(scan_id INTEGER, ip TEXT, hostname TEXT, mac TEXT, PRIMARY KEY(scan_id,ip));''')
                for n,ip in enumerate(('192.168.2.4','192.168.2.5'),1):
                    date=f'2026-11-03T12:0{n}:00+00:00'
                    db.execute('INSERT INTO devices VALUES(?,?,?,?,?,?)',(ip,'nas',MAC,date,date,n))
                    db.execute('INSERT INTO device_sources VALUES(?,?,?,?)',(ip,'network',date,n))
                    db.execute('INSERT INTO sightings VALUES(?,?,?,?)',(n,ip,'nas',MAC))
            storage.init(path);storage.init(path)
            with storage.connect(path) as db:
                devices=db.execute('SELECT * FROM devices').fetchall()
                self.assertEqual(len(devices),1);self.assertEqual(devices[0]['ip'],'192.168.2.5')
                self.assertEqual(devices[0]['first_seen'],'2026-11-03T12:01:00+00:00')
                self.assertEqual(db.execute('SELECT count(*) FROM sightings').fetchone()[0],2)
                self.assertEqual(db.execute('SELECT device_id FROM device_sources').fetchone()[0],'mac:'+MAC)

if __name__=='__main__': unittest.main()
