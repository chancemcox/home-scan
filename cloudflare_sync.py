"""MAC-bound DNS and HTTP tunnel reconciliation. Only tagged records are managed."""
import ipaddress
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
import storage

SUFFIX = 'house.chancecox.com'
OLD_SUFFIX = 'local.chancecox.com'
CONFIG = Path(os.getenv('CLOUDFLARE_CONFIG','/data/cloudflare.json'))
TOKEN_FILE = Path(os.getenv('CLOUDFLARE_TUNNEL_TOKEN','/run/homescan-tunnel/token'))


class CloudflareError(Exception):
    pass


class API:
    def __init__(self, token): self.token = token

    def call(self, method, path, body=None):
        req = urllib.request.Request('https://api.cloudflare.com/client/v4'+path,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            # Never include request headers, tokens, or raw upstream responses.
            raise CloudflareError(f'Cloudflare HTTP {exc.code}. Check token permissions or retry later.') from None
        except (OSError,ValueError):
            raise CloudflareError('Cloudflare could not be reached. Retrying automatically.') from None
        if not result.get('success'):
            codes = ', '.join(str(e.get('code','unknown')) for e in result.get('errors',[]))
            raise CloudflareError('Cloudflare rejected the request (code '+codes+').')
        return result.get('result')


def hostname(value):
    name = str(value or '').strip().lower().rstrip('.')
    if '://' in name:
        parsed = urllib.parse.urlsplit(name)
        if parsed.scheme not in ('http','https') or parsed.path not in ('','/') or parsed.query or parsed.fragment or parsed.port or parsed.username:
            raise ValueError('Enter a hostname without a port or path.')
        name = parsed.hostname or ''
    if '.' not in name: name += '.'+SUFFIX
    label = name.removesuffix('.'+SUFFIX)
    if name != label+'.'+SUFFIX or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label):
        raise ValueError('Use a single hostname such as nas.'+SUFFIX)
    return name


def private_ip(value):
    ip = ipaddress.IPv4Address(value)
    if not any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError('Cloudflare targets must be private LAN IPv4 addresses.')
    return str(ip)


class Manager:
    def __init__(self, db_path, config_path=CONFIG, api_factory=API, on_update=None):
        self.db_path, self.config_path, self.api_factory = db_path,Path(config_path),api_factory
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.on_update = on_update

    def init(self):
        with storage.connect(self.db_path) as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS cf_routes(id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
                kind TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0,
                protocol TEXT NOT NULL DEFAULT 'http', port INTEGER NOT NULL DEFAULT 80,
                state TEXT NOT NULL DEFAULT 'disabled', message TEXT NOT NULL DEFAULT '',
                synced_ip TEXT, last_checked TEXT, UNIQUE(device_id,kind));
            CREATE UNIQUE INDEX IF NOT EXISTS cf_hostname ON cf_routes(hostname) WHERE enabled=1;
            CREATE TABLE IF NOT EXISTS cf_resources(route_id TEXT, hostname TEXT, kind TEXT, record_id TEXT,
                PRIMARY KEY(route_id,hostname));
            CREATE TABLE IF NOT EXISTS cf_tunnel_links(id TEXT PRIMARY KEY, tunnel_id TEXT NOT NULL,
                hostname TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', device_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending', message TEXT NOT NULL DEFAULT '', synced_ip TEXT,
                last_checked TEXT, UNIQUE(tunnel_id,hostname,path));
            ''')
            # Rewrite managed hostnames after the global suffix change; leave cf_resources
            # on the old names so reconcile deletes prior DNS/tunnel ownership.
            for row in db.execute('SELECT id,hostname,enabled FROM cf_routes WHERE hostname LIKE ?',
                                  ('%.'+OLD_SUFFIX,)):
                new = row['hostname'].removesuffix('.'+OLD_SUFFIX)+'.'+SUFFIX
                db.execute('''UPDATE cf_routes SET hostname=?,
                    state=CASE WHEN enabled=1 THEN 'pending' ELSE state END, message='' WHERE id=?''',
                           (new, row['id']))

    def config(self):
        try: return json.loads(self.config_path.read_text())
        except FileNotFoundError: return {}

    def public_state(self):
        try: cfg = self.config()
        except (ValueError,OSError): cfg = {}
        with storage.connect(self.db_path) as db:
            routes = [dict(r) for r in db.execute('SELECT * FROM cf_routes')]
            links = [dict(r) for r in db.execute('SELECT * FROM cf_tunnel_links')]
        return dict(configured=bool(cfg.get('api_token')),zone=cfg.get('zone_name'),
                    tunnel_id=cfg.get('tunnel_id') or '',
                    tunnel_configured=bool(cfg.get('tunnel_id')),suffix=SUFFIX,routes=routes,tunnel_links=links)

    def list_tunnels(self):
        """Account tunnel inventory for the settings UI. Soft-fails without raising."""
        try: cfg = self.config()
        except (ValueError, OSError): cfg = {}
        if not cfg.get('api_token') or not cfg.get('account_id'):
            return dict(configured=False, tunnels=[], error='Connect Cloudflare to list tunnels.')
        try:
            api = self.api_factory(cfg['api_token'])
            rows = api.call('GET', f"/accounts/{cfg['account_id']}/cfd_tunnel?" +
                            urllib.parse.urlencode({'is_deleted': 'false', 'per_page': 100})) or []
        except CloudflareError as exc:
            return dict(configured=True, tunnels=[], error=str(exc))
        except Exception:
            return dict(configured=True, tunnels=[], error='Could not load Cloudflare tunnels.')
        tunnels = []
        for row in rows:
            connections = row.get('connections') or []
            ingress = []
            if row.get('config_src') == 'cloudflare' and row.get('id'):
                try:
                    response = api.call('GET',f"/accounts/{cfg['account_id']}/cfd_tunnel/{row['id']}/configurations") or {}
                    ingress = (response.get('config') or {}).get('ingress') or []
                except Exception:
                    ingress = []
            tunnels.append(dict(
                id=row.get('id') or '',
                name=row.get('name') or '',
                status=row.get('status') or ('healthy' if connections else 'inactive'),
                created_at=row.get('created_at') or '',
                connections=len(connections),
                config_src=row.get('config_src') or '',
                editable=(row.get('config_src') == 'cloudflare'),
                hostnames=[dict(hostname=r.get('hostname') or '',path=r.get('path') or '',service=r.get('service') or '')
                           for r in ingress if r.get('hostname') or r.get('path')],
                homescan=(row.get('id') == cfg.get('tunnel_id')),
            ))
        tunnels.sort(key=lambda t: (not t['homescan'], t['name'].lower()))
        return dict(configured=True, tunnels=tunnels, error='')

    def list_zones(self):
        try: cfg,api=self._tunnel_api()
        except ValueError as exc: return dict(zones=[],error=str(exc))
        try:
            rows=api.call('GET','/zones?'+urllib.parse.urlencode({'status':'active','per_page':100})) or []
            zones=[dict(id=z.get('id') or '',name=z.get('name') or '',account_id=(z.get('account') or {}).get('id') or '')
                   for z in rows if z.get('id') and z.get('name')]
            zones.sort(key=lambda z:z['name'])
            return dict(zones=zones,error='')
        except CloudflareError as exc: return dict(zones=[],error=str(exc))
        except Exception: return dict(zones=[],error='Could not load Cloudflare domains.')

    def _tunnel_api(self):
        try: cfg = self.config()
        except (ValueError, OSError): cfg = {}
        if not cfg.get('api_token') or not cfg.get('account_id'):
            raise ValueError('Connect Cloudflare before editing tunnels.')
        return cfg, self.api_factory(cfg['api_token'])

    @staticmethod
    def _tunnel_id(value):
        value = str(value or '').strip().lower()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
            raise ValueError('Invalid tunnel ID.')
        return value

    @staticmethod
    def _tunnel_config(value):
        if not isinstance(value, dict): raise ValueError('Tunnel configuration must be a JSON object.')
        # Round-trip advanced Cloudflare options, while strictly checking the ingress
        # shape that can affect routing and keeping requests bounded.
        if len(json.dumps(value, separators=(',', ':'))) > 262144:
            raise ValueError('Tunnel configuration is too large.')
        ingress = value.get('ingress')
        if not isinstance(ingress, list) or not 1 <= len(ingress) <= 200:
            raise ValueError('Tunnel configuration needs between 1 and 200 ingress rules.')
        for rule in ingress:
            if not isinstance(rule, dict): raise ValueError('Every ingress rule must be a JSON object.')
            service = rule.get('service')
            if not isinstance(service, str) or not service.strip() or len(service) > 2048:
                raise ValueError('Every ingress rule needs a valid service.')
            for key in ('hostname', 'path'):
                if key in rule and (not isinstance(rule[key], str) or len(rule[key]) > 2048):
                    raise ValueError(f'Ingress {key} must be text.')
            if 'originRequest' in rule and not isinstance(rule['originRequest'], dict):
                raise ValueError('Ingress originRequest must be a JSON object.')
        last = ingress[-1]
        if last.get('hostname') or last.get('path'):
            raise ValueError('The final ingress rule must be a catch-all without hostname or path.')
        return value

    def get_tunnel(self, tunnel_id):
        tunnel_id = self._tunnel_id(tunnel_id)
        cfg, api = self._tunnel_api()
        base = f"/accounts/{cfg['account_id']}/cfd_tunnel/{tunnel_id}"
        tunnel = api.call('GET', base) or {}
        if tunnel.get('config_src') != 'cloudflare':
            raise ValueError('This tunnel is locally managed and cannot be edited from HomeScan.')
        response = api.call('GET', base + '/configurations') or {}
        config = response.get('config') or {'ingress':[{'service':'http_status:404'}]}
        with storage.connect(self.db_path) as db:
            links = [dict(r) for r in db.execute('SELECT * FROM cf_tunnel_links WHERE tunnel_id=?',(tunnel_id,))]
        return dict(id=tunnel_id, name=tunnel.get('name') or '', config=config, links=links,
                    homescan=(tunnel_id == cfg.get('tunnel_id')))

    def update_tunnel(self, body):
        tunnel_id = self._tunnel_id(body.get('tunnel_id'))
        name = str(body.get('name') or '').strip()
        if not 1 <= len(name) <= 100 or re.search(r'[\x00-\x1f\x7f]', name):
            raise ValueError('Tunnel name must be between 1 and 100 characters.')
        desired = self._tunnel_config(body.get('config'))
        with self.lock:
            cfg, api = self._tunnel_api()
            base = f"/accounts/{cfg['account_id']}/cfd_tunnel/{tunnel_id}"
            tunnel = api.call('GET', base) or {}
            if tunnel.get('config_src') != 'cloudflare':
                raise ValueError('This tunnel is locally managed and cannot be edited from HomeScan.')
            response = api.call('GET', base + '/configurations') or {}
            current = response.get('config') or {'ingress':[{'service':'http_status:404'}]}
            if tunnel_id == cfg.get('tunnel_id'):
                with storage.connect(self.db_path) as db:
                    owned = {r['hostname'] for r in db.execute("SELECT hostname FROM cf_resources WHERE kind='tunnel'")}
                before = {r.get('hostname'):r for r in current.get('ingress',[]) if r.get('hostname') in owned}
                after = {r.get('hostname'):r for r in desired.get('ingress',[]) if r.get('hostname') in owned}
                if before != after:
                    raise ValueError('HomeScan-managed ingress rules must be edited from their device settings.')
            if tunnel.get('name') != name:
                api.call('PATCH', base, {'name':name})
            if current != desired:
                api.call('PUT', base + '/configurations', {'config':desired})
        return self.get_tunnel(tunnel_id)

    @staticmethod
    def _rule_key(rule):
        return str(rule.get('hostname') or ''), str(rule.get('path') or '')

    @staticmethod
    def _service_with_ip(service, ip):
        parsed = urllib.parse.urlsplit(str(service or ''))
        if parsed.scheme not in ('http','https','tcp','ssh','rdp','smb') or not parsed.hostname:
            raise ValueError('Only URL-based HTTP, HTTPS, TCP, SSH, RDP, or SMB services can be linked.')
        if parsed.username or parsed.password:
            raise ValueError('Services containing credentials cannot be linked.')
        try: port = parsed.port
        except ValueError: raise ValueError('The linked service has an invalid port.') from None
        netloc = ip + (f':{port}' if port is not None else '')
        return urllib.parse.urlunsplit((parsed.scheme,netloc,parsed.path,parsed.query,parsed.fragment))

    def save_tunnel_link(self, body):
        action = str(body.get('action') or 'save')
        if action == 'delete':
            link_id = str(body.get('link_id') or '')
            with self.lock, storage.connect(self.db_path) as db:
                if db.execute('DELETE FROM cf_tunnel_links WHERE id=?',(link_id,)).rowcount != 1:
                    raise ValueError('Tunnel link was not found.')
            return dict(ok=True)
        tunnel_id = self._tunnel_id(body.get('tunnel_id'))
        did = str(body.get('device_id') or '')
        key = (str(body.get('hostname') or ''),str(body.get('path') or ''))
        with self.lock, storage.connect(self.db_path) as db:
            device = db.execute('SELECT * FROM devices WHERE device_id=?',(did,)).fetchone()
            if not device or not device['mac'] or not did.startswith('mac:'):
                raise ValueError('Choose a computer with a known MAC address.')
        detail = self.get_tunnel(tunnel_id)
        matching = [r for r in detail['config'].get('ingress',[]) if self._rule_key(r)==key]
        if len(matching) != 1: raise ValueError('Choose a unique tunnel ingress rule.')
        private_ip(device['ip'])
        self._service_with_ip(matching[0].get('service'),device['ip'])
        if detail['homescan']:
            with storage.connect(self.db_path) as db:
                owned = db.execute("SELECT 1 FROM cf_resources WHERE kind='tunnel' AND hostname=?",(key[0],)).fetchone()
            if owned: raise ValueError('This route already follows a computer through HomeScan device settings.')
        with self.lock, storage.connect(self.db_path) as db:
            old = db.execute('SELECT id FROM cf_tunnel_links WHERE tunnel_id=? AND hostname=? AND path=?',
                             (tunnel_id,*key)).fetchone()
            link_id = old['id'] if old else uuid.uuid4().hex
            db.execute('''INSERT INTO cf_tunnel_links(id,tunnel_id,hostname,path,device_id,state,message)
                VALUES(?,?,?,?,?,'pending','') ON CONFLICT(id) DO UPDATE SET
                device_id=excluded.device_id,state='pending',message='',synced_ip=NULL''',
                (link_id,tunnel_id,*key,did))
        self.wake.set()
        return dict(ok=True,id=link_id)

    def create_tunnel_route(self, body):
        tunnel_id=self._tunnel_id(body.get('tunnel_id'));zone_id=str(body.get('zone_id') or '')
        did=str(body.get('device_id') or '');label=str(body.get('hostname') or '').strip().lower().rstrip('.')
        protocol=str(body.get('protocol') or 'http')
        if protocol not in ('http','https'): raise ValueError('Choose HTTP or HTTPS for the origin.')
        try: port=int(body.get('port',80))
        except (TypeError,ValueError): raise ValueError('Port must be between 1 and 65535.') from None
        if not 1<=port<=65535: raise ValueError('Port must be between 1 and 65535.')
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label):
            raise ValueError('Use a single hostname label such as files.')
        with self.lock,storage.connect(self.db_path) as db:
            device=db.execute('SELECT * FROM devices WHERE device_id=?',(did,)).fetchone()
            if not device or not device['mac'] or not did.startswith('mac:'):
                raise ValueError('Choose a computer with a known MAC address.')
        ip=private_ip(device['ip']);cfg,api=self._tunnel_api()
        zone=api.call('GET',f'/zones/{zone_id}') or {}
        if not zone.get('name') or (zone.get('account') or {}).get('id')!=cfg['account_id']:
            raise ValueError('Choose an accessible domain from this Cloudflare account.')
        name=label+'.'+zone['name'].lower().rstrip('.')
        base=f"/accounts/{cfg['account_id']}/cfd_tunnel/{tunnel_id}"
        tunnel=api.call('GET',base) or {}
        if tunnel.get('config_src')!='cloudflare': raise ValueError('Choose a remotely managed tunnel.')
        response=api.call('GET',base+'/configurations') or {};config=response.get('config') or {'ingress':[{'service':'http_status:404'}]}
        rules=config.get('ingress') or [{'service':'http_status:404'}]
        matching=[r for r in rules if r.get('hostname')==name and not r.get('path')]
        service=f'{protocol}://{ip}:{port}'
        if len(matching)>1: raise ValueError('That hostname has multiple ingress rules and cannot be managed automatically.')
        if matching: matching[0]['service']=service
        else:
            position=next((i for i,r in enumerate(rules) if not r.get('hostname') and not r.get('path')),len(rules))
            rules.insert(position,{'hostname':name,'service':service})
        records=api.call('GET',f'/zones/{zone_id}/dns_records?'+urllib.parse.urlencode({'name':name,'per_page':100})) or []
        target=tunnel_id+'.cfargotunnel.com'
        foreign=[r for r in records if r.get('type')!='CNAME' or r.get('content')!=target]
        if foreign: raise ValueError('An existing DNS record already owns this hostname.')
        api.call('PUT',base+'/configurations',{'config':dict(config,ingress=rules)})
        if not records:
            api.call('POST',f'/zones/{zone_id}/dns_records',dict(type='CNAME',name=name,content=target,proxied=True,ttl=1,
                                                                 comment='homescan:tunnel-route'))
        return self.save_tunnel_link(dict(tunnel_id=tunnel_id,hostname=name,path='',device_id=did)) | {'hostname':name}

    def _link_status(self, link, state, message='', ip=None):
        with storage.connect(self.db_path) as db:
            db.execute('UPDATE cf_tunnel_links SET state=?,message=?,synced_ip=?,last_checked=? WHERE id=?',
                       (state,message,ip,storage.now(),link['id']))

    def reconcile_tunnel_links(self, api, cfg, links, devices):
        for tunnel_id in sorted({link['tunnel_id'] for link in links}):
            group = [link for link in links if link['tunnel_id']==tunnel_id]
            try:
                path = f"/accounts/{cfg['account_id']}/cfd_tunnel/{tunnel_id}/configurations"
                response = api.call('GET',path) or {};config=response.get('config') or {}
                rules = config.get('ingress') or [];changed=False
                for link in group:
                    device=devices.get(link['device_id'])
                    if not device or not device.get('address_current',False):
                        self._link_status(link,'waiting','Waiting for this MAC to have a confirmed IP assignment.');continue
                    matches=[r for r in rules if self._rule_key(r)==(link['hostname'],link['path'])]
                    if len(matches)!=1:
                        self._link_status(link,'error','The linked ingress rule is missing or no longer unique.');continue
                    ip=private_ip(device['ip']);desired=self._service_with_ip(matches[0].get('service'),ip)
                    if matches[0].get('service')!=desired: matches[0]['service']=desired;changed=True
                    self._link_status(link,'synced','',ip)
                if changed: api.call('PUT',path,{'config':dict(config,ingress=rules)})
            except (CloudflareError,ValueError) as exc:
                for link in group: self._link_status(link,'error',str(exc))
            except Exception:
                for link in group: self._link_status(link,'error','Tunnel link sync could not finish. Retrying automatically.')

    def save(self, body):
        did = str(body.get('device_id',''))
        with self.lock, storage.connect(self.db_path) as db:
            device = db.execute('SELECT * FROM devices WHERE device_id=?',(did,)).fetchone()
            if not device or not device['mac'] or not did.startswith('mac:'):
                raise ValueError('A known MAC address is required for Cloudflare sync.')
            planned = []
            for kind in ('local','tunnel'):
                item = body.get(kind,{})
                if not isinstance(item,dict) or not isinstance(item.get('enabled',False),bool):
                    raise ValueError('Invalid Cloudflare settings.')
                enabled = item.get('enabled',False)
                old = db.execute('SELECT * FROM cf_routes WHERE device_id=? AND kind=?',(did,kind)).fetchone()
                name = hostname(item.get('hostname')) if enabled else (old['hostname'] if old else '')
                protocol = item.get('protocol','http')
                if protocol not in ('http','https'): raise ValueError('Choose HTTP or HTTPS for the origin.')
                try: port = int(item.get('port',80))
                except (ValueError,TypeError): raise ValueError('Port must be between 1 and 65535.')
                if not 1 <= port <= 65535: raise ValueError('Port must be between 1 and 65535.')
                if enabled: private_ip(device['ip'])
                planned.append((old['id'] if old else uuid.uuid4().hex,did,kind,name,int(enabled),protocol,port))
            names = [p[3] for p in planned if p[4]]
            if len(set(names)) != len(names):
                raise ValueError('Local DNS and a tunnel need different hostnames.')
            for name in names:
                if db.execute('SELECT 1 FROM cf_routes WHERE hostname=? AND enabled=1 AND device_id<>?',(name,did)).fetchone():
                    raise ValueError('That hostname is already assigned to another device.')
            # Release unique hostname reservations before applying both settings.
            db.execute('UPDATE cf_routes SET enabled=0 WHERE device_id=?',(did,))
            for values in planned:
                db.execute('''INSERT INTO cf_routes(id,device_id,kind,hostname,enabled,protocol,port,state)
                    VALUES(?,?,?,?,?,?,?,'pending') ON CONFLICT(id) DO UPDATE SET
                    hostname=excluded.hostname,enabled=excluded.enabled,protocol=excluded.protocol,
                    port=excluded.port,state='pending',message='' ''',values)
        self.wake.set()

    def status(self, route, state, message='', ip=None):
        with storage.connect(self.db_path) as db:
            db.execute('UPDATE cf_routes SET state=?,message=?,synced_ip=?,last_checked=? WHERE id=?',
                       (state,message,ip,storage.now(),route['id']))

    def resources(self, rid):
        with storage.connect(self.db_path) as db:
            return [dict(r) for r in db.execute('SELECT * FROM cf_resources WHERE route_id=?',(rid,))]

    def dns_records(self, api, cfg, name):
        return api.call('GET',f"/zones/{cfg['zone_id']}/dns_records?"+urllib.parse.urlencode({'name':name,'per_page':100})) or []

    def tunnel_rule(self, api, cfg, name, service, route_id=None):
        if not cfg.get('tunnel_id'): raise CloudflareError('Run Cloudflare setup with tunnel support enabled.')
        path = f"/accounts/{cfg['account_id']}/cfd_tunnel/{cfg['tunnel_id']}/configurations"
        response = api.call('GET',path) or {}
        config = response.get('config') or {'ingress':[{'service':'http_status:404'}]}
        rules = config.get('ingress') or [{'service':'http_status:404'}]
        with storage.connect(self.db_path) as db:
            owned = db.execute('SELECT 1 FROM cf_resources WHERE hostname=? AND kind=?',(name,'tunnel')).fetchone()
        matching = [r for r in rules if r.get('hostname')==name]
        if matching and not owned:
            raise CloudflareError('A tunnel rule already uses this hostname outside HomeScan.')
        if route_id:
            with storage.connect(self.db_path) as db:
                db.execute('INSERT OR IGNORE INTO cf_resources VALUES(?,?,?,NULL)',(route_id,name,'tunnel'))
        if service is None:
            desired = [r for r in rules if r.get('hostname')!=name]
        elif matching:
            desired = [dict(r,service=service) if r.get('hostname')==name else r for r in rules]
        else:
            desired = list(rules)
            # An ingress catch-all must remain last; preserve unrelated rules.
            position = next((i for i,r in enumerate(desired) if not r.get('hostname') and not r.get('path')),len(desired))
            desired.insert(position,{'hostname':name,'service':service})
        if not desired or desired[-1].get('hostname') or desired[-1].get('path'):
            desired.append({'service':'http_status:404'})
        if desired != rules:
            api.call('PUT',path,{'config':dict(config,ingress=desired)})

    def cleanup(self, api, cfg, resource):
        name,rid = resource['hostname'],resource['route_id']
        for record in self.dns_records(api,cfg,name):
            if record.get('comment')=='homescan:'+rid:
                api.call('DELETE',f"/zones/{cfg['zone_id']}/dns_records/{record['id']}")
        if resource['kind']=='tunnel': self.tunnel_rule(api,cfg,name,None)
        with storage.connect(self.db_path) as db:
            db.execute('DELETE FROM cf_resources WHERE route_id=? AND hostname=?',(rid,name))

    def reconcile(self, api, cfg, route, device):
        resources = self.resources(route['id'])
        if not route['enabled']:
            for resource in resources: self.cleanup(api,cfg,resource)
            self.status(route,'disabled')
            return
        if not device or not device.get('address_current',False):
            for resource in resources: self.cleanup(api,cfg,resource)
            self.status(route,'waiting','Waiting for this MAC to have a confirmed IP assignment.')
            return
        ip = private_ip(device['ip'])
        name = route['hostname']
        for resource in resources:
            if resource['hostname']!=name or resource['kind']!=route['kind']:
                self.cleanup(api,cfg,resource)
        matches = self.dns_records(api,cfg,name)
        if any(r.get('comment')!='homescan:'+route['id'] for r in matches) or len(matches)>1:
            raise CloudflareError('An existing DNS record owns this hostname. Choose another name or remove that record yourself.')
        if route['kind']=='local':
            desired = dict(type='A',name=name,content=ip,proxied=False,ttl=60,comment='homescan:'+route['id'])
        else:
            service = f"{route['protocol']}://{ip}:{route['port']}"
            self.tunnel_rule(api,cfg,name,service,route['id'])
            desired = dict(type='CNAME',name=name,content=cfg['tunnel_id']+'.cfargotunnel.com',proxied=True,ttl=1,comment='homescan:'+route['id'])
        # Persist ingress ownership before DNS writes so retries can recover partial success.
        with storage.connect(self.db_path) as db:
            db.execute('INSERT OR IGNORE INTO cf_resources VALUES(?,?,?,NULL)',(route['id'],name,route['kind']))
        record = matches[0] if matches else None
        if record:
            if any(record.get(k)!=v for k,v in desired.items()):
                record = api.call('PUT',f"/zones/{cfg['zone_id']}/dns_records/{record['id']}",desired)
        else:
            record = api.call('POST',f"/zones/{cfg['zone_id']}/dns_records",desired)
        with storage.connect(self.db_path) as db:
            db.execute('UPDATE cf_resources SET record_id=? WHERE route_id=? AND hostname=?',(record['id'],route['id'],name))
        self.status(route,'synced','',ip)

    def sync_once(self):
        with self.lock:
            with storage.connect(self.db_path) as db:
                routes = [dict(r) for r in db.execute('SELECT * FROM cf_routes')]
                links = [dict(r) for r in db.execute('SELECT * FROM cf_tunnel_links')]
            if not routes and not links: return
            try: cfg = self.config()
            except (OSError,ValueError): cfg = {}
            devices = {d['device_id']:d for d in storage.inventory(self.db_path)['devices']}
            api = self.api_factory(cfg['api_token']) if cfg.get('api_token') else None
            if links:
                if api: self.reconcile_tunnel_links(api,cfg,links,devices)
                else:
                    for link in links: self._link_status(link,'pending','Connect Cloudflare to sync this tunnel link.')
            for route in routes:
                if not api:
                    self.status(route,'pending' if route['enabled'] or self.resources(route['id']) else 'disabled',
                                'Connect Cloudflare to apply these settings.' if route['enabled'] else '')
                    continue
                try: self.reconcile(api,cfg,route,devices.get(route['device_id']))
                except (CloudflareError,ValueError) as exc: self.status(route,'error',str(exc))
                except Exception: self.status(route,'error','Sync could not finish. Retrying automatically.')

    def run(self):
        while True:
            self.wake.wait(60)
            self.wake.clear()
            try:
                self.sync_once()
                if self.on_update: self.on_update()
            except Exception: pass  # Cloudflare outages must not stop local inventory.


def atomic_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value))
    tmp.chmod(0o600)
    tmp.replace(path)


def setup(options):
    """Only invoked interactively with the token supplied through stdin."""
    token = str(options.get('api_token','')).strip()
    if len(token)<20: raise ValueError('Enter a Cloudflare API token.')
    api = API(token)
    old = json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    zone = None
    for name in (SUFFIX,'chancecox.com'):
        zones = api.call('GET','/zones?'+urllib.parse.urlencode({'name':name,'status':'active'})) or []
        if zones:
            zone = zones[0]
            break
    if not zone: raise CloudflareError('The token cannot access an active chancecox.com zone. Grant Zone Read and DNS Edit.')
    if old.get('zone_id') and old['zone_id']!=zone['id']:
        raise CloudflareError('Zone changed. Keep the original zone while HomeScan manages existing records.')
    cfg = dict(old,api_token=token,zone_id=zone['id'],zone_name=zone['name'],account_id=zone['account']['id'])
    # Store the installation identity before creating anything, so setup retries reuse its tunnel.
    cfg.setdefault('installation_id',uuid.uuid4().hex)
    atomic_json(CONFIG,cfg)
    if options.get('tunnel',True):
        base = f"/accounts/{cfg['account_id']}/cfd_tunnel"
        if not cfg.get('tunnel_id'):
            name = 'homescan-'+cfg['installation_id'][:12]
            existing = api.call('GET',base+'?'+urllib.parse.urlencode({'name':name,'is_deleted':'false'})) or []
            exact = [t for t in existing if t.get('name')==name]
            tunnel = exact[0] if exact else api.call('POST',base,{'name':name,'config_src':'cloudflare'})
            cfg['tunnel_id'] = tunnel['id']
            atomic_json(CONFIG,cfg)
            if not exact:
                api.call('PUT',base+'/'+tunnel['id']+'/configurations',{'config':{'ingress':[{'service':'http_status:404'}]}})
        tunnel_token = api.call('GET',base+'/'+cfg['tunnel_id']+'/token')
        TOKEN_FILE.parent.mkdir(parents=True,exist_ok=True)
        temp = TOKEN_FILE.with_suffix('.tmp')
        temp.write_text(tunnel_token)
        temp.chmod(0o644)  # The connector's non-root user reads this dedicated volume.
        temp.replace(TOKEN_FILE)
    return dict(configured=True,zone=cfg['zone_name'],tunnel_configured=bool(cfg.get('tunnel_id')))


if __name__=='__main__':
    try:
        if sys.argv[1:]!=['setup']: raise ValueError('Use the local Cloudflare setup script.')
        print(json.dumps(setup(json.load(sys.stdin))))
    except (CloudflareError,ValueError) as exc:
        print(json.dumps({'error':str(exc)})); sys.exit(1)
    except Exception:
        print(json.dumps({'error':'Cloudflare setup failed. Check connectivity and token permissions.'})); sys.exit(1)
