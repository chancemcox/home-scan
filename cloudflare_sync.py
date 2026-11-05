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
from d1 import ensure_database, D1Error

# Base DNS domain is configured per install (Settings / Cloudflare setup). No personal default.
OLD_SUFFIXES = tuple(s for s in os.getenv('HOMESCAN_OLD_SUFFIXES', '').split(',') if s.strip())
LABEL_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
CONFIG = Path(os.getenv('CLOUDFLARE_CONFIG','/data/cloudflare.json'))
TOKEN_FILE = Path(os.getenv('CLOUDFLARE_TUNNEL_TOKEN','/run/homescan-tunnel/token'))
# Non-secret install settings formerly hardcoded — shared via SQLite/D1 app_settings.
SHARED_SETTING_KEYS = (
    'suffix', 'zone_id', 'zone_name', 'account_id', 'tunnel_id',
    'installation_id', 'd1_database_id', 'cluster_worker_url',
)


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


def normalize_suffix(value):
    name = str(value or '').strip().lower().rstrip('.')
    if name.startswith('*.'): name = name[2:]
    parts = name.split('.')
    if len(parts) < 2 or not all(LABEL_RE.fullmatch(p) for p in parts):
        raise ValueError('Enter a base domain such as house.example.com')
    return name


def _parse_hostname_input(value):
    name = str(value or '').strip().lower().rstrip('.')
    if '://' in name:
        parsed = urllib.parse.urlsplit(name)
        if parsed.scheme not in ('http','https') or parsed.path not in ('','/') or parsed.query or parsed.fragment or parsed.port or parsed.username:
            raise ValueError('Enter a hostname without a port or path.')
        name = parsed.hostname or ''
    return name


def hostname(value, suffix=None, kind='local'):
    """Normalize a device hostname.

    Local DNS must be a single label under the configured base domain.
    Tunnel hostnames may be that short form or any full hostname on a Cloudflare zone.
    """
    configured = ''
    if suffix not in (None, ''):
        configured = normalize_suffix(suffix)
    name = _parse_hostname_input(value)
    if not name:
        raise ValueError('Enter a hostname.')
    if '.' not in name:
        if not configured:
            raise ValueError('Set a base domain in Settings, or enter a full hostname.')
        name += '.'+configured
    parts = name.split('.')
    if not all(LABEL_RE.fullmatch(p) for p in parts):
        raise ValueError('Hostnames may only use letters, numbers, and hyphens.')
    if kind == 'tunnel':
        if len(parts) < 2:
            raise ValueError('Enter a full hostname on a Cloudflare domain, or a short label under your base domain.')
        return name
    if not configured:
        raise ValueError('Set a base domain in Settings before enabling local DNS.')
    label = name.removesuffix('.'+configured)
    if name != label+'.'+configured or not LABEL_RE.fullmatch(label) or '.' in label:
        raise ValueError('Use a single hostname such as nas.'+configured)
    return name


def hostname_under_zone(value, zone_name):
    """Build a tunnel public hostname under an accessible Cloudflare zone."""
    zone = str(zone_name or '').strip().lower().rstrip('.')
    if not zone or not all(LABEL_RE.fullmatch(p) for p in zone.split('.')):
        raise ValueError('Choose an accessible domain from this Cloudflare account.')
    raw = _parse_hostname_input(value)
    if not raw:
        raise ValueError('Enter a hostname such as files or files.house')
    if raw == zone or raw.endswith('.'+zone):
        relative = '' if raw == zone else raw[:-(len(zone)+1)]
        parts = relative.split('.') if relative else []
    else:
        parts = raw.split('.')
    if not parts or not all(LABEL_RE.fullmatch(p) for p in parts):
        raise ValueError('Use a hostname such as files or files.house under '+zone)
    return '.'.join(parts)+'.'+zone


def zone_candidates_for_suffix(suffix):
    suffix = normalize_suffix(suffix)
    parts = suffix.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts)-1)]


def infer_suffix_from_hostnames(hostnames, zone_name=''):
    """Recover a base domain from existing managed hostnames (post-hardcoding installs)."""
    zone = str(zone_name or '').strip().lower().rstrip('.')
    counts = {}
    for raw in hostnames:
        name = str(raw or '').strip().lower().rstrip('.')
        if not name or '.' not in name:
            continue
        candidate = name.split('.', 1)[1]
        if zone and not (candidate == zone or candidate.endswith('.' + zone)):
            continue
        try:
            candidate = normalize_suffix(candidate)
        except ValueError:
            continue
        counts[candidate] = counts.get(candidate, 0) + 1
    if not counts:
        return ''
    return max(counts.items(), key=lambda item: (item[1], len(item[0])))[0]


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
            CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            ''')
            # Optional one-time rewrite when HOMESCAN_OLD_SUFFIXES and a new suffix are set.
            new_suffix = ''
            try:
                cfg = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
                new_suffix = normalize_suffix(cfg['suffix']) if cfg.get('suffix') else ''
            except (OSError, ValueError):
                new_suffix = ''
            if new_suffix:
                for old_suffix in OLD_SUFFIXES:
                    old_suffix = old_suffix.strip().lower().rstrip('.')
                    if not old_suffix or old_suffix == new_suffix:
                        continue
                    for row in db.execute('SELECT id,hostname,enabled FROM cf_routes WHERE hostname LIKE ?',
                                          ('%.'+old_suffix,)):
                        new = row['hostname'].removesuffix('.'+old_suffix)+'.'+new_suffix
                        db.execute('''UPDATE cf_routes SET hostname=?,
                            state=CASE WHEN enabled=1 THEN 'pending' ELSE state END, message='' WHERE id=?''',
                                   (new, row['id']))
        self.sync_shared_settings()

    def config(self):
        try:
            cfg = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
        except (FileNotFoundError, ValueError, OSError):
            cfg = {}
        if not isinstance(cfg, dict):
            cfg = {}
        try:
            shared = storage.get_settings(self.db_path, SHARED_SETTING_KEYS)
        except Exception:
            shared = {}
        for key in SHARED_SETTING_KEYS:
            if shared.get(key):
                cfg[key] = shared[key]
        return cfg

    def sync_shared_settings(self):
        """Keep former hardcoded install defaults in the DB (and D1 when enabled)."""
        with self.lock:
            try:
                local = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
            except (ValueError, OSError):
                local = {}
            if not isinstance(local, dict):
                local = {}
            try:
                shared = storage.get_settings(self.db_path, SHARED_SETTING_KEYS)
            except Exception:
                shared = {}
            changed = False
            for key in SHARED_SETTING_KEYS:
                if not local.get(key) and shared.get(key):
                    local[key] = shared[key]
                    changed = True
            if not local.get('suffix'):
                try:
                    with storage.connect(self.db_path) as db:
                        names = [row['hostname'] for row in db.execute(
                            "SELECT hostname FROM cf_routes WHERE hostname IS NOT NULL AND hostname<>''")]
                except Exception:
                    names = []
                inferred = infer_suffix_from_hostnames(names, local.get('zone_name') or shared.get('zone_name') or '')
                if inferred:
                    local['suffix'] = inferred
                    changed = True
            if changed:
                atomic_json(self.config_path, local)
            payload = {key: local[key] for key in SHARED_SETTING_KEYS if local.get(key) not in (None, '')}
            if payload:
                storage.set_settings(self.db_path, payload)
            return payload

    def suffix(self):
        try: cfg = self.config()
        except (ValueError, OSError): cfg = {}
        raw = cfg.get('suffix') or ''
        if not raw:
            return ''
        try: return normalize_suffix(raw)
        except ValueError: return ''

    def save_domain(self, body):
        """Persist the dashboard base domain used for local DNS and short tunnel labels."""
        suffix = normalize_suffix(body.get('suffix') or body.get('domain'))
        with self.lock:
            try:
                cfg = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
            except (ValueError, OSError):
                cfg = {}
            if not isinstance(cfg, dict):
                cfg = {}
            cfg['suffix'] = suffix
            atomic_json(self.config_path, cfg)
            storage.set_settings(self.db_path, {'suffix': suffix})
        return dict(ok=True, suffix=suffix)

    def public_state(self):
        try: cfg = self.config()
        except (ValueError,OSError): cfg = {}
        with storage.connect(self.db_path) as db:
            routes = [dict(r) for r in db.execute('SELECT * FROM cf_routes')]
            links = [dict(r) for r in db.execute('SELECT * FROM cf_tunnel_links')]
        db_state = storage.backend_state()
        return dict(configured=bool(cfg.get('api_token')),zone=cfg.get('zone_name'),
                    tunnel_id=cfg.get('tunnel_id') or '',
                    tunnel_configured=bool(cfg.get('tunnel_id')),suffix=self.suffix(),routes=routes,tunnel_links=links,
                    d1_database_id=cfg.get('d1_database_id') or '',
                    database=db_state)

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
        did=str(body.get('device_id') or '')
        protocol=str(body.get('protocol') or 'http')
        if protocol not in ('http','https'): raise ValueError('Choose HTTP or HTTPS for the origin.')
        try: port=int(body.get('port',80))
        except (TypeError,ValueError): raise ValueError('Port must be between 1 and 65535.') from None
        if not 1<=port<=65535: raise ValueError('Port must be between 1 and 65535.')
        with self.lock,storage.connect(self.db_path) as db:
            device=db.execute('SELECT * FROM devices WHERE device_id=?',(did,)).fetchone()
            if not device or not device['mac'] or not did.startswith('mac:'):
                raise ValueError('Choose a computer with a known MAC address.')
        ip=private_ip(device['ip']);cfg,api=self._tunnel_api()
        zone=api.call('GET',f'/zones/{zone_id}') or {}
        if not zone.get('name') or (zone.get('account') or {}).get('id')!=cfg['account_id']:
            raise ValueError('Choose an accessible domain from this Cloudflare account.')
        name=hostname_under_zone(body.get('hostname'), zone['name'])
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

    def _cleanup_tunnel_dns(self, api, cfg, tunnel_id, hostname):
        """Best-effort removal of CNAMEs that pointed this hostname at the tunnel."""
        hostname = str(hostname or '').strip().lower().rstrip('.')
        if not hostname or '.' not in hostname: return
        target = (tunnel_id+'.cfargotunnel.com').lower()
        labels = hostname.split('.')
        zone = None
        for i in range(len(labels)-1):
            name = '.'.join(labels[i:])
            try:
                rows = api.call('GET','/zones?'+urllib.parse.urlencode({'name':name,'status':'active','per_page':5})) or []
            except CloudflareError:
                continue
            for candidate in rows:
                if candidate.get('name')==name and (candidate.get('account') or {}).get('id')==cfg['account_id']:
                    zone = candidate; break
            if zone: break
        if not zone: return
        try:
            records = api.call('GET',f"/zones/{zone['id']}/dns_records?"+urllib.parse.urlencode({'name':hostname,'per_page':100})) or []
        except CloudflareError:
            return
        for record in records:
            content = str(record.get('content') or '').rstrip('.').lower()
            if record.get('type')=='CNAME' and content==target and record.get('id'):
                try: api.call('DELETE',f"/zones/{zone['id']}/dns_records/{record['id']}")
                except CloudflareError: pass

    def delete_tunnel_hostname(self, body):
        tunnel_id = self._tunnel_id(body.get('tunnel_id'))
        key = (str(body.get('hostname') or ''), str(body.get('path') or ''))
        if not key[0] and not key[1]:
            raise ValueError('Choose a public hostname to delete.')
        with self.lock:
            cfg, api = self._tunnel_api()
            base = f"/accounts/{cfg['account_id']}/cfd_tunnel/{tunnel_id}"
            tunnel = api.call('GET', base) or {}
            if tunnel.get('config_src') != 'cloudflare':
                raise ValueError('Locally managed tunnels must be edited in their local configuration.')
            if tunnel_id == cfg.get('tunnel_id'):
                with storage.connect(self.db_path) as db:
                    owned = db.execute("SELECT 1 FROM cf_resources WHERE kind='tunnel' AND hostname=?",(key[0],)).fetchone()
                if owned:
                    raise ValueError('HomeScan-managed ingress rules must be removed from their device settings.')
            response = api.call('GET', base+'/configurations') or {}
            config = response.get('config') or {'ingress':[{'service':'http_status:404'}]}
            rules = list(config.get('ingress') or [])
            matches = [i for i, rule in enumerate(rules) if self._rule_key(rule)==key]
            if len(matches) != 1:
                raise ValueError('That hostname was not found as a unique ingress rule.')
            del rules[matches[0]]
            desired = self._tunnel_config(dict(config, ingress=rules))
            api.call('PUT', base+'/configurations', {'config':desired})
            if key[0]: self._cleanup_tunnel_dns(api, cfg, tunnel_id, key[0])
            with storage.connect(self.db_path) as db:
                db.execute('DELETE FROM cf_tunnel_links WHERE tunnel_id=? AND hostname=? AND path=?',(tunnel_id,*key))
        return self.get_tunnel(tunnel_id)

    def delete_tunnel(self, body):
        tunnel_id = self._tunnel_id(body.get('tunnel_id'))
        with self.lock:
            cfg, api = self._tunnel_api()
            if tunnel_id == cfg.get('tunnel_id'):
                raise ValueError('The HomeScan tunnel cannot be deleted from the dashboard.')
            base = f"/accounts/{cfg['account_id']}/cfd_tunnel/{tunnel_id}"
            tunnel = api.call('GET', base) or {}
            if tunnel.get('config_src') != 'cloudflare':
                raise ValueError('Locally managed tunnels must be deleted in their local configuration.')
            try:
                response = api.call('GET', base+'/configurations') or {}
                ingress = (response.get('config') or {}).get('ingress') or []
            except CloudflareError:
                ingress = []
            hostnames = [rule.get('hostname') for rule in ingress if rule.get('hostname')]
            api.call('DELETE', base)
            for name in hostnames:
                self._cleanup_tunnel_dns(api, cfg, tunnel_id, name)
            with storage.connect(self.db_path) as db:
                db.execute('DELETE FROM cf_tunnel_links WHERE tunnel_id=?',(tunnel_id,))
        return dict(ok=True)

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
                suffix = self.suffix()
                name = hostname(item.get('hostname'), suffix=suffix, kind=kind) if enabled else (old['hostname'] if old else '')
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

    def zone_for(self, api, cfg, name):
        """Find the Cloudflare zone that should own a hostname."""
        name = str(name or '').strip().lower().rstrip('.')
        if not name or '.' not in name:
            raise CloudflareError('Hostname is missing a Cloudflare zone.')
        account = cfg.get('account_id')
        zone_name = str(cfg.get('zone_name') or '').strip().lower().rstrip('.')
        if cfg.get('zone_id') and zone_name and (name == zone_name or name.endswith('.'+zone_name)):
            return dict(id=cfg['zone_id'], name=zone_name, account={'id': account})
        labels = name.split('.')
        for i in range(len(labels)-1):
            candidate = '.'.join(labels[i:])
            try:
                rows = api.call('GET','/zones?'+urllib.parse.urlencode({'name':candidate,'status':'active','per_page':5})) or []
            except CloudflareError:
                continue
            for zone in rows:
                if zone.get('name') == candidate and (zone.get('account') or {}).get('id') == account:
                    return zone
        raise CloudflareError('No Cloudflare zone accessible to this token covers '+name+'.')

    def dns_records(self, api, cfg, name, zone=None):
        zone = zone or self.zone_for(api, cfg, name)
        return api.call('GET',f"/zones/{zone['id']}/dns_records?"+urllib.parse.urlencode({'name':name,'per_page':100})) or []

    def ensure_ha_dns(self, ip, hostname=None):
        """Create or point the cluster A record at this node's private LAN IP."""
        ip = private_ip(ip)
        suffix = self.suffix()
        name = str(hostname or '').strip().lower().rstrip('.')
        if not name and suffix:
            name = 'homescan.'+suffix
        if not name:
            raise ValueError('Set HA_HOSTNAME or a base domain before updating cluster DNS.')
        if suffix and not name.endswith('.'+suffix):
            raise ValueError('HA hostname must be under '+suffix)
        with self.lock:
            try: cfg = self.config()
            except (OSError, ValueError): cfg = {}
            if not cfg.get('api_token') or not cfg.get('account_id'):
                raise ValueError('Connect Cloudflare before HA failover can update DNS.')
            api = self.api_factory(cfg['api_token'])
            zone = self.zone_for(api, cfg, name)
            matches = self.dns_records(api, cfg, name, zone)
            foreign = [r for r in matches if r.get('comment') != 'homescan:ha']
            if foreign:
                raise CloudflareError(name+' is owned by another DNS record. Remove it or choose another HA hostname.')
            desired = dict(type='A',name=name,content=ip,proxied=False,ttl=30,comment='homescan:ha')
            if matches:
                record = matches[0]
                if any(record.get(k) != v for k, v in desired.items()):
                    api.call('PUT', f"/zones/{zone['id']}/dns_records/{record['id']}", desired)
            else:
                api.call('POST', f"/zones/{zone['id']}/dns_records", desired)
        return dict(hostname=name, ip=ip)

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
        try: zone = self.zone_for(api, cfg, name)
        except CloudflareError: zone = None
        if zone:
            for record in self.dns_records(api,cfg,name,zone):
                if record.get('comment')=='homescan:'+rid:
                    api.call('DELETE',f"/zones/{zone['id']}/dns_records/{record['id']}")
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
        zone = self.zone_for(api, cfg, name)
        matches = self.dns_records(api,cfg,name,zone)
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
                record = api.call('PUT',f"/zones/{zone['id']}/dns_records/{record['id']}",desired)
        else:
            record = api.call('POST',f"/zones/{zone['id']}/dns_records",desired)
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

    def connect(self, body):
        """Dashboard/API path for adding or rotating the Cloudflare API token."""
        with self.lock:
            result = connect_cloudflare(body, self.config_path, self.api_factory, TOKEN_FILE)
        self.sync_shared_settings()
        self.wake.set()
        return result

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


def connect_cloudflare(options, config_path=CONFIG, api_factory=API, token_file=TOKEN_FILE):
    """Validate a Cloudflare API token and persist account/zone settings."""
    token = str(options.get('api_token') or '').strip()
    try: old = json.loads(config_path.read_text()) if config_path.exists() else {}
    except (OSError, ValueError): old = {}
    if not token: token = str(old.get('api_token') or '').strip()
    if len(token) < 20: raise ValueError('Enter a Cloudflare API token.')
    want_tunnel = options.get('tunnel', True)
    if not isinstance(want_tunnel, bool): raise ValueError('Invalid tunnel option.')
    want_d1 = options.get('d1', True)
    if not isinstance(want_d1, bool): raise ValueError('Invalid D1 option.')
    if options.get('suffix') not in (None, ''):
        suffix = normalize_suffix(options.get('suffix'))
    elif old.get('suffix'):
        suffix = normalize_suffix(old.get('suffix'))
    else:
        suffix = ''
    api = api_factory(token)
    zone = None
    preferred = str(options.get('zone_name') or old.get('zone_name') or '').strip().lower().rstrip('.')
    candidates = []
    if preferred: candidates.append(preferred)
    if suffix: candidates.extend(zone_candidates_for_suffix(suffix))
    seen = set()
    for name in candidates:
        if name in seen: continue
        seen.add(name)
        zones = api.call('GET', '/zones?'+urllib.parse.urlencode({'name':name,'status':'active'})) or []
        if zones:
            zone = zones[0]
            break
    if not zone:
        # Use any active zone the token can see so installs are not tied to one domain.
        zones = api.call('GET', '/zones?'+urllib.parse.urlencode({'status':'active','per_page':100})) or []
        if len(zones) == 1:
            zone = zones[0]
        elif preferred:
            exact = [z for z in zones if z.get('name') == preferred]
            zone = exact[0] if exact else None
        elif zones:
            zones = sorted(zones, key=lambda z: z.get('name') or '')
            zone = zones[0]
    if not zone:
        raise CloudflareError('The token cannot access an active Cloudflare zone. Grant Zone Read and DNS Edit for your domain.')
    if old.get('zone_id') and old['zone_id'] != zone['id']:
        raise CloudflareError('Zone changed. Keep the original zone while HomeScan manages existing records.')
    if not suffix:
        # Default the base domain to the connected zone until Settings overrides it.
        suffix = normalize_suffix(zone['name'])
    cfg = dict(old, api_token=token, zone_id=zone['id'], zone_name=zone['name'], account_id=zone['account']['id'], suffix=suffix)
    # Store the installation identity before creating anything, so setup retries reuse its tunnel.
    cfg.setdefault('installation_id', uuid.uuid4().hex)
    if want_d1:
        try:
            cfg['d1_database_id'] = ensure_database(api, cfg['account_id'], 'homescan')
        except D1Error as exc:
            raise CloudflareError(str(exc)) from None
        except CloudflareError:
            raise
        except Exception:
            raise CloudflareError('Could not create or open the shared Cloudflare D1 database. Grant Account D1 Edit.') from None
    else:
        cfg.pop('d1_database_id', None)
    atomic_json(config_path, cfg)
    if want_tunnel:
        base = f"/accounts/{cfg['account_id']}/cfd_tunnel"
        if not cfg.get('tunnel_id'):
            name = 'homescan-'+cfg['installation_id'][:12]
            existing = api.call('GET', base+'?'+urllib.parse.urlencode({'name':name,'is_deleted':'false'})) or []
            exact = [t for t in existing if t.get('name') == name]
            tunnel = exact[0] if exact else api.call('POST', base, {'name':name,'config_src':'cloudflare'})
            cfg['tunnel_id'] = tunnel['id']
            atomic_json(config_path, cfg)
            if not exact:
                api.call('PUT', base+'/'+tunnel['id']+'/configurations', {'config':{'ingress':[{'service':'http_status:404'}]}})
        tunnel_token = api.call('GET', base+'/'+cfg['tunnel_id']+'/token')
        token_file.parent.mkdir(parents=True, exist_ok=True)
        temp = token_file.with_suffix('.tmp')
        temp.write_text(tunnel_token)
        temp.chmod(0o644)  # The connector's non-root user reads this dedicated volume.
        temp.replace(token_file)
    return dict(configured=True, zone=cfg['zone_name'], tunnel_configured=bool(cfg.get('tunnel_id')),
                d1_database_id=cfg.get('d1_database_id') or '', database_shared=bool(cfg.get('d1_database_id')))


def setup(options):
    """CLI entry used by configure-cloudflare.ps1 (token on stdin)."""
    return connect_cloudflare(options)


if __name__=='__main__':
    try:
        if sys.argv[1:]!=['setup']: raise ValueError('Use the local Cloudflare setup script.')
        print(json.dumps(setup(json.load(sys.stdin))))
    except (CloudflareError,ValueError) as exc:
        print(json.dumps({'error':str(exc)})); sys.exit(1)
    except Exception:
        print(json.dumps({'error':'Cloudflare setup failed. Check connectivity and token permissions.'})); sys.exit(1)
