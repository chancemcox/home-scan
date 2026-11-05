import os, json, threading, time, subprocess, ipaddress, secrets
import xml.etree.ElementTree as ET
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import storage
from storage import device_states
from cloudflare_sync import Manager, CloudflareError
import deco
import auth
from ws import Hub
from ha import Cluster

DB = os.getenv('DB_PATH', '/data/homescan.db')
MODE = os.getenv('SCAN_MODE', 'nmap')
TOKEN = os.getenv('INGEST_TOKEN', '')
NETWORK = os.getenv('SCAN_NETWORK', '192.168.1.0/24')
INTERVAL = 60
CLOUDFLARE = Manager(DB)
HUB = Hub()
CLUSTER = Cluster(CLOUDFLARE, on_change=lambda _state: publish())

def now(): return storage.now()
def connect(): return storage.connect(DB)
def devices_payload():
    result = storage.inventory(DB)
    result.update(mode=MODE,network=NETWORK if MODE=='nmap' else 'Home network',
                  cloudflare=CLOUDFLARE.public_state(),deco=deco.public_state(),
                  ha=CLUSTER.public_state())
    return json.dumps(result)

def publish():
    HUB.broadcast(devices_payload())

def init():
    global CLOUDFLARE, CLUSTER
    storage.init(DB)
    auth.init()
    CLOUDFLARE = Manager(DB, on_update=publish)
    CLOUDFLARE.init()
    cfg = {}
    try: cfg = CLOUDFLARE.config()
    except (OSError, ValueError): pass
    node_id = cfg.get('installation_id') or None
    CLUSTER = Cluster(CLOUDFLARE, on_change=lambda _state: publish(), node_id=node_id)

def record(hosts, started=None, error=None, source='network'):
    storage.record_batches(DB,[dict(hosts=hosts,started=started,error=error,source=source)])
    CLOUDFLARE.wake.set()
    publish()

def scanner():
    net = ipaddress.IPv4Network(NETWORK,strict=False)
    while True:
        tick = time.monotonic()
        if not CLUSTER.is_leader():
            time.sleep(max(1, INTERVAL/2))
            continue
        started = now()
        try:
            result = subprocess.run(['nmap','-sn','-R','--host-timeout','8s','-oX','-',str(net)],capture_output=True,text=True,timeout=50,check=True)
            hosts = []
            for h in ET.fromstring(result.stdout).findall('host'):
                if h.find('status').get('state') != 'up': continue
                addresses = {a.get('addrtype'):a.get('addr') for a in h.findall('address')}
                if 'ipv4' not in addresses: continue
                name = h.find('hostnames/hostname')
                hosts.append(dict(ip=addresses['ipv4'],mac=addresses.get('mac',''),hostname=name.get('name','') if name is not None else ''))
            record(hosts,started)
        except Exception as exc: record([],started,str(exc)[:1000])
        time.sleep(max(0,INTERVAL-(time.monotonic()-tick)))

class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, content_type='application/json', headers=None):
        self.send_response(code)
        self.send_header('Content-Type',content_type)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        size = int(self.headers.get('Content-Length','0'))
        if not 0 < size <= 1048576: raise ValueError('Invalid request size')
        body = json.loads(self.rfile.read(size))
        if not isinstance(body,dict): raise ValueError('Expected a JSON object')
        return body

    def same_origin(self):
        origin = self.headers.get('Origin','')
        return (origin and urlsplit(origin).scheme in ('http','https')
                and urlsplit(origin).netloc == self.headers.get('Host','')
                and self.headers.get('Sec-Fetch-Site','same-origin') not in ('cross-site','same-site')
                and self.headers.get('Content-Type','').split(';')[0]=='application/json')

    def session_token(self):
        return auth.parse_cookie(self.headers.get('Cookie',''))

    def current_user(self):
        return auth.session_user(self.session_token())

    def require_user(self):
        user = self.current_user()
        if user: return user
        accept = self.headers.get('Accept','')
        if 'text/html' in accept or self.path in ('/','/index.html'):
            self.send_response(302)
            self.send_header('Location','/login')
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            return None
        self.send(401,b'{"error":"Sign in required."}')
        return None

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path=='/login':
            if self.current_user():
                self.send_response(302); self.send_header('Location','/'); self.end_headers(); return
            return self.send(200,Path(__file__).with_name('login.html').read_bytes(),'text/html; charset=utf-8')
        if parsed.path in ('/style.css','/login.js'):
            name = 'style.css' if parsed.path.endswith('.css') else 'login.js'
            mime = 'text/css; charset=utf-8' if name.endswith('.css') else 'application/javascript; charset=utf-8'
            return self.send(200,Path(__file__).with_name(name).read_bytes(),mime)
        if parsed.path in ('/','/app.js','/index.html'):
            if not self.require_user(): return
            name = 'index.html' if parsed.path in ('/','/index.html') else 'app.js'
            mime = 'text/html; charset=utf-8' if name=='index.html' else 'application/javascript; charset=utf-8'
            return self.send(200,Path(__file__).with_name(name).read_bytes(),mime)
        if self.path=='/ws':
            if not self.current_user(): return self.send(401,b'{"error":"Sign in required."}')
            return HUB.serve(self, devices_payload)
        if self.path=='/ha': return CLUSTER.serve(self)
        if self.path=='/health': return self.send(200,b'{"ok":true}')
        if self.path=='/api/me':
            user = self.current_user()
            if not user: return self.send(401,b'{"error":"Sign in required."}')
            return self.send(200,json.dumps({'username':user}).encode())
        if not self.current_user() and parsed.path.startswith('/api/'):
            return self.send(401,b'{"error":"Sign in required."}')
        if self.path=='/api/ha': return self.send(200,json.dumps(CLUSTER.public_state()).encode())
        if self.path=='/api/cloudflare': return self.send(200,json.dumps(CLOUDFLARE.public_state()).encode())
        if self.path=='/api/cloudflare/tunnels': return self.send(200,json.dumps(CLOUDFLARE.list_tunnels()).encode())
        if self.path=='/api/cloudflare/zones': return self.send(200,json.dumps(CLOUDFLARE.list_zones()).encode())
        if parsed.path=='/api/cloudflare/tunnel':
            try:
                tunnel_id = parse_qs(parsed.query).get('id',[''])[0]
                return self.send(200,json.dumps(CLOUDFLARE.get_tunnel(tunnel_id)).encode())
            except (ValueError, KeyError, TypeError) as exc:
                return self.send(400,json.dumps({'error':str(exc)}).encode())
            except CloudflareError as exc:
                return self.send(502,json.dumps({'error':str(exc)}).encode())
            except Exception:
                return self.send(502,b'{"error":"Cloudflare could not load this tunnel."}')
        if self.path=='/api/deco': return self.send(200,json.dumps(deco.public_state()).encode())
        if self.path!='/api/devices': return self.send(404,b'{}')
        self.send(200,devices_payload().encode())

    def do_POST(self):
        if self.path=='/api/login':
            try:
                body = self.body()
                result = auth.login(body.get('username'), body.get('password'), bool(body.get('remember')))
                headers = {'Set-Cookie': auth.cookie_header(result['token'], result['remember'], result['max_age'])}
                return self.send(200, json.dumps({'ok':True,'username':result['username']}).encode(), headers=headers)
            except ValueError as exc:
                return self.send(401, json.dumps({'error':str(exc)}).encode())
            except Exception:
                return self.send(500, b'{"error":"Sign in failed."}')
        if self.path=='/api/logout':
            auth.logout(self.session_token())
            return self.send(200, b'{"ok":true}', headers={'Set-Cookie': auth.clear_cookie_header()})
        if self.path in ('/api/cloudflare/settings','/api/cloudflare/domain','/api/cloudflare/sync','/api/cloudflare/connect','/api/cloudflare/tunnels/update','/api/cloudflare/tunnels/link','/api/cloudflare/tunnels/create-route','/api/cloudflare/tunnels/delete','/api/cloudflare/tunnels/delete-hostname','/api/deco/settings'):
            if not self.same_origin(): return self.send(403,b'{"error":"Use the HomeScan dashboard to change settings."}')
            if not self.current_user(): return self.send(401,b'{"error":"Sign in required."}')
            try:
                body = self.body()
                if self.path=='/api/deco/settings':
                    state = deco.save_settings(body)
                    publish()
                    return self.send(200,json.dumps(dict(ok=True,**state)).encode())
                if self.path=='/api/cloudflare/domain':
                    result = CLOUDFLARE.save_domain(body)
                    publish()
                    return self.send(200,json.dumps(result).encode())
                if self.path=='/api/cloudflare/connect':
                    result = CLOUDFLARE.connect(body)
                    publish()
                    return self.send(200,json.dumps(dict(ok=True,**result)).encode())
                if self.path=='/api/cloudflare/tunnels/update':
                    result = CLOUDFLARE.update_tunnel(body)
                    publish()
                    return self.send(200,json.dumps(result).encode())
                if self.path=='/api/cloudflare/tunnels/link':
                    result = CLOUDFLARE.save_tunnel_link(body)
                    publish()
                    return self.send(200,json.dumps(result).encode())
                if self.path=='/api/cloudflare/tunnels/create-route':
                    result=CLOUDFLARE.create_tunnel_route(body)
                    publish()
                    return self.send(200,json.dumps(result).encode())
                if self.path=='/api/cloudflare/tunnels/delete-hostname':
                    result=CLOUDFLARE.delete_tunnel_hostname(body)
                    publish()
                    return self.send(200,json.dumps(result).encode())
                if self.path=='/api/cloudflare/tunnels/delete':
                    result=CLOUDFLARE.delete_tunnel(body)
                    publish()
                    return self.send(200,json.dumps(result).encode())
                if self.path.endswith('/settings'): CLOUDFLARE.save(body)
                else: CLOUDFLARE.wake.set()
                publish()
                return self.send(200,b'{"ok":true}')
            except (ValueError,KeyError,TypeError) as exc:
                return self.send(400,json.dumps({'error':str(exc)}).encode())
            except CloudflareError as exc:
                return self.send(502,json.dumps({'error':str(exc)}).encode())
        if self.path!='/api/scan' or MODE!='agent': return self.send(404,b'{}')
        if not TOKEN or not secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN):
            return self.send(401,b'{"error":"Unauthorized"}')
        if not CLUSTER.is_leader():
            return self.send(503,json.dumps({'error':'This HomeScan node is on standby. Point the scanner at '+CLUSTER.hostname+':'+str(CLUSTER.port)+'.','ha':CLUSTER.public_state()}).encode())
        try:
            body = self.body()
            batches = body.get('sources')
            if batches is None: batches = [dict(source='network',hosts=body['hosts'],error=body.get('error'))]
            if not isinstance(batches,list) or not 1 <= len(batches) <= 8: raise ValueError('Invalid sources')
            # Drop deco batches that are empty+error so an unreachable router cannot
            # poison inventory freshness; network batches still apply.
            cleaned = []
            for batch in batches:
                if not isinstance(batch, dict): raise ValueError('Invalid sources')
                if batch.get('source')=='deco' and batch.get('error') and not batch.get('hosts'):
                    continue
                cleaned.append(batch)
            if not cleaned: raise ValueError('Invalid sources')
            storage.record_batches(DB,cleaned)
            CLOUDFLARE.wake.set()
            publish()
        except (ValueError,KeyError,TypeError) as exc:
            return self.send(400,json.dumps({'error':str(exc)}).encode())
        self.send(200,b'{"ok":true}')

if __name__=='__main__':
    if MODE not in ('nmap','agent'): raise ValueError('Invalid SCAN_MODE')
    if MODE=='agent' and len(TOKEN)<32: raise ValueError('Set INGEST_TOKEN to at least 32 characters')
    if MODE=='nmap':
        net=ipaddress.IPv4Network(NETWORK,strict=False)
        if not net.is_private or net.num_addresses>4096: raise ValueError('Use a private subnet with at most 4096 addresses')
    init()
    threading.Thread(target=CLOUDFLARE.run,daemon=True).start()
    CLOUDFLARE.wake.set()
    threading.Thread(target=CLUSTER.run,daemon=True,name='homescan-ha').start()
    if MODE=='nmap': threading.Thread(target=scanner,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',80),Handler).serve_forever()
