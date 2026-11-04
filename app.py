import os, json, threading, time, subprocess, ipaddress, secrets
import xml.etree.ElementTree as ET
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit
import storage
from storage import device_states
from cloudflare_sync import Manager

DB = os.getenv('DB_PATH', '/data/homescan.db')
MODE = os.getenv('SCAN_MODE', 'nmap')
TOKEN = os.getenv('INGEST_TOKEN', '')
NETWORK = os.getenv('SCAN_NETWORK', '192.168.1.0/24')
INTERVAL = 60
CLOUDFLARE = Manager(DB)

def now(): return storage.now()
def connect(): return storage.connect(DB)
def init():
    global CLOUDFLARE
    storage.init(DB)
    CLOUDFLARE = Manager(DB)
    CLOUDFLARE.init()

def record(hosts, started=None, error=None, source='network'):
    storage.record_batches(DB,[dict(hosts=hosts,started=started,error=error,source=source)])
    CLOUDFLARE.wake.set()

def scanner():
    net = ipaddress.IPv4Network(NETWORK,strict=False)
    while True:
        tick = time.monotonic()
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
    def send(self, code, body, content_type='application/json'):
        self.send_response(code)
        self.send_header('Content-Type',content_type)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
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

    def do_GET(self):
        assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','application/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
        if self.path in assets:
            name,mime = assets[self.path]
            return self.send(200,Path(__file__).with_name(name).read_bytes(),mime)
        if self.path=='/health': return self.send(200,b'{"ok":true}')
        if self.path=='/api/cloudflare': return self.send(200,json.dumps(CLOUDFLARE.public_state()).encode())
        if self.path!='/api/devices': return self.send(404,b'{}')
        result = storage.inventory(DB)
        result.update(mode=MODE,network=NETWORK if MODE=='nmap' else 'Home network',cloudflare=CLOUDFLARE.public_state())
        self.send(200,json.dumps(result).encode())

    def do_POST(self):
        if self.path in ('/api/cloudflare/settings','/api/cloudflare/sync'):
            if not self.same_origin(): return self.send(403,b'{"error":"Use the HomeScan dashboard to change settings."}')
            try:
                body = self.body()
                if self.path.endswith('/settings'): CLOUDFLARE.save(body)
                else: CLOUDFLARE.wake.set()
                return self.send(200,b'{"ok":true}')
            except (ValueError,KeyError,TypeError) as exc:
                return self.send(400,json.dumps({'error':str(exc)}).encode())
        if self.path!='/api/scan' or MODE!='agent': return self.send(404,b'{}')
        if not TOKEN or not secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN):
            return self.send(401,b'{"error":"Unauthorized"}')
        try:
            body = self.body()
            batches = body.get('sources')
            if batches is None: batches = [dict(source='network',hosts=body['hosts'],error=body.get('error'))]
            if not isinstance(batches,list) or not 1 <= len(batches) <= 8: raise ValueError('Invalid sources')
            storage.record_batches(DB,batches)
            CLOUDFLARE.wake.set()
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
    if MODE=='nmap': threading.Thread(target=scanner,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',80),Handler).serve_forever()
