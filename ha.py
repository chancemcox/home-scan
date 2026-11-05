"""Active-passive HomeScan cluster.

When a Cloudflare Durable Object cluster worker is configured, leadership and live
inventory are coordinated there (in-memory shared state). Otherwise nodes fall
back to DNS + WebSocket heartbeats. Hostnames and IPs come from environment /
Cloudflare settings — nothing personal is hardcoded.
"""
import json
import os
import socket
import struct
import threading
import time
import uuid
import ws
import applog
from cloudflare_sync import CloudflareError, private_ip
from cluster_state import ClusterStateError

HA_HOSTNAME = os.getenv('HA_HOSTNAME', '').strip().lower().rstrip('.')
HA_PORT = int(os.getenv('HA_PORT', '8080'))
HA_ENABLED = os.getenv('HA_ENABLED', '1').strip().lower() not in ('0', 'false', 'no', 'off')
HEARTBEAT = float(os.getenv('HA_HEARTBEAT', '3'))
TIMEOUT = float(os.getenv('HA_TIMEOUT', '12'))


def detect_local_ip():
    configured = os.getenv('HA_LOCAL_IP', '').strip()
    if configured:
        return private_ip(configured)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('1.1.1.1', 80))
        ip = sock.getsockname()[0]
        sock.close()
        return private_ip(ip)
    except (OSError, ValueError):
        raise ValueError('Set HA_LOCAL_IP to this host\'s private LAN address.')


def resolve_ipv4(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    seen, ips = set(), []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def masked_frame(opcode, payload=b''):
    mask = os.urandom(4)
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    header = bytes([0x80 | opcode, 0x80 | len(payload)])
    return header + mask + body


class WsClient:
    """Minimal masked client used by followers to watch the leader."""

    def __init__(self, sock, pending=b''):
        self.sock = sock
        self.alive = True
        self._pending = pending

    def send_text(self, text):
        payload = text.encode() if isinstance(text, str) else text
        self.sock.sendall(masked_frame(ws.OP_TEXT, payload))

    def close(self):
        self.alive = False
        try: self.sock.sendall(masked_frame(ws.OP_CLOSE))
        except OSError: pass
        try: self.sock.close()
        except OSError: pass

    def _read(self, n):
        chunks = []
        if self._pending:
            take = self._pending[:n]
            self._pending = self._pending[n:]
            chunks.append(take)
            n -= len(take)
        while n > 0:
            chunk = self.sock.recv(n)
            if not chunk: raise ConnectionError('closed')
            chunks.append(chunk)
            n -= len(chunk)
        return b''.join(chunks)

    def recv(self):
        header = self._read(2)
        opcode, length = header[0] & 0x0F, header[1] & 0x7F
        if length == 126: length = struct.unpack('!H', self._read(2))[0]
        elif length == 127: length = struct.unpack('!Q', self._read(8))[0]
        payload = self._read(length)
        return opcode, payload


def connect_ha(host, port, path='/ha', timeout=5):
    sock = socket.create_connection((host, port), timeout=timeout)
    key = __import__('base64').b64encode(os.urandom(16)).decode()
    req = (
        f'GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n'
        f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'
    ).encode()
    sock.sendall(req)
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk: raise ConnectionError('HA upgrade failed')
        buf += chunk
    head, rest = buf.split(b'\r\n\r\n', 1)
    if b'101' not in head.split(b'\r\n', 1)[0]:
        sock.close()
        raise ConnectionError('HA endpoint rejected WebSocket upgrade')
    return WsClient(sock, rest)


class Cluster:
    def __init__(self, cloudflare, on_change=None, hostname=None, port=HA_PORT,
                 local_ip=None, node_id=None, enabled=HA_ENABLED, cluster_state=None):
        self.cloudflare = cloudflare
        self.on_change = on_change
        self.hostname = (hostname if hostname is not None else HA_HOSTNAME).strip().lower().rstrip('.')
        self.port = port
        self.enabled = enabled
        self.node_id = node_id or uuid.uuid4().hex
        self.local_ip = local_ip
        self.cluster_state = cluster_state
        self.role = 'disabled' if not enabled else 'starting'
        self.leader = {}
        self.message = ''
        self.hub = ws.Hub()
        self.lock = threading.RLock()
        self._stop = threading.Event()
        self._generation = 0

    def resolve_hostname(self):
        if self.hostname:
            return self.hostname
        try:
            suffix = self.cloudflare.suffix()
        except Exception:
            suffix = ''
        if suffix:
            return 'homescan.' + suffix
        return ''

    def public_state(self):
        shared = {}
        if self.cluster_state and self.cluster_state.enabled:
            try: shared = self.cluster_state.public_state()
            except Exception: shared = dict(enabled=True, backend='durable-object-memory')
        with self.lock:
            return dict(
                enabled=self.enabled,
                role=self.role,
                hostname=self.resolve_hostname(),
                port=self.port,
                local_ip=self.local_ip or '',
                node_id=self.node_id,
                leader=dict(self.leader),
                scanning=self.role == 'leader',
                message=self.message,
                shared=shared,
            )

    def is_leader(self):
        return (not self.enabled) or self.role == 'leader'

    def _set_role(self, role, message='', leader=None):
        with self.lock:
            changed = self.role != role or self.message != message
            self.role = role
            self.message = message
            if leader is not None:
                self.leader = leader
            elif role == 'leader':
                self.leader = dict(node_id=self.node_id, ip=self.local_ip, hostname=self.resolve_hostname())
        if changed and self.on_change:
            try: self.on_change(self.public_state())
            except Exception: pass

    def ensure_local_ip(self):
        if not self.local_ip:
            self.local_ip = detect_local_ip()
        return self.local_ip

    def claim(self, reason='failover'):
        ip = self.ensure_local_ip()
        name = self.resolve_hostname()
        if not name:
            raise ValueError('Set HA_HOSTNAME or a base domain in Settings before enabling the cluster.')
        self.cloudflare.ensure_ha_dns(ip, name)
        self._generation += 1
        self._set_role('leader', 'Active · claimed DNS ('+reason+')')
        return ip

    def shared_inventory(self):
        if not self.cluster_state or not self.cluster_state.enabled:
            return None
        try: return self.cluster_state.get_inventory()
        except Exception: return None

    def publish_inventory(self, payload):
        if not self.cluster_state or not self.cluster_state.enabled or not self.is_leader():
            return
        try: self.cluster_state.publish_inventory(payload)
        except Exception: pass

    def serve(self, handler):
        if not self.is_leader():
            return handler.send(503, json.dumps({
                'error': 'This HomeScan node is not the cluster leader.',
                'ha': self.public_state(),
            }).encode())
        snapshot = lambda: json.dumps(self._heartbeat_payload())
        return self.hub.serve(handler, snapshot)

    def _heartbeat_payload(self):
        return dict(type='heartbeat', node_id=self.node_id, ip=self.local_ip or '',
                    hostname=self.resolve_hostname(), ts=time.time(), generation=self._generation)

    def broadcast(self):
        if self.role != 'leader':
            return
        self.hub.broadcast(json.dumps(self._heartbeat_payload()))

    def _follow(self, leader_ip):
        name = self.resolve_hostname()
        self._set_role('follower', 'Standby · watching '+leader_ip,
                       leader=dict(ip=leader_ip, hostname=name))
        client = None
        last = time.monotonic()
        try:
            client = connect_ha(name, self.port)
            client.sock.settimeout(max(1.0, HEARTBEAT + 1))
            client.send_text(json.dumps(dict(type='hello', node_id=self.node_id, ip=self.local_ip or '')))
            timed_out = False
            saw_self = False
            while not self._stop.is_set():
                try:
                    opcode, payload = client.recv()
                except TimeoutError:
                    if time.monotonic() - last >= TIMEOUT:
                        timed_out = True
                        break
                    continue
                if opcode == ws.OP_CLOSE:
                    break
                if opcode == ws.OP_PING:
                    continue
                if opcode != ws.OP_TEXT:
                    continue
                try:
                    message = json.loads(payload.decode())
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    continue
                if message.get('type') != 'heartbeat':
                    continue
                if message.get('node_id') == self.node_id:
                    saw_self = True
                    break
                last = time.monotonic()
                self._set_role('follower', 'Standby · leader '+str(message.get('ip') or leader_ip),
                               leader=dict(node_id=message.get('node_id'), ip=message.get('ip'),
                                           hostname=name, generation=message.get('generation')))
            if self._stop.is_set():
                return
            if saw_self:
                self.claim('dns-points-here')
            elif timed_out or time.monotonic() - last >= TIMEOUT:
                self.claim('leader-timeout')
            else:
                self.claim('leader-disconnect')
        except (OSError, ConnectionError, ValueError, CloudflareError) as exc:
            if not self._stop.is_set():
                self.message = str(exc)
                applog.warning('HA follow failed', source='ha', detail=str(exc))
                try: self.claim('unreachable-leader')
                except (CloudflareError, ValueError) as claim_exc:
                    applog.error('HA claim failed', source='ha', detail=str(claim_exc))
                    self._set_role('error', str(claim_exc))
        finally:
            if client:
                client.close()

    def tick(self):
        if not self.enabled:
            self._set_role('disabled', 'HA disabled')
            return
        try:
            self.ensure_local_ip()
        except ValueError as exc:
            self._set_role('error', str(exc))
            time.sleep(5)
            return
        if self.cluster_state and self.cluster_state.enabled:
            self.cluster_state.local_ip = self.local_ip or ''
            self._tick_durable_object()
            return
        name = self.resolve_hostname()
        if not name:
            self._set_role('waiting', 'Set HA_HOSTNAME or a base domain in Settings')
            time.sleep(5)
            return
        try:
            cfg = self.cloudflare.config()
        except (OSError, ValueError):
            cfg = {}
        if not cfg.get('api_token'):
            self._set_role('waiting', 'Connect Cloudflare so HA can manage '+name)
            time.sleep(5)
            return
        ips = resolve_ipv4(name)
        if not ips:
            try:
                self.claim('dns-missing')
            except (CloudflareError, ValueError) as exc:
                self._set_role('error', str(exc))
                time.sleep(5)
            else:
                self._lead_until_step_down()
            return
        if self.local_ip in ips:
            if self.role != 'leader':
                try:
                    self.claim('dns-points-here')
                except (CloudflareError, ValueError) as exc:
                    self._set_role('error', str(exc))
                    time.sleep(5)
                    return
            self._lead_until_step_down()
            return
        self._follow(ips[0])

    def _lead_until_step_down(self):
        name = self.resolve_hostname()
        self._set_role('leader', 'Active · scanning')
        while not self._stop.is_set() and self.role == 'leader':
            self.broadcast()
            time.sleep(HEARTBEAT)
            ips = resolve_ipv4(name)
            if ips and self.local_ip not in ips:
                self._set_role('follower', 'Standby · DNS moved to '+ips[0],
                               leader=dict(ip=ips[0], hostname=name))
                return
            try:
                self.cloudflare.ensure_ha_dns(self.local_ip, name)
            except (CloudflareError, ValueError) as exc:
                self.message = str(exc)

    def _tick_durable_object(self):
        name = self.resolve_hostname()
        try:
            if self.cluster_state.try_become_leader() or self.cluster_state.is_leader():
                if name:
                    try:
                        self.cloudflare.ensure_ha_dns(self.local_ip, name)
                    except (CloudflareError, ValueError, OSError) as exc:
                        self.message = str(exc)
                self._generation += 1
                self._set_role('leader', 'Active · Durable Object leader')
                while not self._stop.is_set() and self.role == 'leader':
                    if not self.cluster_state.renew_leadership():
                        leader = self.cluster_state.get_leader()
                        self._set_role('follower', 'Standby · lost Durable Object lease',
                                       leader=dict(leader or {}, hostname=name))
                        return
                    self.broadcast()
                    if name:
                        try:
                            self.cloudflare.ensure_ha_dns(self.local_ip, name)
                        except (CloudflareError, ValueError, OSError) as exc:
                            self.message = str(exc)
                    self._stop.wait(HEARTBEAT)
                return
            leader = self.cluster_state.get_leader()
            self._set_role('follower', 'Standby · Durable Object leader '+(leader.get('ip') or leader.get('node_id') or ''),
                           leader=dict(leader or {}, hostname=name))
            self._stop.wait(HEARTBEAT)
        except ClusterStateError as exc:
            applog.error('HA Durable Object error', source='ha', detail=str(exc))
            self._set_role('error', str(exc))
            self._stop.wait(5)

    def run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                applog.exception('HA loop failed', source='ha', exc=exc)
                self._set_role(self.role if self.role != 'starting' else 'error', str(exc))
                self._stop.wait(5)

    def stop(self):
        self._stop.set()
        if self.cluster_state and self.cluster_state.enabled:
            try: self.cluster_state.step_down()
            except Exception: pass
