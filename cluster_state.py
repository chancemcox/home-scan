"""Client for the HomeScan Cloudflare Durable Object cluster worker."""
import json
import os
import threading
import urllib.error
import urllib.request

DEFAULT_TTL = int(os.getenv('CLUSTER_LEADER_TTL', '15'))


class ClusterStateError(Exception):
    pass


class ClusterState:
    """Shared in-memory HA state hosted in a Cloudflare Durable Object."""

    def __init__(self, base_url, secret, node_id, local_ip='', ttl=DEFAULT_TTL, opener=None):
        self.base_url = str(base_url or '').rstrip('/')
        self.secret = str(secret or '')
        self.node_id = node_id
        self.local_ip = local_ip or ''
        self.ttl = max(5, int(ttl))
        self._opener = opener
        self._inventory = None
        self._lock = threading.RLock()

    @property
    def enabled(self):
        return bool(self.base_url and self.secret and self.node_id)

    def _request(self, method, path, body=None, content_type='application/json'):
        if not self.enabled:
            raise ClusterStateError('Cluster Durable Object is not configured.')
        data = None
        headers = {'X-HomeScan-Cluster': self.secret, 'Accept': 'application/json'}
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode()
                headers['Content-Type'] = 'application/json'
            else:
                data = body if isinstance(body, bytes) else str(body).encode()
                headers['Content-Type'] = content_type
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        opener = self._opener or urllib.request.urlopen
        try:
            with opener(req, timeout=12) as response:
                raw = response.read()
                ctype = (response.headers.get('Content-Type') or '').split(';', 1)[0]
                if ctype == 'application/json' or raw[:1] in (b'{', b'['):
                    try:
                        return response.status, json.loads(raw.decode() or 'null')
                    except ValueError:
                        return response.status, raw.decode()
                return response.status, raw.decode()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode() or '{}')
            except ValueError:
                payload = {'error': raw.decode()[:300]}
            return exc.code, payload
        except (OSError, ValueError) as exc:
            raise ClusterStateError('Cluster Durable Object unreachable: ' + str(exc)) from None

    def get_leader(self):
        code, payload = self._request('GET', '/v1/leader')
        if code != 200:
            raise ClusterStateError(str(payload.get('error') if isinstance(payload, dict) else payload))
        leader = (payload or {}).get('leader') if isinstance(payload, dict) else None
        return leader or {}

    def try_become_leader(self):
        code, payload = self._request('PUT', '/v1/leader', {
            'node_id': self.node_id,
            'ip': self.local_ip,
            'ttl': self.ttl,
        })
        if code == 200 and isinstance(payload, dict) and payload.get('ok'):
            return True
        if code == 409:
            return False
        raise ClusterStateError(str(payload.get('error') if isinstance(payload, dict) else payload))

    def renew_leadership(self):
        return self.try_become_leader()

    def step_down(self):
        code, payload = self._request('DELETE', f'/v1/leader?node_id={self.node_id}')
        return code == 200

    def is_leader(self):
        leader = self.get_leader()
        return leader.get('node_id') == self.node_id

    def publish_inventory(self, payload):
        body = payload if isinstance(payload, str) else json.dumps(payload)
        code, result = self._request('PUT', '/v1/inventory', body, content_type='application/json')
        if code != 200:
            raise ClusterStateError(str(result.get('error') if isinstance(result, dict) else result))
        with self._lock:
            self._inventory = body
        return True

    def get_inventory(self):
        with self._lock:
            if self._inventory is not None:
                return self._inventory
        code, payload = self._request('GET', '/v1/inventory')
        if code != 200:
            raise ClusterStateError(str(payload.get('error') if isinstance(payload, dict) else payload))
        body = payload if isinstance(payload, str) else json.dumps(payload)
        with self._lock:
            self._inventory = body
        return body

    def public_state(self):
        try:
            code, payload = self._request('GET', '/v1/state')
            if code == 200 and isinstance(payload, dict):
                return dict(enabled=True, backend=payload.get('backend') or 'durable-object-memory',
                            leader=payload.get('leader') or {}, has_inventory=bool(payload.get('has_inventory')))
        except ClusterStateError:
            pass
        return dict(enabled=self.enabled, backend='durable-object-memory', leader={}, has_inventory=False)
