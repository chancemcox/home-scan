"""Read-only Deco inventory, called by the Windows scan loop."""
import json
import ipaddress
import time
from pathlib import Path
from http.client import IncompleteRead
from tplink_deco_api import DecoClient
from tplink_deco_api.exceptions import AuthenticationError
CONFIG = Path('/run/homescan-secrets/deco.json')
COOLDOWN = Path('/data/deco-auth-retry')
def tolerate_complete_json(transport):
    original = transport._post
    def post(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        except IncompleteRead as exc:
            # Some X10 responses omit the final HTTP chunk. Accept only a
            # complete JSON object; never accept genuinely truncated JSON.
            result = json.loads(exc.partial)
            if not isinstance(result, dict):
                raise ValueError('Invalid Deco response')
            return result
    transport._post = post
def normalize(clients):
    hosts = {}
    for client in clients:
        if not client.online: continue
        try: ip = str(ipaddress.IPv4Address(client.ip))
        except (ValueError, TypeError): continue
        if ip == '0.0.0.0': continue
        hosts[ip] = dict(ip=ip, hostname=client.name or '', mac=(client.mac or '').replace('-', ':').upper())
    return list(hosts.values())
def collect():
    if not CONFIG.exists(): return dict(configured=False, available=False, hosts=[])
    config = json.loads(CONFIG.read_text(encoding='utf-8-sig'))
    if not config.get('password'): return dict(configured=False, available=False, hosts=[])
    if COOLDOWN.exists() and time.time() - COOLDOWN.stat().st_mtime < 600:
        return dict(configured=True, available=False, hosts=[])
    try:
        client = DecoClient(config['host'], config.get('username', 'admin'), config['password'], timeout=20)
        tolerate_complete_json(client._transport)
        with client as deco:
            hosts = normalize(deco.get_client_list())
        COOLDOWN.unlink(missing_ok=True)
        return dict(configured=True, available=True, hosts=hosts)
    except AuthenticationError:
        COOLDOWN.touch()
        return dict(configured=True, available=False, hosts=[])
    except Exception:
        return dict(configured=True, available=False, hosts=[])
if __name__ == '__main__':
    try: print(json.dumps(collect()))
    except Exception: print(json.dumps(dict(configured=True, available=False, hosts=[])))

