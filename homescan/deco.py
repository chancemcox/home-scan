"""Read-only Deco inventory, called by the Windows scan loop."""
import ipaddress
import json
import re
import time
from http.client import IncompleteRead
from pathlib import Path

CONFIG = Path('/data/deco.json')
LEGACY = Path('/run/homescan-secrets/deco.json')
COOLDOWN = Path('/data/deco-auth-retry')


class AuthenticationError(Exception):
    """Stand-in so tests can raise without importing the SDK."""


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


def load_config():
    for path in (CONFIG, LEGACY):
        if not path.exists(): continue
        try:
            config = json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError):
            continue
        if not isinstance(config, dict): continue
        # Prefer the writable data-volume copy; migrate legacy secrets once.
        if path == LEGACY and not CONFIG.exists() and config.get('password'):
            try:
                payload = dict(enabled=bool(config.get('enabled', True)), host=str(config.get('host') or ''),
                               username=str(config.get('username') or 'admin'), password=config['password'])
                CONFIG.parent.mkdir(parents=True, exist_ok=True)
                tmp = CONFIG.with_suffix('.tmp')
                tmp.write_text(json.dumps(payload), encoding='utf-8')
                tmp.chmod(0o600)
                tmp.replace(CONFIG)
                return payload, CONFIG
            except OSError:
                pass
        return config, path
    return {}, None


def public_state():
    """Status without secrets. Failures never raise."""
    try:
        config, _ = load_config()
        enabled = bool(config.get('enabled', True)) if config.get('password') else False
        configured = bool(config.get('password'))
        return dict(
            enabled=enabled and configured,
            configured=configured,
            host=str(config.get('host') or ''),
            username=str(config.get('username') or 'admin'),
            password_set=configured,
            auth_cooldown=COOLDOWN.exists() and time.time() - COOLDOWN.stat().st_mtime < 600,
        )
    except Exception:
        return dict(enabled=False, configured=False, host='', username='admin', password_set=False, auth_cooldown=False)


def save_settings(body):
    """Persist Deco settings. Password omitted keeps the previous value."""
    if not isinstance(body, dict): raise ValueError('Invalid Deco settings.')
    enabled = body.get('enabled', False)
    if not isinstance(enabled, bool): raise ValueError('enabled must be true or false.')
    host = str(body.get('host') or '').strip()
    username = str(body.get('username') or 'admin').strip() or 'admin'
    password = body.get('password')
    if password is not None and not isinstance(password, str): raise ValueError('Invalid password.')
    current, _ = load_config()
    if password is None or password == '':
        password = current.get('password', '')
    if enabled:
        if not host: raise ValueError('Enter the Deco IP or hostname.')
        try:
            ip = ipaddress.IPv4Address(host)
            if not ip.is_private: raise ValueError('Use a private Deco LAN address.')
            host = str(ip)
        except ValueError as exc:
            if 'private' in str(exc): raise
            if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*', host):
                raise ValueError('Enter a private IPv4 address or hostname.')
        if not password: raise ValueError('Enter the Deco owner password.')
    else:
        host = host or str(current.get('host') or '')
        password = password or str(current.get('password') or '')
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(enabled=enabled, host=host, username=username, password=password)
    tmp = CONFIG.with_suffix('.tmp')
    tmp.write_text(json.dumps(payload), encoding='utf-8')
    tmp.chmod(0o600)
    tmp.replace(CONFIG)
    COOLDOWN.unlink(missing_ok=True)
    return public_state()


def sdk():
    from tplink_deco_api import DecoClient
    from tplink_deco_api.exceptions import AuthenticationError as DecoAuthError
    return DecoClient, DecoAuthError


def collect():
    """Return inventory or a soft-failure payload. Never raises."""
    try:
        config, _ = load_config()
        if not config.get('password'):
            return dict(enabled=False, configured=False, available=False, hosts=[])
        enabled = bool(config.get('enabled', True))
        if not enabled:
            return dict(enabled=False, configured=True, available=False, hosts=[])
        if COOLDOWN.exists() and time.time() - COOLDOWN.stat().st_mtime < 600:
            return dict(enabled=True, configured=True, available=False, hosts=[])
        DecoClient, DecoAuthError = sdk()
        client = DecoClient(config['host'], config.get('username', 'admin'), config['password'], timeout=12)
        tolerate_complete_json(client._transport)
        with client as session:
            hosts = normalize(session.get_client_list())
        COOLDOWN.unlink(missing_ok=True)
        return dict(enabled=True, configured=True, available=True, hosts=hosts)
    except Exception as exc:
        try:
            _, DecoAuthError = sdk()
        except Exception:
            DecoAuthError = AuthenticationError
        if isinstance(exc, (AuthenticationError, DecoAuthError)):
            try: COOLDOWN.touch()
            except OSError: pass
        return dict(enabled=True, configured=True, available=False, hosts=[])


if __name__ == '__main__':
    try: print(json.dumps(collect()))
    except Exception: print(json.dumps(dict(enabled=False, configured=False, available=False, hosts=[])))
