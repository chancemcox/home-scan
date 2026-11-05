"""Dashboard login sessions with hashed passwords and remember-me cookies."""
import hashlib
import hmac
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie, CookieError
from pathlib import Path

USERS_PATH = Path(os.getenv('USERS_PATH', '/data/users.json'))
BOOTSTRAP_PASSWORD_PATH = Path(os.getenv('BOOTSTRAP_PASSWORD_PATH', str(USERS_PATH.with_name('initial-admin-password.txt'))))
DEFAULT_USER = (os.getenv('HOMESCAN_ADMIN_USER', 'admin').strip() or 'admin').casefold()
SESSION_COOKIE = 'homescan_session'
SESSION_HOURS = 12
REMEMBER_DAYS = 30
PBKDF2_ROUNDS = 260000

_lock = threading.RLock()
_sessions = {}  # token -> dict(username, expires, remember)
_bootstrap_password = None


def now():
    return datetime.now(timezone.utc)


def _hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS)
    return salt.hex() + ':' + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(':', 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS)
    return hmac.compare_digest(actual, expected)


def _load_users():
    try:
        import json
        data = json.loads(USERS_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get('users'), dict):
            return data['users']
    except (OSError, ValueError, TypeError):
        pass
    return {}


def _save_users(users):
    import json
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = USERS_PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps({'users': users}, indent=2))
    tmp.chmod(0o600)
    tmp.replace(USERS_PATH)


def bootstrap_password():
    """Password created on first boot (env override or generated). Cleared after users exist."""
    return _bootstrap_password


def init():
    """Create the initial admin account when no users are configured.

    Password order: HOMESCAN_ADMIN_PASSWORD env, else a generated secret written once to
    initial-admin-password.txt so shared installs never ship a known default password.
    """
    global _bootstrap_password
    with _lock:
        users = _load_users()
        if not users:
            password = os.getenv('HOMESCAN_ADMIN_PASSWORD', '').strip()
            generated = False
            if not password:
                password = secrets.token_urlsafe(18)
                generated = True
            users[DEFAULT_USER] = _hash_password(password)
            _save_users(users)
            _bootstrap_password = password
            if generated:
                try:
                    BOOTSTRAP_PASSWORD_PATH.parent.mkdir(parents=True, exist_ok=True)
                    BOOTSTRAP_PASSWORD_PATH.write_text(password + '\n')
                    BOOTSTRAP_PASSWORD_PATH.chmod(0o600)
                except OSError:
                    pass
            print('HomeScan admin user {!r} created. {}'.format(
                DEFAULT_USER,
                'Password saved to '+str(BOOTSTRAP_PASSWORD_PATH) if generated else 'Password taken from HOMESCAN_ADMIN_PASSWORD.',
            ), flush=True)
        _purge_sessions()


def _purge_sessions():
    stamp = now()
    expired = [token for token, row in _sessions.items() if row['expires'] <= stamp]
    for token in expired:
        _sessions.pop(token, None)


def _lookup_user(users, username):
    """Resolve a username case-insensitively; returns (canonical_name, hash) or (None, None)."""
    wanted = str(username or '').strip().casefold()
    if not wanted:
        return None, None
    if wanted in users:
        return wanted, users[wanted]
    for name, hashed in users.items():
        if str(name).casefold() == wanted:
            return name, hashed
    return None, None


def login(username, password, remember=False):
    username = str(username or '').strip()
    password = str(password or '')
    if not username or not password:
        raise ValueError('Enter a username and password.')
    with _lock:
        users = _load_users()
        canonical, stored = _lookup_user(users, username)
        if not stored or not verify_password(password, stored):
            raise ValueError('Invalid username or password.')
        _purge_sessions()
        token = secrets.token_urlsafe(32)
        lifetime = timedelta(days=REMEMBER_DAYS) if remember else timedelta(hours=SESSION_HOURS)
        _sessions[token] = dict(username=canonical, expires=now() + lifetime, remember=bool(remember))
        return dict(token=token, username=canonical, remember=bool(remember),
                    max_age=int(lifetime.total_seconds()) if remember else None)


def logout(token):
    with _lock:
        _sessions.pop(str(token or ''), None)


def session_user(token):
    token = str(token or '')
    if not token:
        return None
    with _lock:
        _purge_sessions()
        row = _sessions.get(token)
        if not row:
            return None
        if row['expires'] <= now():
            _sessions.pop(token, None)
            return None
        return row['username']


def cookie_header(token, remember=False, max_age=None):
    parts = [f'{SESSION_COOKIE}={token}', 'Path=/', 'HttpOnly', 'SameSite=Strict']
    if remember and max_age:
        parts.append(f'Max-Age={int(max_age)}')
    return '; '.join(parts)


def clear_cookie_header():
    return f'{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'


def parse_cookie(header):
    cookie = SimpleCookie()
    try:
        cookie.load(header or '')
    except CookieError:
        return ''
    morsel = cookie.get(SESSION_COOKIE)
    return morsel.value if morsel else ''
