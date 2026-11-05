"""Structured HomeScan logging with deploy push id and Cloudflare-backed retention.

Logs are written to stderr and persisted in the shared DB (Cloudflare D1 when
configured, otherwise local SQLite). Rows older than 30 days are deleted automatically.
Every message includes the current git push SHA so failures can be tied to a deploy.
"""
import json
import os
import sys
import threading
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

RETENTION_DAYS = 30
_DB_PATH = os.getenv('DB_PATH', '/data/homescan.db')
_LOCK = threading.Lock()
_LAST_EXPIRE = 0.0


def push_id():
    """Return the deployed git push/commit id baked into the image or env."""
    value = (os.getenv('HOMESCAN_PUSH') or '').strip()
    if value:
        return value[:64]
    for path in (Path(__file__).with_name('PUSH'), Path('/app/PUSH')):
        try:
            text = path.read_text(encoding='utf-8').strip()
            if text:
                return text[:64]
        except OSError:
            continue
    return 'unknown'


PUSH = push_id()


def configure(db_path):
    global _DB_PATH
    _DB_PATH = db_path


def _now():
    return datetime.now(timezone.utc).isoformat()


def _format(level, source, message, push=None):
    pid = push or PUSH
    src = source or 'homescan'
    return f'[{level}] push={pid} source={src} {message}'


def _persist(level, source, message, detail=''):
    path = Path(_DB_PATH)
    # Skip Cloudflare/local persistence until storage.init has a reachable DB path.
    if not path.parent.exists() and str(path.parent) not in ('.', ''):
        return
    try:
        import storage
        storage.append_log(_DB_PATH, level=level, push=PUSH, source=source or 'homescan',
                           message=str(message)[:2000], detail=str(detail or '')[:8000],
                           created_at=_now())
        _maybe_expire()
    except Exception:
        # Never raise from logging; stderr already has the human-readable line.
        return


def expire(force=False):
    """Drop Cloudflare/local log rows past the one-month retention window."""
    import time
    global _LAST_EXPIRE
    now = time.monotonic()
    with _LOCK:
        if not force and now - _LAST_EXPIRE < 3600:
            return
        _LAST_EXPIRE = now
    try:
        import storage
        storage.expire_logs(_DB_PATH, older_than_days=RETENTION_DAYS)
    except Exception as exc:
        sys.stderr.write(_format('error', 'applog', f'log expire failed: {exc}') + '\n')
        sys.stderr.flush()


def _maybe_expire(force=False):
    expire(force=force)


def write(level, message, source='homescan', detail='', exc=None):
    """Emit one log line to stderr and Cloudflare/local DB."""
    level = str(level or 'info').lower()
    if level not in ('debug', 'info', 'warning', 'error'):
        level = 'info'
    text = str(message or '')
    extra = detail
    if exc is not None:
        extra = (str(extra) + '\n' if extra else '') + ''.join(
            traceback.format_exception(type(exc), exc, exc.__traceback__))
    line = _format(level, source, text)
    sys.stderr.write(line + '\n')
    if extra:
        for chunk in str(extra).splitlines()[:80]:
            sys.stderr.write(_format(level, source, chunk) + '\n')
    sys.stderr.flush()
    _persist(level, source, text, extra)


def info(message, source='homescan', detail=''):
    write('info', message, source=source, detail=detail)


def warning(message, source='homescan', detail='', exc=None):
    write('warning', message, source=source, detail=detail, exc=exc)


def error(message, source='homescan', detail='', exc=None):
    write('error', message, source=source, detail=detail, exc=exc)


def exception(message, source='homescan', exc=None):
    write('error', message, source=source, exc=exc or sys.exc_info()[1])
