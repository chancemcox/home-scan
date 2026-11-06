"""Cloudflare Durable Object SQLite adapter (shared in-memory-backed app DB)."""
import json
import urllib.error
import urllib.request


class DoDbError(Exception):
    pass


class DoRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return dict.__getitem__(self, key)


class DoCursor:
    def __init__(self, rows=None, lastrowid=0, rowcount=-1):
        self._rows = [DoRow(row) for row in (rows or [])]
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class DoConnection:
    """DB-API style wrapper over the HomeScan cluster worker /v1/sql API."""

    def __init__(self, base_url, secret, opener=None):
        self.base_url = str(base_url or '').rstrip('/')
        self.secret = str(secret or '')
        self._opener = opener
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        self._closed = True

    def _request(self, sql, params=None):
        if self._closed:
            raise DoDbError('Durable Object connection is closed.')
        if not self.base_url or not self.secret:
            raise DoDbError('Cluster Durable Object is not configured.')
        body = json.dumps({'sql': sql, 'params': list(params or [])}).encode()
        req = urllib.request.Request(
            self.base_url + '/v1/sql',
            data=body,
            method='POST',
            headers={
                'X-HomeScan-Cluster': self.secret,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        )
        opener = self._opener or urllib.request.urlopen
        try:
            with opener(req, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode() or '{}')
            except ValueError:
                payload = {}
            raise DoDbError(payload.get('error') or f'Durable Object SQL HTTP {exc.code}.') from None
        except (OSError, ValueError):
            raise DoDbError('Durable Object SQL could not be reached.') from None
        if not payload.get('success'):
            raise DoDbError(str(payload.get('error') or 'Durable Object rejected the SQL.'))
        return payload

    def execute(self, sql, params=()):
        text = str(sql or '').strip()
        upper = text.upper()
        if upper.startswith('PRAGMA JOURNAL_MODE'):
            return DoCursor([])
        payload = self._request(text, params)
        meta = payload.get('meta') or {}
        rows = payload.get('results') or []
        return DoCursor(
            rows,
            lastrowid=int(meta.get('last_row_id') or 0),
            rowcount=int(meta.get('changes') if meta.get('changes') is not None else -1),
        )

    def executescript(self, sql):
        text = str(sql or '').strip()
        if not text:
            return self
        self._request(text, [])
        return self
