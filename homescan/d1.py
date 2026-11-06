"""Cloudflare D1 HTTP adapter with a sqlite3-like connection surface."""
import json
import urllib.error
import urllib.request


class D1Error(Exception):
    pass


class D1Row(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return dict.__getitem__(self, key)


class D1Cursor:
    def __init__(self, rows=None, lastrowid=0, rowcount=-1):
        self._rows = [D1Row(row) for row in (rows or [])]
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class D1Connection:
    """Minimal DB-API style wrapper over the Cloudflare D1 HTTP query API."""

    def __init__(self, account_id, database_id, token, caller=None):
        self.account_id = account_id
        self.database_id = database_id
        self.token = token
        self._caller = caller
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
            raise D1Error('D1 connection is closed.')
        if self._caller:
            return self._caller(sql, list(params or []))
        body = json.dumps({'sql': sql, 'params': list(params or [])}).encode()
        path = f"/accounts/{self.account_id}/d1/database/{self.database_id}/query"
        req = urllib.request.Request(
            'https://api.cloudflare.com/client/v4' + path,
            data=body, method='POST',
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raise D1Error(f'D1 HTTP {exc.code}. Check the API token has D1 Edit.') from None
        except (OSError, ValueError):
            raise D1Error('Cloudflare D1 could not be reached.') from None
        if not payload.get('success'):
            codes = ', '.join(str(e.get('code', 'unknown')) for e in payload.get('errors', []))
            raise D1Error('D1 rejected the query (code ' + codes + ').')
        return payload.get('result') or []

    def execute(self, sql, params=()):
        text = str(sql or '').strip()
        upper = text.upper()
        if upper.startswith('PRAGMA JOURNAL_MODE'):
            return D1Cursor([])
        chunks = self._request(text, params)
        if not chunks:
            return D1Cursor([])
        last = chunks[-1] or {}
        meta = last.get('meta') or {}
        rows = last.get('results') or []
        return D1Cursor(rows, lastrowid=int(meta.get('last_row_id') or 0),
                        rowcount=int(meta.get('changes') if meta.get('changes') is not None else -1))

    def executescript(self, sql):
        text = str(sql or '').strip()
        if not text:
            return self
        self._request(text)
        return self


def ensure_database(api, account_id, name='homescan'):
    """Return the UUID for a shared account D1 database, creating it when missing."""
    account_id = str(account_id or '')
    name = str(name or 'homescan').strip() or 'homescan'
    if not account_id:
        raise D1Error('Cloudflare account id is required for D1.')
    rows = api.call('GET', f'/accounts/{account_id}/d1/database') or []
    if isinstance(rows, dict):
        rows = rows.get('result') or rows.get('databases') or []
    exact = [row for row in rows if row.get('name') == name]
    if exact:
        return exact[0].get('uuid') or exact[0].get('id')
    created = api.call('POST', f'/accounts/{account_id}/d1/database', {
        'name': name,
        'primary_location_hint': 'enam',
    }) or {}
    database_id = created.get('uuid') or created.get('id')
    if not database_id:
        raise D1Error('Cloudflare did not return a D1 database id.')
    return database_id
