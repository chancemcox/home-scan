import ipaddress
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from d1 import D1Connection


def now():
    return datetime.now(timezone.utc).isoformat()


_BACKEND = {'kind': 'sqlite'}


def use_sqlite():
    """Use the local SQLite file passed to connect()/init()."""
    _BACKEND.clear()
    _BACKEND['kind'] = 'sqlite'


def use_d1(account_id, database_id, token, caller=None):
    """Use a shared Cloudflare D1 database for all HomeScan HA nodes."""
    _BACKEND.clear()
    _BACKEND.update(kind='d1', account_id=account_id, database_id=database_id, token=token, caller=caller)


def backend_state():
    if _BACKEND.get('kind') == 'd1':
        return dict(kind='d1', database_id=_BACKEND.get('database_id') or '', shared=True)
    return dict(kind='sqlite', database_id='', shared=False)


class Connection(sqlite3.Connection):
    def __exit__(self, *args):
        try: return super().__exit__(*args)
        finally: self.close()


def connect(path):
    if _BACKEND.get('kind') == 'd1':
        return D1Connection(_BACKEND['account_id'], _BACKEND['database_id'], _BACKEND['token'],
                            caller=_BACKEND.get('caller'))
    db = sqlite3.connect(path, timeout=30, factory=Connection)
    db.row_factory = sqlite3.Row
    return db


def mac_address(value):
    raw = re.sub(r'[:-]', '', str(value or '')).upper()
    if not re.fullmatch(r'[0-9A-F]{12}', raw) or raw in ('0'*12, 'F'*12):
        return ''
    if int(raw[:2], 16) & 1:
        return ''
    return ':'.join(raw[i:i+2] for i in range(0, 12, 2))


def identity(ip, mac):
    return 'mac:' + mac if mac else 'ip:' + ip


def init(path):
    if _BACKEND.get('kind') != 'd1':
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        if _BACKEND.get('kind') != 'd1':
            db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS status(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS app_logs(
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            level TEXT NOT NULL,
            push TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS app_logs_created ON app_logs(created_at);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started TEXT, finished TEXT, error TEXT, source TEXT NOT NULL DEFAULT 'network');
        CREATE TABLE IF NOT EXISTS sightings(scan_id INTEGER, ip TEXT, hostname TEXT, mac TEXT, device_id TEXT, PRIMARY KEY(scan_id,ip));
        CREATE TABLE IF NOT EXISTS ip_assignments(ip TEXT PRIMARY KEY, device_id TEXT, last_seen TEXT);
        ''')
        if _BACKEND.get('kind') != 'd1':
            db.execute('BEGIN IMMEDIATE')
        old = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices'").fetchone()
        cols = [r['name'] for r in db.execute('PRAGMA table_info(devices)')] if old else []
        migrate = bool(old) and 'device_id' not in cols and _BACKEND.get('kind') != 'd1'
        if migrate:
            db.execute('ALTER TABLE devices RENAME TO devices_legacy')
            db.execute('ALTER TABLE device_sources RENAME TO device_sources_legacy')
        db.execute('''CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, ip TEXT NOT NULL,
            hostname TEXT, mac TEXT, first_seen TEXT, last_seen TEXT, scan_id INTEGER)''')
        db.execute('''CREATE TABLE IF NOT EXISTS device_sources(device_id TEXT, source TEXT,
            last_seen TEXT, scan_id INTEGER, PRIMARY KEY(device_id,source))''')
        sighting_cols = [r['name'] for r in db.execute('PRAGMA table_info(sightings)')]
        if 'device_id' not in sighting_cols:
            db.execute('ALTER TABLE sightings ADD COLUMN device_id TEXT')
        if migrate:
            mapping = {}
            for row in db.execute('SELECT * FROM devices_legacy ORDER BY last_seen').fetchall():
                mac = mac_address(row['mac'])
                did = identity(row['ip'], mac)
                mapping[row['ip']] = did
                db.execute('''INSERT INTO devices VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
                    ip=excluded.ip,hostname=excluded.hostname,mac=excluded.mac,
                    first_seen=min(devices.first_seen,excluded.first_seen),last_seen=excluded.last_seen,scan_id=excluded.scan_id''',
                    (did,row['ip'],row['hostname'],mac,row['first_seen'],row['last_seen'],row['scan_id']))
                if mac:
                    db.execute('DELETE FROM ip_assignments WHERE device_id=?', (did,))
                    db.execute('INSERT OR REPLACE INTO ip_assignments VALUES(?,?,?)',(row['ip'],did,row['last_seen']))
            for row in db.execute('SELECT * FROM device_sources_legacy ORDER BY last_seen').fetchall():
                if row['ip'] in mapping:
                    db.execute('INSERT OR REPLACE INTO device_sources VALUES(?,?,?,?)',
                               (mapping[row['ip']],row['source'],row['last_seen'],row['scan_id']))
            db.execute('DROP TABLE device_sources_legacy')
            db.execute('DROP TABLE devices_legacy')
        for row in db.execute('SELECT rowid,ip,mac FROM sightings WHERE device_id IS NULL').fetchall():
            db.execute('UPDATE sightings SET device_id=? WHERE rowid=?',
                       (identity(row['ip'],mac_address(row['mac'])),row['rowid']))
        db.execute('CREATE INDEX IF NOT EXISTS sightings_device ON sightings(device_id,scan_id)')


def get_settings(path, keys=None):
    """Return app_settings rows. When keys is set, only those entries are returned."""
    wanted = set(keys) if keys is not None else None
    with connect(path) as db:
        rows = db.execute('SELECT key, value FROM app_settings').fetchall()
    result = {}
    for row in rows:
        key = row['key']
        if wanted is not None and key not in wanted:
            continue
        result[key] = row['value']
    return result


def set_settings(path, mapping):
    """Upsert shared install settings (non-secret)."""
    if not mapping:
        return
    with connect(path) as db:
        for key, value in mapping.items():
            if value in (None, ''):
                continue
            db.execute(
                'INSERT INTO app_settings(key, value) VALUES(?,?) '
                'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                (str(key), str(value)),
            )


def append_log(path, level, push, source, message, detail='', created_at=None):
    """Persist one diagnostic log row (Cloudflare D1 when that backend is active)."""
    stamp = created_at or now()
    with connect(path) as db:
        db.execute(
            'INSERT INTO app_logs(created_at, level, push, source, message, detail) VALUES(?,?,?,?,?,?)',
            (stamp, str(level)[:16], str(push)[:64], str(source)[:64],
             str(message)[:2000], str(detail or '')[:8000]),
        )


def expire_logs(path, older_than_days=30):
    """Delete log rows older than the retention window (default one month)."""
    days = max(1, int(older_than_days or 30))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with connect(path) as db:
        cursor = db.execute('DELETE FROM app_logs WHERE created_at < ?', (cutoff,))
        return int(cursor.rowcount if cursor.rowcount is not None and cursor.rowcount >= 0 else 0)


def recent_logs(path, limit=100):
    limit = max(1, min(500, int(limit or 100)))
    with connect(path) as db:
        rows = db.execute(
            'SELECT created_at, level, push, source, message, detail FROM app_logs '
            'ORDER BY created_at DESC, id DESC LIMIT ?',
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def migrate_local_to_d1(path):
    """Copy local SQLite inventory into an empty shared D1 database once.

    Shared app_settings are always upserted so former hardcoded install defaults
    (base domain, zone, tunnel id, …) reach D1 even when inventory already exists.
    """
    if _BACKEND.get('kind') != 'd1' or not Path(path).exists():
        return False
    local = sqlite3.connect(path, timeout=30)
    local.row_factory = sqlite3.Row
    copied = False
    try:
        with connect(path) as remote:
            existing = remote.execute('SELECT count(*) AS c FROM devices').fetchone()
            empty = not existing or int(existing['c'] or 0) == 0
            tables = ('status', 'app_settings', 'app_logs', 'scans', 'sightings', 'ip_assignments',
                      'devices', 'device_sources', 'cf_routes', 'cf_resources', 'cf_tunnel_links')
            for table in tables:
                present = local.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
                ).fetchone()
                if not present:
                    continue
                rows = local.execute(f'SELECT * FROM {table}').fetchall()
                if not rows:
                    continue
                if table not in ('app_settings',) and not empty:
                    continue
                cols = [c for c in rows[0].keys() if not (table == 'app_logs' and c == 'id')]
                placeholders = ','.join('?' for _ in cols)
                col_list = ','.join(cols)
                for row in rows:
                    if table == 'app_settings':
                        remote.execute(
                            'INSERT INTO app_settings(key, value) VALUES(?,?) '
                            'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                            [row['key'], row['value']],
                        )
                    else:
                        remote.execute(
                            f'INSERT OR IGNORE INTO {table}({col_list}) VALUES({placeholders})',
                            [row[c] for c in cols],
                        )
                copied = True
    finally:
        local.close()
    return copied


def normalize(hosts):
    if not isinstance(hosts,list) or len(hosts)>4096:
        raise ValueError('Invalid hosts')
    result = {}
    for host in hosts:
        ip = str(ipaddress.IPv4Address(host['ip']))
        mac = mac_address(host.get('mac'))
        result[ip] = dict(ip=ip,mac=mac,hostname=str(host.get('hostname') or '')[:255],device_id=identity(ip,mac))
    return list(result.values())


def record_batches(path, batches):
    clean = []
    for batch in batches:
        if batch.get('source') not in ('network','deco'): raise ValueError('Invalid scan source')
        clean.append((batch,normalize(batch['hosts'])))
    stamp = now()
    with connect(path) as db:
        for batch, hosts in clean:
            source = batch['source']
            error = str(batch['error'])[:1000] if batch.get('error') else None
            sid = db.execute('INSERT INTO scans(started,finished,error,source) VALUES(?,?,?,?)',
                             (batch.get('started') or stamp,stamp,error,source)).lastrowid
            for host in hosts:
                did,ip,mac,name = host['device_id'],host['ip'],host['mac'],host['hostname']
                if mac:
                    # Promote an IP-only discovery once its MAC is observed.
                    provisional = 'ip:' + ip
                    old = db.execute('SELECT first_seen FROM devices WHERE device_id=?',(provisional,)).fetchone()
                    first = old['first_seen'] if old else stamp
                    db.execute('DELETE FROM device_sources WHERE device_id=?',(provisional,))
                    db.execute('DELETE FROM devices WHERE device_id=?',(provisional,))
                    db.execute('DELETE FROM ip_assignments WHERE device_id=? AND ip<>?',(did,ip))
                    db.execute('INSERT OR REPLACE INTO ip_assignments VALUES(?,?,?)',(ip,did,stamp))
                else:
                    first = stamp
                    # An IP-only response cannot establish a MAC identity. Keep its
                    # observation in history without refreshing a known device's presence.
                    known = db.execute('SELECT 1 FROM ip_assignments WHERE ip=?',(ip,)).fetchone()
                    if known:
                        db.execute('INSERT INTO sightings VALUES(?,?,?,?,?)',(sid,ip,name,mac,did))
                        continue
                db.execute('INSERT INTO sightings VALUES(?,?,?,?,?)',(sid,ip,name,mac,did))
                db.execute('''INSERT INTO devices VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
                    ip=excluded.ip,hostname=CASE WHEN excluded.hostname='' THEN devices.hostname ELSE excluded.hostname END,
                    mac=excluded.mac,first_seen=min(devices.first_seen,excluded.first_seen),last_seen=excluded.last_seen,scan_id=excluded.scan_id''',
                    (did,ip,name,mac,first,stamp,sid))
                db.execute('INSERT OR REPLACE INTO device_sources VALUES(?,?,?,?)',(did,source,stamp,sid))
        db.execute("DELETE FROM sightings WHERE scan_id IN (SELECT id FROM scans WHERE julianday(finished)<julianday('now','-30 days'))")
        db.execute("DELETE FROM scans WHERE julianday(finished)<julianday('now','-30 days')")


def device_states(devices, observations, scans, at=None):
    at = at or datetime.now(timezone.utc)
    latest, good = {}, {}
    for scan in sorted(scans,key=lambda s:s['id']):
        latest[scan['source']] = scan
        if not scan['error']: good[scan['source']] = scan
    fresh = lambda s: s and (at-datetime.fromisoformat(s['finished'])).total_seconds()<150
    for device in devices:
        states = []
        for obs in observations:
            if obs.get('device_id',obs.get('ip')) != device.get('device_id',device.get('ip')): continue
            # A failed source attempt must not wipe a still-fresh successful observation
            # (Deco timeouts should not mark the whole inventory unavailable).
            success = good.get(obs['source'])
            if not fresh(success): states.append('unknown')
            elif obs['scan_id']==success['id']: states.append('seen')
            else: states.append('not_seen')
        device['status'] = 'seen' if 'seen' in states else 'unknown' if not states or 'unknown' in states else 'not_seen'
        if device.get('address_current') is False: device['status'] = 'not_seen'
        device['online'] = device['status']=='seen'
    return any(fresh(s) for s in good.values())


def inventory(path):
    with connect(path) as db:
        latest = db.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1').fetchone()
        scans = [dict(r) for r in db.execute('''SELECT * FROM scans WHERE id IN
            (SELECT max(id) FROM scans GROUP BY source UNION SELECT max(id) FROM scans WHERE error IS NULL GROUP BY source)''')]
        devices = [dict(r) for r in db.execute('SELECT * FROM devices')]
        observations = [dict(r) for r in db.execute('SELECT * FROM device_sources')]
        assignments = {r['ip']:r['device_id'] for r in db.execute('SELECT * FROM ip_assignments')}
    for d in devices:
        d['address_current'] = not d['mac'] or assignments.get(d['ip'])==d['device_id']
    fresh = device_states(devices,observations,scans)
    devices.sort(key=lambda d:(int(ipaddress.IPv4Address(d['ip'])),d['device_id']))
    return dict(devices=devices,latest=dict(latest) if latest else None,stale=not fresh)
