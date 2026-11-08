import fs from 'node:fs';
import path from 'node:path';
import { Cursor, isQuery } from './rows.js';
import { D1Connection, D1Error } from './d1.js';
import { DoConnection } from './doDb.js';

export { D1Error };
export const DB = process.env.DB_PATH || '/data/homescan.db';

const backend = { kind: 'sqlite' };

export function useSqlite() {
  for (const key of Object.keys(backend)) delete backend[key];
  backend.kind = 'sqlite';
}

export function useD1(accountId, databaseId, token) {
  for (const key of Object.keys(backend)) delete backend[key];
  Object.assign(backend, { kind: 'd1', accountId, databaseId, token });
}

export function useDo(baseUrl, secret) {
  for (const key of Object.keys(backend)) delete backend[key];
  Object.assign(backend, { kind: 'durable-object', baseUrl, secret });
}

export function backendState() {
  if (backend.kind === 'd1') return { kind: 'd1', database_id: backend.databaseId || '', shared: true };
  if (backend.kind === 'durable-object') return { kind: 'durable-object', database_id: '', shared: true };
  return { kind: 'sqlite', database_id: '', shared: false };
}

function remote() { return backend.kind === 'd1' || backend.kind === 'durable-object'; }

export function now() { return new Date().toISOString(); }

function openSqlite(dbPath) {
  const { DatabaseSync } = sqliteApi();
  const db = new DatabaseSync(dbPath);
  return {
    execute(sql, params = []) {
      const text = String(sql || '');
      const stmt = db.prepare(text);
      const values = [...params];
      if (isQuery(text)) return new Cursor(values.length ? stmt.all(...values) : stmt.all());
      const info = values.length ? stmt.run(...values) : stmt.run();
      return new Cursor([], Number(info.lastInsertRowid || 0), Number(info.changes ?? -1));
    },
    executescript(sql) {
      const text = String(sql || '').trim();
      if (text) db.exec(text);
      return this;
    },
    close() { try { db.close(); } catch { /* already closed */ } },
  };
}

let sqliteApiCache;
function sqliteApi() {
  if (!sqliteApiCache) {
    throw new Error('node:sqlite is not loaded. Start HomeScan on Node.js 22 or newer.');
  }
  return sqliteApiCache;
}

export async function loadSqlite() {
  sqliteApiCache = await import('node:sqlite');
}

export function connect(dbPath = DB) {
  if (backend.kind === 'd1') return new D1Connection(backend.accountId, backend.databaseId, backend.token);
  if (backend.kind === 'durable-object') return new DoConnection(backend.baseUrl, backend.secret);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  return openSqlite(dbPath);
}

export function withDb(dbPath, fn) {
  const db = connect(dbPath);
  try { return fn(db); }
  finally { db.close(); }
}

const BASE_TABLES = `
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
`;

export function macAddress(value) {
  const raw = String(value || '').replace(/[:-]/g, '').toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(raw) || raw === '0'.repeat(12) || raw === 'F'.repeat(12)) return '';
  if (parseInt(raw.slice(0, 2), 16) & 1) return '';
  return raw.match(/.{2}/g).join(':');
}

export function identity(ip, mac) { return mac ? `mac:${mac}` : `ip:${ip}`; }

export function init(dbPath = DB) {
  if (!remote()) fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = connect(dbPath);
  try {
    if (!remote()) db.execute('PRAGMA journal_mode=WAL');
    db.executescript(BASE_TABLES);
    if (!remote()) db.execute('BEGIN IMMEDIATE');
    const old = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices'").fetchone();
    const cols = old ? db.execute('PRAGMA table_info(devices)').fetchall().map((row) => row.name) : [];
    const migrate = Boolean(old) && !cols.includes('device_id') && !remote();
    if (migrate) {
      db.execute('ALTER TABLE devices RENAME TO devices_legacy');
      db.execute('ALTER TABLE device_sources RENAME TO device_sources_legacy');
    }
    db.execute(`CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, ip TEXT NOT NULL,
      hostname TEXT, mac TEXT, first_seen TEXT, last_seen TEXT, scan_id INTEGER)`);
    db.execute(`CREATE TABLE IF NOT EXISTS device_sources(device_id TEXT, source TEXT,
      last_seen TEXT, scan_id INTEGER, PRIMARY KEY(device_id,source))`);
    const sightingCols = db.execute('PRAGMA table_info(sightings)').fetchall().map((row) => row.name);
    if (sightingCols.length && !sightingCols.includes('device_id')) db.execute('ALTER TABLE sightings ADD COLUMN device_id TEXT');
    if (migrate) {
      const mapping = {};
      for (const row of db.execute('SELECT * FROM devices_legacy ORDER BY last_seen').fetchall()) {
        const mac = macAddress(row.mac);
        const did = identity(row.ip, mac);
        mapping[row.ip] = did;
        db.execute(`INSERT INTO devices VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
          ip=excluded.ip,hostname=excluded.hostname,mac=excluded.mac,
          first_seen=min(devices.first_seen,excluded.first_seen),last_seen=excluded.last_seen,scan_id=excluded.scan_id`,
        [did, row.ip, row.hostname, mac, row.first_seen, row.last_seen, row.scan_id]);
        if (mac) {
          db.execute('DELETE FROM ip_assignments WHERE device_id=?', [did]);
          db.execute('INSERT OR REPLACE INTO ip_assignments VALUES(?,?,?)', [row.ip, did, row.last_seen]);
        }
      }
      for (const row of db.execute('SELECT * FROM device_sources_legacy ORDER BY last_seen').fetchall()) {
        if (mapping[row.ip]) db.execute('INSERT OR REPLACE INTO device_sources VALUES(?,?,?,?)', [mapping[row.ip], row.source, row.last_seen, row.scan_id]);
      }
      db.execute('DROP TABLE device_sources_legacy');
      db.execute('DROP TABLE devices_legacy');
    }
    for (const row of db.execute('SELECT rowid,ip,mac FROM sightings WHERE device_id IS NULL').fetchall()) {
      db.execute('UPDATE sightings SET device_id=? WHERE rowid=?', [identity(row.ip, macAddress(row.mac)), row.rowid]);
    }
    db.execute('CREATE INDEX IF NOT EXISTS sightings_device ON sightings(device_id,scan_id)');
    if (!remote()) db.execute('COMMIT');
  } catch (exc) {
    if (!remote()) { try { db.execute('ROLLBACK'); } catch { /* no transaction */ } }
    throw exc;
  } finally { db.close(); }
}

export function getSettings(dbPath, keys = null) {
  const wanted = keys ? new Set(keys) : null;
  return withDb(dbPath, (db) => {
    const result = {};
    for (const row of db.execute('SELECT key, value FROM app_settings').fetchall()) {
      if (wanted && !wanted.has(row.key)) continue;
      result[row.key] = row.value;
    }
    return result;
  });
}

export function setSettings(dbPath, mapping) {
  if (!mapping) return;
  withDb(dbPath, (db) => {
    for (const [key, value] of Object.entries(mapping)) {
      if (value == null || value === '') continue;
      db.execute('INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [String(key), String(value)]);
    }
  });
}

export function appendLog(dbPath, { level, push, source, message, detail = '', createdAt = null }) {
  withDb(dbPath, (db) => {
    db.execute('INSERT INTO app_logs(created_at, level, push, source, message, detail) VALUES(?,?,?,?,?,?)',
      [createdAt || now(), String(level).slice(0, 16), String(push).slice(0, 64), String(source || '').slice(0, 64),
        String(message).slice(0, 2000), String(detail || '').slice(0, 8000)]);
  });
}

export function expireLogs(dbPath, olderThanDays = 30) {
  const days = Math.max(1, Number(olderThanDays) || 30);
  const cutoff = new Date(Date.now() - days * 86400_000).toISOString();
  return withDb(dbPath, (db) => {
    const cursor = db.execute('DELETE FROM app_logs WHERE created_at < ?', [cutoff]);
    return cursor.rowcount >= 0 ? cursor.rowcount : 0;
  });
}

export function recentLogs(dbPath, limit = 100) {
  limit = Math.max(1, Math.min(500, Number(limit) || 100));
  return withDb(dbPath, (db) => db.execute(
    'SELECT created_at, level, push, source, message, detail FROM app_logs ORDER BY created_at DESC, id DESC LIMIT ?',
    [limit]).fetchall());
}

export function migrateLocalToRemote(dbPath) {
  if (!remote() || !fs.existsSync(dbPath)) return false;
  const local = openSqlite(dbPath);
  let copied = false;
  try {
    const remoteDb = connect(dbPath);
    try {
      const existing = remoteDb.execute('SELECT count(*) AS c FROM devices').fetchone();
      const empty = !existing || !Number(existing.c || 0);
      const tables = ['status', 'app_settings', 'app_logs', 'scans', 'sightings', 'ip_assignments', 'devices', 'device_sources', 'cf_routes', 'cf_resources', 'cf_tunnel_links'];
      for (const table of tables) {
        const present = local.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", [table]).fetchone();
        if (!present) continue;
        const rows = local.execute(`SELECT * FROM ${table}`).fetchall();
        if (!rows.length) continue;
        if (table !== 'app_settings' && !empty) continue;
        const cols = Object.keys(rows[0]).filter((col) => !(table === 'app_logs' && col === 'id'));
        for (const row of rows) {
          if (table === 'app_settings') {
            remoteDb.execute('INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [row.key, row.value]);
          } else {
            remoteDb.execute(`INSERT OR IGNORE INTO ${table}(${cols.join(',')}) VALUES(${cols.map(() => '?').join(',')})`, cols.map((col) => row[col]));
          }
        }
        copied = true;
      }
    } finally { remoteDb.close(); }
  } finally { local.close(); }
  return copied;
}

function ipv4(value) {
  const text = String(value || '').trim();
  const parts = text.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part) || Number(part) > 255)) {
    throw new Error('Invalid hosts');
  }
  return parts.map((part) => String(Number(part))).join('.');
}

export function normalize(hosts) {
  if (!Array.isArray(hosts) || hosts.length > 4096) throw new Error('Invalid hosts');
  const result = new Map();
  for (const host of hosts) {
    const ip = ipv4(host.ip);
    const mac = macAddress(host.mac);
    result.set(ip, { ip, mac, hostname: String(host.hostname || '').trim().toLowerCase().slice(0, 255), device_id: identity(ip, mac) });
  }
  return [...result.values()];
}

export function recordBatches(dbPath, batches) {
  const clean = [];
  for (const batch of batches) {
    if (!['network', 'deco'].includes(batch.source)) throw new Error('Invalid scan source');
    clean.push([batch, normalize(batch.hosts)]);
  }
  const stamp = now();
  withDb(dbPath, (db) => {
    for (const [batch, hosts] of clean) {
      const source = batch.source;
      const error = batch.error ? String(batch.error).slice(0, 1000) : null;
      const sid = db.execute('INSERT INTO scans(started,finished,error,source) VALUES(?,?,?,?)',
        [batch.started || stamp, stamp, error, source]).lastrowid;
      for (const host of hosts) {
        const { device_id: did, ip, mac, hostname: name } = host;
        let first = stamp;
        if (mac) {
          const provisional = `ip:${ip}`;
          const old = db.execute('SELECT first_seen FROM devices WHERE device_id=?', [provisional]).fetchone();
          first = old ? old.first_seen : stamp;
          db.execute('DELETE FROM device_sources WHERE device_id=?', [provisional]);
          db.execute('DELETE FROM devices WHERE device_id=?', [provisional]);
          db.execute('DELETE FROM ip_assignments WHERE device_id=? AND ip<>?', [did, ip]);
          db.execute('INSERT OR REPLACE INTO ip_assignments VALUES(?,?,?)', [ip, did, stamp]);
        } else {
          const known = db.execute('SELECT device_id FROM ip_assignments WHERE ip=?', [ip]).fetchone();
          if (known && known.device_id) {
            db.execute('INSERT INTO sightings VALUES(?,?,?,?,?)', [sid, ip, name, mac, known.device_id]);
            db.execute(
              `UPDATE devices SET last_seen=?, scan_id=?, hostname=CASE WHEN ?='' THEN hostname ELSE ? END WHERE device_id=?`,
              [stamp, sid, name, name, known.device_id],
            );
            db.execute('INSERT OR REPLACE INTO device_sources VALUES(?,?,?,?)', [known.device_id, source, stamp, sid]);
            continue;
          }
        }
        db.execute('INSERT INTO sightings VALUES(?,?,?,?,?)', [sid, ip, name, mac, did]);
        db.execute(`INSERT INTO devices VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
          ip=excluded.ip,hostname=CASE WHEN excluded.hostname='' THEN devices.hostname ELSE excluded.hostname END,
          mac=CASE WHEN excluded.mac='' THEN devices.mac ELSE excluded.mac END,
          first_seen=min(devices.first_seen,excluded.first_seen),last_seen=excluded.last_seen,scan_id=excluded.scan_id`,
        [did, ip, name, mac, first, stamp, sid]);
        db.execute('INSERT OR REPLACE INTO device_sources VALUES(?,?,?,?)', [did, source, stamp, sid]);
      }
    }
    db.execute("DELETE FROM sightings WHERE scan_id IN (SELECT id FROM scans WHERE julianday(finished)<julianday('now','-30 days'))");
    db.execute("DELETE FROM scans WHERE julianday(finished)<julianday('now','-30 days')");
  });
}

function parseStamp(value) {
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

export function deviceStates(devices, observations, scans, at = new Date()) {
  const latest = {};
  const good = {};
  for (const scan of [...scans].sort((a, b) => a.id - b.id)) {
    latest[scan.source] = scan;
    if (!scan.error) good[scan.source] = scan;
  }
  const fresh = (scan) => {
    if (!scan) return false;
    const finished = parseStamp(scan.finished);
    return finished != null && (at.getTime() - finished) / 1000 < 150;
  };
  for (const device of devices) {
    const states = [];
    for (const obs of observations) {
      const obsId = obs.device_id ?? obs.ip;
      const deviceId = device.device_id ?? device.ip;
      if (obsId !== deviceId) continue;
      const success = good[obs.source];
      if (!fresh(success)) states.push('unknown');
      else if (obs.scan_id === success.id) states.push('seen');
      else states.push('not_seen');
    }
    device.status = states.includes('seen') ? 'seen' : (!states.length || states.includes('unknown') ? 'unknown' : 'not_seen');
    if (device.address_current === false) device.status = 'not_seen';
    device.online = device.status === 'seen';
  }
  return Object.values(good).some(fresh);
}

function ipNumber(value) {
  return value.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);
}

export function inventory(dbPath) {
  const data = withDb(dbPath, (db) => ({
    latest: db.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1').fetchone(),
    scans: db.execute(`SELECT * FROM scans WHERE id IN
      (SELECT max(id) FROM scans GROUP BY source UNION SELECT max(id) FROM scans WHERE error IS NULL GROUP BY source)`).fetchall(),
    devices: db.execute('SELECT * FROM devices').fetchall(),
    observations: db.execute('SELECT * FROM device_sources').fetchall(),
    assignments: Object.fromEntries(db.execute('SELECT * FROM ip_assignments').fetchall().map((row) => [row.ip, row.device_id])),
  }));
  for (const device of data.devices) {
    device.address_current = !device.mac || data.assignments[device.ip] === device.device_id;
  }
  const fresh = deviceStates(data.devices, data.observations, data.scans);
  data.devices.sort((a, b) => ipNumber(a.ip) - ipNumber(b.ip) || String(a.device_id).localeCompare(String(b.device_id)));
  return { devices: data.devices, latest: data.latest || null, stale: !fresh };
}
