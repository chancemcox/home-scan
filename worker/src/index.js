/**
 * HomeScan shared state in a Durable Object.
 * Keeps leader + live inventory in memory, and stores all app tables in
 * DO SQLite so every HomeScan node shares one in-memory-backed database.
 */
import { DurableObject } from 'cloudflare:workers';

const SCHEMA = `
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
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY,
  started TEXT,
  finished TEXT,
  error TEXT,
  source TEXT NOT NULL DEFAULT 'network'
);
CREATE TABLE IF NOT EXISTS sightings(
  scan_id INTEGER,
  ip TEXT,
  hostname TEXT,
  mac TEXT,
  device_id TEXT,
  PRIMARY KEY(scan_id, ip)
);
CREATE TABLE IF NOT EXISTS ip_assignments(
  ip TEXT PRIMARY KEY,
  device_id TEXT,
  last_seen TEXT
);
CREATE TABLE IF NOT EXISTS devices(
  device_id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  hostname TEXT,
  mac TEXT,
  first_seen TEXT,
  last_seen TEXT,
  scan_id INTEGER
);
CREATE TABLE IF NOT EXISTS device_sources(
  device_id TEXT,
  source TEXT,
  last_seen TEXT,
  scan_id INTEGER,
  PRIMARY KEY(device_id, source)
);
CREATE TABLE IF NOT EXISTS cf_routes(
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  hostname TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  protocol TEXT NOT NULL DEFAULT 'http',
  port INTEGER NOT NULL DEFAULT 80,
  state TEXT NOT NULL DEFAULT 'disabled',
  message TEXT NOT NULL DEFAULT '',
  synced_ip TEXT,
  last_checked TEXT,
  UNIQUE(device_id, kind)
);
CREATE UNIQUE INDEX IF NOT EXISTS cf_hostname ON cf_routes(hostname) WHERE enabled=1;
CREATE TABLE IF NOT EXISTS cf_resources(
  route_id TEXT,
  hostname TEXT,
  kind TEXT,
  record_id TEXT,
  PRIMARY KEY(route_id, hostname)
);
CREATE TABLE IF NOT EXISTS cf_tunnel_links(
  id TEXT PRIMARY KEY,
  tunnel_id TEXT NOT NULL,
  hostname TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  device_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  message TEXT NOT NULL DEFAULT '',
  synced_ip TEXT,
  last_checked TEXT,
  UNIQUE(tunnel_id, hostname, path)
);
CREATE INDEX IF NOT EXISTS sightings_device ON sightings(device_id, scan_id);
`;

export class HomeScanCluster extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.leader = null;
    this.inventory = null;
    this.ready = this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(SCHEMA);
      this.leader = (await this.ctx.storage.get('leader')) || null;
      this.inventory = (await this.ctx.storage.get('inventory')) || null;
    });
  }

  _runSql(sql, params = []) {
    const text = String(sql || '').trim();
    if (!text) return { results: [], meta: { last_row_id: 0, changes: 0 } };
    // Multi-statement scripts (schema bootstrap) — no bindings.
    if (params.length === 0 && /;\s*\S/.test(text)) {
      for (const part of text.split(';')) {
        const stmt = part.trim();
        if (stmt) this.ctx.storage.sql.exec(stmt);
      }
      return { results: [], meta: { last_row_id: 0, changes: 0 } };
    }
    const cursor = this.ctx.storage.sql.exec(text, ...params);
    const results = cursor.toArray();
    let changes = 0;
    try { changes = Number(cursor.rowsWritten || 0); } catch { changes = 0; }
    let lastRowId = 0;
    if (/^\s*INSERT\b/i.test(text)) {
      try {
        lastRowId = Number(this.ctx.storage.sql.exec('SELECT last_insert_rowid() AS id').one().id || 0);
      } catch {
        lastRowId = 0;
      }
    }
    return { results, meta: { last_row_id: lastRowId, changes } };
  }

  async fetch(request) {
    await this.ready;
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (path === '/sql' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        return Response.json({ success: false, error: 'sql body must be JSON' }, { status: 400 });
      }
      const sql = String(body.sql || '');
      const params = Array.isArray(body.params) ? body.params : [];
      if (sql.length > 200_000) {
        return Response.json({ success: false, error: 'sql too large' }, { status: 400 });
      }
      try {
        const { results, meta } = this._runSql(sql, params);
        return Response.json({ success: true, results, meta });
      } catch (err) {
        return Response.json({ success: false, error: String(err?.message || err) }, { status: 400 });
      }
    }

    if (path === '/leader' && request.method === 'GET') {
      this._expireLeader();
      return Response.json({ leader: this.leader });
    }

    if (path === '/leader' && request.method === 'PUT') {
      const body = await request.json();
      const nodeId = String(body.node_id || '');
      const ip = String(body.ip || '');
      const ttl = Math.max(5, Math.min(120, Number(body.ttl) || 15));
      if (!nodeId) return Response.json({ error: 'node_id required' }, { status: 400 });
      this._expireLeader();
      if (this.leader && this.leader.node_id !== nodeId) {
        return Response.json({ ok: false, leader: this.leader }, { status: 409 });
      }
      this.leader = { node_id: nodeId, ip, expires: Date.now() + ttl * 1000, ts: Date.now() };
      await this.ctx.storage.put('leader', this.leader);
      await this.ctx.storage.setAlarm(this.leader.expires);
      return Response.json({ ok: true, leader: this.leader });
    }

    if (path === '/leader' && request.method === 'DELETE') {
      const nodeId = String(url.searchParams.get('node_id') || '');
      this._expireLeader();
      if (this.leader && nodeId && this.leader.node_id !== nodeId) {
        return Response.json({ ok: false, leader: this.leader }, { status: 409 });
      }
      this.leader = null;
      await this.ctx.storage.delete('leader');
      return Response.json({ ok: true });
    }

    if (path === '/inventory' && request.method === 'GET') {
      return new Response(this.inventory || '{}', {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
    }

    if (path === '/inventory' && request.method === 'PUT') {
      const text = await request.text();
      try { JSON.parse(text); } catch {
        return Response.json({ error: 'inventory must be JSON' }, { status: 400 });
      }
      this.inventory = text;
      await this.ctx.storage.put('inventory', text);
      return Response.json({ ok: true, bytes: text.length });
    }

    if (path === '/state' && request.method === 'GET') {
      this._expireLeader();
      let devices = 0;
      try {
        devices = Number(this.ctx.storage.sql.exec('SELECT count(*) AS c FROM devices').one().c || 0);
      } catch { devices = 0; }
      return Response.json({
        leader: this.leader,
        has_inventory: Boolean(this.inventory),
        devices,
        database_size: this.ctx.storage.sql.databaseSize,
        backend: 'durable-object-memory',
      });
    }

    return Response.json({ error: 'not found' }, { status: 404 });
  }

  async alarm() {
    this._expireLeader();
    if (!this.leader) await this.ctx.storage.delete('leader');
  }

  _expireLeader() {
    if (this.leader && this.leader.expires && Date.now() >= this.leader.expires) {
      this.leader = null;
    }
  }
}

function unauthorized() {
  return Response.json({ error: 'Unauthorized' }, { status: 401 });
}

export default {
  async fetch(request, env) {
    const secret = env.CLUSTER_SECRET || '';
    const provided = request.headers.get('X-HomeScan-Cluster') || '';
    if (!secret || provided !== secret) return unauthorized();

    const stub = env.CLUSTER.getByName(env.CLUSTER_NAME || 'homescan');
    const url = new URL(request.url);
    // Forward /v1/* to the Durable Object as /*.
    url.pathname = url.pathname.replace(/^\/v1/, '') || '/';
    return stub.fetch(url.toString(), request);
  },
};
