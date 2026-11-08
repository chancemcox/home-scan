import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as storage from './storage.js';
import * as applog from './applog.js';
import { requestJson } from './syncHttp.js';

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const CONFIG = process.env.CLOUDFLARE_CONFIG || '/data/cloudflare.json';
export const TOKEN_FILE = process.env.CLOUDFLARE_TUNNEL_TOKEN || '/run/homescan-tunnel/token';
export const SHARED_SETTING_KEYS = [
  'suffix', 'zone_id', 'zone_name', 'account_id', 'tunnel_id',
  'installation_id', 'cluster_worker_url', 'dns_subnet',
  'ha_hostname', 'ha_port', 'ha_enabled', 'scan_mode', 'scan_network',
];
export const RUNTIME_SETTING_ENV = [
  ['ha_hostname', 'HA_HOSTNAME'],
  ['ha_port', 'HA_PORT'],
  ['ha_enabled', 'HA_ENABLED'],
  ['scan_mode', 'SCAN_MODE'],
  ['scan_network', 'SCAN_NETWORK'],
  ['dns_subnet', 'DNS_SUBNET'],
];
const OLD_SUFFIXES = (process.env.HOMESCAN_OLD_SUFFIXES || '').split(',').map((item) => item.trim()).filter(Boolean);

export class CloudflareError extends Error {}

function apiError(response) {
  const result = response && response.payload;
  const details = result && typeof result === 'object'
    ? (result.errors || []).map((item) => item.message || item.code).filter(Boolean).join('; ')
    : '';
  if (response && response.status === 403) {
    return new CloudflareError(details || 'Cloudflare HTTP 403. Grant Zone DNS Edit for the connected zone, then retry.');
  }
  if (details) return new CloudflareError(details);
  if (response && response.status >= 400) return new CloudflareError(`Cloudflare HTTP ${response.status}. Check token permissions or retry later.`);
  return new CloudflareError('Cloudflare could not be reached. Retrying automatically.');
}

export function defaultClusterHostname(cfg = {}, suffix = '') {
  const zone = String(cfg.zone_name || '').trim().toLowerCase().replace(/\.+$/, '');
  if (zone) return 'homescan.' + zone;
  const base = String(suffix || '').trim().toLowerCase().replace(/\.+$/, '');
  if (base) return 'homescan.' + base;
  return '';
}

export function pickAvailableZone(zones, body = {}) {
  const list = Array.isArray(zones) ? zones : [];
  if (!list.length) throw new Error('Connect Cloudflare, then choose a domain this token can access.');
  const zoneId = String(body.zone_id || '').trim();
  if (zoneId) {
    const found = list.find((zone) => zone.id === zoneId);
    if (!found) throw new Error('That domain is not available to this token.');
    return found;
  }
  const raw = String(body.suffix || body.domain || '').trim();
  if (!raw) throw new Error('Choose a Cloudflare domain.');
  const name = normalizeSuffix(raw);
  const found = list.find((zone) => zone.name === name);
  if (!found) throw new Error('Choose a Cloudflare domain this token can access.');
  return found;
}

export class API {
  constructor(token) { this.token = token; }
  call(method, apiPath, body = undefined) {
    let response;
    try {
      response = requestJson({
        method,
        url: 'https://api.cloudflare.com/client/v4' + apiPath,
        headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
        body,
        timeout: 12_000,
      });
    } catch {
      throw new CloudflareError('Cloudflare could not be reached. Retrying automatically.');
    }
    const result = response.payload;
    if (!result || typeof result !== 'object' || response.status >= 400 || result.success === false) {
      throw apiError(response);
    }
    return result.result;
  }
}

function ipv4Parts(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part) || Number(part) > 255)) return null;
  return parts.map(Number);
}

export function privateIp(value) {
  const parts = ipv4Parts(value);
  const ok = parts && (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168));
  if (!ok) throw new Error('Cloudflare targets must be private LAN IPv4 addresses.');
  return parts.join('.');
}

function network(value) {
  const [addr, prefixRaw] = String(value).split('/');
  const prefix = Number(prefixRaw);
  const parts = ipv4Parts(addr);
  if (!parts || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error(value + ' is not an IPv4 subnet.');
  let n = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  n = (n & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  const cidr = [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.') + '/' + prefix;
  const privateNet = [n >>> 24] && false;
  const first = n >>> 24;
  const second = (n >>> 16) & 255;
  const isPrivate = first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
  return { cidr, size, private: isPrivate, loopback: first === 127, linkLocal: first === 169 && second === 254, prefix };
}
void network;

export function parseScanNetworks(value, limit = 16) {
  const text = Array.isArray(value) ? value.map(String).join('\n') : String(value || '');
  const parts = text.split(/[\s,;]+/).map((part) => part.trim()).filter(Boolean);
  if (!parts.length) return [];
  if (parts.length > limit) throw new Error(`Use at most ${limit} subnets.`);
  const nets = [];
  for (const part of parts) {
    let net;
    try { net = parseNetwork(part); }
    catch { throw new Error(part + ' is not an IPv4 subnet.'); }
    if (!net.private || net.size > 4096) throw new Error(`${net.cidr} must be a private subnet with at most 4096 addresses.`);
    if (!nets.includes(net.cidr)) nets.push(net.cidr);
  }
  return nets;
}

export function parseDnsSubnet(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw) return '';
  return parseScanNetworks(raw, 1)[0];
}

export function ipInCidr(ip, cidr) {
  const addr = ipv4Parts(ip);
  if (!addr) return false;
  let net;
  try { net = parseNetwork(cidr); }
  catch { return false; }
  const ipNum = ((addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3]) >>> 0;
  const [netAddr] = String(net.cidr).split('/');
  const netParts = ipv4Parts(netAddr);
  if (!netParts) return false;
  const base = ((netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3]) >>> 0;
  const mask = net.prefix === 0 ? 0 : (0xffffffff << (32 - net.prefix)) >>> 0;
  return ((ipNum & mask) >>> 0) === ((base & mask) >>> 0);
}

export function suffixUnderZone(suffixValue, zoneName) {
  const zone = normalizeSuffix(zoneName);
  const raw = String(suffixValue || '').trim().toLowerCase().replace(/\.+$/, '').replace(/^\*\./, '');
  if (!raw) return zone;
  // Allow a short label like "house" under the selected zone → house.zone.tld
  if (!raw.includes('.')) {
    if (!LABEL_RE.test(raw)) throw new Error('Enter a DNS label such as house, or a full subdomain such as house.' + zone);
    return normalizeSuffix(raw + '.' + zone);
  }
  const suffix = normalizeSuffix(raw);
  if (suffix !== zone && !suffix.endsWith('.' + zone)) {
    throw new Error('DNS subdomain must be ' + zone + ' or a subdomain such as house.' + zone);
  }
  return suffix;
}

function parseNetwork(value) {
  const [addr, prefixRaw] = String(value).split('/');
  const prefix = Number(prefixRaw);
  const parts = ipv4Parts(addr);
  if (!parts || !Number.isInteger(prefix) || prefix < 0 || prefix > 32 || String(value).split('/').length !== 2) {
    throw new Error('bad');
  }
  let n = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  n = (n & mask) >>> 0;
  const first = n >>> 24;
  const second = (n >>> 16) & 255;
  return {
    cidr: [first, second, (n >>> 8) & 255, n & 255].join('.') + '/' + prefix,
    size: 2 ** (32 - prefix),
    private: first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168),
    loopback: first === 127,
    linkLocal: first === 169 && second === 254,
    prefix,
  };
}

export function normalizeRuntimeSetting(key, value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (key === 'ha_hostname') { try { return normalizeSuffix(raw); } catch { return ''; } }
  if (key === 'ha_port') return /^\d+$/.test(raw) && Number(raw) >= 1 && Number(raw) <= 65535 ? String(Number(raw)) : '';
  if (key === 'ha_enabled') return ['0', 'false', 'no', 'off'].includes(raw.toLowerCase()) ? '0' : '1';
  if (key === 'scan_mode') return ['nmap', 'agent'].includes(raw) ? raw : '';
  if (key === 'scan_network') { try { return parseScanNetworks(raw).join(','); } catch { return ''; } }
  if (key === 'dns_subnet') { try { return parseDnsSubnet(raw); } catch { return ''; } }
  return raw;
}

export function normalizeSuffix(value) {
  let name = String(value || '').trim().toLowerCase().replace(/\.+$/, '');
  if (name.startsWith('*.')) name = name.slice(2);
  const parts = name.split('.');
  if (parts.length < 2 || !parts.every((part) => LABEL_RE.test(part))) throw new Error('Enter a base domain such as house.example.com');
  return name;
}

function parseHostnameInput(value) {
  let name = String(value || '').trim().toLowerCase().replace(/\.+$/, '');
  if (name.includes('://')) {
    let parsed;
    try { parsed = new URL(name); } catch { throw new Error('Enter a hostname without a port or path.'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || !['', '/'].includes(parsed.pathname) || parsed.search || parsed.hash || parsed.port || parsed.username) {
      throw new Error('Enter a hostname without a port or path.');
    }
    name = parsed.hostname || '';
  }
  return name;
}

function removeSuffix(name, suffix) {
  const tail = '.' + suffix;
  return name.endsWith(tail) ? name.slice(0, -tail.length) : name;
}

export function hostname(value, suffix = null, kind = 'local') {
  const configured = suffix ? normalizeSuffix(suffix) : '';
  let name = parseHostnameInput(value);
  if (!name) throw new Error('Enter a hostname.');
  if (!name.includes('.')) {
    if (!configured) throw new Error('Set a base domain in Settings, or enter a full hostname.');
    name += '.' + configured;
  }
  const parts = name.split('.');
  if (!parts.every((part) => LABEL_RE.test(part))) throw new Error('Hostnames may only use letters, numbers, and hyphens.');
  if (kind === 'tunnel') {
    if (parts.length < 2) throw new Error('Enter a full hostname on a Cloudflare domain, or a short label under your base domain.');
    return name;
  }
  if (!configured) throw new Error('Set a base domain in Settings before enabling local DNS.');
  const label = removeSuffix(name, configured);
  if (name !== `${label}.${configured}` || !LABEL_RE.test(label) || label.includes('.')) {
    throw new Error('Use a single hostname such as nas.' + configured);
  }
  return name;
}

export function hostnameUnderZone(value, zoneName) {
  const zone = String(zoneName || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!zone || !zone.split('.').every((part) => LABEL_RE.test(part))) throw new Error('Choose an accessible domain from this Cloudflare account.');
  const raw = parseHostnameInput(value);
  if (!raw) throw new Error('Enter a hostname such as files or files.house');
  let parts;
  if (raw === zone || raw.endsWith('.' + zone)) {
    const relative = raw === zone ? '' : raw.slice(0, -(zone.length + 1));
    parts = relative ? relative.split('.') : [];
  } else parts = raw.split('.');
  if (!parts.length || !parts.every((part) => LABEL_RE.test(part))) throw new Error('Use a hostname such as files or files.house under ' + zone);
  return parts.join('.') + '.' + zone;
}

export function zoneCandidatesForSuffix(suffix) {
  const parts = normalizeSuffix(suffix).split('.');
  return parts.slice(0, -1).map((_, index) => parts.slice(index).join('.'));
}

export function inferSuffixFromHostnames(hostnames, zoneName = '') {
  const zone = String(zoneName || '').trim().toLowerCase().replace(/\.+$/, '');
  const counts = new Map();
  for (const raw of hostnames) {
    const name = String(raw || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!name.includes('.')) continue;
    let candidate = name.split('.').slice(1).join('.');
    if (zone && candidate !== zone && !candidate.endsWith('.' + zone)) continue;
    try { candidate = normalizeSuffix(candidate); } catch { continue; }
    counts.set(candidate, (counts.get(candidate) || 0) + 1);
  }
  let best = '';
  let bestScore = [-1, -1];
  for (const [candidate, count] of counts) {
    const score = [count, candidate.length];
    if (score[0] > bestScore[0] || (score[0] === bestScore[0] && score[1] > bestScore[1])) {
      best = candidate;
      bestScore = score;
    }
  }
  return best;
}

export function atomicJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function readConfig(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return {}; }
}

function sameJson(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

export class Wake {
  constructor() { this._waiters = []; this._set = false; }
  set() {
    this._set = true;
    const waiters = this._waiters.splice(0);
    for (const resolve of waiters) resolve();
  }
  wait(ms) {
    if (this._set) { this._set = false; return Promise.resolve(); }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this._waiters = this._waiters.filter((item) => item !== finish);
        this._set = false;
        resolve();
      }, ms);
      const finish = () => { clearTimeout(timer); this._set = false; resolve(); };
      this._waiters.push(finish);
    });
  }
}

const CF_SCHEMA = `
CREATE TABLE IF NOT EXISTS cf_routes(id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
    kind TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT 'http', port INTEGER NOT NULL DEFAULT 80,
    state TEXT NOT NULL DEFAULT 'disabled', message TEXT NOT NULL DEFAULT '',
    synced_ip TEXT, last_checked TEXT, UNIQUE(device_id,kind));
CREATE UNIQUE INDEX IF NOT EXISTS cf_hostname ON cf_routes(hostname) WHERE enabled=1;
CREATE TABLE IF NOT EXISTS cf_resources(route_id TEXT, hostname TEXT, kind TEXT, record_id TEXT,
    PRIMARY KEY(route_id,hostname));
CREATE TABLE IF NOT EXISTS cf_tunnel_links(id TEXT PRIMARY KEY, tunnel_id TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', device_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', message TEXT NOT NULL DEFAULT '', synced_ip TEXT,
    last_checked TEXT, UNIQUE(tunnel_id,hostname,path));
CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

export class Manager {
  constructor(dbPath, configPath = CONFIG, apiFactory = (token) => new API(token), onUpdate = null) {
    this.dbPath = dbPath;
    this.configPath = configPath;
    this.apiFactory = apiFactory;
    this.onUpdate = onUpdate;
    this.wake = new Wake();
  }
  init() {
    storage.withDb(this.dbPath, (db) => {
      db.executescript(CF_SCHEMA);
      let newSuffix = '';
      try {
        const cfg = fs.existsSync(this.configPath) ? JSON.parse(fs.readFileSync(this.configPath, 'utf8')) : {};
        newSuffix = cfg.suffix ? normalizeSuffix(cfg.suffix) : '';
      } catch { newSuffix = ''; }
      if (newSuffix) {
        for (const oldSuffix of OLD_SUFFIXES) {
          const old = oldSuffix.trim().toLowerCase().replace(/\.+$/, '');
          if (!old || old === newSuffix) continue;
          for (const row of db.execute('SELECT id,hostname,enabled FROM cf_routes WHERE hostname LIKE ?', ['%.' + old])) {
            const next = removeSuffix(row.hostname, old) + '.' + newSuffix;
            db.execute(`UPDATE cf_routes SET hostname=?, state=CASE WHEN enabled=1 THEN 'pending' ELSE state END, message='' WHERE id=?`, [next, row.id]);
          }
        }
      }
    });
    this.syncSharedSettings();
  }
  config() {
    const cfg = readConfig(this.configPath);
    const shared = (() => { try { return storage.getSettings(this.dbPath, SHARED_SETTING_KEYS); } catch { return {}; } })();
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return { ...shared };
    for (const key of SHARED_SETTING_KEYS) if (shared[key]) cfg[key] = shared[key];
    return cfg;
  }
  syncSharedSettings() {
    let local = readConfig(this.configPath);
    if (!local || typeof local !== 'object' || Array.isArray(local)) local = {};
    const shared = (() => { try { return storage.getSettings(this.dbPath, SHARED_SETTING_KEYS); } catch { return {}; } })();
    let changed = false;
    for (const key of SHARED_SETTING_KEYS) {
      if (!local[key] && shared[key]) { local[key] = shared[key]; changed = true; }
    }
    for (const [key, envName] of RUNTIME_SETTING_ENV) {
      if (local[key]) continue;
      const normalized = normalizeRuntimeSetting(key, process.env[envName] || '');
      if (!normalized) continue;
      local[key] = normalized;
      changed = true;
    }
    if (local.d1_database_id) { delete local.d1_database_id; changed = true; }
    try { storage.withDb(this.dbPath, (db) => db.execute("DELETE FROM app_settings WHERE key='d1_database_id'")); } catch { /* settings table may not exist yet */ }
    if (!local.suffix) {
      let names = [];
      try {
        storage.withDb(this.dbPath, (db) => {
          names = db.execute("SELECT hostname FROM cf_routes WHERE hostname IS NOT NULL AND hostname<>''").fetchall().map((row) => row.hostname);
        });
      } catch { names = []; }
      const inferred = inferSuffixFromHostnames(names, local.zone_name || shared.zone_name || '');
      if (inferred) { local.suffix = inferred; changed = true; }
    }
    if (changed) atomicJson(this.configPath, local);
    const payload = {};
    for (const key of SHARED_SETTING_KEYS) if (local[key] != null && local[key] !== '') payload[key] = local[key];
    if (Object.keys(payload).length) storage.setSettings(this.dbPath, payload);
    return payload;
  }
  suffix() {
    try { return this.config().suffix ? normalizeSuffix(this.config().suffix) : ''; }
    catch { return ''; }
  }
  clusterHostname(explicit = '') {
    const name = String(explicit || '').trim().toLowerCase().replace(/\.+$/, '');
    if (name) return name;
    let cfg = {};
    try { cfg = this.config(); } catch { cfg = {}; }
    return defaultClusterHostname(cfg, this.suffix());
  }
  saveDomain(body) {
    const listed = this.listZones();
    if (listed.error && !(listed.zones || []).length) throw new Error(listed.error);
    const chosen = pickAvailableZone(listed.zones, body || {});
    const suffix = suffixUnderZone(body && (body.suffix || body.dns_suffix), chosen.name);
    let dnsSubnet = '';
    if (body && Object.prototype.hasOwnProperty.call(body, 'dns_subnet')) {
      dnsSubnet = parseDnsSubnet(body.dns_subnet);
    } else {
      try { dnsSubnet = parseDnsSubnet(readConfig(this.configPath).dns_subnet); } catch { dnsSubnet = ''; }
    }
    const cfg = readConfig(this.configPath);
    cfg.suffix = suffix;
    cfg.zone_id = chosen.id;
    cfg.zone_name = chosen.name;
    cfg.dns_subnet = dnsSubnet;
    if (chosen.account_id) cfg.account_id = chosen.account_id;
    atomicJson(this.configPath, cfg);
    storage.setSettings(this.dbPath, {
      suffix, zone_id: chosen.id, zone_name: chosen.name, dns_subnet: dnsSubnet,
      ...(chosen.account_id ? { account_id: chosen.account_id } : {}),
    });
    return { ok: true, suffix, zone: chosen.name, zone_id: chosen.id, dns_subnet: dnsSubnet };
  }
  saveScanNetworks(body) {
    const nets = parseScanNetworks(body && typeof body === 'object' ? body.networks : body);
    const stored = nets.join(',');
    const cfg = readConfig(this.configPath);
    cfg.scan_network = stored;
    atomicJson(this.configPath, cfg);
    storage.setSettings(this.dbPath, { scan_network: stored });
    return { ok: true, scan_network: stored, networks: nets };
  }
  publicState() {
    let cfg = {};
    try { cfg = this.config(); } catch { cfg = {}; }
    const [routes, links] = storage.withDb(this.dbPath, (db) => [
      db.execute('SELECT * FROM cf_routes').fetchall(),
      db.execute('SELECT * FROM cf_tunnel_links').fetchall(),
    ]);
    let dnsSubnet = '';
    try { dnsSubnet = parseDnsSubnet(cfg.dns_subnet); } catch { dnsSubnet = ''; }
    return {
      configured: Boolean(cfg.api_token), zone: cfg.zone_name, zone_id: cfg.zone_id || '', tunnel_id: cfg.tunnel_id || '',
      tunnel_configured: Boolean(cfg.tunnel_id), suffix: this.suffix(), dns_subnet: dnsSubnet,
      routes, tunnel_links: links, database: storage.backendState(),
    };
  }
  _tunnelApi() {
    let cfg = {};
    try { cfg = this.config(); } catch { cfg = {}; }
    if (!cfg.api_token || !cfg.account_id) throw new Error('Connect Cloudflare before editing tunnels.');
    return [cfg, this.apiFactory(cfg.api_token)];
  }
  listTunnels() {
    let cfg = {};
    try { cfg = this.config(); } catch { cfg = {}; }
    if (!cfg.api_token || !cfg.account_id) return { configured: false, tunnels: [], error: 'Connect Cloudflare to list tunnels.' };
    let rows;
    try {
      const api = this.apiFactory(cfg.api_token);
      rows = api.call('GET', `/accounts/${cfg.account_id}/cfd_tunnel?` + new URLSearchParams({ is_deleted: 'false', per_page: '100' })) || [];
    } catch (exc) {
      if (exc instanceof CloudflareError) return { configured: true, tunnels: [], error: String(exc.message) };
      return { configured: true, tunnels: [], error: 'Could not load Cloudflare tunnels.' };
    }
    const tunnels = [];
    for (const row of rows) {
      const connections = row.connections || [];
      let ingress = [];
      if (row.config_src === 'cloudflare' && row.id) {
        try {
          const response = this.apiFactory(cfg.api_token).call('GET', `/accounts/${cfg.account_id}/cfd_tunnel/${row.id}/configurations`) || {};
          ingress = (response.config || {}).ingress || [];
        } catch { ingress = []; }
      }
      tunnels.push({
        id: row.id || '', name: row.name || '', status: row.status || (connections.length ? 'healthy' : 'inactive'),
        created_at: row.created_at || '', connections: connections.length, config_src: row.config_src || '',
        editable: row.config_src === 'cloudflare',
        hostnames: ingress.filter((rule) => rule.hostname || rule.path).map((rule) => ({ hostname: rule.hostname || '', path: rule.path || '', service: rule.service || '' })),
        homescan: row.id === cfg.tunnel_id,
      });
    }
    tunnels.sort((a, b) => Number(b.homescan) - Number(a.homescan) || a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
    return { configured: true, tunnels, error: '' };
  }
  listZones() {
    let cfg, api;
    try { [cfg, api] = this._tunnelApi(); }
    catch (exc) { return { zones: [], error: String(exc.message || exc) }; }
    try {
      const zones = [];
      const seen = new Set();
      for (let page = 1; page <= 5; page += 1) {
        const rows = api.call('GET', '/zones?' + new URLSearchParams({ status: 'active', per_page: '50', page: String(page) })) || [];
        for (const zone of rows) {
          if (!zone.id || !zone.name || seen.has(zone.id)) continue;
          seen.add(zone.id);
          zones.push({ id: zone.id, name: zone.name, account_id: (zone.account || {}).id || '' });
        }
        if (rows.length < 50) break;
      }
      zones.sort((a, b) => a.name.localeCompare(b.name));
      return { zones, error: '' };
    } catch (exc) {
      if (exc instanceof CloudflareError) return { zones: [], error: String(exc.message) };
      return { zones: [], error: 'Could not load Cloudflare domains.' };
    }
  }
  static tunnelId(value) {
    const text = String(value || '').trim().toLowerCase();
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(text)) throw new Error('Invalid tunnel ID.');
    return text;
  }
  static tunnelConfig(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Tunnel configuration must be a JSON object.');
    if (JSON.stringify(value).length > 262144) throw new Error('Tunnel configuration is too large.');
    const ingress = value.ingress;
    if (!Array.isArray(ingress) || ingress.length < 1 || ingress.length > 200) throw new Error('Tunnel configuration needs between 1 and 200 ingress rules.');
    for (const rule of ingress) {
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new Error('Every ingress rule must be a JSON object.');
      if (typeof rule.service !== 'string' || !rule.service.trim() || rule.service.length > 2048) throw new Error('Every ingress rule needs a valid service.');
      for (const key of ['hostname', 'path']) if (key in rule && (typeof rule[key] !== 'string' || rule[key].length > 2048)) throw new Error(`Ingress ${key} must be text.`);
      if ('originRequest' in rule && (typeof rule.originRequest !== 'object' || Array.isArray(rule.originRequest))) throw new Error('Ingress originRequest must be a JSON object.');
    }
    const last = ingress[ingress.length - 1];
    if (last.hostname || last.path) throw new Error('The final ingress rule must be a catch-all without hostname or path.');
    return value;
  }
  getTunnel(tunnelId) {
    tunnelId = Manager.tunnelId(tunnelId);
    const [cfg, api] = this._tunnelApi();
    const base = `/accounts/${cfg.account_id}/cfd_tunnel/${tunnelId}`;
    const tunnel = api.call('GET', base) || {};
    if (tunnel.config_src !== 'cloudflare') throw new Error('This tunnel is locally managed and cannot be edited from HomeScan.');
    const response = api.call('GET', base + '/configurations') || {};
    const config = response.config || { ingress: [{ service: 'http_status:404' }] };
    const links = storage.withDb(this.dbPath, (db) => db.execute('SELECT * FROM cf_tunnel_links WHERE tunnel_id=?', [tunnelId]).fetchall());
    return { id: tunnelId, name: tunnel.name || '', config, links, homescan: tunnelId === cfg.tunnel_id };
  }
  updateTunnel(body) {
    const tunnelId = Manager.tunnelId(body.tunnel_id);
    const name = String(body.name || '').trim();
    if (name.length < 1 || name.length > 100 || /[\u0000-\u001f\u007f]/.test(name)) throw new Error('Tunnel name must be between 1 and 100 characters.');
    const desired = Manager.tunnelConfig(body.config);
    const [cfg, api] = this._tunnelApi();
    const base = `/accounts/${cfg.account_id}/cfd_tunnel/${tunnelId}`;
    const tunnel = api.call('GET', base) || {};
    if (tunnel.config_src !== 'cloudflare') throw new Error('This tunnel is locally managed and cannot be edited from HomeScan.');
    const response = api.call('GET', base + '/configurations') || {};
    const current = response.config || { ingress: [{ service: 'http_status:404' }] };
    if (tunnelId === cfg.tunnel_id) {
      const owned = new Set(storage.withDb(this.dbPath, (db) => db.execute("SELECT hostname FROM cf_resources WHERE kind='tunnel'").fetchall().map((row) => row.hostname)));
      const pick = (rules) => Object.fromEntries((rules.ingress || []).filter((rule) => owned.has(rule.hostname)).map((rule) => [rule.hostname, rule]));
      if (!sameJson(pick(current), pick(desired))) throw new Error('HomeScan-managed ingress rules must be edited from their device settings.');
    }
    if (tunnel.name !== name) api.call('PATCH', base, { name });
    if (!sameJson(current, desired)) api.call('PUT', base + '/configurations', { config: desired });
    return this.getTunnel(tunnelId);
  }
  static ruleKey(rule) { return [String(rule.hostname || ''), String(rule.path || '')]; }
  static serviceWithIp(service, ip) {
    let parsed;
    try { parsed = new URL(String(service || '')); } catch { throw new Error('Only URL-based HTTP, HTTPS, TCP, SSH, RDP, or SMB services can be linked.'); }
    const scheme = parsed.protocol.replace(':', '');
    if (!['http', 'https', 'tcp', 'ssh', 'rdp', 'smb'].includes(scheme) || !parsed.hostname) throw new Error('Only URL-based HTTP, HTTPS, TCP, SSH, RDP, or SMB services can be linked.');
    if (parsed.username || parsed.password) throw new Error('Services containing credentials cannot be linked.');
    const port = parsed.port;
    return `${scheme}://${ip}${port ? ':' + port : ''}${parsed.pathname}${parsed.search}${parsed.hash}`;
  }
  saveTunnelLink(body) {
    const action = String(body.action || 'save');
    if (action === 'delete') {
      const linkId = String(body.link_id || '');
      const cursor = storage.withDb(this.dbPath, (db) => db.execute('DELETE FROM cf_tunnel_links WHERE id=?', [linkId]));
      if (cursor.rowcount !== 1) throw new Error('Tunnel link was not found.');
      return { ok: true };
    }
    const tunnelId = Manager.tunnelId(body.tunnel_id);
    const did = String(body.device_id || '');
    const key = [String(body.hostname || ''), String(body.path || '')];
    const device = storage.withDb(this.dbPath, (db) => db.execute('SELECT * FROM devices WHERE device_id=?', [did]).fetchone());
    if (!device || !device.mac || !did.startsWith('mac:')) throw new Error('Choose a computer with a known MAC address.');
    const detail = this.getTunnel(tunnelId);
    const matching = (detail.config.ingress || []).filter((rule) => sameJson(Manager.ruleKey(rule), key));
    if (matching.length !== 1) throw new Error('Choose a unique tunnel ingress rule.');
    privateIp(device.ip);
    Manager.serviceWithIp(matching[0].service, device.ip);
    if (detail.homescan) {
      const owned = storage.withDb(this.dbPath, (db) => db.execute("SELECT 1 FROM cf_resources WHERE kind='tunnel' AND hostname=?", [key[0]]).fetchone());
      if (owned) throw new Error('This route already follows a computer through HomeScan device settings.');
    }
    const linkId = storage.withDb(this.dbPath, (db) => {
      const old = db.execute('SELECT id FROM cf_tunnel_links WHERE tunnel_id=? AND hostname=? AND path=?', [tunnelId, ...key]).fetchone();
      const id = old ? old.id : crypto.randomUUID().replace(/-/g, '');
      db.execute(`INSERT INTO cf_tunnel_links(id,tunnel_id,hostname,path,device_id,state,message)
        VALUES(?,?,?,?,?,'pending','') ON CONFLICT(id) DO UPDATE SET device_id=excluded.device_id,state='pending',message='',synced_ip=NULL`,
      [id, tunnelId, ...key, did]);
      return id;
    });
    this.wake.set();
    return { ok: true, id: linkId };
  }
  createTunnelRoute(body) {
    const tunnelId = Manager.tunnelId(body.tunnel_id);
    const zoneId = String(body.zone_id || '');
    const did = String(body.device_id || '');
    const protocol = String(body.protocol || 'http');
    if (!['http', 'https'].includes(protocol)) throw new Error('Choose HTTP or HTTPS for the origin.');
    const port = Number(body.port ?? 80);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be between 1 and 65535.');
    const device = storage.withDb(this.dbPath, (db) => db.execute('SELECT * FROM devices WHERE device_id=?', [did]).fetchone());
    if (!device || !device.mac || !did.startsWith('mac:')) throw new Error('Choose a computer with a known MAC address.');
    const ip = privateIp(device.ip);
    const [cfg, api] = this._tunnelApi();
    const zone = api.call('GET', `/zones/${zoneId}`) || {};
    if (!zone.name || (zone.account || {}).id !== cfg.account_id) throw new Error('Choose an accessible domain from this Cloudflare account.');
    const name = hostnameUnderZone(body.hostname, zone.name);
    const base = `/accounts/${cfg.account_id}/cfd_tunnel/${tunnelId}`;
    const tunnel = api.call('GET', base) || {};
    if (tunnel.config_src !== 'cloudflare') throw new Error('Choose a remotely managed tunnel.');
    const response = api.call('GET', base + '/configurations') || {};
    const config = response.config || { ingress: [{ service: 'http_status:404' }] };
    const rules = config.ingress || [{ service: 'http_status:404' }];
    const matching = rules.filter((rule) => rule.hostname === name && !rule.path);
    const service = `${protocol}://${ip}:${port}`;
    if (matching.length > 1) throw new Error('That hostname has multiple ingress rules and cannot be managed automatically.');
    if (matching.length) matching[0].service = service;
    else {
      const position = rules.findIndex((rule) => !rule.hostname && !rule.path);
      rules.splice(position < 0 ? rules.length : position, 0, { hostname: name, service });
    }
    const records = api.call('GET', `/zones/${zoneId}/dns_records?` + new URLSearchParams({ name, per_page: '100' })) || [];
    const target = tunnelId + '.cfargotunnel.com';
    if (records.some((record) => record.type !== 'CNAME' || record.content !== target)) throw new Error('An existing DNS record already owns this hostname.');
    api.call('PUT', base + '/configurations', { config: { ...config, ingress: rules } });
    if (!records.length) {
      api.call('POST', `/zones/${zoneId}/dns_records`, { type: 'CNAME', name, content: target, proxied: true, ttl: 1, comment: 'homescan:tunnel-route' });
    }
    return { ...this.saveTunnelLink({ tunnel_id: tunnelId, hostname: name, path: '', device_id: did }), hostname: name };
  }
  _cleanupTunnelDns(api, cfg, tunnelId, hostnameValue) {
    const hostnameName = String(hostnameValue || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!hostnameName.includes('.')) return;
    const target = (tunnelId + '.cfargotunnel.com').toLowerCase();
    const labels = hostnameName.split('.');
    let zone = null;
    for (let i = 0; i < labels.length - 1; i++) {
      const name = labels.slice(i).join('.');
      let rows = [];
      try { rows = api.call('GET', '/zones?' + new URLSearchParams({ name, status: 'active', per_page: '5' })) || []; }
      catch (exc) { if (exc instanceof CloudflareError) continue; throw exc; }
      zone = rows.find((candidate) => candidate.name === name && (candidate.account || {}).id === cfg.account_id) || null;
      if (zone) break;
    }
    if (!zone) return;
    let records = [];
    try { records = api.call('GET', `/zones/${zone.id}/dns_records?` + new URLSearchParams({ name: hostnameName, per_page: '100' })) || []; }
    catch (exc) { if (exc instanceof CloudflareError) return; throw exc; }
    for (const record of records) {
      const content = String(record.content || '').replace(/\.+$/, '').toLowerCase();
      if (record.type === 'CNAME' && content === target && record.id) {
        try { api.call('DELETE', `/zones/${zone.id}/dns_records/${record.id}`); } catch (exc) { if (!(exc instanceof CloudflareError)) throw exc; }
      }
    }
  }
  deleteTunnelHostname(body) {
    const tunnelId = Manager.tunnelId(body.tunnel_id);
    const key = [String(body.hostname || ''), String(body.path || '')];
    if (!key[0] && !key[1]) throw new Error('Choose a public hostname to delete.');
    const [cfg, api] = this._tunnelApi();
    const base = `/accounts/${cfg.account_id}/cfd_tunnel/${tunnelId}`;
    const tunnel = api.call('GET', base) || {};
    if (tunnel.config_src !== 'cloudflare') throw new Error('Locally managed tunnels must be edited in their local configuration.');
    if (tunnelId === cfg.tunnel_id) {
      const owned = storage.withDb(this.dbPath, (db) => db.execute("SELECT 1 FROM cf_resources WHERE kind='tunnel' AND hostname=?", [key[0]]).fetchone());
      if (owned) throw new Error('HomeScan-managed ingress rules must be removed from their device settings.');
    }
    const response = api.call('GET', base + '/configurations') || {};
    const config = response.config || { ingress: [{ service: 'http_status:404' }] };
    const rules = [...(config.ingress || [])];
    const matches = rules.map((rule, index) => sameJson(Manager.ruleKey(rule), key) ? index : -1).filter((index) => index >= 0);
    if (matches.length !== 1) throw new Error('That hostname was not found as a unique ingress rule.');
    rules.splice(matches[0], 1);
    const desired = Manager.tunnelConfig({ ...config, ingress: rules });
    api.call('PUT', base + '/configurations', { config: desired });
    if (key[0]) this._cleanupTunnelDns(api, cfg, tunnelId, key[0]);
    storage.withDb(this.dbPath, (db) => db.execute('DELETE FROM cf_tunnel_links WHERE tunnel_id=? AND hostname=? AND path=?', [tunnelId, ...key]));
    return this.getTunnel(tunnelId);
  }
  deleteTunnel(body) {
    const tunnelId = Manager.tunnelId(body.tunnel_id);
    const [cfg, api] = this._tunnelApi();
    if (tunnelId === cfg.tunnel_id) throw new Error('The HomeScan tunnel cannot be deleted from the dashboard.');
    const base = `/accounts/${cfg.account_id}/cfd_tunnel/${tunnelId}`;
    const tunnel = api.call('GET', base) || {};
    if (tunnel.config_src !== 'cloudflare') throw new Error('Locally managed tunnels must be deleted in their local configuration.');
    let ingress = [];
    try { ingress = ((api.call('GET', base + '/configurations') || {}).config || {}).ingress || []; }
    catch (exc) { if (!(exc instanceof CloudflareError)) throw exc; }
    api.call('DELETE', base);
    for (const name of ingress.map((rule) => rule.hostname).filter(Boolean)) this._cleanupTunnelDns(api, cfg, tunnelId, name);
    storage.withDb(this.dbPath, (db) => db.execute('DELETE FROM cf_tunnel_links WHERE tunnel_id=?', [tunnelId]));
    return { ok: true };
  }
  _linkStatus(link, state, message = '', ip = null) {
    storage.withDb(this.dbPath, (db) => db.execute('UPDATE cf_tunnel_links SET state=?,message=?,synced_ip=?,last_checked=? WHERE id=?', [state, message, ip, storage.now(), link.id]));
  }
  reconcileTunnelLinks(api, cfg, links, devices) {
    const ids = [...new Set(links.map((link) => link.tunnel_id))].sort();
    for (const tunnelId of ids) {
      const group = links.filter((link) => link.tunnel_id === tunnelId);
      try {
        const apiPath = `/accounts/${cfg.account_id}/cfd_tunnel/${tunnelId}/configurations`;
        const response = api.call('GET', apiPath) || {};
        const config = response.config || {};
        const rules = config.ingress || [];
        let changed = false;
        for (const link of group) {
          const device = devices.get(link.device_id);
          if (!device || !device.address_current) { this._linkStatus(link, 'waiting', 'Waiting for this MAC to have a confirmed IP assignment.'); continue; }
          const matches = rules.filter((rule) => sameJson(Manager.ruleKey(rule), [link.hostname, link.path]));
          if (matches.length !== 1) { this._linkStatus(link, 'error', 'The linked ingress rule is missing or no longer unique.'); continue; }
          const ip = privateIp(device.ip);
          const desired = Manager.serviceWithIp(matches[0].service, ip);
          if (matches[0].service !== desired) { matches[0].service = desired; changed = true; }
          this._linkStatus(link, 'synced', '', ip);
        }
        if (changed) api.call('PUT', apiPath, { config: { ...config, ingress: rules } });
      } catch (exc) {
        const message = exc instanceof CloudflareError || exc instanceof Error && exc.name === 'Error' ? String(exc.message) : 'Tunnel link sync could not finish. Retrying automatically.';
        if (exc instanceof CloudflareError || exc instanceof Error) applog.error('tunnel link sync error', { source: 'cloudflare', detail: String(exc.message || exc) });
        else applog.exception('tunnel link sync failed', { source: 'cloudflare', exc });
        for (const link of group) this._linkStatus(link, 'error', exc instanceof CloudflareError || (exc instanceof Error && !(exc instanceof TypeError)) ? message : 'Tunnel link sync could not finish. Retrying automatically.');
      }
    }
  }
  save(body) {
    const did = String(body.device_id || '');
    storage.withDb(this.dbPath, (db) => {
      const device = db.execute('SELECT * FROM devices WHERE device_id=?', [did]).fetchone();
      if (!device || !device.mac || !did.startsWith('mac:')) throw new Error('A known MAC address is required for Cloudflare sync.');
      const planned = [];
      for (const kind of ['local', 'tunnel']) {
        const item = body[kind] || {};
        if (typeof item !== 'object' || typeof item.enabled !== 'boolean') throw new Error('Invalid Cloudflare settings.');
        const old = db.execute('SELECT * FROM cf_routes WHERE device_id=? AND kind=?', [did, kind]).fetchone();
        const suffix = this.suffix();
        const name = item.enabled ? hostname(item.hostname, suffix, kind) : (old ? old.hostname : '');
        const protocol = item.protocol || 'http';
        if (!['http', 'https'].includes(protocol)) throw new Error('Choose HTTP or HTTPS for the origin.');
        const port = Number(item.port ?? 80);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be between 1 and 65535.');
        if (item.enabled) privateIp(device.ip);
        planned.push([old ? old.id : crypto.randomUUID().replace(/-/g, ''), did, kind, name, item.enabled ? 1 : 0, protocol, port]);
      }
      const names = planned.filter((row) => row[4]).map((row) => row[3]);
      if (new Set(names).size !== names.length) throw new Error('Local DNS and a tunnel need different hostnames.');
      for (const name of names) {
        if (db.execute('SELECT 1 FROM cf_routes WHERE hostname=? AND enabled=1 AND device_id<>?', [name, did]).fetchone()) {
          throw new Error('That hostname is already assigned to another device.');
        }
      }
      db.execute('UPDATE cf_routes SET enabled=0 WHERE device_id=?', [did]);
      for (const values of planned) {
        db.execute(`INSERT INTO cf_routes(id,device_id,kind,hostname,enabled,protocol,port,state)
          VALUES(?,?,?,?,?,?,?,'pending') ON CONFLICT(id) DO UPDATE SET
          hostname=excluded.hostname,enabled=excluded.enabled,protocol=excluded.protocol,
          port=excluded.port,state='pending',message=''`, values);
      }
    });
    this.wake.set();
  }
  status(route, state, message = '', ip = null) {
    storage.withDb(this.dbPath, (db) => db.execute('UPDATE cf_routes SET state=?,message=?,synced_ip=?,last_checked=? WHERE id=?', [state, message, ip, storage.now(), route.id]));
  }
  resources(routeId) {
    return storage.withDb(this.dbPath, (db) => db.execute('SELECT * FROM cf_resources WHERE route_id=?', [routeId]).fetchall());
  }
  zoneFor(api, cfg, name) {
    name = String(name || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!name.includes('.')) throw new CloudflareError('Hostname is missing a Cloudflare zone.');
    const account = cfg.account_id;
    const zoneName = String(cfg.zone_name || '').trim().toLowerCase().replace(/\.+$/, '');
    if (cfg.zone_id && zoneName && (name === zoneName || name.endsWith('.' + zoneName))) return { id: cfg.zone_id, name: zoneName, account: { id: account } };
    const labels = name.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join('.');
      let rows = [];
      try { rows = api.call('GET', '/zones?' + new URLSearchParams({ name: candidate, status: 'active', per_page: '5' })) || []; }
      catch (exc) { if (exc instanceof CloudflareError) continue; throw exc; }
      const zone = rows.find((item) => item.name === candidate && (item.account || {}).id === account);
      if (zone) return zone;
    }
    throw new CloudflareError('No Cloudflare zone accessible to this token covers ' + name + '.');
  }
  dnsRecords(api, cfg, name, zone = null) {
    zone = zone || this.zoneFor(api, cfg, name);
    return api.call('GET', `/zones/${zone.id}/dns_records?` + new URLSearchParams({ name, per_page: '100' })) || [];
  }
  ensureHaDns(ip, hostnameValue = null) {
    ip = privateIp(ip);
    let cfg = {};
    try { cfg = this.config(); } catch { cfg = {}; }
    const suffix = this.suffix();
    const zoneName = String(cfg.zone_name || '').trim().toLowerCase().replace(/\.+$/, '');
    let name = String(hostnameValue || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!name) name = this.clusterHostname();
    if (!name) throw new Error('Set HA_HOSTNAME or a base domain before updating cluster DNS.');
    const roots = [...new Set([suffix, zoneName].filter(Boolean))];
    if (roots.length && !roots.some((root) => name === root || name.endsWith('.' + root))) {
      throw new Error('HA hostname must be under ' + roots.join(' or '));
    }
    if (!cfg.api_token || !cfg.account_id) throw new Error('Connect Cloudflare before HA failover can update DNS.');
    const api = this.apiFactory(cfg.api_token);
    const zone = this.zoneFor(api, cfg, name);
    const matches = this.dnsRecords(api, cfg, name, zone);
    if (matches.some((record) => record.comment !== 'homescan:ha')) throw new CloudflareError(name + ' is owned by another DNS record. Remove it or choose another HA hostname.');
    const desired = { type: 'A', name, content: ip, proxied: false, ttl: 60, comment: 'homescan:ha' };
    if (matches.length) {
      const record = matches[0];
      if (Object.entries(desired).some(([key, value]) => record[key] !== value)) api.call('PUT', `/zones/${zone.id}/dns_records/${record.id}`, desired);
    } else api.call('POST', `/zones/${zone.id}/dns_records`, desired);
    return { hostname: name, ip };
  }
  tunnelRule(api, cfg, name, service, routeId = null) {
    if (!cfg.tunnel_id) throw new CloudflareError('Run Cloudflare setup with tunnel support enabled.');
    const apiPath = `/accounts/${cfg.account_id}/cfd_tunnel/${cfg.tunnel_id}/configurations`;
    const response = api.call('GET', apiPath) || {};
    const config = response.config || { ingress: [{ service: 'http_status:404' }] };
    const rules = config.ingress || [{ service: 'http_status:404' }];
    const owned = storage.withDb(this.dbPath, (db) => db.execute('SELECT 1 FROM cf_resources WHERE hostname=? AND kind=?', [name, 'tunnel']).fetchone());
    const matching = rules.filter((rule) => rule.hostname === name);
    if (matching.length && !owned) throw new CloudflareError('A tunnel rule already uses this hostname outside HomeScan.');
    if (routeId) storage.withDb(this.dbPath, (db) => db.execute('INSERT OR IGNORE INTO cf_resources VALUES(?,?,?,NULL)', [routeId, name, 'tunnel']));
    let desired;
    if (service == null) desired = rules.filter((rule) => rule.hostname !== name);
    else if (matching.length) desired = rules.map((rule) => rule.hostname === name ? { ...rule, service } : rule);
    else {
      desired = [...rules];
      const position = desired.findIndex((rule) => !rule.hostname && !rule.path);
      desired.splice(position < 0 ? desired.length : position, 0, { hostname: name, service });
    }
    if (!desired.length || desired[desired.length - 1].hostname || desired[desired.length - 1].path) desired.push({ service: 'http_status:404' });
    if (!sameJson(desired, rules)) api.call('PUT', apiPath, { config: { ...config, ingress: desired } });
  }
  cleanup(api, cfg, resource) {
    const name = resource.hostname;
    const routeId = resource.route_id;
    let zone = null;
    try { zone = this.zoneFor(api, cfg, name); } catch (exc) { if (!(exc instanceof CloudflareError)) throw exc; }
    if (zone) {
      for (const record of this.dnsRecords(api, cfg, name, zone)) {
        if (record.comment === 'homescan:' + routeId) api.call('DELETE', `/zones/${zone.id}/dns_records/${record.id}`);
      }
    }
    if (resource.kind === 'tunnel') this.tunnelRule(api, cfg, name, null);
    storage.withDb(this.dbPath, (db) => db.execute('DELETE FROM cf_resources WHERE route_id=? AND hostname=?', [routeId, name]));
  }
  reconcile(api, cfg, route, device) {
    const resources = this.resources(route.id);
    if (!route.enabled) {
      for (const resource of resources) this.cleanup(api, cfg, resource);
      this.status(route, 'disabled');
      return;
    }
    if (!device || !device.address_current) {
      for (const resource of resources) this.cleanup(api, cfg, resource);
      this.status(route, 'waiting', 'Waiting for this MAC to have a confirmed IP assignment.');
      return;
    }
    const ip = privateIp(device.ip);
    let dnsSubnet = '';
    try { dnsSubnet = parseDnsSubnet(cfg.dns_subnet); } catch { dnsSubnet = ''; }
    if (dnsSubnet && !ipInCidr(ip, dnsSubnet)) {
      for (const resource of resources) this.cleanup(api, cfg, resource);
      this.status(route, 'waiting', `Waiting for an IP in ${dnsSubnet} (now ${ip}).`);
      return;
    }
    const name = route.hostname;
    for (const resource of resources) if (resource.hostname !== name || resource.kind !== route.kind) this.cleanup(api, cfg, resource);
    const zone = this.zoneFor(api, cfg, name);
    const matches = this.dnsRecords(api, cfg, name, zone);
    const mine = 'homescan:' + route.id;
    let desired;
    if (route.kind === 'local') desired = { type: 'A', name, content: ip, proxied: false, ttl: 60, comment: mine };
    else {
      this.tunnelRule(api, cfg, name, `${route.protocol}://${ip}:${route.port}`, route.id);
      desired = { type: 'CNAME', name, content: cfg.tunnel_id + '.cfargotunnel.com', proxied: true, ttl: 1, comment: mine };
    }
    // Device routes own this hostname: keep one matching A/CNAME, replace or remove the rest.
    const sameType = matches.filter((record) => record.type === desired.type);
    const other = matches.filter((record) => record.type !== desired.type);
    for (const record of other) api.call('DELETE', `/zones/${zone.id}/dns_records/${record.id}`);
    for (const record of sameType.slice(1)) api.call('DELETE', `/zones/${zone.id}/dns_records/${record.id}`);
    storage.withDb(this.dbPath, (db) => db.execute('INSERT OR IGNORE INTO cf_resources VALUES(?,?,?,NULL)', [route.id, name, route.kind]));
    let record = sameType[0] || null;
    if (record) {
      if (Object.entries(desired).some(([key, value]) => record[key] !== value)) record = api.call('PUT', `/zones/${zone.id}/dns_records/${record.id}`, desired);
    } else record = api.call('POST', `/zones/${zone.id}/dns_records`, desired);
    storage.withDb(this.dbPath, (db) => db.execute('UPDATE cf_resources SET record_id=? WHERE route_id=? AND hostname=?', [record.id, route.id, name]));
    this.status(route, 'synced', '', ip);
  }
  syncOnce() {
    const [routes, links] = storage.withDb(this.dbPath, (db) => [
      db.execute('SELECT * FROM cf_routes').fetchall(),
      db.execute('SELECT * FROM cf_tunnel_links').fetchall(),
    ]);
    if (!routes.length && !links.length) return;
    let cfg = {};
    try { cfg = this.config(); } catch { cfg = {}; }
    const devices = new Map(storage.inventory(this.dbPath).devices.map((device) => [device.device_id, device]));
    const api = cfg.api_token ? this.apiFactory(cfg.api_token) : null;
    if (links.length) {
      if (api) this.reconcileTunnelLinks(api, cfg, links, devices);
      else for (const link of links) this._linkStatus(link, 'pending', 'Connect Cloudflare to sync this tunnel link.');
    }
    for (const route of routes) {
      if (!api) {
        this.status(route, route.enabled || this.resources(route.id).length ? 'pending' : 'disabled', route.enabled ? 'Connect Cloudflare to apply these settings.' : '');
        continue;
      }
      try { this.reconcile(api, cfg, route, devices.get(route.device_id)); }
      catch (exc) {
        if (exc instanceof CloudflareError || exc instanceof Error && exc.constructor === Error) {
          applog.error('route sync error', { source: 'cloudflare', detail: `${route.id} ${route.hostname}: ${exc.message}` });
          this.status(route, 'error', String(exc.message));
        } else {
          applog.exception('route sync failed', { source: 'cloudflare', exc });
          this.status(route, 'error', 'Sync could not finish. Retrying automatically.');
        }
      }
    }
  }
  connect(body) {
    const result = connectCloudflare(body, this.configPath, this.apiFactory, TOKEN_FILE);
    this.syncSharedSettings();
    this.wake.set();
    return result;
  }
  async run() {
    while (true) {
      await this.wake.wait(60_000);
      try {
        this.syncOnce();
        applog.expire();
        if (this.onUpdate) this.onUpdate();
      } catch (exc) {
        applog.exception('cloudflare sync loop failed', { source: 'cloudflare', exc });
      }
    }
  }
}

export function connectCloudflare(options, configPath = CONFIG, apiFactory = (token) => new API(token), tokenFile = TOKEN_FILE) {
  let token = String(options.api_token || '').trim();
  const old = readConfig(configPath);
  if (!token) token = String(old.api_token || '').trim();
  if (token.length < 20) throw new Error('Enter a Cloudflare API token.');
  const wantTunnel = options.tunnel ?? true;
  if (typeof wantTunnel !== 'boolean') throw new Error('Invalid tunnel option.');
  let suffix = '';
  if (options.suffix) suffix = normalizeSuffix(options.suffix);
  else if (old.suffix) suffix = normalizeSuffix(old.suffix);
  const api = apiFactory(token);
  let zone = null;
  const preferred = String(options.zone_name || old.zone_name || '').trim().toLowerCase().replace(/\.+$/, '');
  const candidates = [];
  if (preferred) candidates.push(preferred);
  if (suffix) candidates.push(...zoneCandidatesForSuffix(suffix));
  const seen = new Set();
  for (const name of candidates) {
    if (seen.has(name)) continue;
    seen.add(name);
    const zones = api.call('GET', '/zones?' + new URLSearchParams({ name, status: 'active' })) || [];
    if (zones.length) { zone = zones[0]; break; }
  }
  if (!zone) {
    let zones = api.call('GET', '/zones?' + new URLSearchParams({ status: 'active', per_page: '100' })) || [];
    if (zones.length === 1) zone = zones[0];
    else if (preferred) zone = zones.find((item) => item.name === preferred) || null;
    else if (zones.length) {
      zones = [...zones].sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
      zone = zones[0];
    }
  }
  if (!zone) throw new CloudflareError('The token cannot access an active Cloudflare zone. Grant Zone Read and DNS Edit for your domain.');
  if (old.zone_id && old.zone_id !== zone.id) throw new CloudflareError('Zone changed. Keep the original zone while HomeScan manages existing records.');
  if (!suffix) suffix = normalizeSuffix(zone.name);
  const cfg = { ...old, api_token: token, zone_id: zone.id, zone_name: zone.name, account_id: zone.account.id, suffix };
  if (!cfg.installation_id) cfg.installation_id = crypto.randomUUID().replace(/-/g, '');
  delete cfg.d1_database_id;
  atomicJson(configPath, cfg);
  if (wantTunnel) {
    const base = `/accounts/${cfg.account_id}/cfd_tunnel`;
    if (!cfg.tunnel_id) {
      const name = 'homescan-' + cfg.installation_id.slice(0, 12);
      const existing = api.call('GET', base + '?' + new URLSearchParams({ name, is_deleted: 'false' })) || [];
      const exact = existing.filter((item) => item.name === name);
      const tunnel = exact[0] || api.call('POST', base, { name, config_src: 'cloudflare' });
      cfg.tunnel_id = tunnel.id;
      atomicJson(configPath, cfg);
      if (!exact.length) api.call('PUT', `${base}/${tunnel.id}/configurations`, { config: { ingress: [{ service: 'http_status:404' }] } });
    }
    const tunnelToken = api.call('GET', `${base}/${cfg.tunnel_id}/token`);
    fs.mkdirSync(path.dirname(tokenFile), { recursive: true });
    const temp = tokenFile + '.tmp';
    fs.writeFileSync(temp, String(tunnelToken), { mode: 0o644 });
    fs.renameSync(temp, tokenFile);
  }
  return { configured: true, zone: cfg.zone_name, tunnel_configured: Boolean(cfg.tunnel_id), database_shared: false };
}

export function setup(options) { return connectCloudflare(options); }

if (process.argv[1] && process.argv[1].endsWith('cloudflare.js')) {
  const chunks = [];
  process.stdin.on('data', (chunk) => chunks.push(chunk));
  process.stdin.on('end', () => {
    try {
      if (process.argv.slice(2).join(' ') !== 'setup') throw new Error('Use the local Cloudflare setup script.');
      process.stdout.write(JSON.stringify(setup(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'))) + '\n');
    } catch (exc) {
      const message = exc instanceof CloudflareError || exc instanceof Error ? exc.message : 'Cloudflare setup failed. Check connectivity and token permissions.';
      process.stdout.write(JSON.stringify({ error: message }) + '\n');
      process.exitCode = 1;
    }
  });
}
