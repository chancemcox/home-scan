import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as applog from './lib/applog.js';
import * as auth from './lib/auth.js';
import { CloudflareError, Manager, ipInCidr, parseScanNetworks } from './lib/cloudflare.js';
import { Cluster } from './lib/ha.js';
import { ClusterState } from './lib/clusterState.js';
import * as deco from './lib/deco.js';
import * as storage from './lib/storage.js';
import { Hub, handshakeHeaders } from './lib/ws.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DB = process.env.DB_PATH || '/data/homescan.db';
let MODE = process.env.SCAN_MODE || 'nmap';
let TOKEN = process.env.INGEST_TOKEN || '';
let NETWORK = process.env.SCAN_NETWORK || '192.168.1.0/24';
const INTERVAL = 60;
const SKIPPED = ['lo', 'docker', 'veth', 'br-', 'hassio', 'cni', 'flannel', 'virbr', 'zt', 'tailscale', 'podman', 'nerdctl'];

const dashboard = new Hub();
let cloudflare = new Manager(DB);
let cluster = new Cluster(cloudflare, { onChange: () => publish() });

function routeAddress(hexIp) {
  const raw = Buffer.from(hexIp, 'hex');
  return [...raw].reverse().join('.');
}

function prefixLength(mask) {
  if (!mask.includes('.')) return Number(mask);
  const parts = mask.split('.').map(Number);
  let bits = 0;
  let rest = (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
  while (rest & 0x80000000) { bits += 1; rest = (rest << 1) >>> 0; }
  return bits;
}

function parseNetwork(cidr) {
  const [addr, prefixRaw] = cidr.split('/');
  const prefix = Number(prefixRaw);
  const parts = addr.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => part > 255) || !Number.isInteger(prefix)) return null;
  let n = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  n = (n & mask) >>> 0;
  const first = n >>> 24;
  const second = (n >>> 16) & 255;
  return {
    cidr: [first, second, (n >>> 8) & 255, n & 255].join('.') + '/' + prefix,
    size: 2 ** (32 - prefix),
    prefix,
    private: first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168),
    loopback: first === 127,
    linkLocal: first === 169 && second === 254,
  };
}

function scanCidrsFromRoute(net) {
  if (!net || !net.private || net.loopback || net.linkLocal) return [];
  // Ordinary LAN prefixes only. Skip /31–/32 host routes — they multiply into
  // dozens of nmap runs and never replace a proper fallback /24 sweep.
  if (net.prefix >= 20 && net.prefix <= 30 && net.size <= 4096) return [net.cidr];
  return [];
}

export function discoverScanNetworks(routeText = null) {
  if (routeText == null) {
    try { routeText = fs.readFileSync('/proc/net/route', 'utf8'); }
    catch { return []; }
  }
  const found = [];
  for (const line of routeText.split(/\r?\n/).slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 8 || cols[1] === '00000000') continue;
    const iface = cols[0].toLowerCase();
    if (SKIPPED.some((prefix) => iface.startsWith(prefix))) continue;
    let net;
    try { net = parseNetwork(`${routeAddress(cols[1])}/${prefixLength(routeAddress(cols[7]))}`); }
    catch { continue; }
    const targets = scanCidrsFromRoute(net);
    for (const cidr of targets) if (!found.includes(cidr)) found.push(cidr);
  }
  return found;
}

export function configuredScanNetworks() {
  try { return parseScanNetworks(NETWORK); }
  catch { return []; }
}

export function scanNetworkList() {
  const found = discoverScanNetworks();
  const fallback = configuredScanNetworks();
  // Configured subnets first so a lossy discovered route (e.g. 192.168.86.0/24)
  // cannot delay the primary LAN sweep for minutes at a time.
  const out = [];
  for (const cidr of [...fallback, ...found]) if (cidr && !out.includes(cidr)) out.push(cidr);
  return out;
}

function mergeScanNetwork(...parts) {
  const out = [];
  for (const part of parts) {
    let nets = [];
    try { nets = parseScanNetworks(String(part || '').trim()); } catch { continue; }
    for (const cidr of nets) if (cidr && !out.includes(cidr)) out.push(cidr);
  }
  return out.join(',');
}

function applySharedRuntime(cfg) {
  if (['nmap', 'agent'].includes(cfg.scan_mode)) {
    MODE = cfg.scan_mode;
    process.env.SCAN_MODE = MODE;
  }
  if (cfg.scan_network) {
    // Union addon options with stored settings so a stale settings value cannot drop subnets.
    NETWORK = mergeScanNetwork(NETWORK, cfg.scan_network) || NETWORK;
    process.env.SCAN_NETWORK = NETWORK;
  }
}

function buildClusterState(cfg, nodeId) {
  const url = (cfg.cluster_worker_url || process.env.CLUSTER_WORKER_URL || '').trim();
  const secret = (cfg.cluster_secret || process.env.CLUSTER_SECRET || '').trim();
  if (!url || !secret) return null;
  return new ClusterState(url, secret, nodeId || crypto.randomBytes(16).toString('hex'));
}

function applyDatabaseBackend(cfg = null) {
  if (!cfg) { try { cfg = cloudflare.config(); } catch { cfg = {}; } }
  const doUrl = (cfg.cluster_worker_url || process.env.CLUSTER_WORKER_URL || '').trim();
  const doSecret = (cfg.cluster_secret || process.env.CLUSTER_SECRET || '').trim();
  if (doUrl && doSecret) {
    try { storage.useDo(doUrl, doSecret); storage.init(DB); return true; }
    catch (exc) { applog.error('Durable Object SQL unavailable, using local SQLite', { source: 'storage', detail: String(exc.message || exc) }); storage.useSqlite(); }
  }
  storage.useSqlite();
  storage.init(DB);
  return false;
}

function devicesPayload() {
  if (!cluster.isLeader()) {
    const shared = cluster.sharedInventory();
    if (shared) {
      try {
        const result = JSON.parse(shared);
        if (result && Array.isArray(result.devices)) {
          result.ha = cluster.publicState();
          result.cloudflare = cloudflare.publicState();
          result.deco = deco.publicState();
          result.networks = scanNetworkList();
          result.configured_networks = configuredScanNetworks();
          return JSON.stringify(result);
        }
      } catch { /* fall through */ }
    }
  }
  const result = storage.inventory(DB);
  const nets = scanNetworkList();
  Object.assign(result, {
    mode: MODE,
    network: MODE === 'nmap' ? nets.join(', ') : 'Home network',
    networks: nets,
    configured_networks: configuredScanNetworks(),
    cloudflare: cloudflare.publicState(),
    deco: deco.publicState(),
    ha: cluster.publicState(),
  });
  return JSON.stringify(result);
}

function publish() {
  const payload = devicesPayload();
  dashboard.broadcast(payload);
  cluster.publishInventory(payload);
}

export function init() {
  auth.init();
  applog.configure(DB);
  cloudflare = new Manager(DB, undefined, undefined, () => publish());
  let cfg = {};
  try { cfg = cloudflare.config(); } catch { cfg = {}; }
  applyDatabaseBackend(cfg);
  cloudflare.init();
  if (storage.backendState().shared) {
    storage.migrateLocalToRemote(DB);
    cloudflare.syncSharedSettings();
  }
  try { cfg = cloudflare.config(); } catch { cfg = cfg || {}; }
  applySharedRuntime(cfg);
  const nodeId = cfg.installation_id || null;
  const clusterArgs = { nodeId, clusterState: buildClusterState(cfg, nodeId), onChange: () => publish() };
  if (cfg.ha_hostname) clusterArgs.hostname = cfg.ha_hostname;
  if (/^\d+$/.test(String(cfg.ha_port || ''))) clusterArgs.port = Number(cfg.ha_port);
  if (cfg.ha_enabled != null && cfg.ha_enabled !== '') clusterArgs.enabled = !['0', 'false', 'no', 'off'].includes(String(cfg.ha_enabled).toLowerCase());
  cluster = new Cluster(cloudflare, clusterArgs);
  applog.info('HomeScan started', { source: 'app', detail: JSON.stringify({ push: applog.PUSH, mode: MODE, database: storage.backendState() }) });
}

export function parseNmapHosts(xml) {
  const hosts = [];
  for (const block of String(xml || '').split(/<host(?:\s|>)/).slice(1)) {
    if (!/state="up"/.test(block)) continue;
    const addresses = {};
    for (const match of block.matchAll(/<address([^>]*)>/g)) {
      const addr = /addr="([^"]+)"/i.exec(match[1]);
      const type = /addrtype="([^"]+)"/i.exec(match[1]);
      if (addr && type) addresses[String(type[1]).toLowerCase()] = addr[1];
    }
    if (!addresses.ipv4) continue;
    const names = [...block.matchAll(/<hostname[^>]*name="([^"]*)"/gi)]
      .map((match) => normalizeHostname(match[1]))
      .filter(Boolean);
    hosts.push({
      ip: addresses.ipv4,
      mac: storage.macAddress(addresses.mac || ''),
      hostname: names[0] || '',
    });
  }
  return hosts;
}

export function normalizeHostname(value) {
  const name = String(value || '').trim().replace(/\.+$/, '');
  if (!name || /^[\d.]+$/.test(name)) return '';
  return name.slice(0, 255);
}

export async function resolveHostnames(hosts, lookup = dns.reverse, timeoutMs = 1500) {
  const missing = hosts.filter((host) => host && host.ip && !host.hostname);
  const queue = 16;
  for (let i = 0; i < missing.length; i += queue) {
    const batch = missing.slice(i, i + queue);
    await Promise.all(batch.map(async (host) => {
      try {
        const names = await Promise.race([
          lookup(host.ip),
          new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
        ]);
        const picked = Array.isArray(names)
          ? names.map((name) => normalizeHostname(name)).find(Boolean)
          : normalizeHostname(names);
        if (picked) host.hostname = picked;
      } catch { /* no PTR / timed out */ }
    }));
  }
  return hosts;
}

export function readArpTable(text = null) {
  if (text == null) {
    try { text = fs.readFileSync('/proc/net/arp', 'utf8'); }
    catch { return new Map(); }
  }
  const map = new Map();
  for (const line of String(text || '').split(/\r?\n/).slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const [ip, , flags, mac] = cols;
    if (!ip || flags === '0x0' || !mac || mac === '00:00:00:00:00:00') continue;
    const normalized = storage.macAddress(mac);
    if (normalized) map.set(ip, normalized);
  }
  return map;
}

export function attachMacs(hosts, arp = null) {
  const table = arp || readArpTable();
  for (const host of hosts) {
    if (host.mac) continue;
    const mac = table.get(host.ip);
    if (mac) host.mac = mac;
  }
  return hosts;
}

function cidrIsOnLink(cidr) {
  for (const addrs of Object.values(os.networkInterfaces() || {})) {
    for (const addr of addrs || []) {
      if ((addr.family !== 'IPv4' && addr.family !== 4) || addr.internal) continue;
      try { if (ipInCidr(addr.address, cidr)) return true; }
      catch { /* ignore bad interface data */ }
    }
  }
  return false;
}

function nmapFailureMessage(stderr, code, signal) {
  const lines = String(stderr || '').split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !/RTTVAR/i.test(line));
  if (lines.length) return lines.join('\n').slice(0, 500);
  if (signal) return `nmap killed (${signal})`;
  return `nmap exited ${code}`;
}

function nmapSubnet(cidr) {
  return new Promise((resolve, reject) => {
    // LAN ping sweep with reverse DNS enabled so device names can populate.
    // On-link subnets use ARP ping (-PR) so nmap returns MAC addresses; routed subnets cannot.
    const onLink = cidrIsOnLink(cidr);
    const args = ['-sn'];
    if (onLink) args.push('-PR');
    args.push(
      '--max-retries', '2',
      '--host-timeout', '3s',
      '--max-rtt-timeout', '800ms',
      '--initial-rtt-timeout', '200ms',
      '--min-parallelism', '32',
      '-oX', '-',
      String(cidr),
    );
    const child = spawn('nmap', args, { timeout: 120_000, killSignal: 'SIGKILL' });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      const hosts = attachMacs(parseNmapHosts(stdout));
      const withMac = hosts.filter((host) => host.mac).length;
      const withName = hosts.filter((host) => host.hostname).length;
      if (code === 0 || hosts.length) {
        if (code !== 0) {
          applog.warning(`nmap ${cidr} ended early`, {
            source: 'scanner',
            detail: nmapFailureMessage(stderr, code, signal),
          });
        }
        applog.info(`nmap ${cidr} found ${hosts.length} host${hosts.length === 1 ? '' : 's'} (${withMac} with MAC, ${withName} named)`, {
          source: 'scanner',
          detail: onLink ? 'on-link ARP' : 'routed',
        });
        resolve(hosts);
        return;
      }
      // Lossy or routed targets often exit non-zero with only RTTVAR noise and no hosts.
      // Keep the scan loop healthy so other subnets can still refresh inventory.
      applog.warning(`nmap ${cidr} found no hosts`, {
        source: 'scanner',
        detail: nmapFailureMessage(stderr, code, signal),
      });
      resolve([]);
    });
  });
}

async function scanner() {
  while (true) {
    const tick = Date.now();
    if (!cluster.acceptsScans()) { await new Promise((resolve) => setTimeout(resolve, Math.max(1000, INTERVAL * 500))); continue; }
    const started = storage.now();
    const hosts = [];
    const errors = [];
    const nets = scanNetworkList();
    for (const net of nets) {
      applog.info(`nmap scanning ${net}`, { source: 'scanner' });
      try { hosts.push(...await nmapSubnet(net)); }
      catch (exc) {
        applog.exception('nmap scan failed for ' + net, { source: 'scanner', exc });
        errors.push(`${net}: ${exc.message || exc}`);
      }
    }
    try {
      attachMacs(hosts);
      await resolveHostnames(hosts);
      const withMac = hosts.filter((host) => host.mac).length;
      const withName = hosts.filter((host) => host.hostname).length;
      storage.recordBatches(DB, [{ source: 'network', hosts, started, error: hosts.length || !errors.length ? null : errors.join('; ').slice(0, 1000) }]);
      cloudflare.wake.set();
      publish();
      writeShareStatus();
      applog.info(`scan cycle recorded ${hosts.length} host${hosts.length === 1 ? '' : 's'} across ${nets.length} network${nets.length === 1 ? '' : 's'} (${withMac} with MAC, ${withName} named)`, {
        source: 'scanner',
        detail: errors.length ? errors.join('; ').slice(0, 500) : '',
      });
    } catch (exc) { applog.exception('scan record failed', { source: 'scanner', exc }); }
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, INTERVAL * 1000 - (Date.now() - tick))));
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const size = Number(req.headers['content-length'] || 0);
    if (!(size > 0 && size <= 1048576)) { reject(Object.assign(new Error('Invalid request size'), { user: true })); return; }
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Expected a JSON object');
        resolve(body);
      } catch (exc) { reject(Object.assign(exc instanceof Error ? exc : new Error('Expected a JSON object'), { user: true })); }
    });
    req.on('error', reject);
  });
}

function ingressBase(req) {
  if (process.env.HASS_INGRESS !== '1') return '';
  const base = String(req.headers['x-ingress-path'] || '').trim().replace(/\/$/, '');
  if (!base.startsWith('/') || base.startsWith('//') || /["'<>&\n\r ]/.test(base)) return '';
  return base;
}

function ingressPeerAllowed(peer) {
  const normalized = String(peer || '').replace(/^::ffff:/, '');
  if (process.env.HASS_INGRESS_TRUST_LOOPBACK === '1' && (normalized === '127.0.0.1' || normalized === '::1')) return true;
  // Supervisor / ingress proxy addresses live on the hassio docker networks (172.30.32.0/23 historically,
  // but peers such as 172.30.33.0 appear on current HA OS builds).
  const parts = normalized.split('.').map(Number);
  if (parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) && parts[0] === 172 && parts[1] === 30) return true;
  return normalized === '172.30.32.2';
}

function ingressUser(req) {
  const base = ingressBase(req);
  if (!base) return null;
  const peer = req.socket.remoteAddress || '';
  if (!ingressPeerAllowed(peer)) {
    applog.warning('ingress request ignored', { source: 'auth', detail: `peer ${String(peer).replace(/^::ffff:/, '')}` });
    return null;
  }
  return String(req.headers['x-remote-user-name'] || req.headers['x-remote-user-display-name'] || req.headers['x-remote-user-id'] || 'homeassistant').slice(0, 80);
}

function currentUser(req) {
  return ingressUser(req) || auth.sessionUser(auth.parseCookie(req.headers.cookie || ''));
}

function sameOrigin(req) {
  if (ingressUser(req)) return true;
  const origin = req.headers.origin || '';
  let parsed;
  try { parsed = new URL(origin); } catch { return false; }
  const site = req.headers['sec-fetch-site'] || 'same-origin';
  return ['http:', 'https:'].includes(parsed.protocol)
    && parsed.host === (req.headers.host || '')
    && !['cross-site', 'same-site'].includes(site)
    && String(req.headers['content-type'] || '').split(';')[0] === 'application/json';
}

function send(req, res, code, body, contentType = 'application/json; charset=utf-8', headers = {}) {
  const data = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const framed = ingressBase(req) ? 'frame-ancestors *' : "frame-ancestors 'none'";
  const extra = { ...headers };
  if (!ingressBase(req)) extra['X-Frame-Options'] = 'DENY';
  res.writeHead(code, {
    'Content-Type': contentType,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': `default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; ${framed}; base-uri 'none'`,
    'Content-Length': data.length,
    ...extra,
  });
  res.end(data);
}

function page(req, res, name, contentType) {
  let text = fs.readFileSync(path.join(ROOT, name), 'utf8');
  const base = ingressBase(req);
  if (base && name.endsWith('.html')) {
    text = text.replace('<head>', `<head><meta name="homescan-base" content="${base}">`, 1);
    text = text.replaceAll('href="/', `href="${base}/`).replaceAll('src="/', `src="${base}/`);
  }
  send(req, res, 200, text, contentType);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
  res.end();
}

async function handlePost(req, res, pathname) {
  if (pathname === '/api/login') {
    try {
      const body = await readBody(req);
      const result = auth.login(body.username, body.password, Boolean(body.remember));
      send(req, res, 200, JSON.stringify({ ok: true, username: result.username }), 'application/json; charset=utf-8', {
        'Set-Cookie': auth.cookieHeader(result.token, result.remember, result.max_age),
      });
    } catch (exc) {
      if (exc instanceof Error && exc.user !== false) {
        applog.warning('login rejected', { source: 'auth', detail: exc.message });
        send(req, res, 401, JSON.stringify({ error: exc.message }));
      } else {
        applog.exception('login failed', { source: 'auth', exc });
        send(req, res, 500, '{"error":"Sign in failed."}');
      }
    }
    return;
  }
  if (pathname === '/api/logout') {
    auth.logout(auth.parseCookie(req.headers.cookie || ''));
    send(req, res, 200, '{"ok":true}', 'application/json; charset=utf-8', { 'Set-Cookie': auth.clearCookieHeader() });
    return;
  }
  const settings = ['/api/cloudflare/settings', '/api/cloudflare/domain', '/api/cloudflare/sync', '/api/cloudflare/connect', '/api/cloudflare/tunnels/update', '/api/cloudflare/tunnels/link', '/api/cloudflare/tunnels/create-route', '/api/cloudflare/tunnels/delete', '/api/cloudflare/tunnels/delete-hostname', '/api/deco/settings', '/api/scan/networks'];
  if (settings.includes(pathname)) {
    if (!sameOrigin(req)) { send(req, res, 403, '{"error":"Use the HomeScan dashboard to change settings."}'); return; }
    if (!currentUser(req)) { send(req, res, 401, '{"error":"Sign in required."}'); return; }
    try {
      const body = await readBody(req);
      if (pathname === '/api/deco/settings') {
        const state = deco.saveSettings(body);
        publish();
        send(req, res, 200, JSON.stringify({ ok: true, ...state }));
        return;
      }
      if (pathname === '/api/cloudflare/domain') { const result = cloudflare.saveDomain(body); publish(); send(req, res, 200, JSON.stringify(result)); return; }
      if (pathname === '/api/scan/networks') { const result = cloudflare.saveScanNetworks(body); applySharedRuntime(cloudflare.config()); publish(); send(req, res, 200, JSON.stringify(result)); return; }
      if (pathname === '/api/cloudflare/connect') {
        const result = cloudflare.connect(body);
        applyDatabaseBackend(cloudflare.config());
        cloudflare.init();
        if (storage.backendState().shared) { storage.migrateLocalToRemote(DB); cloudflare.syncSharedSettings(); }
        publish();
        send(req, res, 200, JSON.stringify({ ok: true, ...result }));
        return;
      }
      const actions = {
        '/api/cloudflare/tunnels/update': () => cloudflare.updateTunnel(body),
        '/api/cloudflare/tunnels/link': () => cloudflare.saveTunnelLink(body),
        '/api/cloudflare/tunnels/create-route': () => cloudflare.createTunnelRoute(body),
        '/api/cloudflare/tunnels/delete-hostname': () => cloudflare.deleteTunnelHostname(body),
        '/api/cloudflare/tunnels/delete': () => cloudflare.deleteTunnel(body),
      };
      if (actions[pathname]) { const result = actions[pathname](); publish(); send(req, res, 200, JSON.stringify(result)); return; }
      if (pathname.endsWith('/settings')) cloudflare.save(body);
      else cloudflare.wake.set();
      publish();
      send(req, res, 200, '{"ok":true}');
    } catch (exc) {
      if (exc instanceof CloudflareError) {
        applog.error('settings Cloudflare error', { source: 'api', detail: `${pathname}: ${exc.message}` });
        send(req, res, 502, JSON.stringify({ error: exc.message }));
      } else if (exc instanceof Error) {
        applog.warning('settings request rejected', { source: 'api', detail: `${pathname}: ${exc.message}` });
        send(req, res, 400, JSON.stringify({ error: exc.message }));
      } else {
        applog.exception('settings request failed', { source: 'api', exc });
        send(req, res, 500, '{"error":"Request failed."}');
      }
    }
    return;
  }
  if (pathname !== '/api/scan' || MODE !== 'agent') { send(req, res, 404, '{}'); return; }
  const header = req.headers.authorization || '';
  const expected = Buffer.from('Bearer ' + TOKEN);
  const actual = Buffer.from(header);
  if (!TOKEN || TOKEN.length < 32 || expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    send(req, res, 401, '{"error":"Unauthorized"}');
    return;
  }
  if (!cluster.acceptsScans()) {
    send(req, res, 503, JSON.stringify({ error: `This HomeScan node is on standby. Point the scanner at ${cluster.hostname}:${cluster.port}.`, ha: cluster.publicState() }));
    return;
  }
  try {
    const body = await readBody(req);
    let batches = body.sources;
    if (batches == null) batches = [{ source: 'network', hosts: body.hosts, error: body.error }];
    if (!Array.isArray(batches) || batches.length < 1 || batches.length > 8) throw new Error('Invalid sources');
    const cleaned = [];
    for (const batch of batches) {
      if (!batch || typeof batch !== 'object') throw new Error('Invalid sources');
      if (batch.source === 'deco' && batch.error && !(batch.hosts || []).length) continue;
      cleaned.push(batch);
    }
    if (!cleaned.length) throw new Error('Invalid sources');
    storage.recordBatches(DB, cleaned);
    cloudflare.wake.set();
    publish();
    send(req, res, 200, '{"ok":true}');
  } catch (exc) {
    applog.warning('scan ingest rejected', { source: 'api', detail: exc.message || String(exc) });
    send(req, res, 400, JSON.stringify({ error: exc.message || 'Invalid hosts' }));
  }
}

function handleGet(req, res, pathname, query) {
  const user = currentUser(req);
  const base = ingressBase(req);
  if (pathname === '/login') {
    if (user) { redirect(res, base + '/'); return; }
    page(req, res, 'login.html', 'text/html; charset=utf-8');
    return;
  }
  if (pathname === '/style.css' || pathname === '/login.js') {
    const name = pathname.endsWith('.css') ? 'style.css' : 'login.js';
    page(req, res, name, name.endsWith('.css') ? 'text/css; charset=utf-8' : 'application/javascript; charset=utf-8');
    return;
  }
  if (pathname === '/' || pathname === '/app.js' || pathname === '/index.html') {
    if (!user) {
      const accept = req.headers.accept || '';
      if (accept.includes('text/html') || pathname === '/' || pathname === '/index.html') { redirect(res, base + '/login'); return; }
      send(req, res, 401, '{"error":"Sign in required."}');
      return;
    }
    const name = pathname === '/app.js' ? 'app.js' : 'index.html';
    page(req, res, name, name === 'index.html' ? 'text/html; charset=utf-8' : 'application/javascript; charset=utf-8');
    return;
  }
  if (pathname === '/health') { send(req, res, 200, '{"ok":true}'); return; }
  if (pathname === '/api/me') {
    if (!user) { send(req, res, 401, '{"error":"Sign in required."}'); return; }
    send(req, res, 200, JSON.stringify({ username: user }));
    return;
  }
  if (!user && pathname.startsWith('/api/')) { send(req, res, 401, '{"error":"Sign in required."}'); return; }
  if (pathname === '/api/ha') { send(req, res, 200, JSON.stringify(cluster.publicState())); return; }
  if (pathname === '/api/cloudflare') { send(req, res, 200, JSON.stringify(cloudflare.publicState())); return; }
  if (pathname === '/api/cloudflare/tunnels') { send(req, res, 200, JSON.stringify(cloudflare.listTunnels())); return; }
  if (pathname === '/api/cloudflare/zones') { send(req, res, 200, JSON.stringify(cloudflare.listZones())); return; }
  if (pathname === '/api/cloudflare/tunnel') {
    try { send(req, res, 200, JSON.stringify(cloudflare.getTunnel(query.get('id') || ''))); }
    catch (exc) {
      if (exc instanceof CloudflareError) send(req, res, 502, JSON.stringify({ error: exc.message }));
      else if (exc instanceof Error) send(req, res, 400, JSON.stringify({ error: exc.message }));
      else send(req, res, 502, '{"error":"Cloudflare could not load this tunnel."}');
    }
    return;
  }
  if (pathname === '/api/deco') { send(req, res, 200, JSON.stringify(deco.publicState())); return; }
  if (pathname === '/api/logs') {
    const limit = Number(query.get('limit') || 100);
    send(req, res, 200, JSON.stringify({ push: applog.PUSH, retention_days: applog.RETENTION_DAYS, logs: storage.recentLogs(DB, Number.isFinite(limit) ? limit : 100) }));
    return;
  }
  if (pathname !== '/api/devices') { send(req, res, 404, '{}'); return; }
  send(req, res, 200, devicesPayload());
}

function upgrade(req, socket, head) {
  const url = new URL(req.url, 'http://localhost');
  if (!['/ws', '/ha'].includes(url.pathname)) { socket.destroy(); return; }
  if (url.pathname === '/ws' && !currentUser(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Length: 27\r\n\r\n{"error":"Sign in required."}');
    socket.end();
    return;
  }
  if (url.pathname === '/ha' && !cluster.isLeader()) {
    const body = JSON.stringify({ error: 'This HomeScan node is not the cluster leader.', ha: cluster.publicState() });
    socket.write(`HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    socket.end();
    return;
  }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  socket.write(handshakeHeaders(key));
  const hub = url.pathname === '/ha' ? cluster.hub : dashboard;
  const snapshot = url.pathname === '/ha'
    ? () => JSON.stringify({ type: 'heartbeat', node_id: cluster.nodeId, ip: cluster.localIp || '', hostname: cluster.resolveHostname(), ts: Date.now() / 1000, generation: cluster._generation })
    : () => devicesPayload();
  hub.serve(socket, head, snapshot);
}

export function applyAddonOptions() {
  const file = process.env.HASS_OPTIONS || '/data/options.json';
  if (!fs.existsSync(file)) return;
  let opts;
  try { opts = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return; }
  if (!opts || typeof opts !== 'object') return;
  if (opts.scan_network) {
    NETWORK = mergeScanNetwork(NETWORK, opts.scan_network) || String(opts.scan_network).trim();
    process.env.SCAN_NETWORK = NETWORK;
  }
  if (opts.ha_local_ip) process.env.HA_LOCAL_IP = String(opts.ha_local_ip).trim();
  if (['nmap', 'agent'].includes(opts.scan_mode)) { MODE = opts.scan_mode; process.env.SCAN_MODE = MODE; }
  if (opts.ingest_token) { TOKEN = String(opts.ingest_token).trim(); process.env.INGEST_TOKEN = TOKEN; }
}

function writeShareStatus() {
  const dir = '/share/homescan';
  try { fs.mkdirSync(dir, { recursive: true }); } catch { return; }
  let cfg = {};
  try { cfg = cloudflare.config(); } catch { cfg = {}; }
  let zones = { count: 0, error: '' };
  try {
    const listed = cloudflare.listZones();
    zones = { count: (listed.zones || []).length, error: listed.error || '' };
  } catch (exc) { zones = { count: 0, error: String(exc.message || exc) }; }
  const inventory = storage.inventory(DB);
  const payload = {
    at: new Date().toISOString(),
    zone: cfg.zone_name || '',
    suffix: cfg.suffix || '',
    dns_subnet: cfg.dns_subnet || '',
    token_set: Boolean(cfg.api_token),
    token_prefix: cfg.api_token ? String(cfg.api_token).slice(0, 4) : '',
    zones,
    devices: inventory.devices.length,
    seen: inventory.devices.filter((d) => d.online).length,
    with_mac: inventory.devices.filter((d) => d.mac).length,
    with_name: inventory.devices.filter((d) => d.hostname).length,
    networks: scanNetworkList(),
    configured_networks: configuredScanNetworks(),
    ha: cluster ? cluster.publicState() : null,
  };
  try { fs.writeFileSync(path.join(dir, 'status.json'), JSON.stringify(payload, null, 2)); } catch { /* share may be missing */ }
}

function cloudflareConfigFile() {
  return cloudflare?.configPath || process.env.CLOUDFLARE_CONFIG || '/data/cloudflare.json';
}

function importSharedCloudflareToken() {
  const candidates = [
    process.env.HOMESCAN_CF_TOKEN_FILE || '',
    '/share/homescan/cloudflare-token',
    '/share/homescan/cloudflare-token.txt',
  ].filter(Boolean);
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    let token = '';
    try { token = fs.readFileSync(file, 'utf8').trim().split(/\r?\n/)[0].trim(); } catch { continue; }
    if (token.length < 20) continue;
    const connectOnce = () => cloudflare.connect({
      api_token: token,
      zone_name: 'chancecox.com',
      suffix: 'house.chancecox.com',
      tunnel: true,
    });
    try {
      const result = connectOnce();
      let after = {};
      try { after = cloudflare.config(); } catch { after = {}; }
      try {
        cloudflare.saveDomain({
          zone_id: after.zone_id,
          suffix: after.suffix || 'house.chancecox.com',
          dns_subnet: after.dns_subnet || '192.168.2.0/24',
        });
      } catch (domainExc) {
        applog.warning('Share import could not set DNS subdomain', {
          source: 'cloudflare',
          detail: String(domainExc.message || domainExc),
        });
      }
      try { fs.unlinkSync(file); } catch { /* keep file if unlink fails */ }
      applog.info('Imported Cloudflare token from share', {
        source: 'cloudflare',
        detail: JSON.stringify({ zone: result.zone || after.zone_name || '', suffix: after.suffix || 'house.chancecox.com' }),
      });
      return true;
    } catch (exc) {
      // Zone-changed guard: clear the old zone ids and retry once for share imports.
      if (/Zone changed/i.test(String(exc.message || exc))) {
        try {
          const pathName = cloudflareConfigFile();
          const raw = JSON.parse(fs.readFileSync(pathName, 'utf8'));
          delete raw.zone_id;
          delete raw.zone_name;
          delete raw.suffix;
          fs.writeFileSync(pathName, JSON.stringify(raw));
          const result = connectOnce();
          let after = {};
          try { after = cloudflare.config(); } catch { after = {}; }
          try {
            cloudflare.saveDomain({
              zone_id: after.zone_id,
              suffix: 'house.chancecox.com',
              dns_subnet: '192.168.2.0/24',
            });
          } catch { /* subdomain can be set in Settings */ }
          try { fs.unlinkSync(file); } catch { /* ignore */ }
          applog.info('Imported Cloudflare token from share after zone reset', {
            source: 'cloudflare',
            detail: JSON.stringify({ zone: result.zone || after.zone_name || '' }),
          });
          return true;
        } catch (retryExc) {
          applog.error('Shared Cloudflare token import failed', { source: 'cloudflare', detail: String(retryExc.message || retryExc) });
          return false;
        }
      }
      applog.error('Shared Cloudflare token import failed', { source: 'cloudflare', detail: String(exc.message || exc) });
      return false;
    }
  }
  return false;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  applyAddonOptions();
  if (!['nmap', 'agent'].includes(MODE)) throw new Error('Invalid SCAN_MODE');
  if (MODE === 'agent' && TOKEN.length < 32) throw new Error('Set INGEST_TOKEN to at least 32 characters');
  if (MODE === 'nmap') parseScanNetworks(NETWORK);
  await storage.loadSqlite();
  try {
    init();
    importSharedCloudflareToken();
    writeShareStatus();
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (req.method === 'GET') handleGet(req, res, url.pathname, url.searchParams);
      else if (req.method === 'POST') handlePost(req, res, url.pathname);
      else send(req, res, 405, '{}');
    });
    server.on('upgrade', upgrade);
    server.listen(Number(process.env.PORT || 80), '0.0.0.0');
    cloudflare.run();
    cluster.run();
    if (MODE === 'nmap') {
      applog.info('Scan networks', { source: 'scanner', detail: scanNetworkList().join(', ') || '(none)' });
      scanner();
    }
  } catch (exc) {
    applog.exception('HomeScan process crashed', { source: 'app', exc });
    throw exc;
  }
}
