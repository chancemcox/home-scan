import crypto from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import net from 'node:net';
import { networkInterfaces } from 'node:os';
import { CloudflareError, privateIp } from './cloudflare.js';
import { ClusterStateError } from './clusterState.js';
import * as applog from './applog.js';
import { Hub, OP_CLOSE, OP_PING, OP_TEXT, acceptKey } from './ws.js';

export const HA_HOSTNAME = (process.env.HA_HOSTNAME || '').trim().toLowerCase().replace(/\.+$/, '');
export const HA_PORT = Number(process.env.HA_PORT || 8080);
export const HA_ENABLED = !['0', 'false', 'no', 'off'].includes((process.env.HA_ENABLED || '1').trim().toLowerCase());
export const HEARTBEAT = Number(process.env.HA_HEARTBEAT || 3);
export const TIMEOUT = Number(process.env.HA_TIMEOUT || 12);
export const SKIPPED_IFACES = ['lo', 'docker', 'veth', 'br-', 'hassio', 'cni', 'flannel', 'virbr', 'zt', 'tailscale', 'podman', 'nerdctl'];

export function detectLocalIp(ifaces = networkInterfaces()) {
  const configured = (process.env.HA_LOCAL_IP || '').trim();
  if (configured) return privateIp(configured);
  for (const [name, entries] of Object.entries(ifaces)) {
    const iface = String(name || '').toLowerCase();
    if (SKIPPED_IFACES.some((prefix) => iface.startsWith(prefix))) continue;
    for (const entry of entries || []) {
      const family = entry.family === 'IPv4' || entry.family === 4;
      if (!family || entry.internal) continue;
      try { return privateIp(entry.address); } catch { /* skip public */ }
    }
  }
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    socket.once('error', () => { socket.close(); reject(new Error("Set HA_LOCAL_IP to this host's private LAN address.")); });
    socket.connect(80, '1.1.1.1', () => {
      try { resolve(privateIp(socket.address().address)); }
      catch (exc) { reject(exc); }
      finally { socket.close(); }
    });
  });
}

export async function resolveIpv4(hostname) {
  try {
    const records = await dns.lookup(hostname, { family: 4, all: true });
    return [...new Set(records.map((record) => record.address))];
  } catch { return []; }
}

export async function resolveHaIpv4(hostname) {
  const ips = await resolveIpv4(hostname);
  return ips.filter((ip) => { try { privateIp(ip); return true; } catch { return false; } });
}

function maskedFrame(opcode, payload = Buffer.alloc(0)) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const mask = crypto.randomBytes(4);
  const body = Buffer.from(data.map((byte, index) => byte ^ mask[index % 4]));
  return Buffer.concat([Buffer.from([0x80 | opcode, 0x80 | data.length]), mask, body]);
}

export class WsClient {
  constructor(socket, pending = Buffer.alloc(0)) {
    this.socket = socket;
    this.alive = true;
    this._pending = pending;
  }
  sendText(text) { this.socket.write(maskedFrame(OP_TEXT, Buffer.from(text))); }
  close() {
    this.alive = false;
    try { this.socket.write(maskedFrame(OP_CLOSE)); } catch { /* ignore */ }
    try { this.socket.destroy(); } catch { /* ignore */ }
  }
  _read(n) {
    return new Promise((resolve, reject) => {
      const take = () => {
        if (this._pending.length >= n) {
          const out = this._pending.subarray(0, n);
          this._pending = this._pending.subarray(n);
          resolve(Buffer.from(out));
          return true;
        }
        return false;
      };
      if (take()) return;
      const onData = (chunk) => {
        this._pending = Buffer.concat([this._pending, chunk]);
        if (take()) cleanup();
      };
      const onClose = () => { cleanup(); reject(new Error('closed')); };
      const cleanup = () => { this.socket.off('data', onData); this.socket.off('close', onClose); };
      this.socket.on('data', onData);
      this.socket.on('close', onClose);
    });
  }
  async recv() {
    const header = await this._read(2);
    let length = header[1] & 0x7f;
    const opcode = header[0] & 0x0f;
    if (length === 126) length = (await this._read(2)).readUInt16BE(0);
    else if (length === 127) length = Number((await this._read(8)).readBigUInt64BE(0));
    return [opcode, await this._read(length)];
  }
}

export function connectHa(host, port, pathName = '/ha', timeout = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('HA upgrade failed')); }, timeout);
    socket.once('error', (exc) => { clearTimeout(timer); reject(exc); });
    socket.once('connect', () => {
      const key = crypto.randomBytes(16).toString('base64');
      socket.write(`GET ${pathName} HTTP/1.1\r\nHost: ${host}:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const split = buf.indexOf('\r\n\r\n');
      if (split < 0) return;
      socket.off('data', onData);
      clearTimeout(timer);
      const head = buf.subarray(0, split).toString('utf8');
      const rest = buf.subarray(split + 4);
      if (!head.split('\r\n')[0].includes('101')) { socket.destroy(); reject(new Error('HA endpoint rejected WebSocket upgrade')); return; }
      resolve(new WsClient(socket, rest));
    };
    socket.on('data', onData);
  });
}

const sleep = (ms, stop) => new Promise((resolve) => {
  const timer = setTimeout(resolve, ms);
  if (stop) stop.then(() => { clearTimeout(timer); resolve(); });
});

export class Cluster {
  constructor(cloudflare, { onChange = null, hostname = null, port = HA_PORT, localIp = null, nodeId = null, enabled = HA_ENABLED, clusterState = null, lookup = resolveHaIpv4 } = {}) {
    this.cloudflare = cloudflare;
    this.onChange = onChange;
    this.hostname = (hostname == null ? HA_HOSTNAME : hostname).trim().toLowerCase().replace(/\.+$/, '');
    this.port = port;
    this.enabled = enabled;
    this.nodeId = nodeId || crypto.randomBytes(16).toString('hex');
    this.localIp = localIp;
    this.clusterState = clusterState;
    this.lookup = lookup;
    this.role = enabled ? 'starting' : 'disabled';
    this.leader = {};
    this.message = '';
    this.hub = new Hub();
    this._stop = { set: false, waiters: [] };
    this._generation = 0;
  }
  resolveHostname() {
    if (this.hostname) return this.hostname;
    try {
      if (typeof this.cloudflare.clusterHostname === 'function') return this.cloudflare.clusterHostname();
      const cfg = typeof this.cloudflare.config === 'function' ? this.cloudflare.config() : {};
      const zone = String((cfg || {}).zone_name || '').trim().toLowerCase().replace(/\.+$/, '');
      if (zone) return 'homescan.' + zone;
      const suffix = this.cloudflare.suffix();
      if (suffix) return 'homescan.' + suffix;
    } catch { /* ignore */ }
    return '';
  }
  publicState() {
    let shared = {};
    if (this.clusterState && this.clusterState.enabled) {
      try { shared = this.clusterState.publicState(); }
      catch { shared = { enabled: true, backend: 'durable-object-memory' }; }
    }
    return {
      enabled: this.enabled, role: this.role, hostname: this.resolveHostname(), port: this.port,
      local_ip: this.localIp || '', node_id: this.nodeId, leader: { ...this.leader },
      scanning: this.acceptsScans(), message: this.message, shared,
    };
  }
  isLeader() { return !this.enabled || this.role === 'leader'; }
  // Scan locally unless another node is known to be the leader. Cluster DNS or
  // Cloudflare token errors must not pause Home Assistant inventory.
  acceptsScans() { return !this.enabled || this.role !== 'follower'; }
  _setRole(role, message = '', leader = null) {
    const changed = this.role !== role || this.message !== message;
    this.role = role;
    this.message = message;
    if (leader) this.leader = leader;
    else if (role === 'leader') this.leader = { node_id: this.nodeId, ip: this.localIp, hostname: this.resolveHostname() };
    if (changed && this.onChange) { try { this.onChange(this.publicState()); } catch { /* ignore */ } }
  }
  async ensureLocalIp() {
    if (!this.localIp) this.localIp = await detectLocalIp();
    return this.localIp;
  }
  async claim(reason = 'failover') {
    const ip = await this.ensureLocalIp();
    const name = this.resolveHostname();
    if (!name) throw new Error('Set HA_HOSTNAME or a base domain in Settings before enabling the cluster.');
    this.cloudflare.ensureHaDns(ip, name);
    this._generation += 1;
    this._setRole('leader', 'Active · claimed DNS (' + reason + ')');
    return ip;
  }
  sharedInventory() {
    if (!this.clusterState || !this.clusterState.enabled) return null;
    try { return this.clusterState.getInventory(); } catch { return null; }
  }
  publishInventory(payload) {
    if (!this.clusterState || !this.clusterState.enabled || !this.isLeader()) return;
    try { this.clusterState.publishInventory(payload); } catch { /* ignore */ }
  }
  stopped() { return this._stop.set; }
  stop() {
    this._stop.set = true;
    for (const resolve of this._stop.waiters.splice(0)) resolve();
    if (this.clusterState && this.clusterState.enabled) { try { this.clusterState.stepDown(); } catch { /* ignore */ } }
  }
  _wait(ms) {
    if (this._stop.set) return Promise.resolve();
    return new Promise((resolve) => {
      let timer;
      const done = () => { clearTimeout(timer); resolve(); };
      timer = setTimeout(done, ms);
      this._stop.waiters.push(done);
    });
  }
  broadcast() {
    if (this.role !== 'leader') return;
    this.hub.broadcast(JSON.stringify(this._heartbeat()));
  }
  _heartbeat() {
    return { type: 'heartbeat', node_id: this.nodeId, ip: this.localIp || '', hostname: this.resolveHostname(), ts: Date.now() / 1000, generation: this._generation };
  }
  async _follow(leaderIp) {
    const name = this.resolveHostname();
    this._setRole('follower', 'Standby · watching ' + leaderIp, { ip: leaderIp, hostname: name });
    let client = null;
    let last = Date.now();
    try {
      client = await connectHa(name, this.port);
      client.socket.setTimeout(Math.max(1000, (HEARTBEAT + 1) * 1000));
      client.sendText(JSON.stringify({ type: 'hello', node_id: this.nodeId, ip: this.localIp || '' }));
      let timedOut = false;
      let sawSelf = false;
      while (!this.stopped()) {
        let opcode, payload;
        try { [opcode, payload] = await client.recv(); }
        catch {
          if (Date.now() - last >= TIMEOUT * 1000) { timedOut = true; break; }
          continue;
        }
        if (opcode === OP_CLOSE) break;
        if (opcode === OP_PING) continue;
        if (opcode !== OP_TEXT) continue;
        let message;
        try { message = JSON.parse(payload.toString('utf8')); } catch { continue; }
        if (message.type !== 'heartbeat') continue;
        if (message.node_id === this.nodeId) { sawSelf = true; break; }
        last = Date.now();
        this._setRole('follower', 'Standby · leader ' + String(message.ip || leaderIp), {
          node_id: message.node_id, ip: message.ip, hostname: name, generation: message.generation,
        });
      }
      if (this.stopped()) return;
      if (sawSelf) await this.claim('dns-points-here');
      else if (timedOut || Date.now() - last >= TIMEOUT * 1000) await this.claim('leader-timeout');
      else await this.claim('leader-disconnect');
    } catch (exc) {
      if (!this.stopped()) {
        this.message = String(exc.message || exc);
        applog.warning('HA follow failed', { source: 'ha', detail: this.message });
        try { await this.claim('unreachable-leader'); }
        catch (claimExc) {
          if (claimExc instanceof CloudflareError || claimExc instanceof Error) {
            applog.error('HA claim failed', { source: 'ha', detail: String(claimExc.message || claimExc) });
            this._setRole('error', String(claimExc.message || claimExc));
          }
        }
      }
    } finally { if (client) client.close(); }
  }
  async tick() {
    if (!this.enabled) { this._setRole('disabled', 'HA disabled'); await this._wait(5000); return; }
    try { await this.ensureLocalIp(); }
    catch (exc) { this._setRole('error', String(exc.message || exc)); await this._wait(5000); return; }
    if (this.clusterState && this.clusterState.enabled) {
      this.clusterState.localIp = this.localIp || '';
      await this._tickDurableObject();
      return;
    }
    const name = this.resolveHostname();
    if (!name) { this._setRole('waiting', 'Set HA_HOSTNAME or a base domain in Settings'); await this._wait(5000); return; }
    let cfg = {};
    try { cfg = this.cloudflare.config(); } catch { cfg = {}; }
    if (!cfg.api_token) { this._setRole('waiting', 'Connect Cloudflare so HA can manage ' + name); await this._wait(5000); return; }
    const ips = await this.lookup(name);
    if (!ips.length) {
      try { await this.claim('dns-missing'); }
      catch (exc) { this._setRole('error', String(exc.message || exc)); }
      if (this.role === 'leader') await this._leadUntilStepDown();
      else await this._wait(5000);
      return;
    }
    if (ips.includes(this.localIp)) {
      if (this.role !== 'leader') {
        try { await this.claim('dns-points-here'); }
        catch (exc) { this._setRole('error', String(exc.message || exc)); await this._wait(5000); return; }
      }
      await this._leadUntilStepDown();
      return;
    }
    await this._follow(ips[0]);
  }
  async _leadUntilStepDown() {
    const name = this.resolveHostname();
    this._setRole('leader', 'Active · scanning');
    while (!this.stopped() && this.role === 'leader') {
      this.broadcast();
      await this._wait(HEARTBEAT * 1000);
      const ips = await this.lookup(name);
      if (ips.length && !ips.includes(this.localIp)) {
        this._setRole('follower', 'Standby · DNS moved to ' + ips[0], { ip: ips[0], hostname: name });
        return;
      }
      try { this.cloudflare.ensureHaDns(this.localIp, name); }
      catch (exc) { if (exc instanceof CloudflareError || exc instanceof Error) this.message = String(exc.message || exc); }
    }
  }
  async _tickDurableObject() {
    const name = this.resolveHostname();
    try {
      if (this.clusterState.tryBecomeLeader() || this.clusterState.isLeader()) {
        if (name) { try { this.cloudflare.ensureHaDns(this.localIp, name); } catch (exc) { this.message = String(exc.message || exc); } }
        this._generation += 1;
        this._setRole('leader', 'Active · Durable Object leader');
        while (!this.stopped() && this.role === 'leader') {
          if (!this.clusterState.renewLeadership()) {
            const leader = this.clusterState.getLeader();
            this._setRole('follower', 'Standby · lost Durable Object lease', { ...(leader || {}), hostname: name });
            return;
          }
          this.broadcast();
          if (name) { try { this.cloudflare.ensureHaDns(this.localIp, name); } catch (exc) { this.message = String(exc.message || exc); } }
          await this._wait(HEARTBEAT * 1000);
        }
        return;
      }
      const leader = this.clusterState.getLeader();
      this._setRole('follower', 'Standby · Durable Object leader ' + (leader.ip || leader.node_id || ''), { ...(leader || {}), hostname: name });
      await this._wait(HEARTBEAT * 1000);
    } catch (exc) {
      if (exc instanceof ClusterStateError) {
        applog.error('HA Durable Object error', { source: 'ha', detail: String(exc.message) });
        this._setRole('error', String(exc.message));
        await this._wait(5000);
      } else throw exc;
    }
  }
  async run() {
    while (!this.stopped()) {
      try { await this.tick(); }
      catch (exc) {
        applog.exception('HA loop failed', { source: 'ha', exc });
        this._setRole(this.role === 'starting' ? 'error' : this.role, String(exc.message || exc));
        await this._wait(5000);
      }
    }
  }
}

export { acceptKey };
