import * as applog from './applog.js';
import { requestJson } from './syncHttp.js';

export const DEFAULT_TTL = Number(process.env.CLUSTER_LEADER_TTL || 15);
export class ClusterStateError extends Error {}

export class ClusterState {
  constructor(baseUrl, secret, nodeId, localIp = '', ttl = DEFAULT_TTL) {
    this.baseUrl = String(baseUrl || '').replace(/\/$/, '');
    this.secret = String(secret || '');
    this.nodeId = nodeId;
    this.localIp = localIp || '';
    this.ttl = Math.max(5, Number(ttl) || DEFAULT_TTL);
    this._inventory = null;
  }
  get enabled() { return Boolean(this.baseUrl && this.secret && this.nodeId); }
  _request(method, path, body = undefined, contentType = 'application/json') {
    if (!this.enabled) throw new ClusterStateError('Cluster Durable Object is not configured.');
    const headers = { 'X-HomeScan-Cluster': this.secret, Accept: 'application/json' };
    let payload = undefined;
    if (body !== undefined) {
      headers['Content-Type'] = contentType;
      payload = typeof body === 'string' ? body : body;
    }
    try {
      const response = requestJson({ method, url: this.baseUrl + path, headers, body: payload, timeout: 12_000 });
      return [response.status, response.payload ?? response.text];
    } catch (exc) {
      throw new ClusterStateError('Cluster Durable Object unreachable: ' + (exc.message || exc));
    }
  }
  getLeader() {
    const [code, payload] = this._request('GET', '/v1/leader');
    if (code !== 200) throw new ClusterStateError(String(payload && payload.error ? payload.error : payload));
    return (payload && payload.leader) || {};
  }
  tryBecomeLeader() {
    const [code, payload] = this._request('PUT', '/v1/leader', { node_id: this.nodeId, ip: this.localIp, ttl: this.ttl });
    if (code === 200 && payload && payload.ok) return true;
    if (code === 409) return false;
    throw new ClusterStateError(String(payload && payload.error ? payload.error : payload));
  }
  renewLeadership() { return this.tryBecomeLeader(); }
  stepDown() {
    const [code] = this._request('DELETE', `/v1/leader?node_id=${encodeURIComponent(this.nodeId)}`);
    return code === 200;
  }
  isLeader() { return this.getLeader().node_id === this.nodeId; }
  publishInventory(body) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    const [code, result] = this._request('PUT', '/v1/inventory', text, 'application/json');
    if (code !== 200) throw new ClusterStateError(String(result && result.error ? result.error : result));
    this._inventory = text;
    return true;
  }
  getInventory() {
    if (this._inventory != null) return this._inventory;
    const [code, payload] = this._request('GET', '/v1/inventory');
    if (code !== 200) throw new ClusterStateError(String(payload && payload.error ? payload.error : payload));
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    this._inventory = body;
    return body;
  }
  publicState() {
    try {
      const [code, payload] = this._request('GET', '/v1/state');
      if (code === 200 && payload && typeof payload === 'object') {
        return { enabled: true, backend: payload.backend || 'durable-object-memory', leader: payload.leader || {}, has_inventory: Boolean(payload.has_inventory) };
      }
    } catch (exc) {
      if (!(exc instanceof ClusterStateError)) throw exc;
    }
    return { enabled: this.enabled, backend: 'durable-object-memory', leader: {}, has_inventory: false };
  }
}

export function fromEnv(nodeId) {
  const base = (process.env.CLUSTER_WORKER_URL || '').trim();
  const secret = process.env.CLUSTER_SECRET || '';
  if (base && secret) applog.info('HA cluster state via Durable Object', { source: 'ha' });
  return new ClusterState(base, secret, nodeId);
}
