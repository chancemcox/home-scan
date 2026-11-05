/**
 * HomeScan shared cluster state in a Durable Object.
 * Keeps leader + inventory in memory and mirrors them to DO storage
 * so hibernation does not lose HA coordination.
 */
import { DurableObject } from 'cloudflare:workers';

export class HomeScanCluster extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.leader = null;
    this.inventory = null;
    this.ready = this.ctx.blockConcurrencyWhile(async () => {
      this.leader = (await this.ctx.storage.get('leader')) || null;
      this.inventory = (await this.ctx.storage.get('inventory')) || null;
    });
  }

  async fetch(request) {
    await this.ready;
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

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
      return Response.json({
        leader: this.leader,
        has_inventory: Boolean(this.inventory),
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
