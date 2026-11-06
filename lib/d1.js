import { Cursor } from './rows.js';
import { requestJson } from './syncHttp.js';

const API = 'https://api.cloudflare.com/client/v4';

export class D1Error extends Error {}

export class D1Connection {
  constructor(accountId, databaseId, token) {
    this.accountId = accountId;
    this.databaseId = databaseId;
    this.token = token;
    this._closed = false;
  }
  close() { this._closed = true; }
  _request(sql, params = null) {
    if (this._closed) throw new D1Error('D1 connection is closed.');
    let response;
    try {
      response = requestJson({
        method: 'POST',
        url: `${API}/accounts/${this.accountId}/d1/database/${this.databaseId}/query`,
        headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
        body: { sql, params: [...(params || [])] },
        timeout: 30_000,
      });
    } catch {
      throw new D1Error('Cloudflare D1 could not be reached.');
    }
    const payload = response.payload || {};
    if (response.status >= 400) throw new D1Error(`D1 HTTP ${response.status}. Check the API token has D1 Edit.`);
    if (!payload.success) {
      const codes = (payload.errors || []).map((item) => item.code || 'unknown').join(', ');
      throw new D1Error(`D1 rejected the query (code ${codes}).`);
    }
    return payload.result || [];
  }
  execute(sql, params = []) {
    const text = String(sql || '').trim();
    if (text.toUpperCase().startsWith('PRAGMA JOURNAL_MODE')) return new Cursor([]);
    const chunks = this._request(text, params);
    if (!chunks.length) return new Cursor([]);
    const last = chunks[chunks.length - 1] || {};
    const meta = last.meta || {};
    return new Cursor(last.results || [], Number(meta.last_row_id || 0), meta.changes == null ? -1 : Number(meta.changes));
  }
  executescript(sql) {
    const text = String(sql || '').trim();
    if (text) this._request(text);
    return this;
  }
}

export function ensureDatabase(api, accountId, name = 'homescan') {
  accountId = String(accountId || '');
  name = String(name || 'homescan').trim() || 'homescan';
  if (!accountId) throw new D1Error('Cloudflare account id is required for D1.');
  let rows = api.call('GET', `/accounts/${accountId}/d1/database`) || [];
  if (!Array.isArray(rows)) rows = rows.result || rows.databases || [];
  const exact = rows.filter((row) => row.name === name);
  if (exact.length) return exact[0].uuid || exact[0].id;
  const created = api.call('POST', `/accounts/${accountId}/d1/database`, { name, primary_location_hint: 'enam' }) || {};
  const databaseId = created.uuid || created.id;
  if (!databaseId) throw new D1Error('Cloudflare did not return a D1 database id.');
  return databaseId;
}
