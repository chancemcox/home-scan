import { Cursor } from './rows.js';
import { requestJson } from './syncHttp.js';

export class DoDbError extends Error {}

export class DoConnection {
  constructor(baseUrl, secret) {
    this.baseUrl = String(baseUrl || '').replace(/\/$/, '');
    this.secret = String(secret || '');
    this._closed = false;
  }
  close() { this._closed = true; }
  _request(sql, params = []) {
    if (this._closed) throw new DoDbError('Durable Object connection is closed.');
    if (!this.baseUrl || !this.secret) throw new DoDbError('Cluster Durable Object is not configured.');
    let response;
    try {
      response = requestJson({
        method: 'POST',
        url: `${this.baseUrl}/v1/sql`,
        headers: { 'X-HomeScan-Cluster': this.secret, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: { sql, params: [...(params || [])] },
        timeout: 30_000,
      });
    } catch {
      throw new DoDbError('Durable Object SQL could not be reached.');
    }
    const payload = response.payload || {};
    if (response.status >= 400 || payload.success === false) {
      throw new DoDbError(payload.error || `Durable Object SQL HTTP ${response.status}.`);
    }
    return payload;
  }
  execute(sql, params = []) {
    const text = String(sql || '').trim();
    if (text.toUpperCase().startsWith('PRAGMA JOURNAL_MODE')) return new Cursor([]);
    const payload = this._request(text, params);
    const meta = payload.meta || {};
    return new Cursor(payload.results || [], Number(meta.last_row_id || 0), meta.changes == null ? -1 : Number(meta.changes));
  }
  executescript(sql) {
    const text = String(sql || '').trim();
    if (text) this._request(text, []);
    return this;
  }
}
