/** sqlite3.Row-shaped results for local SQLite, D1, and the Durable Object. */
export class Cursor {
  constructor(rows = [], lastrowid = 0, rowcount = -1) {
    this._rows = rows.map((row) => (row && typeof row === 'object' ? row : {}));
    this.lastrowid = lastrowid;
    this.rowcount = rowcount;
  }
  fetchone() { return this._rows[0] ?? null; }
  fetchall() { return this._rows.slice(); }
  [Symbol.iterator]() { return this._rows[Symbol.iterator](); }
}

export function isQuery(sql) {
  const text = String(sql || '').trim().replace(/^--.*$/gm, '').trim().toUpperCase();
  return text.startsWith('SELECT') || text.startsWith('PRAGMA') || text.startsWith('WITH') || text.startsWith('EXPLAIN');
}
