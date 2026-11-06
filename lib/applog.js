import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RETENTION_DAYS = 30;
let dbPath = process.env.DB_PATH || '/data/homescan.db';
let lastExpire = 0;

export function pushId() {
  const env = (process.env.HOMESCAN_PUSH || '').trim();
  if (env) return env.slice(0, 64);
  const here = path.dirname(fileURLToPath(import.meta.url));
  for (const file of [path.join(here, '..', 'PUSH'), '/app/PUSH']) {
    try {
      const text = fs.readFileSync(file, 'utf8').trim();
      if (text) return text.slice(0, 64);
    } catch { /* missing */ }
  }
  return 'unknown';
}

export const PUSH = pushId();
export function configure(next) { dbPath = next; }

function format(level, source, message) {
  return `[${level}] push=${PUSH} source=${source || 'homescan'} ${message}`;
}

function persist(level, source, message, detail = '') {
  const parent = path.dirname(dbPath);
  if (!fs.existsSync(parent) && parent !== '.' && parent !== '') return;
  import('./storage.js').then((storage) => {
    storage.appendLog(dbPath, {
      level, push: PUSH, source: source || 'homescan',
      message: String(message).slice(0, 2000), detail: String(detail || '').slice(0, 8000),
    });
    expire(false);
  }).catch(() => {});
}

export function expire(force = false) {
  const now = Date.now();
  if (!force && now - lastExpire < 3600_000) return;
  lastExpire = now;
  import('./storage.js').then((storage) => storage.expireLogs(dbPath, RETENTION_DAYS)).catch((exc) => {
    process.stderr.write(format('error', 'applog', `log expire failed: ${exc}`) + '\n');
  });
}

export function write(level, message, { source = 'homescan', detail = '', exc = null } = {}) {
  level = String(level || 'info').toLowerCase();
  if (!['debug', 'info', 'warning', 'error'].includes(level)) level = 'info';
  const text = String(message || '');
  let extra = detail || '';
  if (exc) extra = (extra ? extra + '\n' : '') + (exc.stack || String(exc));
  process.stderr.write(format(level, source, text) + '\n');
  if (extra) {
    for (const chunk of String(extra).split(/\r?\n/).slice(0, 80)) process.stderr.write(format(level, source, chunk) + '\n');
  }
  persist(level, source, text, extra);
}

export const info = (message, opts) => write('info', message, opts);
export const warning = (message, opts) => write('warning', message, opts);
export const error = (message, opts) => write('error', message, opts);
export function exception(message, opts = {}) { write('error', message, { ...opts, exc: opts.exc || new Error(message) }); }
