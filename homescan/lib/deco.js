import fs from 'node:fs';
import path from 'node:path';

export const CONFIG = process.env.DECO_CONFIG || '/data/deco.json';
export const LEGACY = process.env.DECO_LEGACY || '/run/homescan-secrets/deco.json';
export const COOLDOWN = process.env.DECO_COOLDOWN || '/data/deco-auth-retry';

function readJson(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
  const config = JSON.parse(text);
  return config && typeof config === 'object' ? config : null;
}

export function loadConfig() {
  for (const file of [CONFIG, LEGACY]) {
    if (!fs.existsSync(file)) continue;
    let config;
    try { config = readJson(file); } catch { continue; }
    if (!config) continue;
    if (file === LEGACY && !fs.existsSync(CONFIG) && config.password) {
      try {
        const payload = {
          enabled: config.enabled !== false,
          host: String(config.host || ''),
          username: String(config.username || 'admin'),
          password: config.password,
        };
        fs.mkdirSync(path.dirname(CONFIG), { recursive: true });
        const tmp = CONFIG + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
        fs.renameSync(tmp, CONFIG);
        return [payload, CONFIG];
      } catch { /* keep the legacy copy */ }
    }
    return [config, file];
  }
  return [{}, null];
}

function cooldownActive() {
  try {
    const age = (Date.now() - fs.statSync(COOLDOWN).mtimeMs) / 1000;
    return age < 600;
  } catch { return false; }
}

export function publicState() {
  try {
    const [config] = loadConfig();
    const configured = Boolean(config.password);
    const enabled = configured && config.enabled !== false;
    return {
      enabled: enabled && configured,
      configured,
      host: String(config.host || ''),
      username: String(config.username || 'admin'),
      password_set: configured,
      auth_cooldown: cooldownActive(),
    };
  } catch {
    return { enabled: false, configured: false, host: '', username: 'admin', password_set: false, auth_cooldown: false };
  }
}

function privateHost(host) {
  const parts = host.split('.').map(Number);
  if (parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
    const privateAddr = parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
    if (!privateAddr) throw new Error('Use a private Deco LAN address.');
    return parts.join('.');
  }
  if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(host)) {
    throw new Error('Enter a private IPv4 address or hostname.');
  }
  return host;
}

export function saveSettings(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid Deco settings.');
  const enabled = body.enabled ?? false;
  if (typeof enabled !== 'boolean') throw new Error('enabled must be true or false.');
  let host = String(body.host || '').trim();
  const username = String(body.username || 'admin').trim() || 'admin';
  let password = body.password;
  if (password != null && typeof password !== 'string') throw new Error('Invalid password.');
  const [current] = loadConfig();
  if (password == null || password === '') password = current.password || '';
  if (enabled) {
    if (!host) throw new Error('Enter the Deco IP or hostname.');
    host = privateHost(host);
    if (!password) throw new Error('Enter the Deco owner password.');
  } else {
    host = host || String(current.host || '');
    password = password || String(current.password || '');
  }
  fs.mkdirSync(path.dirname(CONFIG), { recursive: true });
  const payload = { enabled, host, username, password };
  const tmp = CONFIG + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG);
  try { fs.unlinkSync(COOLDOWN); } catch { /* absent */ }
  return publicState();
}

export function collect() {
  try {
    const [config] = loadConfig();
    if (!config.password) return { enabled: false, configured: false, available: false, hosts: [] };
    const enabled = config.enabled !== false;
    if (!enabled || cooldownActive()) return { enabled, configured: true, available: false, hosts: [] };
    return { enabled: true, configured: true, available: false, hosts: [] };
  } catch {
    return { enabled: false, configured: false, available: false, hosts: [] };
  }
}

if (process.argv[1] && process.argv[1].endsWith('deco.js')) {
  const save = process.argv.includes('save');
  if (!save) process.stdout.write(JSON.stringify(collect()) + '\n');
  else {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => {
      try { process.stdout.write(JSON.stringify(saveSettings(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'))) + '\n'); }
      catch (exc) {
        process.stdout.write(JSON.stringify({ error: exc.message || 'Invalid Deco settings.' }) + '\n');
        process.exitCode = 1;
      }
    });
  }
}
