import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function usersPath() { return process.env.USERS_PATH || '/data/users.json'; }
export function bootstrapPasswordPath() { return process.env.BOOTSTRAP_PASSWORD_PATH || path.join(path.dirname(usersPath()), 'initial-admin-password.txt'); }
export const DEFAULT_USER = (process.env.HOMESCAN_ADMIN_USER || 'admin').trim().toLowerCase() || 'admin';
export const SESSION_COOKIE = 'homescan_session';
const SESSION_HOURS = 12;
const REMEMBER_DAYS = 30;
const PBKDF2_ROUNDS = 260_000;

const sessions = new Map();
let bootstrapPassword = null;

export function hashPassword(password, salt = crypto.randomBytes(16)) {
  const digest = crypto.pbkdf2Sync(password, salt, PBKDF2_ROUNDS, 32, 'sha256');
  return `${salt.toString('hex')}:${digest.toString('hex')}`;
}

export function verifyPassword(password, stored) {
  try {
    const [saltHex, digestHex] = String(stored).split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(digestHex, 'hex');
    const actual = crypto.pbkdf2Sync(String(password), salt, PBKDF2_ROUNDS, expected.length, 'sha256');
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

function loadUsers() {
  try {
    const data = JSON.parse(fs.readFileSync(usersPath(), 'utf8'));
    if (data && typeof data.users === 'object') return data.users;
  } catch { /* missing or unreadable */ }
  return {};
}

function saveUsers(users) {
  fs.mkdirSync(path.dirname(usersPath()), { recursive: true });
  const tmp = usersPath() + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ users }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, usersPath());
}

export function bootstrap() { return bootstrapPassword; }

export function init() {
  const users = loadUsers();
  if (!Object.keys(users).length) {
    let password = (process.env.HOMESCAN_ADMIN_PASSWORD || '').trim();
    let generated = false;
    if (!password) {
      password = crypto.randomBytes(18).toString('base64url');
      generated = true;
    }
    users[DEFAULT_USER] = hashPassword(password);
    saveUsers(users);
    bootstrapPassword = password;
    if (generated) {
      try {
        fs.mkdirSync(path.dirname(bootstrapPasswordPath()), { recursive: true });
        fs.writeFileSync(bootstrapPasswordPath(), password + '\n', { mode: 0o600 });
      } catch { /* volume may be read-only during tests */ }
    }
    process.stdout.write(`HomeScan admin user '${DEFAULT_USER}' created. ${generated ? 'Password saved to ' + bootstrapPasswordPath() : 'Password taken from HOMESCAN_ADMIN_PASSWORD.'}\n`);
  }
  purge();
}

function purge() {
  const stamp = Date.now();
  for (const [token, row] of sessions) if (row.expires <= stamp) sessions.delete(token);
}

function lookup(users, username) {
  const wanted = String(username || '').trim().toLowerCase();
  if (!wanted) return [null, null];
  if (users[wanted]) return [wanted, users[wanted]];
  for (const [name, hashed] of Object.entries(users)) {
    if (String(name).toLowerCase() === wanted) return [name, hashed];
  }
  return [null, null];
}

export function login(username, password, remember = false) {
  username = String(username || '').trim();
  password = String(password || '');
  if (!username || !password) throw new Error('Enter a username and password.');
  const users = loadUsers();
  const [canonical, stored] = lookup(users, username);
  if (!stored || !verifyPassword(password, stored)) throw new Error('Invalid username or password.');
  purge();
  const token = crypto.randomBytes(32).toString('base64url');
  const maxAge = remember ? REMEMBER_DAYS * 86400 : null;
  sessions.set(token, { username: canonical, expires: Date.now() + (remember ? REMEMBER_DAYS * 86400_000 : SESSION_HOURS * 3600_000), remember: Boolean(remember) });
  return { token, username: canonical, remember: Boolean(remember), max_age: maxAge };
}

export function logout(token) { sessions.delete(String(token || '')); }

export function sessionUser(token) {
  token = String(token || '');
  if (!token) return null;
  purge();
  const row = sessions.get(token);
  if (!row) return null;
  if (row.expires <= Date.now()) { sessions.delete(token); return null; }
  return row.username;
}

export function cookieHeader(token, remember = false, maxAge = null) {
  const parts = [`${SESSION_COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (remember && maxAge) parts.push(`Max-Age=${Number(maxAge)}`);
  return parts.join('; ');
}

export function clearCookieHeader() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}

export function parseCookie(header) {
  for (const part of String(header || '').split(';')) {
    const text = part.trim();
    if (text.startsWith(SESSION_COOKIE + '=')) return decodeURIComponent(text.slice(SESSION_COOKIE.length + 1));
  }
  return '';
}
