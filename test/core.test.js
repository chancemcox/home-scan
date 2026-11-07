import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { discoverScanNetworks } from '../server.js';
import { defaultClusterHostname, parseScanNetworks, pickAvailableZone } from '../lib/cloudflare.js';
import * as auth from '../lib/auth.js';

test('reachable subnets come from the routing table', () => {
  const routes = [
    'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT',
    'eth0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0',
    'eth0 0001A8C0 0102A8C0 0003 0 0 0 00FFFFFF 0 0 0',
    'docker0 000011AC 00000000 0001 0 0 0 0000FFFF 0 0 0',
    'eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0',
    'lo 0000007F 00000000 0001 0 0 0 000000FF 0 0 0',
  ].join('\n');
  assert.deepEqual(discoverScanNetworks(routes), ['192.168.2.0/24', '192.168.1.0/24']);
});

test('a /32 host route expands to the covering LAN /24', () => {
  const routes = [
    'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT',
    'eth0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0',
    'eth0 0156A8C0 00000000 0001 0 0 0 FFFFFFFF 0 0 0',
    'eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0',
  ].join('\n');
  assert.deepEqual(discoverScanNetworks(routes), ['192.168.2.0/24', '192.168.86.0/24']);
});

test('settings domain must be a Cloudflare zone this token can access', () => {
  const zones = [
    { id: 'zone-a', name: 'apparelishoweyeroll.com' },
    { id: 'zone-c', name: 'chancecox.com' },
  ];
  assert.equal(pickAvailableZone(zones, { zone_id: 'zone-c' }).name, 'chancecox.com');
  assert.equal(pickAvailableZone(zones, { suffix: 'apparelishoweyeroll.com' }).id, 'zone-a');
  assert.throws(() => pickAvailableZone(zones, { suffix: 'example.com' }), /token can access/);
  assert.throws(() => pickAvailableZone([], { zone_id: 'zone-c' }), /Connect Cloudflare/);
});

test('cluster DNS prefers the connected Cloudflare zone over a mismatched base domain', () => {
  assert.equal(
    defaultClusterHostname({ zone_name: 'apparelishoweyeroll.com' }, 'chancecox.com'),
    'homescan.apparelishoweyeroll.com',
  );
  assert.equal(defaultClusterHostname({}, 'chancecox.com'), 'homescan.chancecox.com');
});

test('scan networks accept several private subnets', () => {
  assert.deepEqual(parseScanNetworks('192.168.2.0/24, 10.0.0.0/24'), ['192.168.2.0/24', '10.0.0.0/24']);
  assert.throws(() => parseScanNetworks('8.8.8.8/32'), /private/);
  assert.throws(() => parseScanNetworks('not-a-subnet'), /not an IPv4 subnet/);
});

test('login is case insensitive and sessions expire from the cookie', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'homescan-auth-'));
  process.env.USERS_PATH = path.join(dir, 'users.json');
  process.env.BOOTSTRAP_PASSWORD_PATH = path.join(dir, 'initial-admin-password.txt');
  process.env.HOMESCAN_ADMIN_PASSWORD = 'correct-horse-battery';
  auth.init();
  const result = auth.login('Admin', 'correct-horse-battery', false);
  assert.equal(result.username, 'admin');
  assert.equal(auth.sessionUser(result.token), 'admin');
  assert.equal(auth.parseCookie(auth.cookieHeader(result.token, false, null)), result.token);
  assert.throws(() => auth.login('admin', 'wrong-password-here'), /Invalid username or password/);
});

test('a MAC replaces the provisional IP identity', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'homescan-db-'));
  const dbPath = path.join(dir, 'homescan.db');
  const storage = await import('../lib/storage.js');
  await storage.loadSqlite();
  storage.useSqlite();
  storage.init(dbPath);
  storage.recordBatches(dbPath, [{ source: 'network', hosts: [{ ip: '192.168.1.20', hostname: 'phone' }] }]);
  storage.recordBatches(dbPath, [{ source: 'network', hosts: [{ ip: '192.168.1.20', mac: 'aa:bb:cc:dd:ee:ff', hostname: 'phone' }] }]);
  const inventory = storage.inventory(dbPath);
  assert.equal(inventory.devices.length, 1);
  assert.equal(inventory.devices[0].device_id, 'mac:AA:BB:CC:DD:EE:FF');
  assert.equal(inventory.devices[0].address_current, true);
});
