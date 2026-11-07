import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { attachMacs, discoverScanNetworks, parseNmapHosts, readArpTable } from '../server.js';
import * as storageMod from '../lib/storage.js';
import {
  defaultClusterHostname, ipInCidr, parseDnsSubnet, parseScanNetworks,
  pickAvailableZone, suffixUnderZone,
} from '../lib/cloudflare.js';
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

test('a /32 host route is ignored so fallback /24 sweeps stay first', () => {
  const routes = [
    'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT',
    'eth0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0',
    'eth0 0156A8C0 00000000 0001 0 0 0 FFFFFFFF 0 0 0',
    'eth0 00000000 0102A8C0 0003 0 0 0 00000000 0 0 0',
  ].join('\n');
  assert.deepEqual(discoverScanNetworks(routes), ['192.168.2.0/24']);
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

test('local DNS domain can be a subdomain under the Cloudflare zone', () => {
  assert.equal(suffixUnderZone('', 'example.com'), 'example.com');
  assert.equal(suffixUnderZone('house.example.com', 'example.com'), 'house.example.com');
  assert.equal(suffixUnderZone('*.house.example.com', 'example.com'), 'house.example.com');
  assert.throws(() => suffixUnderZone('other.com', 'example.com'), /subdomain/);
});

test('DNS subnet constrains which LAN IPs local DNS may publish', () => {
  assert.equal(parseDnsSubnet(''), '');
  assert.equal(parseDnsSubnet('192.168.1.0/24'), '192.168.1.0/24');
  assert.equal(ipInCidr('192.168.1.50', '192.168.1.0/24'), true);
  assert.equal(ipInCidr('192.168.2.50', '192.168.1.0/24'), false);
  assert.throws(() => parseDnsSubnet('8.8.8.0/24'), /private/);
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

test('nmap XML keeps hosts even when stderr was noisy', () => {
  const xml = `<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/><address addr="192.168.86.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/><hostnames><hostname name="nest"/></hostnames></host>
<host><status state="down"/><address addr="192.168.86.11" addrtype="ipv4"/></host>
</nmaprun>`;
  assert.deepEqual(parseNmapHosts(xml), [{ ip: '192.168.86.10', mac: 'AA:BB:CC:DD:EE:FF', hostname: 'nest' }]);
});

test('ARP table fills missing MACs for on-link hosts', () => {
  const arp = readArpTable([
    'IP address       HW type     Flags       HW address            Mask     Device',
    '192.168.2.50     0x1         0x2         58:d8:12:47:d9:ab     *        eth0',
    '192.168.2.99     0x1         0x0         00:00:00:00:00:00     *        eth0',
  ].join('\n'));
  assert.equal(arp.get('192.168.2.50'), '58:D8:12:47:D9:AB');
  assert.equal(arp.has('192.168.2.99'), false);
  const hosts = attachMacs([{ ip: '192.168.2.50', mac: '', hostname: '' }, { ip: '192.168.2.1', mac: 'AA:BB:CC:DD:EE:FF', hostname: 'gw' }], arp);
  assert.equal(hosts[0].mac, '58:D8:12:47:D9:AB');
  assert.equal(hosts[1].mac, 'AA:BB:CC:DD:EE:FF');
});

test('empty MAC updates do not wipe a known address', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'homescan-mac-'));
  const dbPath = path.join(dir, 'homescan.db');
  await storageMod.loadSqlite();
  storageMod.useSqlite();
  storageMod.init(dbPath);
  storageMod.recordBatches(dbPath, [{ source: 'network', hosts: [{ ip: '192.168.2.20', mac: '10:22:33:44:55:66', hostname: 'cam' }] }]);
  storageMod.recordBatches(dbPath, [{ source: 'network', hosts: [{ ip: '192.168.2.20', mac: '', hostname: 'cam' }] }]);
  const inventory = storageMod.inventory(dbPath);
  assert.equal(inventory.devices.length, 1);
  assert.equal(inventory.devices[0].mac, '10:22:33:44:55:66');
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
