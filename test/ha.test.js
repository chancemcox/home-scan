import assert from 'node:assert/strict';
import test from 'node:test';
import { CloudflareError } from '../lib/cloudflare.js';
import { Cluster, detectLocalIp } from '../lib/ha.js';

function mockCloudflare(overrides = {}) {
  return {
    suffix: () => 'example.com',
    config: () => ({ api_token: 'token' }),
    ensureHaDns: () => ({ hostname: 'homescan.example.com', ip: '192.168.1.10' }),
    ...overrides,
  };
}

function cluster(overrides = {}, cloudflare = mockCloudflare()) {
  return new Cluster(cloudflare, {
    enabled: true,
    localIp: '192.168.1.10',
    hostname: 'homescan.example.com',
    nodeId: 'node-a',
    lookup: async () => [],
    ...overrides,
  });
}

test('detectLocalIp skips Home Assistant and Docker interfaces', () => {
  const previous = process.env.HA_LOCAL_IP;
  delete process.env.HA_LOCAL_IP;
  try {
    assert.equal(detectLocalIp({
      hassio: [{ family: 'IPv4', internal: false, address: '172.30.32.1' }],
      docker0: [{ family: 'IPv4', internal: false, address: '172.17.0.1' }],
      veth0: [{ family: 'IPv4', internal: false, address: '172.30.232.2' }],
      end0: [{ family: 'IPv4', internal: false, address: '192.168.1.50' }],
    }), '192.168.1.50');
  } finally {
    if (previous == null) delete process.env.HA_LOCAL_IP;
    else process.env.HA_LOCAL_IP = previous;
  }
});

test('a follower is the only cluster role that refuses scans', () => {
  const node = cluster();
  assert.equal(node.role, 'starting');
  assert.equal(node.acceptsScans(), true);
  node._setRole('waiting', 'Set HA_HOSTNAME or a base domain in Settings');
  assert.equal(node.acceptsScans(), true);
  node._setRole('error', 'Cloudflare HTTP 403. Check token permissions or retry later.');
  assert.equal(node.acceptsScans(), true);
  assert.equal(node.isLeader(), false);
  node._setRole('leader', 'Active · scanning');
  assert.equal(node.acceptsScans(), true);
  node._setRole('follower', 'Standby · watching 192.168.1.2', { ip: '192.168.1.2' });
  assert.equal(node.acceptsScans(), false);
});

test('Cloudflare DNS 403 does not pause local scanning', async () => {
  const node = cluster({}, mockCloudflare({
    ensureHaDns() { throw new CloudflareError('Cloudflare HTTP 403. Check token permissions or retry later.'); },
  }));
  node._wait = async () => {};
  await node.tick();
  assert.equal(node.role, 'error');
  assert.match(node.message, /403/);
  assert.equal(node.acceptsScans(), true);
  assert.equal(node.publicState().scanning, true);
});

test('a node without cluster DNS still scans for Home Assistant', async () => {
  const node = cluster({ hostname: '' }, {
    suffix() { throw new Error('no suffix'); },
    config: () => ({}),
    ensureHaDns() { throw new Error('unreachable'); },
  });
  node._wait = async () => {};
  await node.tick();
  assert.equal(node.role, 'waiting');
  assert.equal(node.acceptsScans(), true);
  assert.equal(node.publicState().scanning, true);
});
