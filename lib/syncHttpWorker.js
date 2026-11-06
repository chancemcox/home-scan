import { parentPort, workerData } from 'node:worker_threads';

const sab = workerData.sab;
const flag = new Int32Array(sab, 0, 1);
const view = new DataView(sab);
const bytes = new Uint8Array(sab);
const MAX_BODY = sab.byteLength - 8;

function publish(id, message) {
  const encoded = Buffer.from(JSON.stringify(message));
  if (encoded.length > MAX_BODY) {
    const error = Buffer.from(JSON.stringify({ id, error: 'HTTP response is too large', status: 0 }));
    view.setUint32(4, error.length, true);
    bytes.set(error, 8);
  } else {
    view.setUint32(4, encoded.length, true);
    bytes.set(encoded, 8);
  }
  Atomics.store(flag, 0, id);
  Atomics.notify(flag, 0);
}

parentPort.on('message', async (job) => {
  try {
    const response = await fetch(job.url, {
      method: job.method,
      headers: job.headers,
      body: job.body == null ? undefined : (typeof job.body === 'string' ? job.body : JSON.stringify(job.body)),
      signal: AbortSignal.timeout(job.timeout || 30_000),
    });
    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { payload = null; }
    publish(job.id, { id: job.id, status: response.status, text, payload });
  } catch (exc) {
    publish(job.id, { id: job.id, error: exc.message || String(exc), status: 0 });
  }
});
