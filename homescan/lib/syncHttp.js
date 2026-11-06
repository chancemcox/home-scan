import { Worker } from 'node:worker_threads';

const MAX_BODY = 4 * 1024 * 1024;
const sab = new SharedArrayBuffer(8 + MAX_BODY);
const flag = new Int32Array(sab, 0, 1);
const view = new DataView(sab);
let nextId = 1;

const worker = new Worker(new URL('./syncHttpWorker.js', import.meta.url), { workerData: { sab } });
worker.unref();

/** Blocking HTTP JSON call. The worker writes the result into shared memory so the main thread can wait without missing the reply. */
export function requestJson({ method = 'GET', url, headers = {}, body = null, timeout = 30_000 }) {
  const id = nextId++;
  Atomics.store(flag, 0, 0);
  worker.postMessage({ id, method, url, headers, body, timeout });
  const deadline = Date.now() + timeout + 2_000;
  while (Atomics.load(flag, 0) !== id) {
    const wait = Math.max(1, deadline - Date.now());
    Atomics.wait(flag, 0, 0, wait);
    if (Date.now() > deadline && Atomics.load(flag, 0) !== id) {
      const error = new Error('HTTP request timed out');
      error.status = 0;
      throw error;
    }
  }
  const length = view.getUint32(4, true);
  const message = JSON.parse(Buffer.from(new Uint8Array(sab, 8, length)).toString('utf8'));
  if (message.error) {
    const error = new Error(message.error);
    error.status = message.status || 0;
    error.payload = message.payload;
    throw error;
  }
  return { status: message.status, payload: message.payload, text: message.text };
}
