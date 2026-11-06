import { Worker } from 'node:worker_threads';

const sab = new SharedArrayBuffer(4);
const flag = new Int32Array(sab);
let nextId = 1;
const pending = new Map();

const worker = new Worker(new URL('./syncHttpWorker.js', import.meta.url));
worker.unref();
worker.on('message', (message) => {
  const slot = pending.get(message.id);
  if (!slot) return;
  slot.message = message;
  Atomics.store(flag, 0, message.id);
  Atomics.notify(flag, 0);
});

/** Blocking HTTP JSON call so the scanner, HA loop, and request handler share one code path. */
export function requestJson({ method = 'GET', url, headers = {}, body = null, timeout = 30_000 }) {
  const id = nextId++;
  pending.set(id, {});
  Atomics.store(flag, 0, 0);
  worker.postMessage({ id, method, url, headers, body, timeout });
  const deadline = Date.now() + timeout + 2_000;
  while (Atomics.load(flag, 0) !== id) {
    const wait = Math.max(1, deadline - Date.now());
    Atomics.wait(flag, 0, 0, wait);
    if (Date.now() > deadline && Atomics.load(flag, 0) !== id) {
      pending.delete(id);
      const error = new Error('HTTP request timed out');
      error.status = 0;
      throw error;
    }
  }
  const message = pending.get(id).message;
  pending.delete(id);
  if (message.error) {
    const error = new Error(message.error);
    error.status = message.status || 0;
    error.payload = message.payload;
    throw error;
  }
  return { status: message.status, payload: message.payload, text: message.text };
}
