import { parentPort } from 'node:worker_threads';

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
    parentPort.postMessage({ id: job.id, status: response.status, text, payload });
  } catch (exc) {
    parentPort.postMessage({ id: job.id, error: exc.message || String(exc), status: 0 });
  }
});
