# HomeScan cluster Durable Object

Shared **in-memory SQLite** for all HomeScan app tables (devices, routes, settings, logs),
plus leader election and live inventory fan-out.

```bash
npm install
npx wrangler secret put CLUSTER_SECRET
npx wrangler deploy
```

Then set the same values on every HomeScan host (`.env`):

```
CLUSTER_WORKER_URL=https://homescan-cluster.<your-subdomain>.workers.dev
CLUSTER_SECRET=<the secret you put>
```

HomeScan prefers this Durable Object database over D1/local SQLite whenever both URL and secret are set.
