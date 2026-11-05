# HomeScan cluster Durable Object

Shared in-memory leader + inventory state for multi-node HomeScan.

```bash
npm install
npx wrangler secret put CLUSTER_SECRET
npx wrangler deploy
```

Then set the same values on every HomeScan host:

```
CLUSTER_WORKER_URL=https://homescan-cluster.<your-subdomain>.workers.dev
CLUSTER_SECRET=<the secret you put>
```
