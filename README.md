# HomeScan

HomeScan inventories home-network devices, stores observations, and serves a searchable dashboard. Publish the app on host port **8080** by default (`compose.yaml`). Configure domains, credentials, and cluster settings for **your** network — nothing personal is baked into the code.

Copy `.env.example` to `.env` and fill in values before `docker compose up`.

## First login

On first boot HomeScan creates an `admin` user:

1. Set `HOMESCAN_ADMIN_PASSWORD` in `.env`, **or**
2. Read the generated password from `/data/initial-admin-password.txt` inside the app volume / container.

There is no shared default password in the image.

## Device identity and status

MAC addresses are the unique identity. When the same MAC receives a different IP, its inventory entry and Cloudflare settings follow the new address. Entries without a MAC are provisional and cannot enable Cloudflare sync.

Network and Deco observations have separate presence states. Deco connection failures are skipped silently; authentication failures use a short cooldown.

## Shared state options

- **Local SQLite** (`/data/homescan.db`) — default single-node store.
- **Durable Object SQL** (`worker/`) — preferred shared store when `CLUSTER_WORKER_URL` + `CLUSTER_SECRET` are set. All inventory, Cloudflare routes, settings, and logs live in the DO’s in-memory SQLite tables (also used for leader election + live inventory).
- **Cloudflare D1** — optional shared SQL fallback if the Durable Object worker is not configured (enable in Cloudflare setup; needs Account → D1 → Edit).

## Diagnostics

Errors are written to stderr and stored in the shared DB (`app_logs` in the Durable Object SQL store when configured, otherwise D1/local). Rows auto-expire after **30 days**. Every log line includes the deploy push id (`HOMESCAN_PUSH` / image `PUSH` file) so you can match failures to a commit.

```powershell
$env:HOMESCAN_PUSH = (git rev-parse --short HEAD)
docker compose up -d --build
```

Signed-in clients can read recent rows from `GET /api/logs`.

## Cloudflare per-device settings

Set your **base domain** under **Settings** (also set automatically from the zone you connect). Then use **Configure** on a device with a known MAC:

- **Local DNS sync** — DNS-only A record under your base domain (for example `nas.lan.example.com` → private IP).
- **Cloudflare Tunnel** — short label under the base domain, or any full hostname on a zone the token can edit.
- Both modes need different hostnames when enabled together.

### Connect the account

Create a Cloudflare API token with Zone Read, DNS Edit, Tunnel Edit (optional), and D1 Edit (optional). Paste it under **Cloudflare setup**, or run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\configure-cloudflare.ps1 [-Suffix lan.example.com]
```

Tokens and tunnel connector secrets stay in Docker volumes, not in Git.

## Cluster failover

Set per host in `.env`:

- `HA_LOCAL_IP` — this machine’s LAN IP (required under Docker)
- `HA_HOSTNAME` — shared name scanners use (or leave empty to use `homescan.<base-domain>` once Settings has a domain)
- Optional: `HA_ENABLED`, `HA_PORT`, `CLUSTER_WORKER_URL`, `CLUSTER_SECRET`

With a Durable Object worker configured, leadership is leased there. DNS for `HA_HOSTNAME` still points browsers/scanners at the active node.

## Windows scanning

```powershell
docker compose up -d --build
powershell -NoProfile -ExecutionPolicy Bypass -File .\scanner.ps1 -Subnet 192.168.1.0/24
```

Default ingest URL is `http://127.0.0.1:8080`, or set `HOMESCAN_SERVER` / `-Server` to your cluster hostname.

### Deco

Optional TP-Link Deco import is configured in **Settings** (or `configure-deco.ps1`). Credentials live in `/data/deco.json`.

## Linux all-in-one

```bash
docker compose -f compose.linux.yaml up -d --build
```

Uses host networking and Nmap. Set `SCAN_NETWORK` for your subnet.

## Durable Object worker

```bash
cd worker
npm install
npx wrangler secret put CLUSTER_SECRET
npx wrangler deploy
```

Put the resulting `https://<worker>.workers.dev` URL and the same secret into `.env` as `CLUSTER_WORKER_URL` / `CLUSTER_SECRET` on every HomeScan node.

## Operations

- `docker compose logs -f homescan`
- `docker compose --profile cloudflare logs -f cloudflared`
- Named volumes keep data across `docker compose down` (add `-v` to wipe)
