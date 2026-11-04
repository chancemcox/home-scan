# HomeScan

HomeScan inventories home-network devices every minute, stores observations in SQLite, and serves a searchable dashboard at http://192.168.2.100:8080. Pi-hole retains port 80. The Docker app listens on container port 80, published as host port 8080.

## Device identity and status

MAC addresses are the unique identity. When the same MAC receives a different IP, its inventory entry and Cloudflare settings follow the new address. Separate network interfaces or randomized MACs are separate identities. An entry without a MAC is provisional and cannot enable Cloudflare sync. If a different MAC takes an old IP, it does not inherit the previous device's settings.

Network and Deco observations have separate presence states. A successful fresh observation shows Seen. A successful check that omits a device shows Not seen. Stale or unavailable checks show Status unavailable. Deco connection failures are silently skipped; saved devices and their original last-seen timestamps remain intact. Authentication failures retain a silent ten-minute cooldown; connection failures retry on the next scan.

The existing SQLite inventory is migrated automatically from IP keys to MAC keys. Historical sightings remain available in the database; detailed observations are retained for 30 days and the device inventory indefinitely. A database backup was created in the data volume before the MAC migration (`homescan.db.before-mac-cloudflare-*.bak`).

## Cloudflare per-device settings

Click **Configure** on a device with a known MAC address:

- **Local DNS sync** creates a DNS-only A record, for example `nas.local.chancecox.com -> 192.168.2.20`. It resolves to the private IP and needs LAN/VPN connectivity. DNS does not specify a service port. Use `http://nas.local.chancecox.com:8080` if the service requires port 8080.
- **Cloudflare Tunnel** publishes an HTTP or HTTPS service on a selectable origin port, for example `nas-web.local.chancecox.com -> http://192.168.2.20:8080`. The DNS record is a proxied CNAME to the dedicated HomeScan tunnel. When the IP changes, the tunnel's origin address changes; the CNAME remains pointed at the tunnel.
- Both can be enabled with **different hostnames**. One hostname cannot simultaneously be a private A record and a tunnel CNAME.
- Hostnames must be a single label below `local.chancecox.com`; enter a short label or the full hostname. A wildcard record is not created.
- Disabling a mode removes its HomeScan-managed DNS record and tunnel rule. Renaming removes the previous managed hostname. Unrelated DNS records or tunnel rules are not overwritten; conflicting hostnames show a descriptive error.

After each complete scan, a background worker reads the actual Cloudflare records and tunnel config. It writes only when the destination or settings differ, so it also repairs manual drift in HomeScan-owned records. Failed updates retry automatically and do not block network scanning. **Sync now** queues an immediate reconciliation. Unknown/stale devices retain their last confirmed address; if another MAC is observed taking that IP, their published mappings are removed until their own MAC gets a confirmed address.

Settings can be saved before connecting Cloudflare; they remain pending. The dashboard's Config synced state means the Cloudflare configuration matches, not that the destination service or public HTTPS certificate has been tested.

### Connect the account

Create a Cloudflare API token with:

- Zone / Zone / Read, scoped to `chancecox.com` (or a separately managed `local.chancecox.com` zone).
- Zone / DNS / Edit for that zone.
- Account / Cloudflare Tunnel / Edit for the zone's account, if using tunnels.

Run in PowerShell on this PC:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\homeScan\configure-cloudflare.ps1
```

The script prompts privately for the token, discovers the zone and account IDs, creates a dedicated remotely managed HomeScan tunnel, stores its connector token in a dedicated Docker volume, and starts the optional cloudflared service. It does not modify the existing Paperless tunnel. Re-running setup reuses the HomeScan tunnel. For DNS only, add `-LocalDnsOnly`; an existing HomeScan tunnel is not removed by this option.

The API token is stored in `/data/cloudflare.json` with owner-only file permissions, not in the dashboard, Docker image, command-line arguments, or Git. The connector token is in the `homescan-tunnel` volume, mounted read-only by cloudflared. Protect volume backups because the data volume includes credentials. The dashboard is intended for a trusted LAN; write endpoints reject cross-origin browser requests, but it has no user login.

The tunnel publishes the selected service to the Internet. Use the service's authentication or configure Cloudflare Access. For HTTPS names like `nas-web.local.chancecox.com`, a standard Universal SSL certificate on the `chancecox.com` zone does not cover that depth. Configure an appropriate edge certificate (for example Advanced Certificate Manager / Total TLS). No certificate purchases or account-plan changes are made by HomeScan. Local DNS-only HTTPS is handled by the local service's own certificate.

Cloudflare references:
- https://developers.cloudflare.com/tunnel/get-started/
- https://developers.cloudflare.com/dns/proxy-status/
- https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/

## Windows scanning

Docker Desktop cannot do physical LAN ARP discovery. `scanner.ps1` runs natively and submits observations to Docker. The **HomeScan Scanner** scheduled task runs at sign-in and scans `192.168.2.0/24,192.168.1.0/24` every minute. It pings targets, reads Windows neighbors, tries reverse DNS, and merges the Deco inventory. Windows neighbor caching means presence is approximate. Routed devices may have no MAC until reported by Deco.

```powershell
docker compose up -d --build
powershell -NoProfile -ExecutionPolicy Bypass -File C:\homeScan\scanner.ps1 -Subnet 192.168.2.0/24,192.168.1.0/24 -Server http://localhost:8080
```

Use `-Once` for a diagnostic scan. The existing task should normally be the only running scanner. The ingestion secret is loaded from `.env`; keep this file local. Windows Firewall rule **HomeScan HTTP 8080** permits TCP 8080 from the local subnet.

### Deco

The main Deco is an X10 at `192.168.86.233`, firmware 1.4.0. The read-only importer uses `tplink-deco-api==2.1.0`. Configure its owner password locally:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\homeScan\configure-deco.ps1
```

Credentials are saved in `.secrets/deco.json`, excluded from Git and the image, with the Windows folder restricted to the current user and SYSTEM. Online clients with usable IPv4 addresses are imported across any subnet. The reader tolerates complete JSON responses with a missing final HTTP chunk and rejects genuinely truncated JSON.

## Linux all-in-one scanner

On a Linux host directly attached to the subnet, set `SCAN_NETWORK` in `.env` and run:

```sh
docker compose -f compose.linux.yaml up -d --build
```

This mode runs Nmap host discovery with host networking every 60 seconds, times out after 50 seconds, and serves the dashboard on host port 80. MAC discovery works for directly connected subnets. The Cloudflare worker is also available in this deployment; the optional connector uses the same `cloudflare` profile. Account setup can be invoked inside the app container with `cloudflare_sync.py setup` and a JSON object on stdin containing `api_token` and `tunnel`.

## Operations and checks

- `docker compose logs -f homescan` — app logs.
- `docker compose --profile cloudflare logs -f cloudflared` — connector logs.
- `docker compose down` preserves named volumes; adding `-v` deletes data and credentials.
- SQLite: `/data/homescan.db` in `homescan-data`. Stop the app or use SQLite's backup API for a consistent copy.
- Read API: `/health`, `/api/devices`, `/api/cloudflare`.
- Scanner ingestion: authenticated `POST /api/scan`.
- Dashboard settings: same-origin JSON `POST /api/cloudflare/settings`, `/api/cloudflare/sync`.
- Tests: `test_cloudflare.py` (identity, migration, ownership, IP changes, retries, cleanup), `test_status.py`, `test_deco.py`.

Example test command in PowerShell:

```powershell
Get-Content test_cloudflare.py -Raw | docker compose exec -T homescan python -
```

Cloudflare reconciliation is tested against a simulated API. Live DNS and tunnel verification requires account setup and a selected hostname/service. Browser testing covered the per-device settings, hostname conflicts, mobile layout, preserving settings across DHCP changes, and request authentication checks.
