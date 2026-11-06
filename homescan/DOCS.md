# HomeScan

HomeScan records devices on your LAN, keeps Cloudflare tunnel routes lined up with those devices, and can share one cluster address across HomeScan nodes.

## Install

1. In Home Assistant, open **Settings → Apps → Add-on store**.
2. Open the menu and choose **Repositories**.
3. Add `https://github.com/chancemcox/home-scan`.
4. Install **HomeScan**, set **Scan network** to your private subnet, and start the app.
5. Open **HomeScan** in the sidebar. Home Assistant has already signed you in.

## Options

- **Scan network**: private IPv4 subnet, at most 4096 addresses. Example: `192.168.1.0/24`.
- **Scan mode**: `nmap` scans from this host. `agent` waits for an external scanner and requires an ingest token of at least 32 characters.
- **This node's LAN IP**: optional address used when this node claims the shared cluster hostname.
- **Agent ingest token**: used only in agent mode.

The first local password, if you open the app outside the sidebar, is written to `/data/initial-admin-password.txt` inside the app.

Cloudflare credentials are saved from the Cloudflare setup screen and stored in the app data, not in these options.
