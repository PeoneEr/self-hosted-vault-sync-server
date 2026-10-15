# Self-Hosted Vault Sync — Server

Companion sync server for the [Self-Hosted Vault Sync](https://github.com/PeoneEr/self-hosted-vault-sync)
Obsidian plugin. Content-addressable blob storage, append-only changelog
for delta sync, Server-Sent Events for real-time push, and per-device
tokens with in-app pairing (no shared secret to copy between devices).

## Quick start (Docker Compose)

Requires [Docker](https://docs.docker.com/get-docker/) with the Compose
plugin (`docker compose`, not the old standalone `docker-compose`).

```bash
curl -O https://raw.githubusercontent.com/PeoneEr/self-hosted-vault-sync-server/main/docker-compose.yml
docker compose up -d
docker compose logs -f vault-sync
```

Watch the logs for a line like:

```
bootstrap device token (save this now — it will not be shown again): <64 hex chars>
```

Copy that token — it's what you paste into the plugin's Server URL / Auth
token fields on your **first** device. Every device after that is paired
in-app (Settings → "Pair new device" in the plugin), no more manual token
copying.

**Verify it's up** before configuring the plugin (replace `<token>`):

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/devices
# expect: [{"id":"dev_...","label":"bootstrap", ...}]
```

## Exposing it to your other devices

The Quick start above only listens on `localhost:8080` — fine for a
desktop-only test, useless for the actual point of this plugin: syncing a
phone that's on cellular data, not your home LAN. Pick one:

**Option A — Tailscale (simplest for one person).** Install
[Tailscale](https://tailscale.com/download) on the machine running the
server and on every device you want to sync. Point the plugin's Server URL
at the server's Tailscale hostname/IP, e.g. `http://my-server:8080` (no
port-forwarding, no domain, no certificate needed — Tailscale's own
WireGuard tunnel already encrypts everything between your devices, so
plain HTTP inside it is fine).

**Option B — Reverse proxy with a real domain.** If you already have a
domain pointed at your server, put a TLS-terminating reverse proxy in
front of container port `8080` and use `https://sync.yourdomain.com` as
the plugin's Server URL. [Caddy](https://caddyfile.app/) is the least
fuss — it gets a Let's Encrypt certificate automatically from a two-line
Caddyfile:

```
sync.yourdomain.com {
  reverse_proxy localhost:8080
}
```

(nginx + certbot works too if you already run nginx — just proxy `/` to
`127.0.0.1:8080` and point Certonly at the same domain.)

**Do not** expose port `8080` directly to the internet without one of the
above. The bearer token is the only thing standing between anyone and your
vault — sent in plaintext over unencrypted HTTP, it's readable by anything
between you and the server.

## Backups and updates

`./data` (the Compose volume) holds everything: content-addressable blobs,
the changelog, and `tokens.json` (your paired devices). It's the only copy
outside your devices' own vaults — back it up like you would any other
data directory.

To update to a new release:

```bash
docker compose pull && docker compose up -d
```

## Configuration

| Env var          | Default | Purpose                                                              |
|-------------------|---------|------------------------------------------------------------------------|
| `PORT`            | `8080`  | HTTP listen port                                                       |
| `DATA_DIR`        | `/data` | Where blobs, the changelog, and `tokens.json` are stored               |
| `BOOTSTRAP_TOKEN` | (unset) | Seed a specific first-device token instead of generating one randomly  |
| `ADMIN_TOKEN`     | (unset) | Enables the `/admin` web UI (see below). Unset = `/admin*` return 404  |
| `AUDIT_RETENTION_DAYS` | `30` | How long the activity journal (`audit.jsonl`) is kept              |
| `TRUST_PROXY_HEADERS` | `false` | Take the client IP in the journal from `X-Forwarded-For`. Only set to `true` behind a proxy that overwrites that header |

## API

- `GET /changes?since=<unix-ts>` — changelog entries newer than `since`
- `GET /file/{path}`, `PUT /file/{path}`, `DELETE /file/{path}` — content-addressed file ops (`X-Base-Hash` header for conflict detection)
- `GET /events` — Server-Sent Events stream of changes
- `POST /pair` — body `{"label": "phone"}`, issues a new device token
- `GET /devices` — list paired devices (no tokens)
- `DELETE /devices/{id}` — revoke a device

All endpoints except the unauthenticated preflight (`OPTIONS`) require
`Authorization: Bearer <device-token>`.

## Admin web UI

Set `ADMIN_TOKEN` to a long random value (separate from any device token) and
open `/admin`. After entering the token you see every issued device token
(label, created, last seen, a 24 h polling sparkline) and the activity log:
file uploads/deletes, SSE connects/disconnects, tokens issued/revoked, and
failed authentications (with IP). A **Revoke** button cuts a token off
immediately — handy if a phone is lost and you only have a browser.

- `ADMIN_TOKEN` opens only `/admin/api/*`; it cannot sync files, and device
  tokens cannot open the admin API.
- Failed admin logins are journaled and rate-limited (10 per minute per IP, then `429`).
- High-frequency requests (`GET /changes`, `GET /file/...`) are not logged line by
  line, only counted per device and hour.
- The journal lives in `DATA_DIR/audit.jsonl` and is pruned after `AUDIT_RETENTION_DAYS`.

Admin API (Bearer `ADMIN_TOKEN`): `GET /admin/api/devices`,
`DELETE /admin/api/devices/{id}`,
`GET /admin/api/events?device=&event=&exclude=&since=<RFC3339>&limit=`,
`GET /admin/api/stats`.

## Other deployment options

- **Kubernetes**: a generic Helm chart is in [`deploy/helm/`](deploy/helm/).
  It doesn't manage the auth-token secret for you — create it yourself and
  point `auth.existingSecret` at it (see comments in
  [`values.yaml`](deploy/helm/values.yaml)). Ingress is optional and off by
  default (`ingress.enabled: false`) — turn it on and adapt `className`/
  `host`/TLS to your own cluster. (This project's own author runs a
  separate, environment-specific chart in `.helm/` against ArgoCD/Vault —
  not published here, since it's wired to one specific cluster.)
- **Plain Docker**: `docker run -v $(pwd)/data:/data -p 8080:8080 ghcr.io/peoneer/self-hosted-vault-sync-server:latest`

## License

MIT — see [LICENSE](LICENSE).
