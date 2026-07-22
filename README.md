# WCPOS Cloud Print

WCPOS Cloud Print is a small multi-tenant service that terminates printer-compatible TLS for Star CloudPRNT and Epson Server Direct Print devices, then forwards only the supported WCPOS print endpoints to registered sites over modern TLS. It keeps no print payloads, preserves the printer's existing authentication query string end to end, and can absorb idle polling while still forwarding job fetches and confirmations.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `RELAY_LISTEN` | No | `:8443` | Printer-facing HTTPS listen address. |
| `RELAY_HEALTH` | No | `127.0.0.1:8080` | Plain-HTTP health listen address. |
| `RELAY_CERT` | Yes | — | Path to the leaf-first full certificate chain. |
| `RELAY_KEY` | Yes | — | Path to the RSA private key. |
| `RELAY_SITES` | No | `sites.json` | Path to the JSON site registry. |
| `RELAY_PUBLIC_URL` | Yes | — | Public base URL, such as `https://cloudprint.wcpos.com`. |
| `RELAY_MODE` | No | `transparent` | Polling mode: `transparent` or `adaptive`. |
| `RELAY_MASTER_SECRET` | Yes | — | 64 hexadecimal characters (32 bytes) used to derive deterministic site keys. |
| `RELAY_HEARTBEAT` | No | `60s` | Maximum interval between origin polls in adaptive mode. |
| `RELAY_PENDING_TTL` | No | `120s` | Lifetime of a job-pending hint in adaptive mode. |

## API contract

| Endpoint | Auth | Request | Response |
|---|---|---|---|
| `POST /api/register` | none (rate-limited; proves consent via callback) | `{"site_url":"https://shop.example","verify_token":"<random>"}`; relay GETs `<site>/wp-json/wcpos/v1/print-jobs/relay-verification` expecting `{"token":"<same>"}` | `201 {"site_key":"<32hex>","hint_secret":"<64hex>","printer_base_url":"https://cloudprint.wcpos.com/p/<site_key>"}` |
| `POST /api/hint/{site_key}` | `X-Relay-Timestamp` (unix) + `X-Relay-Signature` = hex HMAC-SHA256(hint_secret, ts + "." + raw body); ±5 min window | `{"printer_id":"<id>"}` | `204` |
| `GET /api/status/{site_key}?printer_id=<id>` | same headers; signature payload = the printer_id string | — | `200 {"printer_id":"<id>","last_seen_seconds_ago":42|null,"origin_status":"ok|blocked|unknown","origin_block_signal":"cloudflare-challenge|http-403|…|"}` |
| `/p/{site_key}/cloudprnt` | printer's existing `pt` query token, passed through untouched | Star CloudPRNT POST/GET/DELETE | pass-through (or local `{"jobReady":false}` when gated) |
| `/p/{site_key}/epson-sdp` | same | Epson SDP POST | pass-through (or local `<response success="true" code="" status=""/>` when gated) |


## Registry backup cron

Create the remote directory and configure key-based access to the Hetzner Storage Box, then install this nightly cron entry on the host (replace the placeholders):

```cron
0 2 * * * /usr/bin/rsync -a /opt/wcpos-cloudprint/data/sites.json <storage-user>@<storage-host>:wcpos-cloudprint/sites.json
```

The registry contains no print payloads. Back up `RELAY_MASTER_SECRET` separately in the team password manager; it is not stored in `sites.json`.

## Deploying

CI builds and pushes `ghcr.io/wcpos/wcpos-cloudprint` on every `v*` tag. No repository secrets are needed (GHCR push uses the automatic `GITHUB_TOKEN`). To deploy on the box:

```
cd /opt/wcpos-cloudprint && docker compose pull && docker compose up -d
```

## Certificate

Free Let's Encrypt certificate with an **RSA key**, issued on the box (no TLS-terminating proxy or load balancer in front — the service must own its listener, that is the whole point):

```
certbot certonly --standalone -d cloudprint.wcpos.com --key-type rsa --rsa-key-size 2048
```

Copy `fullchain.pem`/`privkey.pem` into `/opt/wcpos-cloudprint/certs/` as `relay.crt`/`relay.key` on each renewal (certbot `--deploy-hook`). After first issuance, verify the served chain against a real printer on factory TLS settings; if legacy firmware rejects the Let's Encrypt chain, switch to a commercial RSA certificate with an older root.

## Container file ownership

The image runs as the distroless `nonroot` user (uid **65532**). The bind-mounted `certs/` and `data/` directories must be accessible to that uid or the process fails to read its key / write `sites.json`:

```
sudo chown -R 65532:65532 /opt/wcpos-cloudprint/data
sudo chmod 640 /opt/wcpos-cloudprint/certs/relay.key && sudo chown 65532 /opt/wcpos-cloudprint/certs/relay.key
```

Have the certbot `--deploy-hook` re-apply the key ownership after each renewal.
