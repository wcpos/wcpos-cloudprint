# WCPOS Cloud Print

WCPOS Cloud Print is a small multi-tenant relay for Star CloudPRNT and Epson Server Direct Print polling printers. Printers poll `https://cloudprint.wcpos.com/p/<site_key>/…`; the relay forwards only the two supported WCPOS print endpoints to registered sites. It keeps no print payloads, preserves the printer's existing authentication query string end to end, and absorbs idle polling (an idle printer costs the site ~1 request/minute instead of ~12) while always forwarding job fetches and confirmations.

The service is plain HTTP on port `8080`. TLS is terminated by the Coolify Traefik proxy in front of the container (see below).

## Configuration

One secret, no other configuration — every other knob is a compile-time constant in `config.go`.

| Variable | Purpose |
|---|---|
| `RELAY_MASTER_SECRET` | 64 hexadecimal characters (32 bytes). Derives the deterministic `site_key` for every registered site — must stay stable for the life of the service. Stored as a Coolify secret and backed up in the team password manager. |

## API contract

| Endpoint | Auth | Request | Response |
|---|---|---|---|
| `POST /api/register` | none (rate-limited; proves consent via callback) | `{"site_url":"https://shop.example","verify_token":"<random>"}`; relay GETs `<site>/wp-json/wcpos/v1/print-jobs/relay-verification` expecting `{"token":"<same>"}` | `201 {"site_key":"<32hex>","hint_secret":"<64hex>","printer_base_url":"https://cloudprint.wcpos.com/p/<site_key>"}` |
| `POST /api/hint/{site_key}` | `X-Relay-Timestamp` (unix) and `X-Relay-Signature` = hex HMAC-SHA256(hint_secret, method + `"\n"` + path + `"\n"` + timestamp + `"\n"` + raw body); path excludes the query string; ±5 min window | `{"printer_id":"<id>"}` | `204` |
| `GET /api/status/{site_key}?printer_id=<id>` | same headers and HMAC input; payload is the `printer_id` string | — | `200 {"printer_id":"<id>","last_seen_seconds_ago":42,"origin_status":"ok","origin_block_signal":"http-403"}`; last seen may be `null`, status is `ok`, `blocked`, or `unknown`, and the signal may be empty or identify Cloudflare or an HTTP status |
| `GET /healthz` | none | — | `200 ok` |
| `/p/{site_key}/{printer_id}/{pt}/cloudprnt` | `pt` token in the path; the relay replaces `wcpos`, `printer_id`, and `pt` from the path while preserving the printer's runtime query parameters | Star CloudPRNT POST/GET/DELETE | pass-through (or local `{"jobReady":false}` when gated) |
| `/p/{site_key}/{printer_id}/{pt}/epson-sdp` | same | Epson SDP POST | pass-through (or local `<response success="true" code="" status=""/>` when gated) |
| `/p/{site_key}/cloudprnt` | legacy: printer's existing `pt` query token, passed through untouched | Star CloudPRNT POST/GET/DELETE | pass-through |
| `/p/{site_key}/epson-sdp` | legacy: same | Epson SDP POST | pass-through |

Path-credential URLs exist because Star printers (verified on a TSP100IV) URL-encode the configured query string on the wire — every `&` becomes `%26` — so `printer_id` and `pt` never arrive as query parameters. The path is transmitted verbatim. The relay replaces the credential values from the path and forwards the printer's runtime parameters, such as `t`, `token`, and `type`. New printer URLs are always issued in path form; the query form remains for URLs already burned into printer configs.

## Deployment (Coolify)

Any push to `main` is auto-deployed by Coolify using the **Docker Compose build pack** (`docker-compose.yml` at the repo root). The compose file is deliberately minimal: no `ports:` mapping and no TLS anywhere — Traefik routes to the container's port 8080 and terminates TLS. App settings in Coolify:

- **Domain:** `https://cloudprint.wcpos.com` on the `relay` service (port 8080).
- **Secret:** `RELAY_MASTER_SECRET` (the only env var; referenced by the compose file).
- **Volume:** the compose file declares `relay-data` mounted at `/data` (holds `sites.json`). The image runs as the distroless `nonroot` user (uid **65532**), so the volume directory must be writable by that uid: `chown -R 65532:65532` its host path once.
- **Health check:** none, on purpose — the distroless image has no shell for one to exec. Point external uptime monitoring at `https://cloudprint.wcpos.com/healthz` instead.
- **DNS:** `cloudprint.wcpos.com` is a plain A record to the box. Never put it behind a CDN — a CDN edge in front of the relay recreates the exact printer-TLS failure this service exists to fix.

Losing `sites.json` is recoverable without touching printers: site keys are deterministic, and the plugin re-registers automatically, so no separate backup is required. Losing `RELAY_MASTER_SECRET` is not — back it up in the team password manager.

## TLS and legacy printers

Traefik (Coolify's proxy) terminates TLS with a Let's Encrypt RSA certificate. As verified against this box's edge, it accepts TLS 1.2 with the `ECDHE_RSA` GCM and CBC suites from the TSP100IV specification (§10.3.2), and serves the certificate chain cross-signed back to **ISRG Root X1** — a root present in printer firmware CA bundles since ~2016. The acceptance test is a real TSP100IV on factory TLS settings.

If a legacy printer still fails the handshake, do **not** add TLS handling to this service — widen Traefik's cipher list for this app only, via Coolify → Proxy → Dynamic Configurations:

```yaml
tls:
  options:
    printers:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        - TLS_RSA_WITH_AES_128_GCM_SHA256
        - TLS_RSA_WITH_AES_256_GCM_SHA384
        - TLS_RSA_WITH_AES_128_CBC_SHA
        - TLS_RSA_WITH_AES_256_CBC_SHA
```

then attach it to the cloudprint router with the label `traefik.http.routers.<router>.tls.options=printers@file`. If even that fails (chain trust rather than ciphers), load a commercial RSA certificate with an older root into Traefik for this hostname — still no TLS code in this service.

## Development

```sh
go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs gofmt, `go vet`, and the race-enabled test suite on every push and pull request.
