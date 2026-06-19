# Backend API

This project now treats the backend as a real scan service boundary rather than a same-origin helper for the browser app.

For client integration guidance, see [`CONSUMER-API-MAP.md`](CONSUMER-API-MAP.md).

## Current service metadata resources

- `GET /api/health`
- `GET /api/capabilities`
- `GET /api/certificates/live?url=...`

`GET /api/capabilities` is public and additive. It lets web, mobile, CLI, and future SDK clients discover supported API version, scan modes, auth modes, monitoring resources, export formats, package versions, and passive-safety boundaries without relying on hard-coded assumptions.

## Current scan resources

- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans?url=...`
- `GET /api/scans/:id`
- `GET /api/scans/:id/summary`
- `GET /api/scans/:id/findings`
- `GET /api/scans/:id/digest`
- `GET /api/scans/:id/brief`
- `GET /api/scans/:id/vendors`
- `GET /api/scans/:id/action-plan`
- `GET /api/scans/:id/events`
- `GET /api/scans/:id/evidence`
- `GET /api/scans/:id/history`
- `GET /api/scans/:id/comparison`
- `GET /api/scans/:id/drift`
- `GET /api/scans/:id/export?format=json|markdown|sarif|ci-json`
- `GET /api/scans/:id/share` (public — no auth required)

`POST /api/scans` accepts an optional `mode`:

- `standard`: default bounded passive enrichment for normal product scans.
- `quiet`: lower-noise scans that skip page-body analysis, crawl, probe-heavy enrichment, OSV lookups, and CT host sampling.
- `deep-passive`: broader passive recon for release readiness and scheduled review passes. It expands CT host sampling, related-page crawl, exposure probes, and API-surface probes while keeping strict limits and timeout bounds.

Successful `POST /api/scans` responses include a `resources` object with relative paths for follow-up reads such as `events`, `digest`, `summary`, `evidence`, `comparison`, and `drift`. Clients can use these links instead of constructing endpoint paths themselves.

Runtime controls:

- `SCAN_TIMEOUT_MS`: standard/quiet scan timeout, default `45000`.
- `DEEP_PASSIVE_SCAN_TIMEOUT_MS`: deep-passive timeout, default `75000`, never lower than `SCAN_TIMEOUT_MS`.
- `SCAN_CONCURRENCY`: in-process queued scan concurrency, default `2`.
- `STALE_RUNNING_SCAN_MS`: startup recovery threshold for scans left `running`, default `120000`.
- `MONITORING_SCHEDULER_ENABLED`: enables backend-owned due target sweeps when set to `true`, default `false`.
- `MONITORING_SWEEP_INTERVAL_MS`: due target sweep interval, default `900000`, minimum `60000`.
- `MONITORING_SWEEP_LIMIT`: maximum due targets queued per sweep, default `20`.
- `MONITORING_SCAN_MODE`: scan mode for scheduled monitoring sweeps, default `quiet`.

`GET /api/scans/:id/comparison` returns the completed scan summary, the previous completed scan summary for the same URL and owner when available, and the same diff/risk-event payload used by target history and monitoring detail views.

`GET /api/scans/:id/digest` returns a compact posture digest for lightweight clients. `GET /api/scans/:id/brief` returns a concise exposure brief for mobile, CLI, and report clients that need the highest-priority public entry points, trust gaps, abuse indicators, and next actions without loading the full evidence payload. `GET /api/scans/:id/vendors` returns a compact vendor and supply-chain exposure brief covering third-party providers, visible data-flow categories, SRI gaps, priority vendors, and next actions. `GET /api/scans/:id/action-plan` returns a prioritized fix narrative that combines remediation, score drivers, exposure brief, and vendor context into owner/effort/impact-ranked actions. `GET /api/scans/:id/drift` returns the same drift/risk-event analysis used for monitoring when previous scans exist. Export resources return machine-readable JSON, Markdown, SARIF, or CI JSON once the scan is complete.

`GET /api/scans/:id/events` returns a Server-Sent Events stream of scan lifecycle events and closes after `scan_terminal`. Mobile clients can use this instead of polling the full scan detail response while a scan is queued or running.

## Current certificate resources

`GET /api/certificates/live?url=...` performs a bounded TLS handshake only. It returns the served certificate expiry, issuer, subject, SANs, fingerprint, serial number, negotiated protocol/cipher, key hints, and observed chain without running the full posture scanner.

Smoke-check the live API contract with:

```sh
npm run smoke:api
```

The smoke command checks health, readiness, capabilities, scan creation, scan detail resources, digest/brief/vendors/action-plan/events/evidence resources, live certificate lookup, comparison/drift resources, export formats, and the public share resource.

Optional overrides:

```sh
npm run smoke:api -- --base-url=https://securl-app-production.up.railway.app --target=https://securl.online --mode=quiet
```

## Current monitoring resources

- `POST /api/monitoring-targets`
- `GET /api/monitoring-targets`
- `GET /api/monitoring-targets/:id`
- `POST /api/monitoring-targets/:id/run`
- `DELETE /api/monitoring-targets/:id`

## Current notification resources

- `POST /api/notification-devices`
- `GET /api/notification-devices`
- `DELETE /api/notification-devices/:id`

`POST /api/notification-devices` registers an iOS APNs device token against the same owner boundary used for scans and monitoring targets. The backend never echoes the raw token in list responses. When `MONITORING_SCHEDULER_ENABLED=true`, scheduled monitoring scans can send APNs alerts when a registered target's grade, score, headers, certificate window, or risk events change.

APNs delivery is disabled until all of these are configured:

- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- `APNS_PRIVATE_KEY`
- `APNS_BUNDLE_ID`

Without those values, device registration still works and monitoring scans continue normally, but delivery is logged as skipped.

## Current auth resources

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/session`
- `POST /api/auth/logout`

Monitoring targets are currently scoped by the same client-owned `X-Scan-Owner` token as scan resources.

The collection payload includes:

- target metadata
- cadence
- due/next-due state
- latest completed scan summary when available
- previous completed scan summary when available
- simple score delta when available

The detail payload includes:

- target metadata and due state
- recent scan summaries for that target
- latest-vs-previous comparison when two completed scans exist
- recent lifecycle events aggregated from recent scans

When `MONITORING_SCHEDULER_ENABLED=true`, the backend periodically queues due monitoring targets itself. The scheduler uses the same scan queue as user-triggered scans and skips targets that already have a queued or running scan.

## Auth model

The backend now supports two client auth modes:

### Preferred: bearer session auth

Registered clients can authenticate with:

- `Authorization: Bearer <session-token>`

That mode gives us:

- user-owned scans and monitoring targets
- a stable ownership boundary across browsers and future mobile clients
- a cleaner path to shared SDKs and future paid tiers

### Transitional fallback: browser-owned scan token

Unauthenticated browser-style clients can still scope scan resources with:

- `X-Scan-Owner`

That mode remains available as a migration bridge. It still gives us:

- resource scoping per client
- fewer shared-IP collisions
- a non-shared fallback for anonymous use

But it is no longer the long-term auth story.

## Web client base URL

The web app can now target a separate backend origin by setting:

- `VITE_API_BASE_URL`

Examples:

- local integrated mode: leave unset and the app will call relative `/api/...` routes
- split frontend/backend mode: `VITE_API_BASE_URL=https://api.securl.online`

## Cross-origin frontend support

When the frontend is hosted separately from the Node backend, the API now supports browser CORS for approved origins.

Set:

- `ALLOWED_ORIGINS=https://app.securl.online,https://securl.online`

You can provide multiple origins as a comma-separated list if needed.

Example split deployment:

- Hostinger marketing site: `https://securl.online`
- Hostinger frontend app: `https://app.securl.online`
- Railway backend: `https://securl-app-production.up.railway.app`
- frontend build env: `VITE_API_BASE_URL=https://securl-app-production.up.railway.app`
- backend runtime env: `ALLOWED_ORIGINS=https://app.securl.online,https://securl.online`

## Why this matters

This is the first real separation step for future native clients:

- the browser app uses a typed API client
- the backend exposes explicit scan resources
- the frontend no longer assumes the backend only exists as same-origin helper routes
