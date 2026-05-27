# Backend API

This project now treats the backend as a real scan service boundary rather than a same-origin helper for the browser app.

## Current scan resources

- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans?url=...`
- `GET /api/scans/:id`
- `GET /api/scans/:id/summary`
- `GET /api/scans/:id/findings`
- `GET /api/scans/:id/evidence`
- `GET /api/scans/:id/history`
- `GET /api/scans/:id/share` (public — no auth required)

`POST /api/scans` accepts an optional `mode`:

- `standard`: default bounded passive enrichment for normal product scans.
- `quiet`: lower-noise scans that skip page-body analysis, crawl, probe-heavy enrichment, OSV lookups, and CT host sampling.
- `deep-passive`: broader passive recon for release readiness and scheduled review passes. It expands CT host sampling, related-page crawl, exposure probes, and API-surface probes while keeping strict limits and timeout bounds.

Runtime controls:

- `SCAN_TIMEOUT_MS`: standard/quiet scan timeout, default `45000`.
- `DEEP_PASSIVE_SCAN_TIMEOUT_MS`: deep-passive timeout, default `75000`, never lower than `SCAN_TIMEOUT_MS`.
- `SCAN_CONCURRENCY`: in-process queued scan concurrency, default `2`.
- `STALE_RUNNING_SCAN_MS`: startup recovery threshold for scans left `running`, default `120000`.

## Current monitoring resources

- `POST /api/monitoring-targets`
- `GET /api/monitoring-targets`
- `GET /api/monitoring-targets/:id`
- `POST /api/monitoring-targets/:id/run`
- `DELETE /api/monitoring-targets/:id`

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

- `ALLOWED_ORIGINS=https://app.securl.online`

You can provide multiple origins as a comma-separated list if needed.

Example split deployment:

- Hostinger frontend: `https://app.securl.online`
- Railway backend: `https://securl-app-production.up.railway.app`
- frontend build env: `VITE_API_BASE_URL=https://securl-app-production.up.railway.app`
- backend runtime env: `ALLOWED_ORIGINS=https://app.securl.online`

## Why this matters

This is the first real separation step for future native clients:

- the browser app uses a typed API client
- the backend exposes explicit scan resources
- the frontend no longer assumes the backend only exists as same-origin helper routes
