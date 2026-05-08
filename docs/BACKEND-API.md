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

## Current monitoring resources

- `POST /api/monitoring-targets`
- `GET /api/monitoring-targets`
- `GET /api/monitoring-targets/:id`
- `POST /api/monitoring-targets/:id/run`
- `DELETE /api/monitoring-targets/:id`

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

## Scan-owner model

Unauthenticated browser-style clients currently authenticate scan resources with a client-owned token sent in:

- `X-Scan-Owner`

That token is still a transitional model, not the final multi-user auth story, but it gives us:

- resource scoping per client
- fewer shared-IP collisions
- a service contract that mobile clients can also use until real user auth lands

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
