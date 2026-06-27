# Backend API

This project now treats the backend as a real scan service boundary rather than a same-origin helper for the browser app.

For client integration guidance, see [`CONSUMER-API-MAP.md`](CONSUMER-API-MAP.md).

## Current service metadata resources

- `GET /api/health`
- `GET /api/capabilities`
- `GET /api/certificates/live?url=...`

`GET /api/capabilities` is public and additive. It lets web, mobile, CLI, and future SDK clients discover supported API version, scan modes, auth modes, monitoring resources, export formats, package versions, and passive-safety boundaries without relying on hard-coded assumptions.

## Optional client identity headers

First-party and third-party clients may identify their product and release on any API request with:

- `X-SecURL-Client`: a stable product identifier such as `securl-ios`, `header-watch-ios`, `cert-watch-ios`, `securl-web`, or a reverse-domain app id.
- `X-SecURL-Client-Version`: a release/build identifier such as `1.2.0+19`.

Both headers are optional and additive. Existing clients require no changes. Values are treated as aggregate product telemetry only: identifiers are lowercased and limited to 64 characters, versions are limited to 40 characters, whitespace, free-form values, UUIDs, and long hexadecimal identifiers are rejected, and aggregate bucket cardinality is capped. No device identifier is requested or inferred. Invalid values are silently ignored rather than failing the API request.

Mobile clients should set these headers alongside `X-Scan-Owner` on every request. The backend then separates scan requests and service usage by product/version without storing personal data. Support is advertised by `service.clientTelemetry` in `GET /api/capabilities`.

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
- `GET /api/scans/:id/observations`
- `GET /api/scans/:id/observation-drift`
- `GET /api/scans/:id/policy-evaluation`
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
- `SCAN_CONCURRENCY`: per-worker queued scan concurrency, default `2`.
- `STALE_RUNNING_SCAN_MS`: recovery threshold for scans left `running`, default `120000`.
- `MONITORING_SCHEDULER_ENABLED`: enables backend-owned due target sweeps when set to `true`, default `false`.
- `MONITORING_SWEEP_INTERVAL_MS`: due target sweep interval, default `900000`, minimum `60000`.
- `MONITORING_SWEEP_LIMIT`: maximum due targets queued per sweep, default `20`.
- `MONITORING_SCAN_MODE`: scan mode for scheduled monitoring sweeps, default `quiet`.

`GET /api/scans/:id/comparison` returns the completed scan summary, the previous completed scan summary for the same URL and owner when available, and the same diff/risk-event payload used by target history and monitoring detail views.

`GET /api/scans/:id/digest` returns a compact posture digest for lightweight clients. `GET /api/scans/:id/insights` returns a display-ready posture intelligence layer: risk themes, top insights, and next-best actions derived from the action plan without requiring clients to interpret raw findings. `GET /api/scans/:id/observations` returns Observation Ledger v1: deterministic, source-aware evidence records with explicit status, confidence, observation time, and freshness. `GET /api/scans/:id/observation-drift` compares those stable records with the previous completed scan and classifies regressions, improvements, and neutral changes without treating ordinary certificate-day decay as an alert. `GET /api/scans/:id/brief` returns a concise exposure brief for mobile, CLI, and report clients that need the highest-priority public entry points, trust gaps, abuse indicators, and next actions without loading the full evidence payload. `GET /api/scans/:id/vendors` returns a compact vendor and supply-chain exposure brief covering third-party providers, visible data-flow categories, SRI gaps, priority vendors, and next actions. `GET /api/scans/:id/action-plan` returns a prioritized fix narrative that combines remediation, score drivers, exposure brief, and vendor context into owner/effort/impact-ranked actions. `GET /api/scans/:id/drift` returns the existing high-level drift/risk-event analysis. Export resources return machine-readable JSON, Markdown, SARIF, or CI JSON once the scan is complete.

`GET /api/scans/:id/events` returns a Server-Sent Events stream of scan lifecycle events and closes after `scan_terminal`. Mobile clients can use this instead of polling the full scan detail response while a scan is queued or running.

Posture monitoring targets may include an optional `policy` object when created or updated through `POST /api/monitoring-targets`. Policies are limited to 25 declarative rules and support exact kind, kind-prefix, or category selectors with `eq`, `neq`, `in`, `gte`, and `lte` assertions. Rules can evaluate current observations or observation changes. Invalid or executable policy content is rejected. Targets without a custom policy use `securl-baseline-v1`. `GET /api/scans/:id/policy-evaluation` resolves the matching target policy when available and otherwise evaluates the maintained baseline.

Production scan jobs are durable when the Postgres repository is enabled. Each worker atomically leases queued rows before execution, so multiple Railway instances cannot run the same scan concurrently. Startup and periodic recovery rebuild work from persisted rows; interrupted running scans are requeued with a bounded three-attempt policy before becoming failed. Lease and attempt metadata are internal and do not change public scan payloads.

## Current certificate resources

`GET /api/certificates/live?url=...` performs a bounded TLS handshake only. It returns the served certificate expiry, issuer, subject, SANs, fingerprint, serial number, negotiated protocol/cipher, key hints, and observed chain without running the full posture scanner.

Certificate monitoring history entries include additive event context for Cert Watch timelines: event severity, title/detail text, expiry warning band, previous issuer/serial/expiry/day count, and day-count delta. First-seen expired, expiring, or unreachable certificates do not fire a transition push, but their attention state and first-seen attention type are stored so mobile clients can still show the problem immediately.

Smoke-check the live API contract with:

```sh
npm run smoke:api
```

The smoke command checks health, readiness, capabilities, scan creation, scan detail resources, digest/brief/vendors/action-plan/events/evidence/observations resources, live certificate lookup, comparison/drift resources, export formats, and the public share resource.

Optional overrides:

```sh
npm run smoke:api -- --base-url=https://securl-app-production.up.railway.app --target=https://securl.online --mode=quiet
```

## Current monitoring resources

- `POST /api/monitoring-targets`
- `GET /api/monitoring-targets`
- `GET /api/monitoring-mobile-summary`
- `GET /api/monitoring-targets/:id`
- `GET /api/monitoring-targets/:id/history`
- `POST /api/monitoring-targets/:id/run`
- `DELETE /api/monitoring-targets/:id`

`GET /api/monitoring-mobile-summary` returns a compact owner-scoped view for the iOS apps. Each target keeps the existing `latestScan`, `latestDigest`, `cert`, `posture`, and `changes` fields, and also includes additive mobile hints:

- `status`: stable machine state such as `stable`, `pending`, `due`, `changed`, or `needs_attention`, with severity and reason.
- `change`: the most relevant posture or certificate change summary for compact list/detail UI.
- `nextCheck`: cadence, scheduled time, due flag, seconds until due, and last checked time.
- `actions`: short stable action ids and labels, such as `review_posture_regression`, `review_certificate`, `check_tls_endpoint`, or `run_scheduled_check`.

These fields are derived server-side from stored scan drift, certificate attention, and scheduler timing so mobile clients do not need to fetch full scan detail just to render watch-list state.

## Current notification resources

- `POST /api/notification-devices`
- `GET /api/notification-devices`
- `GET /api/notification-devices/health`
- `POST /api/notification-devices/:id/test`
- `DELETE /api/notification-devices/:id`

`POST /api/notification-devices` registers an iOS APNs device token against the same owner boundary used for scans and monitoring targets. The backend never echoes the raw token in list responses. When `MONITORING_SCHEDULER_ENABLED=true`, scheduled monitoring scans can send APNs alerts when a registered target's grade, score, headers, certificate window, or risk events change.

`POST /api/notification-devices/:id/test` sends one owner-scoped test notification to an active registration. It returns `200` only when APNs accepts the notification and `503` with a sanitized delivery result when delivery is unavailable or fails. The raw device token is never returned.

APNs delivery is enabled when these credentials are configured:

- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- `APNS_PRIVATE_KEY`

Each device registration's `appId` is used as its APNs topic, allowing SecURL, Header Watch, and Cert Watch to share the same provider key. `APNS_BUNDLE_ID` is an optional fallback for registrations without an app id. `APNS_TIMEOUT_MS` controls the per-attempt deadline (default `10000`) and `APNS_MAX_ATTEMPTS` controls bounded delivery attempts (default `3`, maximum `5`).

Transient network errors, timeouts, `429`, and `5xx` responses are retried with short bounded backoff. Tokens are disabled only for APNs `Unregistered`, `BadDeviceToken`, or `DeviceTokenNotForTopic` responses; topic, payload, and provider-auth errors remain visible as recoverable delivery failures.

Every device delivery is first written to a durable, idempotent notification outbox. Postgres workers claim pending rows with leases and `SKIP LOCKED`, reclaim work after interrupted workers, and retry recoverable failures on a bounded delayed schedule. APNs collapse identifiers reduce duplicate-visible alerts during at-least-once recovery. Completed outbox rows are retained for seven days and then pruned in bounded batches.

## Policy alert destinations

- `POST /api/alert-destinations`
- `GET /api/alert-destinations`
- `POST /api/alert-destinations/:id/test`
- `DELETE /api/alert-destinations/:id`

Alert destinations require an authenticated user session or user API key; anonymous scan-owner tokens cannot create network or email delivery. Each account is limited to ten destinations. Supported types are `webhook` and `email`; APNs continues to use notification-device registrations.

Webhook URLs must use HTTPS and cannot contain credentials, query parameters, or fragments. They are checked for public-only DNS at registration and again at delivery, and the outbound socket is pinned to the validated addresses to close DNS-rebinding gaps. Redirects are not followed. Payloads include `X-SecURL-Timestamp` and `X-SecURL-Signature: sha256=<hmac>` headers; the webhook signing secret is returned when the destination is created and is never returned by list endpoints.

Email delivery uses Resend when both `RESEND_API_KEY` and `ALERT_EMAIL_FROM` are configured. Without both values, email rows remain queued for bounded retry rather than being silently discarded.

Policy alerts are generated only for newly introduced violation fingerprints. Existing unresolved violations do not notify on every scan. Alert payloads keep the raw policy fields and also include a compact `brief`, `summary.newBySeverity`, categorized violation entries, and stable `actions` so mobile, web, webhook, and email clients can render the incident without interpreting policy internals. APNs is attempted immediately, while webhook and email deliveries are persisted to a separate idempotent outbox with leases, stale-worker recovery, bounded retry, audit status, and seven-day completed-row retention.

Without APNs credentials, device registration and monitoring continue normally, while delivery is recorded as skipped.

## Telemetry readout

When the production telemetry endpoint is explicitly exposed for admin use, `GET /api/telemetry` includes `clients.consumption` and `clients.identity`. The consumption readout rolls up backend-owned client activity that frontend analytics may miss: monitoring target registrations, mobile monitoring summary reads, APNs device registrations, notification health reads, and live certificate reads. Identity separates scan requests and service events by the optional product/version headers. It stores aggregate labels and counts only, not owner tokens, APNs tokens, device ids, IP addresses, or raw user agents.

`notifications.delivery` reports aggregate batches, devices attempted, APNs attempts, sends, failures, retries, disabled invalid tokens, skipped reasons, channels, and today's counters. Notification payloads and device tokens are not retained in telemetry.

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
