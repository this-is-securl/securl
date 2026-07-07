# Consumer API Map

Use this map when building web, iOS, CLI, report, or automation clients. The full scan result remains available, but most product surfaces should prefer the smaller purpose-built resources below.

## Primary Product Clients

For web and mobile experiences, prefer:

- `GET /api/scans/:id/summary`: scan lifecycle, score, grade, and target metadata.
- `GET /api/scans/:id/digest`: compact posture overview, signal clarity, top findings, score drivers, controls, trust, evidence quality, and timing.
- `GET /api/scans/:id/insights`: display-ready risk themes, top insights, and next-best actions for mobile/web summary screens.
- `GET /api/scans/:id/mobile-summary`: one-call app result payload containing scan summary, digest, and insights after scan completion.
- `GET /api/scans/:id/brief`: outside-observer exposure brief with public entry points, trust gaps, abuse indicators, and next actions.
- `GET /api/scans/:id/vendors`: vendor and supply-chain exposure brief with third-party providers, data-flow categories, SRI gaps, and review priorities.
- `GET /api/scans/:id/action-plan`: prioritized fix narrative combining remediation, evidence, score drivers, exposure, and vendor context.
- `GET /api/scans/:id/observations`: stable source, confidence, status, and freshness-aware observations for monitoring, inventory, and integrations.
- `GET /api/scans/:id/observation-drift`: observation-level added, removed, status, value, and confidence changes against the previous completed scan.
- `GET /api/scans/:id/policy-evaluation`: current policy result, violation severity, expected assertion, and observed value.
- `GET /api/scans/:id/share-card`: public, lightweight share metadata for mobile/web share sheets, including title, summary, grade, score, top issues, next best action, and web links.

Authenticated automation clients can manage signed webhook or email routes through `/api/alert-destinations`. APNs clients continue to use `/api/notification-devices`. Destination test endpoints provide forceable delivery checks without waiting for a real policy transition. Policy alert payloads include a display-ready `brief`, severity counts, categorized violations, and stable `actions` alongside the raw policy details.
- `GET /api/scans/:id/events`: Server-Sent Events lifecycle stream so apps can stop polling once a scan reaches `completed` or `failed`.

These endpoints are stable additive resources. They are the safest shape for client UI because they avoid coupling screens to the full internal scan object.

For mobile clients, use `/mobile-summary` for the main scan result screen after SSE terminal. Use `/digest` or `/insights` directly only when a specific view needs one part of that payload.

For mobile-to-web acquisition and sharing, use the scanner handoff, public report URL, and `/share-card` templates in [`MOBILE-WEB-GROWTH-CONTRACT.md`](MOBILE-WEB-GROWTH-CONTRACT.md). The hosted web app accepts `?url=` for auto-starting a scan and still supports the older `?target=` fallback.

## Client Telemetry Headers

First-party clients should send the optional product metadata headers on every backend request:

- `X-SecURL-Client`: `securl-ios`, `header-watch-ios`, `cert-watch-ios`, `securl-web`, or another stable product identifier.
- `X-SecURL-Client-Version`: release/build identifier such as `1.0.4+19`.
- `X-SecURL-Client-Channel`: `app-store`, `testflight`, `development`, or `automation`.

These headers are additive and privacy-safe. They are used for aggregate product pulse and adoption readouts only. The backend rejects UUID-like or long hexadecimal values so clients do not accidentally send device identifiers.

## Mobile Monitoring And Cert Watch

- Register APNs tokens with `POST /api/notification-devices` using the same `X-Scan-Owner` or bearer session used for scans.
- Add monitored URLs with `POST /api/monitoring-targets`; backend scheduler scans due targets and sends APNs alerts when meaningful drift appears.
- Use `GET /api/monitoring-health` for owner-scoped reliability status: due/overdue targets, cert attention, posture failures, scheduler state, notification outbox state, and per-app push registration health.
- Use `GET /api/monitoring-mobile-summary` for watch-list refreshes. It returns compact target state, next-check timing, posture/certificate change summaries, monitoring events, signal-clarity headlines, and stable action hints without loading full scan detail.
- Use `GET /api/monitoring-cert-summary` for the Cert Watch watch-list home screen. It returns only certificate targets, attention counts, next scheduled check, recent certificate changes, monitoring events, and Cert Watch push registration health.
- Use `GET /api/certificates/live?url=...` for Cert Watch refreshes that only need the currently served TLS certificate.

## Investigation And Reporting

For deeper technical views, export, or analyst workflows, use:

- `GET /api/scans/:id/findings`: raw findings plus remediation and evidence summaries.
- `GET /api/scans/:id/evidence`: full supporting evidence from headers, TLS, DNS, HTML, exposure probes, vendors, CT discovery, and passive intelligence.
- `GET /api/scans/:id/drift`: scan-to-scan drift and risk events.
- `GET /api/scans/:id/comparison`: current and previous scan summaries with direct diff context.
- `GET /api/scans/:id/export?format=json|markdown|sarif|ci-json`: downloadable report and automation formats.

## Heavy Or Legacy Reads

`GET /api/scans/:id` includes the full result object and is useful for debugging or compatibility. New product UI should avoid relying on it unless a smaller resource does not yet expose the needed field.

## Capability Discovery

Clients should check `GET /api/capabilities` before assuming optional resources exist. The `service.clientTelemetry`, `scans.features`, and `scans.resources` arrays advertise additive backend capabilities without requiring app releases.
