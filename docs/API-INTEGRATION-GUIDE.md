# API Integration Guide

This guide is for teams building against the SecURL hosted API or mirroring its resource model in another client. It complements the endpoint list in [`BACKEND-API.md`](BACKEND-API.md) and the product-client map in [`CONSUMER-API-MAP.md`](CONSUMER-API-MAP.md).

## Integration Principles

- Prefer compact resources over the full scan object.
- Treat endpoint fields as additive unless explicitly documented otherwise.
- Discover optional capabilities with `GET /api/capabilities`.
- Send privacy-safe client metadata headers if you operate a first-party or partner client.
- Keep polling light: use Server-Sent Events while scans are running, then fetch stable resources once the scan is terminal.
- Use manifests and observations for audit-style workflows, not primary mobile screens.

## Identify Your Client

Send these optional headers on every request:

```http
X-SecURL-Client: your-client-id
X-SecURL-Client-Version: 1.0.0+1
X-SecURL-Client-Channel: production
```

First-party examples:

- `securl-web`
- `securl-ios`
- `header-watch-ios`
- `cert-watch-ios`
- `automation`

The backend uses these values for aggregate product pulse and compatibility tracking. Do not send device ids, user ids, APNs tokens, email addresses, or long random identifiers in these headers. These values are self-reported metadata, not credentials: requests authorized by a session, API key, or stable owner token are reported separately from unauthenticated assertions, while smoke/CI identities are always classified as automation. Clients do not need to change request handling; the provenance fields are additive telemetry semantics.

## Basic Scan Flow

1. Create the scan.
2. Watch lifecycle events until terminal.
3. Fetch the smallest resource your client needs.

```http
POST /api/scans
Content-Type: application/json
X-Scan-Owner: owner-token
X-SecURL-Client: automation

{
  "url": "https://example.com",
  "mode": "quiet"
}
```

Use the returned `resources` object where possible rather than constructing every path yourself.

While the scan is queued or running, connect to:

```http
GET /api/scans/:id/events
```

After completion, choose the right read:

- Product summary: `GET /api/scans/:id/mobile-summary`
- Lightweight posture: `GET /api/scans/:id/digest`
- Technical recipe card: `GET /api/scans/:id/manifest`
- Findings only: `GET /api/scans/:id/findings`
- Evidence only: `GET /api/scans/:id/evidence`
- SARIF or CI JSON: `GET /api/scans/:id/export?format=sarif`

## Choosing A Resource

| Need | Recommended resource |
| --- | --- |
| Show grade, score, headline, and next action | `/mobile-summary` or `/digest` |
| Build a report or executive summary | `/summary`, `/digest`, `/action-plan`, `/share-card` |
| Track what changed since last scan | `/comparison`, `/drift`, `/observation-drift` |
| Evaluate policy fit | `/policy-evaluation` or `/manifest` |
| Store an audit artifact | `/manifest` |
| Feed GitHub or security tooling | `/export?format=sarif` or `/export?format=ci-json` |
| Review visible vendors, infrastructure, identity, AI, and supply-chain exposure | `/vendors` (External Exposure Inventory v1) |
| Review certificate only | `/api/certificates/live?url=...` |

## Posture Manifest

The posture manifest is the external security recipe card. It records:

- target URLs and final host
- scan mode and timing
- score, grade, summary, and score drivers
- observation ledger
- skipped or limited assessment context
- evidence quality and signal clarity
- engine version
- resolved policy evaluation

Use it when you need a stable artifact for CI, reports, vendor review, or internal records. Normal product screens should usually use `/digest`, `/insights`, or `/mobile-summary`.

CLI users can produce the same artifact without the hosted API:

```sh
npx securl scan https://example.com --format manifest --output posture-manifest.json
```

For the concise external exposure inventory (visible vendors, infrastructure,
identity, AI, and supply-chain signals), use the CLI's `exposure` format:

```sh
npx securl scan https://example.com --format exposure --output external-exposure.json
```

Use the package schema when you need to validate stored manifests or wire the artifact into CI, evidence archives, or vendor-risk tooling:

```sh
npx securl schema manifest --output posture-manifest.schema.json
```

## Monitoring Flow

Register a target:

```http
POST /api/monitoring-targets
Content-Type: application/json
X-Scan-Owner: owner-token

{
  "url": "https://example.com",
  "kind": "posture",
  "cadence": "daily"
}
```

For certificate monitoring, set `kind` to `cert`. Certificate targets can also use named warning profiles:

```json
{
  "url": "https://example.com",
  "kind": "cert",
  "cadence": "daily",
  "policy": "production"
}
```

Supported certificate policies:

- `production`
- `strict`
- `renewal-watch`

Use these reads for client screens:

- `GET /api/monitoring-mobile-summary`
- `GET /api/monitoring-cert-summary`
- `GET /api/monitoring-health`
- `GET /api/monitoring-targets/:id/history`

## Push And Alert Delivery

Mobile apps register push devices with:

```http
POST /api/notification-devices
```

Use the same owner boundary as scans and monitoring targets. iOS sends
`platform:"ios"` with `apnsToken`; Android sends `platform:"android"` with
`fcmToken`. The backend never returns raw APNs or FCM tokens in list responses.
Clients can feature-detect Android support through `GET /api/capabilities`
where `notifications.features` includes `android-fcm-push-v1`.

Server-side test notifications are available through:

```http
POST /api/notification-devices/:id/test
```

Authenticated automation clients can use alert destinations for policy alerts:

- `POST /api/alert-destinations`
- `POST /api/alert-destinations/:id/test`

Webhook destinations must be HTTPS and are validated against public-only DNS before delivery.

## Error Handling

Clients should treat failures as normal operational states:

- `400`: invalid URL, unsupported mode, invalid policy, or malformed request.
- `401` or `403`: missing or invalid auth/session/API key.
- `404`: scan, target, or device not found inside the current owner boundary.
- `409`: resource exists or state transition cannot be performed.
- `429`: rate limited.
- `503`: dependency or delivery unavailable.

Scan resources may return `queued`, `running`, `completed`, or `failed`. Do not assume a created scan is immediately complete.

## Safety Notes For Integrators

- Ask users to scan systems they own or are authorized to assess.
- Avoid sending private intranet targets to the hosted API. The service rejects private targets, but clients should still keep the UX clear.
- Do not place secrets, bearer tokens, customer names, or device identifiers in URLs, target labels, client metadata headers, or webhook query strings.
- Use quiet mode for high-frequency automation unless the broader passive evidence is needed.
- Cache completed resources where practical; posture scans are not designed to be fired on every page render.
