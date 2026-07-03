# iOS Suite Backend Notes

SecURL now has a small iOS suite, so the backend contract should stay stable for the hosted web app, SecURL, Header Watch, Cert Watch, CLI users, and future clients.

This document defines the service boundary web, mobile clients, and background monitoring share through the same server-owned scan model.

## Why This Shift Matters

The original browser app started with a single helper endpoint, which was convenient early on but not a good long-term service boundary. Moving to server-owned scan resources gives us capabilities that endpoint never could:

- `POST /api/scans`
- `GET /api/scans/:id`

That shift matters because it gives us:

- server-owned history across devices
- async scan jobs
- user ownership of scans
- durable monitoring targets
- mobile-friendly summary/detail responses
- a credible auth story for multiple users

## Current Transitional State

The current backend service exposes:

- `GET /api/telemetry`
- `GET /api/product-pulse`
- `GET /api/capabilities`
- `GET /api/scans`
- `GET /api/scans?url=...`
- `POST /api/scans`
- `GET /api/scans/:id`
- `GET /api/scans/:id/summary`
- `GET /api/scans/:id/findings`
- `GET /api/scans/:id/digest`
- `GET /api/scans/:id/insights`
- `GET /api/scans/:id/mobile-summary`
- `GET /api/scans/:id/brief`
- `GET /api/scans/:id/vendors`
- `GET /api/scans/:id/action-plan`
- `GET /api/scans/:id/events`
- `GET /api/certificates/live?url=...`
- `POST /api/notification-devices`
- `GET /api/notification-devices`
- `GET /api/notification-devices/health`
- `POST /api/notification-devices/:id/test`
- `DELETE /api/notification-devices/:id`
- `GET /api/scans/:id/evidence`
- `GET /api/scans/:id/history`
- `GET /api/scans/:id/comparison`
- `GET /api/scans/:id/drift`
- `GET /api/scans/:id/observations`
- `GET /api/scans/:id/observation-drift`
- `GET /api/scans/:id/policy-evaluation`
- `POST /api/monitoring-targets`
- `GET /api/monitoring-targets`
- `GET /api/monitoring-health`
- `GET /api/monitoring-mobile-summary`
- `GET /api/monitoring-cert-summary`
- `GET /api/monitoring-targets/:id`
- `POST /api/monitoring-targets/:id/run`
- `DELETE /api/monitoring-targets/:id`

These scan resources still default to **in-memory** storage for local development. Postgres deployments persist both scan state and queued work: workers claim jobs with leases, recover queued scans after restarts, and retry interrupted running scans without changing the mobile API contract.

Mobile clients should send the optional aggregate telemetry headers on each request:

- `X-SecURL-Client`: `securl-ios`, `header-watch-ios`, or `cert-watch-ios`
- `X-SecURL-Client-Version`: release/build identifier such as `1.0.4+19`
- `X-SecURL-Client-Channel`: `app-store`, `testflight`, `development`, or `automation`

The backend uses these for product-pulse attribution only. UUID-like and long hexadecimal values are rejected so device identifiers are not collected by mistake.

## Target Service Model

### Scan lifecycle

Every scan should become a first-class server resource with a lifecycle:

- `queued`
- `running`
- `completed`
- `failed`

### Target endpoints

Phase 1:

- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans?url=...`
- `GET /api/scans/:id`

Phase 2:

- `GET /api/scans/:id/summary`
- `GET /api/scans/:id/findings`
- `GET /api/scans/:id/digest`
- `GET /api/scans/:id/insights`
- `GET /api/scans/:id/mobile-summary`
- `GET /api/scans/:id/brief`
- `GET /api/scans/:id/vendors`
- `GET /api/scans/:id/action-plan`
- `GET /api/scans/:id/events`
- `GET /api/certificates/live?url=...`
- `GET /api/scans/:id/evidence`
- `GET /api/scans/:id/history`
- `GET /api/scans/:id/comparison`

Phase 3:

- `POST /api/monitoring-targets`
- `GET /api/monitoring-targets`
- `GET /api/monitoring-targets/:id`
- `DELETE /api/monitoring-targets/:id`
- `POST /api/monitoring-targets/:id/run`
- `GET /api/monitoring-health`
- `GET /api/monitoring-mobile-summary`
- `GET /api/monitoring-cert-summary`
- `POST /api/notification-devices`
- `GET /api/notification-devices`
- `GET /api/notification-devices/health`
- `POST /api/notification-devices/:id/test`
- `DELETE /api/notification-devices/:id`

Phase 4:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/session`
- `POST /api/auth/logout`

## Resource Shape

### Scan summary

This is the payload shape mobile and list views should prefer.

```json
{
  "id": "uuid",
  "status": "completed",
  "url": "https://example.com",
  "mode": "standard",
  "requestedAt": "2026-05-02T10:00:00.000Z",
  "startedAt": "2026-05-02T10:00:01.000Z",
  "completedAt": "2026-05-02T10:00:07.000Z",
  "score": 74,
  "grade": "C",
  "limited": false,
  "limitedKind": null,
  "title": "Example title",
  "mainRisk": "Browser hardening gaps are the main visible risk.",
  "findingsCount": 6
}
```

### Full scan resource

This should eventually be shaped like:

```json
{
  "scan": {
    "id": "uuid",
    "status": "completed",
    "summary": {},
    "result": {}
  }
}
```

The `result` payload can remain rich for now, but the long-term goal is to split it into focused DTOs for:

- summary
- findings
- evidence
- history

### Target history

Repeated scans of the same canonical target URL should be retrievable as a server-owned summary timeline.

Current transitional shape:

```json
{
  "target": {
    "url": "https://example.com/"
  },
  "scans": [
    {
      "id": "uuid",
      "status": "completed",
      "score": 74,
      "grade": "C"
    }
  ],
  "comparison": {
    "currentScanId": "uuid",
    "previousScanId": "uuid",
    "diff": {}
  }
}
```

## Persistence Roadmap

The in-memory store is only a stepping stone. The durable version should store:

- users
- auth sessions
- scans
- scan summaries
- monitoring targets
- comparison history
- telemetry aggregates
- scan lifecycle events

Recommended first tables/documents:

- `users`
- `scans`
- `scan_summaries`
- `monitoring_targets`
- `scan_events`

### Repository boundary

The server should not talk directly to one hard-coded storage strategy.

Instead, it should depend on a repository contract that can be backed by:

- in-memory storage for local development
- Postgres for Railway/public deployments
- a future queue or worker-backed scan orchestrator

Current repository responsibilities:

- `createUser`
- `getUserByEmail`
- `getUserById`
- `createAuthSession`
- `getAuthSessionByTokenHash`
- `touchAuthSession`
- `deleteAuthSession`
- `createScan`
- `markRunning`
- `markCompleted`
- `markFailed`
- `getScan`
- `listScans`
- `listScanEvents`
- `upsertMonitoringTarget`
- `listMonitoringTargets`
- `deleteMonitoringTarget`

Current persisted-record shape:

```json
{
  "id": "uuid",
  "ownerId": null,
  "status": "completed",
  "url": "https://example.com",
  "mode": "standard",
  "requestedAt": "2026-05-02T10:00:00.000Z",
  "startedAt": "2026-05-02T10:00:01.000Z",
  "completedAt": "2026-05-02T10:00:07.000Z",
  "requesterScope": "ip:203.0.113.10",
  "clientIp": "203.0.113.10",
  "failureClass": null,
  "error": null,
  "summary": {},
  "result": {}
}
```

That record is intentionally simple: it lets us persist the current service model first, then normalize tables further once auth and ownership arrive.

### First Postgres shape

Suggested first cut:

- `scans`
  - `id uuid primary key`
  - `owner_id uuid null`
  - `status text not null`
  - `url text not null`
  - `mode text not null`
  - `requested_at timestamptz not null`
  - `started_at timestamptz null`
  - `completed_at timestamptz null`
  - `requester_scope text not null`
  - `client_ip text not null`
  - `failure_class text null`
  - `error text null`
  - `summary jsonb not null`
  - `result jsonb null`

- `scan_events`
  - `id uuid primary key`
  - `scan_id uuid not null references scans(id) on delete cascade`
  - `event_type text not null`
  - `occurred_at timestamptz not null`
  - `status text not null`
  - `failure_class text null`
  - `message text null`
  - `metadata jsonb not null default '{}'::jsonb`

This is not the final ideal relational model. It is the fastest safe step toward durability.

### Initialization behavior

The first Postgres-backed implementation should be able to bootstrap itself safely in a fresh environment:

- create the configured schema if missing
- create the `scans` table if missing
- create the `scan_events` table if missing
- create the basic ownership and recency indexes if missing

That keeps Railway-style deployments practical while we are still pre-migrations-framework.

## Auth Roadmap

The current shared API key model is not suitable for a multi-user client platform.

Minimum future requirements:

- per-user auth
- bearer tokens or session-backed API auth
- ownership checks on scans and monitoring targets
- rate limits keyed by user as well as IP

## Response Shaping for Mobile

The `AnalysisResult` object is rich but too large to treat as the only client contract. We should progressively add smaller DTOs for:

- `ScanSummary`
- `ScanFinding`
- `ScanEvidenceSection`
- `ScanHistoryEntry`
- `MonitoringTarget`

This will help both iOS and the web app.

## Remaining Operational Requirements

- distributed rate limiting for public multi-instance mode
- bounded concurrency for queued scans
- durable scan storage
- deeper production persistence and retention controls
- richer mobile adoption dashboards once enough post-channel telemetry exists

## Completed Backend Milestones

- telemetry foundation
- privacy-safe product-pulse telemetry
- server-owned scan resources
- persisted scan records
- async queue semantics and bounded concurrency
- server-owned monitoring targets
- Cert Watch live certificate and watch-list summary resources
- monitoring health control-plane resource
- APNs device registration, test notification, delivery audit, and per-app topic routing
- auth sessions and API keys
- mobile-friendly scan DTOs
- direct scan comparison API
