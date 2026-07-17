# Monitoring Control Room Contract

Status: partial implementation for the `1.25` monitoring control-room milestone.
`monitoring-attention-v1` and `monitoring-timeline-v1` are implemented in the backend and
should only be handed to mobile after they are merged, deployed, production-smoked, and
recorded as `BACKEND_READY` in the mobile/backend channel. Policy-fit resources remain
proposed.

## Goal

Monitoring should answer one question first: what needs attention right now?

The current monitoring summaries already expose target state, certificate status,
scheduler timing, and push registration health. The `1.25` control-room contract turns
those pieces into a single server-authored owner view that web, API, mobile, and alert
surfaces can consume without reinterpreting raw scan, certificate, policy, or notification
state client-side.

## Capabilities

Clients must feature-detect these flags through `GET /api/capabilities` before consuming
the new resources:

- `monitoring-attention-v1`: owner/app attention rollup is available.
- `monitoring-timeline-v1`: stable per-target timeline DTOs are available.
- `monitoring-policy-fit-v1`: compact policy-fit verdicts are available on monitoring
  surfaces.
  Proposed, not live.

Until a specific flag is present, clients must continue using the existing
`/api/monitoring-mobile-summary`, `/api/monitoring-cert-summary`,
`/api/monitoring-health`, and `/api/monitoring-targets/:id/history` resources for that
area.

## Resource: owner attention rollup

```http
GET /api/monitoring-attention
X-Scan-Owner: <owner token>
```

Optional query:

- `appId`: filters the rollup to one first-party app/product surface.
- `limit`: bounds the owner target scan. Defaults to 100 and caps at 250.

Response:

```jsonc
{
  "generatedAt": "2026-07-15T12:00:00.000Z",
  "owner": {
    "scope": "scan-owner"
  },
  "summary": {
    "state": "healthy",              // healthy | needs_attention | degraded | unknown
    "highestSeverity": null,         // info | warning | critical | null
    "targetsTotal": 4,
    "targetsNeedingAttention": 0,
    "targetsUnhealthy": 0,
    "monitoringEnabled": true,
    "push": {
      "state": "configured",         // configured | not_configured | failing | unknown
      "providers": ["apns", "fcm"],
      "recentSent": 12,
      "recentFailed": 0,
      "disabledTokens": 0
    }
  },
  "attention": [
    {
      "targetId": "mon_123",
      "target": "https://example.com",
      "host": "example.com",
      "kind": "posture",             // posture | cert
      "appId": "com.ktbatterham.headerwatch",
      "state": "needs_attention",    // needs_attention | degraded | unknown
      "severity": "warning",         // info | warning | critical
      "reason": "posture_regression",
      "headline": "HSTS was removed",
      "detail": "The latest check no longer observed Strict-Transport-Security.",
      "lastCheckedAt": "2026-07-15T11:58:00.000Z",
      "lastChangedAt": "2026-07-15T11:58:00.000Z",
      "eventId": "evt_abc",
      "policyFit": {
        "verdict": "drift",          // pass | drift | fail | unknown
        "policy": "securl-baseline-v1",
        "changedSince": "2026-07-15T11:58:00.000Z",
        "headline": "No longer meets the baseline policy"
      },
      "timeline": {
        "href": "/api/monitoring-targets/mon_123/timeline",
        "latestEventId": "evt_abc"
      },
      "actions": [
        { "id": "review_posture_regression", "label": "Review change" },
        { "id": "run_scheduled_check", "label": "Run check now" }
      ],
      "links": {
        "target": "/api/monitoring-targets/mon_123",
        "latestScan": "/api/scans/scan_456/mobile-summary"
      }
    }
  ]
}
```

Rules:

- `attention[]` contains only targets that are not healthy, ordered worst first by
  severity, then most recent change.
- Headlines and details are backend-authored in the same voice as monitoring explanations
  and push payloads.
- `targetId` and `eventId` are join keys for list rows, push payloads, target detail, and
  timeline/history focus.
- The endpoint is owner-scoped. It must not expose global service totals.
- The push summary is aggregate-only. It must not expose device identifiers, tokens,
  owner identifiers, IP addresses, or raw user agents.

## Resource: stable target timeline

```http
GET /api/monitoring-targets/:id/timeline
X-Scan-Owner: <owner token>
```

Optional query:

- `limit`: caps returned timeline events. Defaults to 50 and caps at 100.
- `scanLimit`: caps posture scan history inspected when deriving drift events. Defaults to
  25 and caps at 100.

Response:

```jsonc
{
  "apiVersion": "2026-05-14",
  "targetId": "mon_123",
  "generatedAt": "2026-07-15T12:00:00.000Z",
  "target": {
    "id": "mon_123",
    "url": "https://example.com/",
    "label": "example.com",
    "kind": "posture",
    "appId": "com.ktbatterham.headerwatch",
    "policy": "securl-baseline-v1"
  },
  "summary": {
    "events": 1,
    "latestEventId": "evt_abc",
    "latestChangedAt": "2026-07-15T11:58:00.000Z",
    "hasCritical": false,
    "hasWarning": true
  },
  "timeline": [
    {
      "eventId": "evt_abc",
      "targetId": "mon_123",
      "occurredAt": "2026-07-15T11:58:00.000Z",
      "firstSeenAt": "2026-07-15T11:58:00.000Z",
      "changedAt": "2026-07-15T11:58:00.000Z",
      "recoveredAt": null,
      "type": "changed",
      "sourceType": "posture_drift",
      "severity": "warning",
      "mattersToPolicy": true,
      "title": "HSTS was removed",
      "body": "The latest check no longer observed Strict-Transport-Security.",
      "explanation": {
        "headline": "HSTS was removed",
        "detail": "The latest check no longer observed Strict-Transport-Security.",
        "action": "Compare the latest response headers with the previous passing response."
      },
      "evidence": [
        {
          "kind": "header",
          "name": "strict-transport-security",
          "previous": "max-age=31536000; includeSubDomains",
          "current": null,
          "confidence": "high"
        }
      ],
      "policy": {
        "id": "securl-baseline-v1",
        "verdict": "drift",
        "headline": "No longer meets the baseline policy"
      },
      "links": {
        "scan": "/api/scans/scan_456",
        "comparison": "/api/scans/scan_456/comparison"
      }
    }
  ]
}
```

Timeline `type` values are additive. Initial values should include:

- `first_seen`
- `changed`
- `recovered`
- `still_unhealthy`
- `policy_regressed`
- `policy_recovered`
- `cert_expiring`
- `cert_expired`
- `cert_renewed`
- `issuer_changed`
- `unreachable`
- `push_delivery_changed`

Rules:

- `eventId` is stable across reads and appears in matching push payloads and attention
  rollup items where the underlying monitoring event is already present.
- Recovery is explicit: do not make clients infer recovery only from a missing current
  problem. The first live slice exposes `recoveredAt: null` until recovery events are
  persisted explicitly.
- Certificate day-count decay should not create noisy timeline churn unless it crosses a
  configured policy or warning band.
- Push delivery changes describe owner/app delivery health, not raw device state. They are
  not included in the first live timeline slice.

## Policy-fit block

When `monitoring-policy-fit-v1` is advertised, monitoring list/detail resources may include:

```jsonc
"policyFit": {
  "verdict": "pass",                 // pass | drift | fail | unknown
  "policy": "production",
  "changedSince": null,
  "headline": "Still meets production policy"
}
```

The block must be server-authored and compact. Mobile and web clients should render it as
an explanation, not as a local rule engine.

## Push-health block

The control-room contract treats push delivery state as part of monitoring confidence.
Owner-scoped resources may include:

```jsonc
"push": {
  "state": "configured",
  "providers": ["apns", "fcm"],
  "recentSent": 12,
  "recentFailed": 0,
  "disabledTokens": 0,
  "lastFailureReason": null
}
```

Rules:

- Use provider-level and owner/app-level aggregates only.
- Never expose APNs tokens, FCM tokens, device identifiers, raw user agents, owner tokens,
  or IP addresses.
- Distinguish `not_configured` from `failing` so clients can tell whether monitoring is
  unavailable by environment or degraded by delivery errors.

## Privacy and safety

- All resources remain scoped by bearer session auth or the existing `X-Scan-Owner`
  boundary.
- Payloads are additive and compact; clients should not need full scan detail for a home
  screen.
- The backend owns interpretation. Clients should not parse posture manifests,
  detection-pack internals, or raw notification outbox state to decide urgency.
- Telemetry and coordination notes should remain aggregate/product-level only.

## Non-goals for this slice

- No mobile implementation work.
- No `BACKEND_READY` handoff from this design document alone.
- No public plugin or executable detection-pack runtime.
- No client-side policy engine requirement.
- No change to existing monitoring endpoints until the capability-gated implementation is
  live.
