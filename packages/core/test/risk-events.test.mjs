import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHistoryDiffFromSnapshots,
  buildPostureRiskEventsFromSnapshots,
} from "../dist/index.js";

function buildSnapshot(overrides = {}) {
  return {
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-01T10:00:00.000Z",
    score: 90,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 100,
    certificateDaysRemaining: 90,
    thirdPartyProviders: [],
    aiVendors: [],
    identityProvider: null,
    wafProviders: ["Cloudflare"],
    ctPriorityHosts: [],
    headers: [
      {
        label: "Strict-Transport-Security",
        status: "pass",
        value: "max-age=31536000",
      },
    ],
    issues: [],
    ...overrides,
  };
}

test("posture risk events classify monitoring regressions", () => {
  const previous = buildSnapshot();
  const current = buildSnapshot({
    score: 62,
    grade: "C",
    certificateDaysRemaining: 6,
    wafProviders: [],
    ctPriorityHosts: ["admin.example.com"],
    headers: [
      {
        label: "Strict-Transport-Security",
        status: "missing",
        value: null,
      },
    ],
    issues: [
      {
        severity: "critical",
        title: "Exposed admin surface",
        detail: "An admin path was reachable.",
        confidence: "medium",
        source: "surface",
      },
    ],
  });
  const diff = buildHistoryDiffFromSnapshots(current, previous);

  const events = buildPostureRiskEventsFromSnapshots(current, previous, diff);
  const eventTypes = events.map((event) => event.eventType);

  assert.equal(diff.currentGrade, "C");
  assert.equal(events[0].eventType, "new_critical_findings");
  assert.equal(events[0].severity, "critical");
  assert.ok(eventTypes.includes("score_regressed"));
  assert.ok(eventTypes.includes("grade_dropped"));
  assert.ok(eventTypes.includes("certificate_expiring_soon"));
  assert.ok(eventTypes.includes("security_header_regressed"));
  assert.ok(eventTypes.includes("waf_signal_removed"));
  assert.ok(eventTypes.includes("new_ct_priority_hosts"));
});
