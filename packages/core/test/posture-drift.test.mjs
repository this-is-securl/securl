import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHistoryDiffFromSnapshots,
  buildPostureDriftReportFromDiff,
  buildPostureDriftReportFromSnapshots,
} from "../dist/index.js";

function buildSnapshot(overrides = {}) {
  return {
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-01T10:00:00.000Z",
    score: 92,
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

test("posture drift report summarizes scan-to-scan regressions", () => {
  const previous = buildSnapshot();
  const current = buildSnapshot({
    score: 58,
    grade: "D",
    statusCode: 503,
    certificateDaysRemaining: 5,
    wafProviders: [],
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
        source: "observed",
      },
    ],
  });

  const report = buildPostureDriftReportFromSnapshots(current, previous);

  assert.equal(report.current.score, 58);
  assert.equal(report.previous.score, 92);
  assert.equal(report.summary.direction, "regressed");
  assert.equal(report.summary.severity, "critical");
  assert.equal(report.summary.scoreDelta, -34);
  assert.equal(report.summary.gradeChanged, true);
  assert.equal(report.summary.hasRegression, true);
  assert.equal(report.summary.eventCounts.critical, 4);
  assert.ok(report.summary.changedAreas.includes("score"));
  assert.ok(report.summary.changedAreas.includes("headers"));
  assert.ok(report.summary.changedAreas.includes("findings"));
  assert.equal(report.summary.topEvents[0].severity, "critical");
  assert.ok(report.riskEvents.some((event) => event.eventType === "new_critical_findings"));
});

test("posture drift report can reuse a precomputed diff and risk events", () => {
  const previous = buildSnapshot({ score: 70, grade: "C" });
  const current = buildSnapshot({
    score: 81,
    grade: "B",
    issues: [],
  });
  const diff = buildHistoryDiffFromSnapshots(current, previous);
  const report = buildPostureDriftReportFromDiff(current, previous, diff, []);

  assert.equal(report.diff, diff);
  assert.equal(report.summary.direction, "improved");
  assert.equal(report.summary.severity, "none");
  assert.equal(report.summary.hasImprovement, true);
  assert.deepEqual(report.summary.topEvents, []);
});
