import assert from "node:assert/strict";
import test from "node:test";
import { buildMonitoringMobileSummaryPayload } from "../scanDtos.mjs";

function buildAnalysisResult(overrides = {}) {
  return {
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-19T08:00:00.000Z",
    score: 92,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: {
      daysRemaining: 90,
    },
    thirdPartyTrust: {
      providers: [],
    },
    aiSurface: {
      vendors: [],
    },
    identityProvider: {
      provider: null,
    },
    wafFingerprint: {
      providers: ["Cloudflare"],
    },
    ctDiscovery: {
      prioritizedHosts: [],
    },
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

function buildCompletedRecord(id, resultOverrides = {}) {
  const result = buildAnalysisResult(resultOverrides);
  return {
    id,
    status: "completed",
    result,
    summary: {
      id,
      status: "completed",
      grade: result.grade,
      score: result.score,
      completedAt: result.scannedAt,
      findingsCount: result.issues.length,
      mainRisk: result.issues[0]?.title ?? null,
    },
  };
}

test("mobile monitoring summary exposes certificate attention state", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-cert-1",
        url: "https://example.com/",
        label: "Example cert",
        cadence: "daily",
        kind: "cert",
        mode: null,
        appId: "com.ktbatterham.certwatch",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastCheckedAt: "2026-06-19T08:01:00.000Z",
        certState: {
          reachable: true,
          checkedAt: "2026-06-19T08:01:00.000Z",
          host: "example.com",
          issuer: "Example CA",
          validTo: "2026-06-25T00:00:00.000Z",
          daysRemaining: 6,
          serialNumber: "ABC123",
          lastEventType: null,
          lastWarnedBand: null,
          attention: {
            type: "cert_expiring",
            severity: "critical",
            warningBand: 7,
            title: "Certificate expiring: example.com",
            body: "6 days remaining.",
          },
          issues: [],
          history: [],
        },
      },
      records: [],
    },
  ]);

  assert.equal(payload.summary.certTargets, 1);
  assert.equal(payload.targets[0].cert.attention.type, "cert_expiring");
  assert.equal(payload.targets[0].cert.attention.severity, "critical");
  assert.equal(payload.targets[0].cert.attention.warningBand, 7);
});

test("mobile monitoring summary exposes compact posture drift for apps", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-posture-1",
        url: "https://example.com/",
        label: "Example posture",
        cadence: "daily",
        kind: "posture",
        mode: "quiet",
        appId: "com.ktbatterham.securl",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastScannedAt: "2026-06-19T09:00:00.000Z",
      },
      records: [
        buildCompletedRecord("scan-current", {
          scannedAt: "2026-06-19T09:00:00.000Z",
          score: 58,
          grade: "D",
          certificate: {
            daysRemaining: 5,
          },
          wafFingerprint: {
            providers: [],
          },
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
        }),
        buildCompletedRecord("scan-previous"),
      ],
    },
  ]);

  const target = payload.targets[0];
  assert.equal(target.scoreDelta, -34);
  assert.equal(target.posture.currentScanId, "scan-current");
  assert.equal(target.posture.previousScanId, "scan-previous");
  assert.equal(target.posture.direction, "regressed");
  assert.equal(target.posture.severity, "critical");
  assert.equal(target.posture.gradeChanged, true);
  assert.equal(target.posture.hasRegression, true);
  assert.ok(target.posture.changedAreas.includes("score"));
  assert.ok(target.posture.changedAreas.includes("headers"));
  assert.ok(target.posture.changedAreas.includes("certificate"));
  assert.ok(target.posture.eventCounts.critical >= 4);
  assert.ok(target.posture.topEvents.length > 0);
  assert.equal(target.changes.postureRiskEvents, 6);
  assert.equal(payload.summary.changes, target.changes.postureRiskEvents);
});
