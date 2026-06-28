import assert from "node:assert/strict";
import test from "node:test";

import {
  buildEvidenceQualitySummary,
  buildPostureDigest,
} from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    inputUrl: "https://example.com",
    normalizedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-28T08:00:00.000Z",
    responseTimeMs: 120,
    statusCode: 200,
    score: 86,
    grade: "B",
    summary: "Good posture.",
    headers: [{ key: "strict-transport-security", status: "present" }],
    certificate: { available: true, authorized: true },
    issues: [
      {
        severity: "warning",
        area: "headers",
        title: "Content-Security-Policy is missing",
        detail: "Add a CSP.",
        confidence: "high",
        source: "observed",
        owasp: [],
        mitre: [],
      },
    ],
    evidenceSummary: {
      generatedAt: "2026-06-28T08:00:00.000Z",
      summary: "Evidence exists.",
      totalEvidenceReferences: 14,
      byKind: { header: 5, tls: 2, dns: 2, html: 2, score_driver: 3 },
      bySource: { headers: 5, tls: 2, dns: 2, html: 2, score_driver: 3 },
      observedCount: 11,
      derivedCount: 3,
      topEvidence: [],
      scoreDriverEvidence: [],
      findingEvidence: [],
      limitation: null,
    },
    assessmentLimitation: { limited: false, kind: null, title: null, detail: null },
    scanTiming: { totalMs: 1200, coreMs: 700, enrichmentMs: 500, timedOut: false, timeoutMs: 45000 },
    ...overrides,
  };
}

test("evidence quality summarizes reliable outside-in scan coverage", () => {
  const quality = buildEvidenceQualitySummary(buildAnalysis());

  assert.equal(quality.level, "high");
  assert.equal(quality.score >= 80, true);
  assert.equal(quality.evidence.totalReferences, 14);
  assert.equal(quality.evidence.observedRatio, 0.79);
  assert.equal(quality.findings.highConfidence, 1);
  assert.ok(quality.strengths.some((signal) => signal.id === "observed_evidence"));
  assert.equal(quality.gaps.length, 0);
});

test("evidence quality is conservative for limited or timeout scans", () => {
  const quality = buildEvidenceQualitySummary(buildAnalysis({
    statusCode: 503,
    certificate: { available: false },
    issues: [{
      severity: "info",
      area: "availability",
      title: "Service unavailable",
      detail: "Target unavailable.",
      confidence: "low",
      source: "inferred",
      owasp: [],
      mitre: [],
    }],
    evidenceSummary: {
      generatedAt: "2026-06-28T08:00:00.000Z",
      summary: "Thin evidence.",
      totalEvidenceReferences: 2,
      byKind: { score_driver: 2 },
      bySource: { assessment_limit: 2 },
      observedCount: 0,
      derivedCount: 2,
      topEvidence: [],
      scoreDriverEvidence: [],
      findingEvidence: [],
      limitation: { limited: true, kind: "service_unavailable", title: "Unavailable", detail: "HTTP 503." },
    },
    assessmentLimitation: { limited: true, kind: "service_unavailable", title: "Unavailable", detail: "HTTP 503." },
    scanTiming: { totalMs: 45000, coreMs: 1200, enrichmentMs: 43800, timedOut: true, timeoutMs: 45000 },
  }));

  assert.equal(quality.level, "low");
  assert.equal(quality.scan.limited, true);
  assert.equal(quality.scan.timedOut, true);
  assert.ok(quality.gaps.some((signal) => signal.id === "limited_assessment"));
  assert.ok(quality.recommendedFollowUp.some((item) => /Restore complete scan coverage/i.test(item)));
});

test("posture digest includes evidence quality even for older result payloads", () => {
  const digest = buildPostureDigest(buildAnalysis({ evidenceQuality: undefined }));

  assert.equal(digest.evidenceQuality.level, "high");
  assert.equal(typeof digest.evidenceQuality.summary, "string");
  assert.ok(Array.isArray(digest.evidenceQuality.recommendedFollowUp));
});
