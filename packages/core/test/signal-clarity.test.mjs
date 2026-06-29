import assert from "node:assert/strict";
import test from "node:test";

import { buildSignalClaritySummary } from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    host: "example.com",
    finalUrl: "https://example.com/",
    scannedAt: "2026-06-29T08:00:00.000Z",
    score: 79,
    grade: "B",
    summary: "External posture is mostly healthy.",
    strengths: ["TLS certificate is valid and trusted."],
    executiveSummary: {
      overview: "Mostly healthy with a visible CSP gap.",
      mainRisk: "CSP needs tightening.",
      posture: "mixed",
      takeaways: ["Tighten CSP."],
    },
    assessmentLimitation: {
      limited: false,
      kind: null,
      title: null,
      detail: null,
    },
    scoreDrivers: [
      {
        areaKey: "content",
        areaLabel: "Content",
        impact: 12,
        label: "Content-Security-Policy gap",
        detail: "CSP is missing or weak.",
        source: "headers",
      },
      {
        areaKey: "domain",
        areaLabel: "Domain",
        impact: 4,
        label: "Domain and public-trust findings",
        detail: "security.txt is missing.",
        source: "dns",
      },
    ],
    evidenceQuality: {
      generatedAt: "2026-06-29T08:00:00.000Z",
      level: "high",
      score: 88,
      summary: "Evidence quality is high.",
      evidence: {
        totalReferences: 16,
        observedReferences: 13,
        derivedReferences: 3,
        observedRatio: 0.81,
        kinds: ["header", "tls", "dns"],
      },
      scan: {
        limited: false,
        limitedKind: null,
        timedOut: false,
        statusCode: 200,
        responseTimeMs: 123,
      },
      findings: {
        total: 2,
        lowConfidence: 0,
        mediumConfidence: 0,
        highConfidence: 2,
      },
      strengths: [{
        id: "observed_evidence",
        label: "Observed evidence",
        detail: "Most evidence came from directly observed target data.",
        impact: "positive",
      }],
      gaps: [],
      recommendedFollowUp: [],
      limitation: null,
    },
    actionPlan: {
      generatedAt: "2026-06-29T08:00:00.000Z",
      summary: "Two actions",
      posture: {
        score: 79,
        grade: "B",
        limited: false,
        mainRisk: "CSP needs tightening.",
      },
      totalActions: 2,
      highImpactActions: 1,
      quickWins: 1,
      nextReview: "Rerun after fixes.",
      limitation: null,
      items: [
        {
          id: "remediation:missing-csp",
          priority: 1,
          title: "Add Content-Security-Policy",
          whyNow: "This is costing about 12 points in the passive score.",
          action: "Deploy a strict Content-Security-Policy for the application.",
          verify: "Rescan and confirm CSP is present.",
          owner: "edge",
          effort: "medium",
          impact: "high",
          scoreImpact: 12,
          confidence: "high",
          theme: "browser_hardening",
          evidence: [],
          relatedFindings: ["Content-Security-Policy is missing"],
          source: "remediation",
        },
      ],
    },
    scanTiming: {
      totalMs: 1234,
      coreMs: 900,
      enrichmentMs: 334,
      timedOut: false,
      timeoutMs: null,
    },
    ...overrides,
  };
}

test("signal clarity produces a one-screen verdict with drivers and next action", () => {
  const clarity = buildSignalClaritySummary(buildAnalysis());

  assert.equal(clarity.verdict, "positive");
  assert.match(clarity.headline, /mostly healthy/i);
  assert.equal(clarity.target.score, 79);
  assert.equal(clarity.confidence.level, "high");
  assert.equal(clarity.score.driversReviewed, 2);
  assert.equal(clarity.score.topNegativeDrivers[0].label, "Content-Security-Policy gap");
  assert.equal(clarity.score.topNegativeDrivers[0].severity, "critical");
  assert.equal(clarity.score.topPositiveSignals[0].source, "evidence_quality");
  assert.equal(clarity.nextBestAction.label, "Deploy a strict Content-Security-Policy for the application.");
  assert.match(clarity.audienceNotes.developer, /Content-Security-Policy/i);
});

test("signal clarity is conservative for limited scans", () => {
  const clarity = buildSignalClaritySummary(buildAnalysis({
    score: 55,
    grade: "D",
    assessmentLimitation: {
      limited: true,
      kind: "rate_limited",
      title: "Rate limited",
      detail: "The target rate-limited passive evidence collection.",
    },
    evidenceQuality: {
      ...buildAnalysis().evidenceQuality,
      level: "low",
      score: 38,
      summary: "Evidence quality is low.",
      recommendedFollowUp: ["Rescan when rate limiting is no longer active."],
    },
  }));

  assert.equal(clarity.verdict, "limited");
  assert.match(clarity.headline, /complete read/i);
  assert.ok(clarity.caveats.some((item) => /rate-limited/i.test(item)));
  assert.match(clarity.audienceNotes.developer, /readable/i);
});
