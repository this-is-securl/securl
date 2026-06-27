import assert from "node:assert/strict";
import test from "node:test";

import { buildPostureInsights } from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    score: 72,
    grade: "B",
    assessmentLimitation: {
      limited: false,
      kind: null,
      title: null,
      detail: null,
    },
    actionPlan: {
      generatedAt: "2026-06-27T00:00:00.000Z",
      summary: "Two actions",
      posture: {
        score: 72,
        grade: "B",
        limited: false,
        mainRisk: "Add Content-Security-Policy",
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
          evidence: [{
            kind: "header",
            label: "Content-Security-Policy",
            observed: null,
            expected: "present",
            source: "score_driver",
          }],
          relatedFindings: ["Content-Security-Policy is missing"],
          source: "remediation",
        },
        {
          id: "remediation:security-txt",
          priority: 2,
          title: "Publish security.txt",
          whyNow: "Security contact metadata is missing.",
          action: "Publish security.txt with a monitored contact.",
          verify: "Rescan and confirm security.txt is reachable.",
          owner: "app",
          effort: "low",
          impact: "medium",
          scoreImpact: 3,
          confidence: "high",
          theme: "public_exposure",
          evidence: [],
          relatedFindings: ["security.txt missing"],
          source: "remediation",
        },
      ],
    },
    ...overrides,
  };
}

test("posture insights summarize action plan themes for client surfaces", () => {
  const insights = buildPostureInsights(buildAnalysis());

  assert.equal(insights.posture.score, 72);
  assert.equal(insights.summary, "1 critical insight should be reviewed first because it carries the highest posture impact.");
  assert.equal(insights.themes[0].theme, "browser_hardening");
  assert.equal(insights.themes[0].highestSeverity, "critical");
  assert.equal(insights.themes[0].scoreImpact, 12);
  assert.equal(insights.topInsights[0].id, "insight:remediation:missing-csp");
  assert.equal(insights.topInsights[0].severity, "critical");
  assert.equal(insights.topInsights[0].nextAction, "Deploy a strict Content-Security-Policy for the application.");
  assert.equal(insights.nextBestActions.length, 2);
  assert.equal(insights.nextBestActions[0].owner, "edge");
});

test("posture insights preserve limited-assessment guidance", () => {
  const insights = buildPostureInsights(buildAnalysis({
    assessmentLimitation: {
      limited: true,
      kind: "timeout",
      title: "Scan timed out",
      detail: "Only partial evidence was collected.",
    },
    actionPlan: {
      ...buildAnalysis().actionPlan,
      posture: {
        score: 50,
        grade: "D",
        limited: true,
        mainRisk: "Scan timed out",
      },
      limitation: {
        limited: true,
        kind: "timeout",
        title: "Scan timed out",
        detail: "Only partial evidence was collected.",
      },
    },
  }));

  assert.equal(insights.posture.limited, true);
  assert.equal(insights.limitation.kind, "timeout");
  assert.match(insights.summary, /scan was limited/i);
});

test("posture insights use singular wording for one non-critical action", () => {
  const analysis = buildAnalysis({
    actionPlan: {
      ...buildAnalysis().actionPlan,
      items: [{
        ...buildAnalysis().actionPlan.items[1],
        scoreImpact: 3,
      }],
    },
  });

  const insights = buildPostureInsights(analysis);

  assert.equal(insights.summary, "1 actionable insight is available for follow-up.");
});
