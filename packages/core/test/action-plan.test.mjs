import assert from "node:assert/strict";
import test from "node:test";

import { buildActionPlan } from "../dist/index.js";

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
    remediationPlan: {
      generatedAt: "2026-06-15T00:00:00.000Z",
      summary: "Two actions",
      totalActions: 2,
      highImpactActions: 1,
      quickWins: 1,
      items: [
        {
          id: "missing-csp",
          priority: 1,
          title: "Add Content-Security-Policy",
          detail: "A strong CSP reduces script injection blast radius.",
          owner: "edge",
          effort: "medium",
          impact: "high",
          action: "Deploy a strict Content-Security-Policy for the application.",
          verify: "Rescan and confirm CSP is present.",
          scoreImpact: 12,
          relatedFindings: ["Content-Security-Policy is missing"],
          evidence: [{
            kind: "header",
            label: "Content-Security-Policy",
            observed: null,
            expected: "present",
            source: "score_driver",
          }],
        },
        {
          id: "security-txt",
          priority: 2,
          title: "Publish security.txt",
          detail: "Security contact metadata is missing.",
          owner: "app",
          effort: "low",
          impact: "medium",
          action: "Publish security.txt with a monitored contact.",
          verify: "Rescan and confirm security.txt is reachable.",
          scoreImpact: 3,
          relatedFindings: ["security.txt missing"],
          evidence: [],
        },
      ],
    },
    exposureBrief: {
      topRisks: [
        {
          title: "Admin endpoint looks like an API surface",
          detail: "A public admin-shaped endpoint was observed.",
          severity: "watch",
          category: "entry_point",
          confidence: "medium",
          source: "api",
          evidence: ["200 https://example.com/admin"],
          action: "Confirm the endpoint is intentional, authenticated where needed, and covered by monitoring.",
        },
      ],
    },
    vendorExposure: {
      highPriorityProviders: [
        {
          name: "Example Replay",
          domain: "replay.example.net",
          category: "session_replay",
          risk: "high",
          evidence: "script src",
          reviewPriority: "urgent",
          dataFlow: "telemetry",
          action: "Confirm session replay masking, consent coverage, retention, and vendor ownership.",
        },
      ],
    },
    ...overrides,
  };
}

test("action plan combines remediation, exposure, and vendor priorities", () => {
  const plan = buildActionPlan(buildAnalysis());

  assert.equal(plan.posture.score, 72);
  assert.equal(plan.posture.grade, "B");
  assert.equal(plan.posture.limited, false);
  assert.equal(plan.totalActions, 4);
  assert.equal(plan.highImpactActions, 2);
  assert.equal(plan.quickWins, 2);
  assert.equal(plan.items[0].title, "Add Content-Security-Policy");
  assert.equal(plan.items[0].theme, "browser_hardening");
  assert.equal(plan.items[0].source, "remediation");
  assert.ok(plan.items.some((item) => item.source === "exposure_brief"));
  assert.ok(plan.items.some((item) => item.source === "vendor_exposure"));
  assert.ok(plan.items.every((item, index) => item.priority === index + 1));
});

test("action plan falls back to score drivers when no richer plan exists", () => {
  const plan = buildActionPlan(buildAnalysis({
    remediationPlan: null,
    exposureBrief: null,
    vendorExposure: null,
    scoreDrivers: [
      {
        areaKey: "edge",
        areaLabel: "Edge",
        label: "Strict-Transport-Security",
        detail: "HSTS is missing.",
        impact: 8,
        source: "headers",
      },
    ],
  }));

  assert.equal(plan.totalActions, 1);
  assert.equal(plan.items[0].source, "score_driver");
  assert.equal(plan.items[0].owner, "edge");
  assert.equal(plan.items[0].theme, "browser_hardening");
});
