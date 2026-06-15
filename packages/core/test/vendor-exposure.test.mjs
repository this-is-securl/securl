import assert from "node:assert/strict";
import test from "node:test";

import { buildVendorExposureBrief } from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    host: "example.com",
    finalUrl: "https://example.com/",
    thirdPartyTrust: {
      totalProviders: 4,
      highRiskProviders: 2,
      providers: [
        {
          name: "Example Replay",
          domain: "replay.example.net",
          category: "session_replay",
          risk: "high",
          evidence: "script src",
        },
        {
          name: "Stripe",
          domain: "js.stripe.com",
          category: "payments",
          risk: "high",
          evidence: "payment script",
        },
        {
          name: "Plausible",
          domain: "plausible.io",
          category: "analytics",
          risk: "low",
          evidence: "analytics script",
        },
        {
          name: "Unknown CDN",
          domain: "cdn.example.net",
          category: "cdn",
          risk: "medium",
          evidence: "stylesheet",
        },
      ],
      issues: [
        "Session replay or experience analytics tooling appears to be present.",
        "Some third-party scripts are loaded without Subresource Integrity.",
      ],
      strengths: ["A consent-management provider appears to be present."],
      summary: "The page depends on several third-party providers.",
    },
    htmlSecurity: {
      missingSriScriptUrls: [
        "https://replay.example.net/agent.js",
        "https://js.stripe.com/v3/",
      ],
    },
    aiSurface: {
      vendors: [
        {
          name: "OpenAI",
          confidence: "medium",
          category: "ai_vendor",
          evidence: "assistant markup",
        },
      ],
    },
    assessmentLimitation: {
      limited: false,
      kind: null,
      title: null,
      detail: null,
    },
    ...overrides,
  };
}

test("vendor exposure brief prioritizes high-risk providers and data flows", () => {
  const brief = buildVendorExposureBrief(buildAnalysis());

  assert.equal(brief.risk, "high");
  assert.equal(brief.counts.totalProviders, 4);
  assert.equal(brief.counts.highRiskProviders, 2);
  assert.equal(brief.counts.mediumRiskProviders, 1);
  assert.equal(brief.counts.sessionReplayProviders, 1);
  assert.equal(brief.counts.analyticsProviders, 1);
  assert.equal(brief.counts.aiProviders, 1);
  assert.equal(brief.counts.paymentProviders, 1);
  assert.equal(brief.counts.missingSriScripts, 2);
  assert.equal(brief.providers[0].reviewPriority, "urgent");
  assert.ok(brief.highPriorityProviders.some((provider) => provider.name === "Stripe"));
  assert.ok(brief.nextActions.some((action) => /Subresource Integrity/i.test(action)));
  assert.equal(brief.limitation, null);
});

test("vendor exposure brief handles clean pages", () => {
  const brief = buildVendorExposureBrief(buildAnalysis({
    thirdPartyTrust: {
      totalProviders: 0,
      highRiskProviders: 0,
      providers: [],
      issues: [],
      strengths: ["No obvious third-party script or stylesheet domains were detected on the fetched page."],
      summary: "Minimal visible third-party footprint on the fetched page.",
    },
    htmlSecurity: { missingSriScriptUrls: [] },
    aiSurface: { vendors: [] },
  }));

  assert.equal(brief.risk, "low");
  assert.equal(brief.providers.length, 0);
  assert.equal(brief.highPriorityProviders.length, 0);
  assert.deepEqual(brief.nextActions, [
    "Keep monitoring vendor drift after frontend, analytics, support, payment, or AI changes.",
  ]);
});
