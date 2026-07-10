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
    infrastructure: {
      providers: [
        {
          provider: "Cloudflare",
          category: "edge",
          confidence: "high",
          source: "headers",
          evidence: "cf-ray response header",
        },
      ],
      waf: {
        detected: true,
        provider: "Cloudflare",
        confidence: "high",
        evidence: "Observed Cloudflare edge headers.",
      },
    },
    identityProvider: {
      detected: true,
      provider: "Okta",
      protocol: "oidc",
      redirectOrigins: ["https://example.okta.com"],
      openIdConfigurationUrl: "https://example.okta.com/.well-known/openid-configuration",
      issuer: "https://example.okta.com",
      authorizationEndpoint: "https://example.okta.com/oauth2/v1/authorize",
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
  assert.equal(brief.schemaVersion, "1.0");
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
  assert.equal(brief.inventoryCounts.total, 7);
  assert.equal(brief.inventoryCounts.thirdParty, 4);
  assert.equal(brief.inventoryCounts.infrastructure, 1);
  assert.equal(brief.inventoryCounts.identity, 1);
  assert.equal(brief.inventoryCounts.aiSurface, 1);
  assert.equal(brief.inventoryCounts.urgent, 2);
  assert.equal(brief.inventoryCounts.telemetryFlows, 2);
  assert.equal(brief.inventoryCounts.integrityGaps, 2);
  assert.ok(brief.inventory.every((item) => item.id.startsWith("exposure:")));
  assert.equal(
    brief.inventory.find((item) => item.name === "Stripe")?.integrity,
    "missing",
  );
  assert.equal(
    brief.inventory.find((item) => item.name === "Okta")?.dataFlow,
    "identity",
  );
  assert.equal(
    brief.inventory.filter((item) => item.name === "Cloudflare").length,
    1,
  );
  assert.match(brief.collectionBoundary, /do not prove internal dependency/i);
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
    infrastructure: { providers: [], waf: { detected: false, provider: null } },
    identityProvider: { detected: false, provider: null },
  }));

  assert.equal(brief.risk, "low");
  assert.equal(brief.providers.length, 0);
  assert.equal(brief.highPriorityProviders.length, 0);
  assert.equal(brief.inventory.length, 0);
  assert.equal(brief.inventoryCounts.total, 0);
  assert.deepEqual(brief.nextActions, [
    "Keep monitoring vendor drift after frontend, analytics, support, payment, or AI changes.",
  ]);
});
