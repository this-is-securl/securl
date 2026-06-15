import assert from "node:assert/strict";
import test from "node:test";

import { buildExposureBrief } from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    inputUrl: "https://example.com",
    normalizedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    host: "example.com",
    score: 76,
    grade: "C",
    remediationPlan: {
      items: [
        {
          action: "Tighten Content-Security-Policy and retest.",
        },
      ],
    },
    compromiseSignals: {
      collectionBoundary: "Passive public evidence only.",
      indicators: [
        {
          category: "script_anomaly",
          severity: "warning",
          title: "Suspicious script loader",
          detail: "A dynamic script loader matched a review heuristic.",
          confidence: "medium",
          source: "html",
          evidence: ["loader.js"],
          action: "Review the script loader and remove it if it is not expected.",
        },
      ],
    },
    exposure: {
      probes: [
        {
          label: "Environment file",
          path: "/.env",
          statusCode: 200,
          finalUrl: "https://example.com/.env",
          finding: "exposed",
          detail: "A sensitive-looking file returned a successful response.",
        },
      ],
    },
    apiSurface: {
      probes: [
        {
          label: "API root",
          path: "/api",
          statusCode: 200,
          finalUrl: "https://example.com/api",
          classification: "public",
          contentType: "application/json",
          detail: "API root returned JSON.",
        },
      ],
    },
    ctDiscovery: {
      sourceUrl: "https://crt.sh/?q=%25.example.com&output=json",
      prioritizedHosts: [
        {
          host: "admin.example.com",
          category: "admin",
          priority: "high",
          evidence: "admin host",
        },
      ],
    },
    domainSecurity: {
      issues: ["DMARC policy is not enforcing."],
    },
    securityTxt: {
      url: "https://example.com/.well-known/security.txt",
      issues: ["security.txt was not found."],
    },
    publicSignals: {
      hstsPreload: {
        sourceUrl: "https://hstspreload.org/?domain=example.com",
      },
      issues: ["Domain is not preloaded."],
    },
    thirdPartyTrust: {
      totalProviders: 2,
      highRiskProviders: 1,
      providers: [
        {
          name: "Example Replay",
          domain: "replay.example.net",
          category: "session_replay",
          risk: "high",
          evidence: "script src",
        },
      ],
    },
    aiSurface: {
      vendors: [
        {
          name: "OpenAI",
          category: "ai_vendor",
          confidence: "medium",
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
    passiveIntelligence: {
      collectionBoundary: "Passive read.",
    },
    ...overrides,
  };
}

test("exposure brief summarizes public attack surface signals", () => {
  const brief = buildExposureBrief(buildAnalysis());

  assert.equal(brief.exposureLevel, "high");
  assert.equal(brief.counts.publicEntryPoints, 2);
  assert.equal(brief.counts.sensitiveExposures, 1);
  assert.equal(brief.counts.trustGaps, 3);
  assert.equal(brief.counts.abuseIndicators, 1);
  assert.equal(brief.counts.highRiskThirdParties, 1);
  assert.equal(brief.counts.aiVendors, 1);
  assert.equal(brief.topRisks[0].severity, "warning");
  assert.ok(brief.topRisks.some((risk) => risk.title === "Environment file appears exposed"));
  assert.ok(brief.publicEntryPoints.some((risk) => risk.title === "API root is publicly reachable"));
  assert.ok(brief.trustGaps.some((risk) => risk.title === "Domain trust gap"));
  assert.ok(brief.nextActions.includes("Review the script loader and remove it if it is not expected."));
  assert.equal(brief.limitation, null);
});

test("exposure brief handles limited scans without invented findings", () => {
  const analysis = buildAnalysis({
    compromiseSignals: {
      collectionBoundary: "Limited passive evidence.",
      indicators: [],
    },
    exposure: { probes: [] },
    apiSurface: { probes: [] },
    ctDiscovery: { prioritizedHosts: [] },
    domainSecurity: { issues: [] },
    securityTxt: { issues: [] },
    publicSignals: { issues: [] },
    thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, providers: [] },
    aiSurface: { vendors: [] },
    assessmentLimitation: {
      limited: true,
      kind: "blocked_edge_response",
      title: "Assessment limited",
      detail: "The edge blocked passive assessment.",
    },
    remediationPlan: { items: [] },
  });

  const brief = buildExposureBrief(analysis);

  assert.equal(brief.exposureLevel, "unknown");
  assert.equal(brief.topRisks.length, 0);
  assert.equal(brief.limitation.kind, "blocked_edge_response");
  assert.deepEqual(brief.nextActions, [
    "Keep the target in monitoring and rescan after meaningful deployment, DNS, or vendor changes.",
  ]);
});
