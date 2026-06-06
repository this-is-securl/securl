import assert from "node:assert/strict";
import test from "node:test";

import { buildPostureDigest } from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    inputUrl: "https://example.com",
    normalizedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-04T10:00:00.000Z",
    responseTimeMs: 123,
    statusCode: 200,
    score: 86,
    grade: "B",
    summary: "External posture is broadly sound.",
    headers: [
      { label: "Strict-Transport-Security", status: "present" },
      { label: "Content-Security-Policy", status: "warning" },
      { label: "Permissions-Policy", status: "missing" },
    ],
    rawHeaders: {},
    cookies: [],
    cookieAnalysis: { issues: ["Session cookie is missing HttpOnly."] },
    technologies: [],
    certificate: {
      available: true,
      valid: true,
      authorized: true,
      issuer: "Example CA",
      daysRemaining: 42,
      issues: [],
    },
    redirects: [],
    redirectChain: {
      totalHops: 1,
      hasMixedRedirect: false,
      crossesDomain: false,
      issues: [],
    },
    issues: [
      {
        severity: "warning",
        title: "CSP allows unsafe inline script",
        detail: "The observed CSP permits inline script execution.",
        confidence: "high",
        source: "observed",
        owasp: ["A05 Security Misconfiguration"],
        mitre: ["Defense Evasion"],
      },
      {
        severity: "info",
        title: "Security.txt missing",
        detail: "No security.txt file was found.",
        confidence: "medium",
        source: "heuristic",
        owasp: [],
        mitre: ["Reconnaissance"],
      },
    ],
    strengths: [],
    remediation: [],
    crawl: { pages: [] },
    securityTxt: { status: "missing", contact: [] },
    domainSecurity: {
      emailDeliverabilityScore: { score: 80, grade: "B", breakdown: {} },
      issues: ["DMARC is monitor-only."],
      strengths: ["SPF is present."],
    },
    identityProvider: { provider: "Okta" },
    ctDiscovery: { prioritizedHosts: [{ host: "admin.example.com" }] },
    htmlSecurity: { issues: [] },
    aiSurface: { vendors: [{ name: "OpenAI" }] },
    thirdPartyTrust: {
      providers: [{ name: "Stripe" }],
      highRiskProviders: 0,
      issues: [],
    },
    infrastructure: {
      providers: [{ provider: "Cloudflare" }],
    },
    passiveIntelligence: {
      postureRead: "Passive public signals look mostly stable.",
    },
    compromiseSignals: {
      posture: "review_recommended",
      summary: "One suspicious public signal needs review.",
      indicators: [
        {
          severity: "warning",
          category: "script_anomaly",
          title: "Suspicious inline script marker",
          detail: "A script marker matched a review heuristic.",
          confidence: "medium",
        },
      ],
    },
    executiveSummary: {
      overview: "Broadly sound with one content-security gap.",
      mainRisk: "CSP needs tightening.",
      posture: "mixed",
      takeaways: ["Tighten CSP."],
    },
    scoreDrivers: [
      {
        areaKey: "content",
        areaLabel: "Content",
        impact: 18,
        label: "Content-Security-Policy gap",
        detail: "CSP is weak.",
        source: "headers",
      },
    ],
    assessmentLimitation: {
      limited: false,
      kind: null,
      title: null,
      detail: null,
    },
    exposure: {
      probes: [{ finding: "interesting" }],
      issues: ["Admin path returned a review-worthy response."],
    },
    corsSecurity: {
      issues: [],
      allowCredentials: null,
      allowedOrigin: null,
    },
    apiSurface: {
      probes: [{ classification: "public" }],
      issues: [],
    },
    publicSignals: { issues: [] },
    wafFingerprint: { providers: [{ name: "Cloudflare" }] },
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

test("posture digest condenses scan results for API consumers", () => {
  const digest = buildPostureDigest(buildAnalysis());

  assert.equal(digest.target.host, "example.com");
  assert.equal(digest.posture.score, 86);
  assert.equal(digest.findings.total, 2);
  assert.equal(digest.findings.bySeverity.warning, 1);
  assert.equal(digest.controls.headers.missing, 1);
  assert.equal(digest.controls.headers.warning, 1);
  assert.equal(digest.controls.tls.issuer, "Example CA");
  assert.equal(digest.surface.exposure.interesting, 1);
  assert.deepEqual(digest.trust.wafProviders, ["Cloudflare"]);
  assert.deepEqual(digest.trust.infrastructureProviders, ["Cloudflare"]);
  assert.deepEqual(digest.intelligence.ctPriorityHosts, ["admin.example.com"]);
  assert.equal(digest.intelligence.riskIndicators[0].title, "Suspicious inline script marker");
});
