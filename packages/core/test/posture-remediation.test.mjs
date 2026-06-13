import assert from "node:assert/strict";
import test from "node:test";

import {
  attachIssueEvidence,
  buildPostureRemediationPlan,
} from "../dist/index.js";

function buildAnalysis(overrides = {}) {
  return {
    inputUrl: "https://example.com",
    normalizedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-13T10:00:00.000Z",
    responseTimeMs: 120,
    statusCode: 200,
    score: 72,
    grade: "C",
    summary: "Mixed posture.",
    headers: [
      {
        key: "content-security-policy",
        label: "Content-Security-Policy",
        description: "Controls script sources.",
        recommendation: "Add a CSP and avoid unsafe-inline / unsafe-eval where possible.",
        value: null,
        status: "missing",
        severity: "warning",
        summary: "Missing.",
      },
    ],
    rawHeaders: {},
    cookies: [],
    cookieAnalysis: null,
    technologies: [],
    certificate: { issues: [] },
    redirects: [],
    redirectChain: { totalHops: 0 },
    issues: [
      {
        severity: "warning",
        area: "headers",
        title: "Content-Security-Policy is missing",
        detail: "Add a CSP and avoid unsafe-inline / unsafe-eval where possible.",
        confidence: "high",
        source: "observed",
        owasp: ["A05 Security Misconfiguration"],
        mitre: ["Reconnaissance"],
      },
    ],
    strengths: [],
    remediation: [],
    crawl: { pages: [] },
    securityTxt: { issues: [] },
    domainSecurity: { issues: [] },
    identityProvider: {},
    ctDiscovery: {},
    htmlSecurity: { issues: [] },
    aiSurface: {},
    thirdPartyTrust: {},
    infrastructure: {},
    passiveIntelligence: {},
    compromiseSignals: {},
    executiveSummary: {
      overview: "CSP needs work.",
      mainRisk: "Browser hardening is incomplete.",
      posture: "mixed",
      takeaways: ["Add CSP."],
    },
    scoreDrivers: [
      {
        areaKey: "content",
        areaLabel: "Content Security",
        impact: 12,
        label: "Content-Security-Policy gap",
        detail: "A missing or weak CSP reduced content security confidence.",
        source: "headers",
      },
    ],
    assessmentLimitation: { limited: false, kind: null, title: null, detail: null },
    exposure: { issues: [], probes: [] },
    corsSecurity: { issues: [] },
    apiSurface: { issues: [], probes: [] },
    publicSignals: { issues: [] },
    wafFingerprint: { providers: [] },
    ...overrides,
  };
}

test("attachIssueEvidence adds observed header evidence to findings", () => {
  const result = attachIssueEvidence(buildAnalysis());
  const [issue] = result.issues;

  assert.equal(issue.evidence.length, 1);
  assert.equal(issue.evidence[0].kind, "header");
  assert.equal(issue.evidence[0].label, "Content-Security-Policy");
  assert.equal(issue.evidence[0].observed, "missing");
  assert.match(issue.evidence[0].expected, /CSP/);
});

test("buildPostureRemediationPlan prioritizes score drivers and keeps related findings", () => {
  const result = attachIssueEvidence(buildAnalysis());
  const plan = buildPostureRemediationPlan(result);

  assert.equal(plan.totalActions >= 1, true);
  assert.equal(plan.items[0].title, "Content-Security-Policy gap");
  assert.equal(plan.items[0].owner, "edge");
  assert.equal(plan.items[0].impact, "medium");
  assert.equal(plan.items[0].effort, "medium");
  assert.equal(plan.items[0].scoreImpact, 12);
  assert.ok(plan.items[0].relatedFindings.includes("Content-Security-Policy is missing"));
  assert.equal(plan.items[0].evidence[0].kind, "score_driver");
});

test("buildPostureRemediationPlan does not connect broad domain text to header findings", () => {
  const result = attachIssueEvidence(buildAnalysis({
    issues: [
      {
        severity: "warning",
        area: "headers",
        title: "Strict-Transport-Security is missing",
        detail: "Set HSTS so browsers remember the HTTPS version of this domain.",
        confidence: "high",
        source: "observed",
        owasp: ["A05 Security Misconfiguration"],
        mitre: ["Reconnaissance"],
      },
    ],
    scoreDrivers: [
      {
        areaKey: "domain",
        areaLabel: "Domain & Trust",
        impact: 15,
        label: "Domain and public-trust findings",
        detail: "DNS and public trust posture reduced confidence.",
        source: "dns",
      },
    ],
  }));
  const plan = buildPostureRemediationPlan(result);

  assert.equal(plan.items[0].title, "Domain and public-trust findings");
  assert.deepEqual(plan.items[0].relatedFindings, []);
});
