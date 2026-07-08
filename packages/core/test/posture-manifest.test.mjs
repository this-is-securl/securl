import assert from "node:assert/strict";
import test from "node:test";

import { buildPostureManifest } from "../dist/postureManifest.js";

function buildAnalysis(overrides = {}) {
  return {
    inputUrl: "example.com",
    normalizedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-07-08T08:00:00.000Z",
    responseTimeMs: 321,
    statusCode: 200,
    score: 82,
    grade: "B",
    summary: "External posture is broadly sound.",
    headers: [
      { key: "strict-transport-security", label: "HSTS", status: "present", value: "max-age=31536000" },
      { key: "content-security-policy", label: "CSP", status: "missing", value: null },
    ],
    rawHeaders: {},
    cookies: [],
    cookieAnalysis: null,
    technologies: [{ name: "Example Framework", category: "frontend", evidence: "asset path", version: "1.2.3", confidence: "medium", detection: "observed" }],
    certificate: {
      available: true,
      valid: true,
      authorized: true,
      issuer: "Example CA",
      subject: "example.com",
      validFrom: "2026-06-01T00:00:00.000Z",
      validTo: "2026-08-01T00:00:00.000Z",
      daysRemaining: 24,
      protocol: "TLSv1.3",
      cipher: "TLS_AES_128_GCM_SHA256",
      fingerprint: "aa:bb",
      subjectAltName: ["example.com"],
      issues: [],
    },
    redirects: [],
    redirectChain: { totalHops: 0, hasMixedRedirect: false, crossesDomain: false, issues: [] },
    issues: [
      {
        severity: "warning",
        area: "headers",
        source: "observed",
        confidence: "high",
        title: "Content-Security-Policy missing",
        detail: "The response did not include a CSP.",
        owasp: ["A05 Security Misconfiguration"],
        mitre: ["Reconnaissance"],
      },
    ],
    strengths: ["TLS certificate is valid."],
    remediation: [],
    evidenceSummary: { totalEvidenceReferences: 3 },
    evidenceQuality: { score: 92, level: "high", summary: "Evidence is strong.", strengths: [], limitations: [] },
    signalClarity: { verdict: "strong", headline: "Clear signal", summary: "Enough evidence was observed.", topNegativeDrivers: [], nextBestAction: null, driversReviewed: 1 },
    scoreDrivers: [{ label: "CSP gap", impact: -8, detail: "Missing CSP.", source: "headers" }],
    crawl: { enabled: false, pagesVisited: 0, discoveredUrls: [] },
    securityTxt: { status: "present_valid" },
    domainSecurity: {
      host: "example.com",
      dnssec: { enabled: false, status: "not_signed" },
      emailPolicy: {
        spf: { status: "strong" },
        dmarc: { status: "watch" },
      },
    },
    identityProvider: { providers: [] },
    ctDiscovery: { coverageSummary: "No CT issues.", prioritizedHosts: [] },
    htmlSecurity: {},
    aiSurface: {},
    thirdPartyTrust: {},
    infrastructure: {
      providers: [{ provider: "Example Edge", category: "edge", confidence: "high", source: "headers", evidence: "server header" }],
    },
    passiveIntelligence: {},
    compromiseSignals: {},
    executiveSummary: {},
    assessmentLimitation: { limited: false, kind: null, detail: null },
    exposure: {},
    corsSecurity: {},
    apiSurface: {},
    publicSignals: {},
    wafFingerprint: { providers: [] },
    scanTiming: { totalMs: 1200, coreMs: 700, enrichmentMs: 500, timedOut: false, timeoutMs: 45000 },
    ...overrides,
  };
}

test("posture manifest creates a stable external recipe card", () => {
  const manifest = buildPostureManifest(buildAnalysis(), {
    engineVersion: "1.20.0",
    scanMode: "quiet",
  });

  assert.equal(manifest.version, "1.0");
  assert.match(manifest.manifestId, /^pm_[a-f0-9]{24}$/);
  assert.equal(manifest.engine.name, "securl");
  assert.equal(manifest.engine.version, "1.20.0");
  assert.equal(manifest.target.host, "example.com");
  assert.equal(manifest.scan.mode, "quiet");
  assert.equal(manifest.posture.score, 82);
  assert.equal(manifest.posture.issueCounts.warning, 1);
  assert.equal(manifest.checks.observationLedger.version, "1.0");
  assert.ok(manifest.checks.observationLedger.observations.length > 0);
  assert.equal(manifest.evidence.evidenceQuality.level, "high");
  assert.equal(manifest.policy.source, "default");
  assert.equal(manifest.policy.evaluation.policy.id, "securl-baseline-v1");
});

test("posture manifest records skipped assessment context for limited scans", () => {
  const manifest = buildPostureManifest(buildAnalysis({
    statusCode: 0,
    assessmentLimitation: {
      limited: true,
      kind: "service_unavailable",
      detail: "The target did not respond in time.",
    },
  }));

  assert.equal(manifest.checks.skipped.length, 1);
  assert.equal(manifest.checks.skipped[0].id, "complete_assessment");
  assert.equal(manifest.checks.skipped[0].reason, "service_unavailable");
});
