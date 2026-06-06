import assert from "node:assert/strict";
import test from "node:test";
import { buildExecutiveSummary } from "../dist/htmlInsights.js";
import { getPostureAreaScores, getPostureScoreDrivers, scoreAnalysis, scorePostureAnalysis } from "../dist/scoring.js";

test("scoreAnalysis heavily penalizes plain HTTP and invalid transport posture", () => {
  const result = scoreAnalysis({
    isHttps: false,
    headerResults: [
      { key: "strict-transport-security", status: "missing" },
      { key: "content-security-policy", status: "missing" },
      { key: "x-frame-options", status: "missing" },
    ],
    certificate: {
      available: false,
      valid: false,
      authorized: false,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      protocol: null,
      cipher: null,
      fingerprint: null,
      subjectAltName: [],
      issues: [],
    },
    cookies: [],
    redirects: [],
  });

  assert.equal(result.score < 50, true);
  assert.equal(result.grade, "F");
});

test("scoreAnalysis preserves a strong score for a hardened HTTPS site", () => {
  const result = scoreAnalysis({
    isHttps: true,
    headerResults: [
      { key: "strict-transport-security", status: "present" },
      { key: "content-security-policy", status: "present" },
      { key: "x-frame-options", status: "present" },
      { key: "x-content-type-options", status: "present" },
      { key: "referrer-policy", status: "present" },
    ],
    certificate: {
      available: true,
      valid: true,
      authorized: true,
      issuer: "Example CA",
      subject: "example.com",
      validFrom: null,
      validTo: null,
      daysRemaining: 120,
      protocol: "TLSv1.3",
      cipher: null,
      fingerprint: null,
      subjectAltName: [],
      issues: [],
    },
    cookies: [
      { name: "session", secure: true, httpOnly: true, sameSite: "Lax", expires: null },
    ],
    redirects: [{ url: "https://example.com", statusCode: 200, location: null, secure: true }],
  });

  assert.equal(result.score >= 90, true);
  assert.equal(["A+", "A"].includes(result.grade), true);
});

const createPostureAnalysis = (overrides = {}) => ({
  finalUrl: "https://example.com/",
  statusCode: 200,
  headers: [
    { key: "strict-transport-security", status: "present" },
    { key: "content-security-policy", status: "present" },
    { key: "x-frame-options", status: "present" },
    { key: "x-content-type-options", status: "present" },
    { key: "referrer-policy", status: "present" },
  ],
  certificate: {
    available: true,
    valid: true,
    protocol: "TLSv1.3",
    daysRemaining: 120,
  },
  cookies: [],
  redirects: [],
  corsSecurity: { issues: [] },
  htmlSecurity: { issues: [] },
  domainSecurity: { issues: [] },
  securityTxt: { issues: [] },
  publicSignals: { issues: [] },
  infrastructure: { providers: [] },
  exposure: { issues: [], probes: [] },
  apiSurface: { issues: [], probes: [] },
  thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, issues: [] },
  aiSurface: { detected: false, disclosures: [], issues: [] },
  assessmentLimitation: { limited: false },
  ...overrides,
});

test("scorePostureAnalysis grades the wider passive posture, not just core header hardening", () => {
  const oldBaseline = scoreAnalysis({
    isHttps: true,
    headerResults: createPostureAnalysis().headers,
    certificate: createPostureAnalysis().certificate,
    cookies: [],
    redirects: [],
  });

  const posture = scorePostureAnalysis(
    createPostureAnalysis({
      domainSecurity: { issues: ["Missing MTA-STS", "SPF policy is weak", "DMARC policy is monitoring only"] },
      securityTxt: { issues: ["No valid security.txt disclosure route was detected."] },
      publicSignals: { issues: ["Domain is not HSTS preloaded."] },
      htmlSecurity: {
        issues: [
          "Inline scripts detected",
          "Inline style blocks detected",
          "Some third-party scripts are missing SRI",
          "Passive leak signal detected",
        ],
      },
      exposure: {
        issues: ["Directory listing style response"],
        probes: [{ finding: "interesting" }],
      },
      thirdPartyTrust: { totalProviders: 4, highRiskProviders: 2, issues: ["High-risk adtech provider present"] },
    }),
  );

  assert.equal(oldBaseline.score >= 90, true);
  assert.equal(posture.score < oldBaseline.score, true);
  assert.equal(posture.score < 90, true);
  assert.equal(posture.grade, "C");
  assert.equal(posture.scoreDrivers.length > 0, true);
});

test("getPostureScoreDrivers explains the largest score deductions without changing the score", () => {
  const analysis = createPostureAnalysis({
    headers: [
      { key: "strict-transport-security", status: "missing" },
      { key: "content-security-policy", status: "missing" },
      { key: "x-frame-options", status: "missing" },
    ],
    htmlSecurity: { issues: ["Inline scripts detected", "SRI coverage is incomplete"] },
    domainSecurity: { issues: ["No DMARC record detected."] },
    securityTxt: { issues: ["No valid security.txt disclosure route was detected."] },
    publicSignals: { issues: [] },
    exposure: { issues: ["Environment file may be exposed"], probes: [] },
    thirdPartyTrust: { totalProviders: 4, highRiskProviders: 2, issues: ["Session replay tooling appears present"] },
  });

  const posture = scorePostureAnalysis(analysis);
  const drivers = getPostureScoreDrivers(analysis);

  assert.equal(posture.scoreDrivers[0].impact >= posture.scoreDrivers.at(-1).impact, true);
  assert.equal(drivers.some((driver) => driver.label === "Content-Security-Policy gap"), true);
  assert.equal(drivers.some((driver) => driver.areaKey === "exposure" && driver.impact === 20), true);
  assert.equal(posture.score, scorePostureAnalysis(analysis).score);
});

test("scorePostureAnalysis keeps calibrated profile grades stable", () => {
  const profiles = [
    {
      name: "hardened owned domain",
      analysis: createPostureAnalysis({
        aiSurface: { detected: true, disclosures: ["AI disclosure visible"], issues: [] },
      }),
      expected: { score: 100, grade: "A+" },
    },
    {
      name: "mature SaaS homepage with common passive gaps",
      analysis: createPostureAnalysis({
        headers: [
          { key: "strict-transport-security", status: "present" },
          { key: "content-security-policy", status: "warning" },
          { key: "x-frame-options", status: "present" },
          { key: "x-content-type-options", status: "present" },
          { key: "referrer-policy", status: "present" },
        ],
        htmlSecurity: { issues: ["Some third-party scripts are missing SRI"] },
        domainSecurity: { issues: ["No DNSSEC DS records detected at the domain apex."] },
        publicSignals: { issues: ["Domain is not shown as preloaded in the public HSTS preload dataset."] },
        thirdPartyTrust: {
          totalProviders: 5,
          highRiskProviders: 1,
          issues: ["Session replay tooling appears present"],
        },
      }),
      expected: { score: 87, grade: "B" },
    },
    {
      name: "early-stage launch site with broad hygiene gaps",
      analysis: createPostureAnalysis({
        headers: [
          { key: "strict-transport-security", status: "missing" },
          { key: "content-security-policy", status: "missing" },
          { key: "x-frame-options", status: "missing" },
          { key: "x-content-type-options", status: "present" },
          { key: "referrer-policy", status: "missing" },
        ],
        cookies: [{ issues: ["missing Secure"] }, { issues: ["missing HttpOnly"] }],
        htmlSecurity: { issues: ["Inline scripts detected", "Some third-party scripts are missing SRI"] },
        domainSecurity: { issues: ["No SPF", "No DMARC", "No DNSSEC"] },
        securityTxt: { issues: ["No security.txt"] },
        publicSignals: { issues: ["Not preloaded"] },
        thirdPartyTrust: {
          totalProviders: 8,
          highRiskProviders: 3,
          issues: ["adtech", "session replay"],
        },
      }),
      expected: { score: 69, grade: "D" },
    },
    {
      name: "blocked edge response",
      analysis: createPostureAnalysis({
        statusCode: 403,
        assessmentLimitation: {
          limited: true,
          kind: "blocked_edge_response",
        },
      }),
      expected: { score: 41, grade: "U" },
    },
  ];

  for (const profile of profiles) {
    const result = scorePostureAnalysis(profile.analysis);
    assert.equal(result.score, profile.expected.score, profile.name);
    assert.equal(result.grade, profile.expected.grade, profile.name);
  }
});

test("posture edge scoring weights missing headers by severity, not a flat rate", () => {
  const edgeScore = (headers) =>
    getPostureAreaScores(createPostureAnalysis({ headers })).find((area) => area.key === "edge").score;

  // The three universally-omitted, low-value headers (1 pt each in HEADER_PENALTY).
  const trivialGaps = edgeScore([
    { key: "strict-transport-security", status: "present" },
    { key: "content-security-policy", status: "present" },
    { key: "permissions-policy", status: "missing" },
    { key: "cross-origin-opener-policy", status: "missing" },
    { key: "cross-origin-resource-policy", status: "missing" },
  ]);
  // A single missing HSTS — a genuinely important edge header (10 pts).
  const hstsGap = edgeScore([
    { key: "strict-transport-security", status: "missing" },
    { key: "content-security-policy", status: "present" },
  ]);

  // The old flat-rate bug scored three trivial gaps at 24 and one HSTS gap at 8 —
  // backwards. Severity weighting puts them at 3 and 10 respectively.
  assert.equal(trivialGaps, 97);
  assert.equal(hstsGap, 90);
  assert.equal(trivialGaps > hstsGap, true);
});

test("scorePostureAnalysis softens domain-trust penalties for known hosted app subdomains", () => {
  const ownedDomain = scorePostureAnalysis(
    createPostureAnalysis({
      finalUrl: "https://example.com/",
      domainSecurity: {
        issues: [
          "No MX records found.",
          "No SPF record detected at the zone apex.",
          "No DMARC record detected.",
          "No CAA records found.",
          "No DNSSEC DS records detected at the domain apex.",
          "No MTA-STS DNS policy record detected.",
        ],
      },
    }),
  );

  const hostedPlatform = scorePostureAnalysis(
    createPostureAnalysis({
      finalUrl: "https://demo.up.railway.app/",
      domainSecurity: {
        issues: [
          "No MX records found.",
          "No SPF record detected at the zone apex.",
          "No DMARC record detected.",
          "No CAA records found.",
          "No DNSSEC DS records detected at the domain apex.",
          "No MTA-STS DNS policy record detected.",
        ],
      },
      infrastructure: {
        providers: [{ provider: "Railway", category: "paas" }],
      },
    }),
  );

  assert.equal(hostedPlatform.score > ownedDomain.score, true);
});

test("getPostureAreaScores treats absent AI surface as fully neutral", () => {
  const areas = getPostureAreaScores(
    createPostureAnalysis({
      aiSurface: {
        detected: false,
        issues: [],
        disclosures: [],
      },
    }),
  );

  // No public AI/automation surface is not a weakness, so the AI area is neutral
  // (no penalty) rather than carrying a standing deduction.
  const ai = areas.find((area) => area.key === "ai");
  assert.equal(ai?.score, 100);
  assert.equal(ai?.status, "strong");
});

test("scorePostureAnalysis caps unavailable targets below a C grade", () => {
  const posture = scorePostureAnalysis(
    createPostureAnalysis({
      statusCode: 503,
      assessmentLimitation: {
        limited: true,
        kind: "service_unavailable",
      },
    }),
  );

  assert.equal(posture.score <= 49, true);
  assert.equal(posture.grade, "U");
  assert.equal(posture.scoreDrivers.some((driver) => driver.label === "Limited assessment score cap"), true);
});

test("scorePostureAnalysis marks blocked or restricted reads as unable to complete", () => {
  const posture = scorePostureAnalysis(
    createPostureAnalysis({
      statusCode: 403,
      assessmentLimitation: {
        limited: true,
        kind: "blocked_edge_response",
      },
    }),
  );

  assert.equal(posture.score <= 64, true);
  assert.equal(posture.grade, "U");
});

test("buildExecutiveSummary keeps browser hardening as the main risk when header gaps dominate", () => {
  const summary = buildExecutiveSummary({
    score: 72,
    headers: [
      { key: "strict-transport-security", status: "missing" },
      { key: "content-security-policy", status: "missing" },
      { key: "x-frame-options", status: "missing" },
      { key: "x-content-type-options", status: "missing" },
      { key: "referrer-policy", status: "missing" },
      { key: "permissions-policy", status: "missing" },
    ],
    thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, issues: [] },
    aiSurface: { detected: false, issues: [], disclosures: [] },
    domainSecurity: { issues: ["Missing SPF", "Missing DMARC"] },
    publicSignals: { issues: ["Not HSTS preloaded"] },
    htmlSecurity: { issues: [] },
    assessmentLimitation: { limited: false, kind: null, title: null, detail: null },
  });

  assert.equal(summary.mainRisk, "Browser-layer hardening gaps are the main visible risk.");
  assert.equal(summary.takeaways[0], "6 browser-facing protections are missing or weak on the scanned response.");
});

test("buildExecutiveSummary describes unavailable targets as limited availability reads", () => {
  const summary = buildExecutiveSummary({
    score: 0,
    headers: [],
    thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, issues: [] },
    aiSurface: { detected: false, issues: [], disclosures: [] },
    domainSecurity: { issues: [] },
    publicSignals: { issues: [] },
    htmlSecurity: { issues: [] },
    assessmentLimitation: {
      limited: true,
      kind: "service_unavailable",
      title: "The target did not respond in time.",
      detail: "The scanner could not complete a trusted response fetch before timing out, so this is only a limited assessment.",
    },
  });

  assert.match(summary.overview, /limited availability read/i);
  assert.equal(summary.mainRisk, "Availability or reachability issues prevented a normal posture read.");
});

test("buildExecutiveSummary adds lab/training interpretation without changing the main risk model", () => {
  const summary = buildExecutiveSummary({
    score: 65,
    headers: [
      { key: "strict-transport-security", status: "missing" },
      { key: "content-security-policy", status: "missing" },
    ],
    thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, issues: [] },
    aiSurface: { detected: false, issues: [], disclosures: [] },
    domainSecurity: { issues: [] },
    publicSignals: { issues: [] },
    htmlSecurity: {
      issues: ["Page content suggests an intentionally vulnerable training or challenge surface."],
    },
    assessmentLimitation: { limited: false, kind: null, title: null, detail: null },
  });

  assert.match(summary.overview, /intentionally vulnerable lab or training surface/i);
  assert.equal(summary.mainRisk, "Browser-layer hardening gaps are the main visible risk.");
  assert.equal(
    summary.takeaways[0],
    "This target appears to be an intentionally vulnerable lab or training surface, so read the grade as posture-only context rather than a business-risk verdict.",
  );
});
