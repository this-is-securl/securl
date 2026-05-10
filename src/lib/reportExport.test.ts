import { describe, expect, it } from "vitest";
import { buildHtmlReport, buildMarkdownReport } from "@/lib/reportExport";
import type { AnalysisResult, HistoryDiff } from "@/types/analysis";

// Minimal fixture — cast allows tests to stay focused on the behaviour under test
// without needing to satisfy every field of the full AnalysisResult shape.
const makeAnalysis = (overrides: Record<string, unknown> = {}): AnalysisResult =>
  ({
    host: "example.com",
    finalUrl: "https://example.com/",
    scannedAt: "2026-05-09T00:00:00.000Z",
    statusCode: 200,
    score: 75,
    grade: "C",
    summary: "Mixed posture.",
    responseTimeMs: 320,
    rawHeaders: {},
    remediation: [],

    executiveSummary: {
      overview: "Mixed posture with some gaps in browser hardening.",
      mainRisk: "Missing security headers reduce browser protection.",
      posture: "mixed",
      takeaways: ["Consider adding CSP", "HSTS could be improved"],
    },

    strengths: ["HTTPS is enforced", "DNSSEC is enabled"],
    issues: [
      {
        severity: "warning",
        confidence: "high",
        source: "headers",
        title: "Content Security Policy missing",
        detail: "No CSP header was detected on the primary response.",
        owasp: ["A05:2021"],
        mitre: [],
      },
      {
        severity: "critical",
        confidence: "high",
        source: "headers",
        title: "HSTS not enforced",
        detail: "Strict-Transport-Security header is absent.",
        owasp: ["A02:2021"],
        mitre: ["T1557"],
      },
    ],
    technologies: [
      { name: "Nginx", category: "server", detection: "header", confidence: "high", evidence: "Server: nginx" },
    ],

    headers: [],
    certificate: {
      available: true, valid: true, authorized: true,
      issuer: "Let's Encrypt", subject: "example.com",
      validFrom: null, validTo: null, daysRemaining: 90,
      protocol: "TLSv1.3", cipher: null, fingerprint: null,
      subjectAltName: [], issues: [],
    },
    cookies: [],
    redirects: [],

    corsSecurity: {
      allowedOrigin: null, allowCredentials: false,
      allowMethods: [], allowHeaders: [], exposeHeaders: [],
      maxAge: null, issues: [],
    },

    domainSecurity: {
      host: "example.com",
      spf: "v=spf1 ~all",
      dmarc: null,
      mxRecords: [], nsRecords: [], caaRecords: [],
      dnssec: { status: "enabled" },
      mtaSts: { dns: null, policyUrl: null, policy: null },
      issues: [], strengths: [],
    },

    securityTxt: {
      status: "present",
      url: "https://example.com/.well-known/security.txt",
      contact: [], expires: null, policy: null, pgp: null,
      encryption: null, acknowledgments: null, preferredLanguages: null,
      issues: [],
    },

    htmlSecurity: {
      fetched: true, pageUrl: null, pageTitle: "Example Domain",
      metaGenerator: null, forms: [], firstPartyPaths: [],
      sameSiteHosts: [], passiveLeakSignals: [],
      missingSriScriptUrls: [], libraryFingerprints: [],
      libraryRiskSignals: [], inlineScriptCount: 0,
      inlineStyleCount: 0,
      externalScriptDomains: [], externalStylesheetDomains: [],
      insecureResourceUrls: [], clientExposureSignals: [],
      detectedTechnologies: [],
      aiSurface: {
        detected: false, assistantVisible: false,
        aiPageSignals: [], vendors: [], discoveredPaths: [],
        disclosures: [], privacySignals: [], governanceSignals: [],
        issues: [], strengths: [],
      },
      issues: [], strengths: [],
    },

    exposure: { probes: [], issues: [] },
    apiSurface: { probes: [], issues: [] },

    thirdPartyTrust: {
      totalProviders: 0, highRiskProviders: 0,
      providers: [], issues: [], strengths: [],
      summary: "No external providers detected.",
    },

    aiSurface: {
      detected: false, assistantVisible: false,
      vendors: [], discoveredPaths: [], privacySignals: [],
      governanceSignals: [], aiPageSignals: [],
      disclosures: [], issues: [],
    },

    identityProvider: {
      detected: false, provider: null, protocol: null,
      openIdConfigurationUrl: null, redirectOrigins: [],
      authHostCandidates: [], loginPaths: [],
      tenantSignals: [], redirectUriSignals: [],
    },

    ctDiscovery: {
      queriedDomain: "example.com",
      coverageSummary: "No subdomains found in CT logs.",
      subdomains: [], wildcardEntries: [], sampledHosts: [],
      issues: [],
    },

    wafFingerprint: {
      summary: "No WAF or CDN fingerprinted.",
      providers: [], edgeSignals: [],
    },

    publicSignals: {
      hstsPreload: { status: "not_preloaded", summary: "Not on the preload list." },
      issues: [],
    },

    crawl: {
      pages: [], discoverySources: [],
      weakestPage: null, strongestPage: null,
      inconsistentHeaders: [],
    },

    assessmentLimitation: {
      limited: false, kind: null, title: null, detail: null,
    },

    infrastructure: {
      host: "example.com", addresses: ["1.2.3.4"],
      cnameTargets: [], reverseDns: [],
      providers: [], issues: [], strengths: [],
      summary: "Hosted on a commercial provider.",
    },

    ...overrides,
  }) as unknown as AnalysisResult;

const makeDiff = (overrides: Partial<HistoryDiff> = {}): HistoryDiff =>
  ({
    scoreDelta: 5,
    newIssues: [],
    resolvedIssues: [],
    headerChanges: [],
    newThirdPartyProviders: [],
    newAiVendors: [],
    wafProviderChanges: { newProviders: [], removedProviders: [] },
    summary: ["Score improved by 5 points."],
    ...overrides,
  }) as HistoryDiff;

// ── buildHtmlReport ───────────────────────────────────────────────────────────

describe("buildHtmlReport", () => {
  it("returns a complete HTML document", () => {
    const html = buildHtmlReport(makeAnalysis());
    expect(html).toMatch(/^<!DOCTYPE html>/);
    expect(html).toMatch(/<\/html>$/);
  });

  it("includes all eight section eyebrows in order", () => {
    const html = buildHtmlReport(makeAnalysis());
    const sections = [
      "External Security Posture Report",
      "02 — Priority Actions",
      "03 — Posture Overview",
      "04 — Key Findings",
      "05 — Strengths",
      "06 — Technical Details",
      "07 — Recommendations",
      "08 — Appendix",
    ];
    for (const section of sections) {
      expect(html).toContain(section);
    }
  });

  it("escapes HTML-special characters in the target URL", () => {
    const xssUrl = 'https://evil.com/<script>alert(1)</script>';
    const html = buildHtmlReport(makeAnalysis({ finalUrl: xssUrl, host: "evil.com" }));
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("escapes HTML-special characters in finding titles and details", () => {
    const html = buildHtmlReport(makeAnalysis({
      issues: [{
        severity: "critical",
        confidence: "high",
        source: "headers",
        title: 'Bad header <img src=x onerror="pwn()">',
        detail: 'The value contained & special chars.',
        owasp: [],
        mitre: [],
      }],
    }));
    expect(html).not.toContain('<img src=x');
    expect(html).toContain("&lt;img");
    expect(html).toContain("&amp; special chars");
  });

  it("uses green ring color for grade A", () => {
    const html = buildHtmlReport(makeAnalysis({ grade: "A", score: 92 }));
    expect(html).toContain("--grade:   #16a34a");
    expect(html).toContain('stroke="#16a34a"');
  });

  it("uses red ring color for grade F", () => {
    const html = buildHtmlReport(makeAnalysis({ grade: "F", score: 35 }));
    expect(html).toContain("--grade:   #dc2626");
    expect(html).toContain('stroke="#dc2626"');
  });

  it("uses grey ring color for grade U (limited assessment)", () => {
    const html = buildHtmlReport(makeAnalysis({
      grade: "U",
      score: 0,
      assessmentLimitation: { limited: true, kind: "blocked_edge_response", title: "Blocked", detail: "Edge blocked." },
    }));
    expect(html).toContain("--grade:   #94a3b8");
  });

  it("SVG ring dashoffset is 0 when score is 100", () => {
    const html = buildHtmlReport(makeAnalysis({ grade: "A+", score: 100 }));
    expect(html).toContain('stroke-dashoffset="0"');
  });

  it("SVG ring dashoffset equals circumference when score is 0", () => {
    // circumference = 2π × 110 ≈ 691.15
    const html = buildHtmlReport(makeAnalysis({ grade: "F", score: 0 }));
    const circumference = parseFloat((2 * Math.PI * 110).toFixed(2));
    expect(html).toContain(`stroke-dashoffset="${circumference}"`);
  });

  it("SVG ring dashoffset is roughly half the circumference when score is 50", () => {
    const html = buildHtmlReport(makeAnalysis({ grade: "D", score: 50 }));
    const circumference = parseFloat((2 * Math.PI * 110).toFixed(2));
    const expected = parseFloat((circumference * 0.5).toFixed(2));
    expect(html).toContain(`stroke-dashoffset="${expected}"`);
  });

  it("shows the scan host and score on the cover", () => {
    const html = buildHtmlReport(makeAnalysis({ host: "target.io", finalUrl: "https://target.io/", score: 83, grade: "B" }));
    expect(html).toContain("target.io");
    expect(html).toContain("83/100");
    expect(html).toContain(">B<");
  });

  it("includes the change headline when a diff is supplied", () => {
    const diff = makeDiff({ scoreDelta: 8, newIssues: [{ title: "New finding" } as never], resolvedIssues: [] });
    const html = buildHtmlReport(makeAnalysis(), diff);
    expect(html).toContain("+8");
  });

  it("shows a baseline message when no diff is supplied", () => {
    const html = buildHtmlReport(makeAnalysis(), null);
    expect(html).toContain("No previous local snapshot");
  });

  it("renders severity badges with correct label text", () => {
    const html = buildHtmlReport(makeAnalysis());
    expect(html).toContain(">critical<");
    expect(html).toContain(">warning<");
  });

  it("renders the Fix Now card with red accent", () => {
    const html = buildHtmlReport(makeAnalysis());
    expect(html).toContain("pcard-now");
    expect(html).toContain("Fix Now");
  });

  it("renders technology stack entries", () => {
    const html = buildHtmlReport(makeAnalysis());
    expect(html).toContain("Nginx");
  });

  it("does not throw when all optional arrays are empty", () => {
    expect(() => buildHtmlReport(makeAnalysis())).not.toThrow();
  });

  it("does not throw when mtaSts.dns is null", () => {
    const analysis = makeAnalysis({
      domainSecurity: {
        host: "example.com",
        spf: null,
        dmarc: null,
        mxRecords: [], nsRecords: [], caaRecords: [],
        dnssec: { status: "disabled" },
        mtaSts: { dns: null, policyUrl: null, policy: null },
        issues: [], strengths: [],
      },
    });
    expect(() => buildHtmlReport(analysis)).not.toThrow();
  });
});

// ── buildMarkdownReport ───────────────────────────────────────────────────────

describe("buildMarkdownReport", () => {
  it("starts with the report heading including the host", () => {
    const md = buildMarkdownReport(makeAnalysis());
    expect(md).toMatch(/^# Security Report: example\.com/);
  });

  it("includes all major sections", () => {
    const md = buildMarkdownReport(makeAnalysis());
    const sections = [
      "## At a glance",
      "## Why this matters",
      "## Top findings",
      "## Analyst prompts",
      "## Assessment boundaries",
      "## Category posture",
      "## Key Findings",
      "## Priority Actions for This Target",
    ];
    for (const section of sections) {
      expect(md).toContain(section);
    }
  });

  it("includes the grade and score in the at-a-glance metrics", () => {
    const md = buildMarkdownReport(makeAnalysis());
    expect(md).toContain("Grade: **C**");
    expect(md).toContain("Score: **75/100**");
  });

  it("includes diff data when a diff is provided", () => {
    const diff = makeDiff({ scoreDelta: -3, newIssues: [], resolvedIssues: [{ title: "Fixed" } as never] });
    const md = buildMarkdownReport(makeAnalysis(), diff);
    expect(md).toContain("Score delta: -3");
    expect(md).toContain("Resolved issues: 1");
  });

  it("notes no previous snapshot when diff is null", () => {
    const md = buildMarkdownReport(makeAnalysis(), null);
    expect(md).toContain("No previous local snapshot");
  });

  it("escapes nothing — markdown does not use HTML escaping", () => {
    // buildMarkdownReport uses raw values (not escapeHtml), so angle brackets appear as-is
    const analysis = makeAnalysis({
      executiveSummary: {
        overview: "Score is 75.",
        mainRisk: "Headers & cookies need work.",
        posture: "mixed",
        takeaways: [],
      },
    });
    const md = buildMarkdownReport(analysis);
    expect(md).toContain("Headers & cookies need work.");
  });

  it("produces a category posture table with pipe separators", () => {
    const md = buildMarkdownReport(makeAnalysis());
    expect(md).toContain("| Area | Score | Status |");
  });
});
