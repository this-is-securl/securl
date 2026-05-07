import { describe, expect, it } from "vitest";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";
import { AnalysisResult } from "@/types/analysis";

const createAnalysis = (overrides: Partial<AnalysisResult> = {}): AnalysisResult =>
  ({
    finalUrl: "https://example.com/",
    statusCode: 200,
    headers: [],
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
    corsSecurity: { issues: [] },
    redirects: [],
    htmlSecurity: { issues: [], missingSriScriptUrls: [], passiveLeakSignals: [] },
    cookies: [],
    exposure: { issues: [], probes: [] },
    apiSurface: { issues: [], probes: [] },
    domainSecurity: { issues: [], dmarc: "v=DMARC1; p=reject;" },
    securityTxt: { issues: [], status: "present" },
    publicSignals: { issues: [], hstsPreload: { status: "not_listed" } },
    thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, issues: [] },
    aiSurface: { detected: false, disclosures: [], issues: [] },
    ...overrides,
  }) as AnalysisResult;

describe("getAreaScores", () => {
  it("penalizes content security when CSP is missing", () => {
    const analysis = createAnalysis({
      headers: [{ key: "content-security-policy", status: "missing" }],
    });

    const content = getAreaScores(analysis).find((area) => area.key === "content");
    expect(content?.score).toBe(82);
    expect(content?.status).toBe("watch");
  });

  it("clamps heavily penalized edge score at zero and marks it weak", () => {
    const analysis = createAnalysis({
      headers: Array.from({ length: 20 }, (_, index) => ({
        key: `x-test-header-${index}`,
        status: "missing",
      })),
      corsSecurity: { issues: ["open wildcard", "credentials+wildcard", "unsafe methods"] },
      redirects: [{ statusCode: 301 }, { statusCode: 302 }, { statusCode: 302 }],
    });

    const edge = getAreaScores(analysis).find((area) => area.key === "edge");
    expect(edge?.score).toBe(0);
    expect(edge?.status).toBe("weak");
  });

  it("penalizes edge security when the target returns a server error", () => {
    const analysis = createAnalysis({
      statusCode: 503,
      assessmentLimitation: { limited: true, kind: "service_unavailable" },
    });

    const edge = getAreaScores(analysis).find((area) => area.key === "edge");
    expect(edge?.score).toBe(35);
    expect(edge?.notes).toContain("HTTP 503 limited assessment");
  });

  it("caps page-dependent areas when the assessment is limited by a blocked response", () => {
    const analysis = createAnalysis({
      assessmentLimitation: { limited: true, kind: "blocked_edge_response" },
      htmlSecurity: { issues: [], missingSriScriptUrls: [], passiveLeakSignals: [] },
    });

    const content = getAreaScores(analysis).find((area) => area.key === "content");
    const domain = getAreaScores(analysis).find((area) => area.key === "domain");

    expect(content?.score).toBe(59);
    expect(content?.notes).toContain("Page-dependent findings may be incomplete");
    expect(domain?.score).toBe(78);
  });

  it("applies status thresholds consistently", () => {
    const strong = getAreaScores(createAnalysis()).find((area) => area.key === "domain");
    const watch = getAreaScores(
      createAnalysis({
        domainSecurity: { issues: ["mx warning", "spf warning", "dmarc warning"], dmarc: "v=DMARC1; p=none;" },
      }),
    ).find((area) => area.key === "domain");
    const weak = getAreaScores(
      createAnalysis({
        domainSecurity: { issues: Array.from({ length: 8 }, (_, i) => `issue-${i}`), dmarc: "v=DMARC1; p=none;" },
      }),
    ).find((area) => area.key === "domain");

    expect(strong?.status).toBe("strong");
    expect(watch?.status).toBe("watch");
    expect(weak?.status).toBe("weak");
  });

  it("treats no visible AI surface as strong-neutral rather than perfect", () => {
    const ai = getAreaScores(createAnalysis()).find((area) => area.key === "ai");

    expect(ai?.score).toBe(88);
    expect(ai?.status).toBe("strong");
    expect(ai?.notes[0]).toMatch(/low exposure rather than perfect assurance/i);
  });
});

describe("getUnifiedIssueSummary", () => {
  it("keeps normalized warnings separate from supporting panel watch items", () => {
    const analysis = createAnalysis({
      issues: [
        {
          severity: "critical",
          area: "headers",
          title: "Critical issue",
          detail: "Critical detail",
          confidence: "high",
          source: "observed",
          owasp: [],
          mitre: [],
        },
        {
          severity: "warning",
          area: "headers",
          title: "Warning issue",
          detail: "Warning detail",
          confidence: "high",
          source: "observed",
          owasp: [],
          mitre: [],
        },
        {
          severity: "info",
          area: "headers",
          title: "Info issue",
          detail: "Info detail",
          confidence: "high",
          source: "observed",
          owasp: [],
          mitre: [],
        },
      ],
      domainSecurity: { issues: ["Missing MTA-STS"], dmarc: "v=DMARC1; p=reject;" },
      htmlSecurity: { issues: ["Inline scripts detected"], missingSriScriptUrls: [], passiveLeakSignals: [] },
      exposure: { issues: [], probes: [{ finding: "interesting" }] },
    } as Partial<AnalysisResult>);

    const summary = getUnifiedIssueSummary(analysis);

    expect(summary.critical).toBe(1);
    expect(summary.warning).toBe(1);
    expect(summary.priorityWarnings).toBe(1);
    expect(summary.supportingWatchItems).toBe(2);
    expect(summary.observedSignals).toBe(2);
  });
});
