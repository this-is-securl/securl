import type { AnalysisResult, ScanIssue, Severity } from "./types.js";

type IssueSeverity = Exclude<Severity, "good">;

const SEVERITY_ORDER: Record<IssueSeverity, number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

const countIssuesBySeverity = (issues: ScanIssue[]) => ({
  critical: issues.filter((issue) => issue.severity === "critical").length,
  warning: issues.filter((issue) => issue.severity === "warning").length,
  info: issues.filter((issue) => issue.severity === "info").length,
});

const topIssues = (issues: ScanIssue[], limit: number) =>
  [...issues]
    .sort((left, right) => {
      const severityDelta = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
      if (severityDelta !== 0) {
        return severityDelta;
      }
      return left.title.localeCompare(right.title);
    })
    .slice(0, limit)
    .map((issue) => ({
      severity: issue.severity,
      title: issue.title,
      detail: issue.detail,
      confidence: issue.confidence,
      source: issue.source,
      owasp: issue.owasp,
      mitre: issue.mitre,
    }));

export function buildPostureDigest(analysis: AnalysisResult, { findingLimit = 8 } = {}) {
  const issues = normalizeArray(analysis.issues);
  const compromiseIndicators = normalizeArray(analysis.compromiseSignals?.indicators);
  const riskIndicators = compromiseIndicators.filter((indicator) =>
    ["warning", "critical"].includes(indicator.severity),
  );

  return {
    generatedAt: new Date().toISOString(),
    target: {
      inputUrl: analysis.inputUrl,
      finalUrl: analysis.finalUrl,
      host: analysis.host,
      statusCode: analysis.statusCode,
      responseTimeMs: analysis.responseTimeMs,
      scannedAt: analysis.scannedAt,
    },
    posture: {
      score: analysis.score,
      grade: analysis.grade,
      summary: analysis.summary,
      overview: analysis.executiveSummary?.overview ?? null,
      mainRisk: analysis.executiveSummary?.mainRisk ?? null,
      posture: analysis.executiveSummary?.posture ?? null,
      takeaways: normalizeArray(analysis.executiveSummary?.takeaways),
      limited: analysis.assessmentLimitation?.limited ?? false,
      limitedKind: analysis.assessmentLimitation?.kind ?? null,
      limitation: analysis.assessmentLimitation ?? null,
      scoreDrivers: normalizeArray(analysis.scoreDrivers).slice(0, 8),
    },
    findings: {
      total: issues.length,
      bySeverity: countIssuesBySeverity(issues),
      top: topIssues(issues, findingLimit),
    },
    controls: {
      headers: {
        total: normalizeArray(analysis.headers).length,
        missing: normalizeArray(analysis.headers).filter((header) => header.status === "missing").length,
        warning: normalizeArray(analysis.headers).filter((header) => header.status === "warning").length,
        present: normalizeArray(analysis.headers).filter((header) => header.status === "present").length,
      },
      cookies: {
        total: normalizeArray(analysis.cookies).length,
        issues: normalizeArray(analysis.cookieAnalysis?.issues),
      },
      tls: {
        available: analysis.certificate?.available ?? false,
        valid: analysis.certificate?.valid ?? false,
        authorized: analysis.certificate?.authorized ?? false,
        issuer: analysis.certificate?.issuer ?? null,
        daysRemaining: analysis.certificate?.daysRemaining ?? null,
        issues: normalizeArray(analysis.certificate?.issues),
      },
    },
    surface: {
      redirects: {
        totalHops: analysis.redirectChain?.totalHops ?? normalizeArray(analysis.redirects).length,
        hasMixedRedirect: analysis.redirectChain?.hasMixedRedirect ?? false,
        crossesDomain: analysis.redirectChain?.crossesDomain ?? false,
        issues: normalizeArray(analysis.redirectChain?.issues),
      },
      exposure: {
        issues: normalizeArray(analysis.exposure?.issues),
        interesting: normalizeArray(analysis.exposure?.probes).filter((probe) => probe.finding === "interesting").length,
        exposed: normalizeArray(analysis.exposure?.probes).filter((probe) => probe.finding === "exposed").length,
      },
      api: {
        issues: normalizeArray(analysis.apiSurface?.issues),
        public: normalizeArray(analysis.apiSurface?.probes).filter((probe) => probe.classification === "public").length,
        interesting: normalizeArray(analysis.apiSurface?.probes).filter((probe) => probe.classification === "interesting").length,
      },
      cors: {
        issues: normalizeArray(analysis.corsSecurity?.issues),
        allowCredentials: analysis.corsSecurity?.allowCredentials ?? null,
        allowedOrigin: analysis.corsSecurity?.allowedOrigin ?? null,
      },
    },
    trust: {
      domainSecurity: {
        emailDeliverabilityScore: analysis.domainSecurity?.emailDeliverabilityScore ?? null,
        issues: normalizeArray(analysis.domainSecurity?.issues),
        strengths: normalizeArray(analysis.domainSecurity?.strengths),
      },
      securityTxt: {
        status: analysis.securityTxt?.status ?? null,
        contact: normalizeArray(analysis.securityTxt?.contact),
      },
      thirdParty: {
        providers: normalizeArray(analysis.thirdPartyTrust?.providers).map((provider) => provider.name),
        highRiskProviders: analysis.thirdPartyTrust?.highRiskProviders ?? 0,
        issues: normalizeArray(analysis.thirdPartyTrust?.issues),
      },
      identityProvider: analysis.identityProvider?.provider ?? null,
      wafProviders: normalizeArray(analysis.wafFingerprint?.providers).map((provider) => provider.name),
      infrastructureProviders: normalizeArray(analysis.infrastructure?.providers).map((provider) => provider.provider),
    },
    intelligence: {
      passiveRead: analysis.passiveIntelligence?.postureRead ?? null,
      compromisePosture: analysis.compromiseSignals?.posture ?? null,
      compromiseSummary: analysis.compromiseSignals?.summary ?? null,
      riskIndicators: riskIndicators.slice(0, 8).map((indicator) => ({
        severity: indicator.severity,
        category: indicator.category,
        title: indicator.title,
        detail: indicator.detail,
        confidence: indicator.confidence,
      })),
      ctPriorityHosts: normalizeArray(analysis.ctDiscovery?.prioritizedHosts)
        .slice(0, 10)
        .map((host) => host.host),
      aiVendors: normalizeArray(analysis.aiSurface?.vendors).map((vendor) => vendor.name),
    },
    timing: analysis.scanTiming ?? null,
  };
}
