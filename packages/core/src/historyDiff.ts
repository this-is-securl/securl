import type { AnalysisResult, HistoryDiff, HistorySnapshot } from "./types.js";

export const snapshotFromAnalysis = (analysis: AnalysisResult): HistorySnapshot => ({
  finalUrl: analysis.finalUrl,
  host: analysis.host,
  scannedAt: analysis.scannedAt,
  score: analysis.score,
  grade: analysis.grade,
  statusCode: analysis.statusCode,
  responseTimeMs: analysis.responseTimeMs,
  certificateDaysRemaining: analysis.certificate.daysRemaining,
  thirdPartyProviders: analysis.thirdPartyTrust.providers.map((provider) => provider.name),
  aiVendors: analysis.aiSurface.vendors.map((vendor) => vendor.name),
  identityProvider: analysis.identityProvider.provider,
  wafProviders: analysis.wafFingerprint.providers.map((provider) => provider.name),
  ctPriorityHosts: analysis.ctDiscovery.prioritizedHosts.map((host) => host.host),
  headers: analysis.headers.map((header) => ({
    label: header.label,
    status: header.status,
    value: header.value,
  })),
  issues: analysis.issues.map((issue) => ({
    severity: issue.severity,
    title: issue.title,
    detail: issue.detail,
    confidence: issue.confidence,
    source: issue.source,
  })),
});

export const buildHistoryDiffFromSnapshots = (
  current: HistorySnapshot,
  previous: HistorySnapshot,
): HistoryDiff => {
  const currentIssues = new Set(current.issues.map((issue) => issue.title));
  const previousIssues = new Set(previous.issues.map((issue) => issue.title));
  const previousHeaders = new Map(previous.headers.map((header) => [header.label, header.status]));
  const currentThirdParties = new Set(current.thirdPartyProviders ?? []);
  const previousThirdParties = new Set(previous.thirdPartyProviders ?? []);
  const currentAiVendors = new Set(current.aiVendors ?? []);
  const previousAiVendors = new Set(previous.aiVendors ?? []);
  const currentWafProviders = new Set(current.wafProviders ?? []);
  const previousWafProviders = new Set(previous.wafProviders ?? []);
  const currentCtPriorityHosts = new Set(current.ctPriorityHosts ?? []);
  const previousCtPriorityHosts = new Set(previous.ctPriorityHosts ?? []);

  const scoreDelta = current.score - previous.score;
  const certificateDaysRemainingDelta =
    current.certificateDaysRemaining !== null &&
    current.certificateDaysRemaining !== undefined &&
    previous.certificateDaysRemaining !== null &&
    previous.certificateDaysRemaining !== undefined
      ? current.certificateDaysRemaining - previous.certificateDaysRemaining
      : null;

  const newWafProviders = [...currentWafProviders].filter((provider) => !previousWafProviders.has(provider));
  const newThirdPartyProviders = [...currentThirdParties].filter((provider) => !previousThirdParties.has(provider));
  const newCtPriorityHosts = [...currentCtPriorityHosts].filter((host) => !previousCtPriorityHosts.has(host));

  const summary = [
    scoreDelta > 0 ? `Score improved by ${scoreDelta} point${scoreDelta === 1 ? "" : "s"}.` : null,
    scoreDelta < 0 ? `Score regressed by ${Math.abs(scoreDelta)} point${Math.abs(scoreDelta) === 1 ? "" : "s"}.` : null,
    current.statusCode !== previous.statusCode
      ? `HTTP status changed from ${previous.statusCode} to ${current.statusCode}.`
      : null,
    (current.identityProvider ?? null) !== (previous.identityProvider ?? null)
      ? `Identity provider changed from ${previous.identityProvider ?? "none"} to ${current.identityProvider ?? "none"}.`
      : null,
    newWafProviders.length ? `New WAF or edge signals appeared: ${newWafProviders.join(", ")}.` : null,
    newThirdPartyProviders.length
      ? `New third-party providers were observed: ${newThirdPartyProviders.join(", ")}.`
      : null,
    newCtPriorityHosts.length ? `New high-priority CT hosts appeared: ${newCtPriorityHosts.join(", ")}.` : null,
    certificateDaysRemainingDelta !== null && certificateDaysRemainingDelta < 0
      ? `Certificate window shortened by ${Math.abs(certificateDaysRemainingDelta)} day${Math.abs(certificateDaysRemainingDelta) === 1 ? "" : "s"}.`
      : null,
  ].filter((item): item is string => Boolean(item));

  return {
    previousScore: previous.score,
    scoreDelta,
    previousGrade: previous.grade,
    currentGrade: current.grade,
    statusCodeDelta: {
      from: previous.statusCode,
      to: current.statusCode,
    },
    certificateDaysRemainingDelta: {
      from: previous.certificateDaysRemaining ?? null,
      to: current.certificateDaysRemaining ?? null,
      delta: certificateDaysRemainingDelta,
    },
    newIssues: [...currentIssues].filter((issue) => !previousIssues.has(issue)),
    resolvedIssues: [...previousIssues].filter((issue) => !currentIssues.has(issue)),
    headerChanges: current.headers
      .map((header) => ({
        label: header.label,
        from: previousHeaders.get(header.label) ?? "unknown",
        to: header.status,
      }))
      .filter((change) => change.from !== change.to),
    newThirdPartyProviders,
    removedThirdPartyProviders: [...previousThirdParties].filter((provider) => !currentThirdParties.has(provider)),
    newAiVendors: [...currentAiVendors].filter((vendor) => !previousAiVendors.has(vendor)),
    removedAiVendors: [...previousAiVendors].filter((vendor) => !currentAiVendors.has(vendor)),
    identityProviderChange:
      (current.identityProvider ?? null) !== (previous.identityProvider ?? null)
        ? {
            from: previous.identityProvider ?? null,
            to: current.identityProvider ?? null,
          }
        : null,
    wafProviderChanges: {
      newProviders: newWafProviders,
      removedProviders: [...previousWafProviders].filter((provider) => !currentWafProviders.has(provider)),
    },
    ctPriorityHostChanges: {
      newHosts: newCtPriorityHosts,
      removedHosts: [...previousCtPriorityHosts].filter((host) => !currentCtPriorityHosts.has(host)),
    },
    summary,
  };
};

export const buildHistoryDiff = (history: HistorySnapshot[]): HistoryDiff | null => {
  if (history.length < 2) {
    return null;
  }

  return buildHistoryDiffFromSnapshots(history[0], history[1]);
};
