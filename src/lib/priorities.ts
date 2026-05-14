import { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";

type PriorityAreaKey = "edge" | "content" | "domain" | "exposure" | "api" | "trust" | "ai";

export interface PrioritizedAction {
  readonly title: string;
  readonly detail: string;
  readonly severity: "critical" | "warning" | "info";
  readonly area: string;
  readonly areaKey?: PriorityAreaKey;
  readonly priorityReason?: string;
}

export interface MonitoringAlert {
  title: string;
  detail: string;
  severity: "warning" | "info";
}

const severityOrder: Record<PrioritizedAction["severity"], number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

export const getPriorityActions = (analysis: AnalysisResult): ReadonlyArray<PrioritizedAction> => {
  const actions: PrioritizedAction[] = [];
  const seen = new Set<string>();
  const areaScores = getAreaScores(analysis);
  const areaScoreByKey = new Map(areaScores.map((area) => [area.key, area.score] as const));
  const areaLabelByKey = new Map(areaScores.map((area) => [area.key, area.label] as const));
  const domainAreaScore = areaScores.find((area) => area.key === "domain")?.score ?? 100;
  const domainTrustIssueCount =
    analysis.domainSecurity.issues.length +
    analysis.securityTxt.issues.length +
    analysis.publicSignals.issues.length;

  const addAction = (action: PrioritizedAction) => {
    const key = `${action.title}:${action.area}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    actions.push(action);
  };

  const hasHeaderIssue = (key: string, status?: "missing" | "warning") =>
    analysis.headers.some((header) => header.key === key && (status ? header.status === status : header.status !== "present"));

  if (hasHeaderIssue("strict-transport-security")) {
    addAction({
      title: "Strengthen HTTPS persistence",
      detail: "Add or harden HSTS with a long max-age, includeSubDomains, and preload readiness where appropriate.",
      severity: "critical",
      area: "Transport",
      areaKey: "edge",
    });
  }

  if (hasHeaderIssue("content-security-policy")) {
    addAction({
      title: "Tighten the content security policy",
      detail: "A stronger CSP will reduce script injection and unsafe resource loading risk.",
      severity: "critical",
      area: "Headers",
      areaKey: "content",
    });
  }

  if (domainAreaScore <= 70 && domainTrustIssueCount >= 3) {
    addAction({
      title: "Raise domain and trust baseline controls",
      detail: `Domain and trust posture is currently weaker than target (${domainTrustIssueCount} findings across DNS/email, security.txt, and public trust signals).`,
      severity: "warning",
      area: "Domain & Trust",
      areaKey: "domain",
    });
  }

  if (analysis.crawl.inconsistentHeaders.length > 0) {
    addAction({
      title: "Normalize protections across routes",
      detail: `Header behavior varies across ${analysis.crawl.inconsistentHeaders.length} protections, which usually points to inconsistent middleware or CDN rules.`,
      severity: "warning",
      area: "Crawl",
      areaKey: "edge",
    });
  }

  if (analysis.htmlSecurity.missingSriScriptUrls.length > 0) {
    addAction({
      title: "Add integrity checks for third-party scripts",
      detail: "Subresource Integrity would reduce tampering risk on externally hosted scripts.",
      severity: "warning",
      area: "Content",
      areaKey: "content",
    });
  }

  if (analysis.htmlSecurity.passiveLeakSignals.some((signal) => signal.severity === "warning")) {
    addAction({
      title: "Review passive leak signals in page markup",
      detail: "The fetched page exposed source-map references or public token-like values that deserve a quick review before deeper testing.",
      severity: "warning",
      area: "Content",
      areaKey: "content",
    });
  }

  if (analysis.thirdPartyTrust.highRiskProviders > 0) {
    addAction({
      title: "Review high-trust third-party providers",
      detail: `The page loads ${analysis.thirdPartyTrust.highRiskProviders} higher-risk third-party integration${analysis.thirdPartyTrust.highRiskProviders === 1 ? "" : "s"} that expand data-flow and review scope.`,
      severity: analysis.thirdPartyTrust.highRiskProviders >= 3 ? "critical" : "warning",
      area: "Third Parties",
      areaKey: "trust",
    });
  }

  if (analysis.aiSurface.detected && analysis.aiSurface.issues.length > 0) {
    addAction({
      title: "Add clearer AI disclosure and privacy guidance",
      detail: "Public AI or automation signals were detected, but the fetched page offers limited visible disclosure, privacy, or governance language.",
      severity: "warning",
      area: "AI",
      areaKey: "ai",
    });
  }

  if (analysis.securityTxt.status !== "present") {
    addAction({
      title: "Publish a security.txt file",
      detail: "A valid security.txt gives researchers and partners a clear disclosure route.",
      severity: domainAreaScore <= 70 ? "warning" : "info",
      area: "Disclosure",
      areaKey: "domain",
    });
  }

  if (!analysis.domainSecurity.dmarc || !/p=(reject|quarantine)/i.test(analysis.domainSecurity.dmarc)) {
    addAction({
      title: "Improve email-domain enforcement",
      detail: "Stronger DMARC helps reduce spoofing and improves overall trust posture.",
      severity: "warning",
      area: "Domain",
      areaKey: "domain",
    });
  }

  if (analysis.domainSecurity.issues.some((issue) => issue.includes("MTA-STS"))) {
    addAction({
      title: "Add MTA-STS if email matters for this domain",
      detail: "MTA-STS improves SMTP transport integrity for domains that receive mail.",
      severity: domainAreaScore <= 70 ? "warning" : "info",
      area: "Domain",
      areaKey: "domain",
    });
  }

  if (analysis.apiSurface.issues.length > 0) {
    addAction({
      title: "Review public API exposure",
      detail: "A limited set of API-style endpoints looked publicly reachable and should be reviewed.",
      severity: "warning",
      area: "API",
      areaKey: "api",
    });
  }

  if (analysis.publicSignals.hstsPreload.status === "eligible") {
    addAction({
      title: "Consider HSTS preload submission",
      detail: "Public preload data suggests the domain may be close to preload-ready.",
      severity: "info",
      area: "Public Signals",
      areaKey: "domain",
    });
  }

  const weakestArea = [...areaScores].sort((left, right) => left.score - right.score)[0];
  const hasWeakestAreaAction = actions.some((action) => action.areaKey === weakestArea?.key);
  if (weakestArea && weakestArea.score < 85 && !hasWeakestAreaAction) {
    addAction({
      title: `Review ${weakestArea.label.toLowerCase()} posture`,
      detail: `${weakestArea.label} is currently the weakest category in this scan at ${weakestArea.score}/100.`,
      severity: weakestArea.score < 65 ? "warning" : "info",
      area: weakestArea.label,
      areaKey: weakestArea.key,
    });
  }

  return actions
    .map((action) => {
      const score = action.areaKey ? areaScoreByKey.get(action.areaKey) ?? 100 : 100;
      const label = action.areaKey ? areaLabelByKey.get(action.areaKey) ?? action.area : action.area;
      return {
        ...action,
        priorityReason: `Why this matters for the scanned target: ${label} is currently at ${score}/100.`,
      };
    })
    .sort((left, right) => {
      const leftScore = left.areaKey ? areaScoreByKey.get(left.areaKey) ?? 100 : 100;
      const rightScore = right.areaKey ? areaScoreByKey.get(right.areaKey) ?? 100 : 100;
      if (leftScore !== rightScore) return leftScore - rightScore;
      if (severityOrder[left.severity] !== severityOrder[right.severity]) {
        return severityOrder[left.severity] - severityOrder[right.severity];
      }
      return left.title.localeCompare(right.title);
    })
    .slice(0, 5);
};

export const getMonitoringAlerts = (analysis: AnalysisResult, diff: HistoryDiff | null): MonitoringAlert[] => {
  const alerts: MonitoringAlert[] = [];

  if (diff?.scoreDelta && diff.scoreDelta < 0) {
    alerts.push({
      title: "Score regressed",
      detail: `This scan dropped ${Math.abs(diff.scoreDelta)} points versus the previous local snapshot.`,
      severity: "warning",
    });
  }

  if (diff?.newIssues.length) {
    alerts.push({
      title: "New findings appeared",
      detail: `${diff.newIssues.length} issue${diff.newIssues.length === 1 ? "" : "s"} were not present in the previous snapshot.`,
      severity: "warning",
    });
  }

  if (diff?.headerChanges.length) {
    alerts.push({
      title: "Header posture changed",
      detail: `${diff.headerChanges.length} header status change${diff.headerChanges.length === 1 ? "" : "s"} detected since the last scan.`,
      severity: "info",
    });
  }

  if (analysis.certificate.daysRemaining !== null && analysis.certificate.daysRemaining <= 30) {
    alerts.push({
      title: "Certificate expiry window is approaching",
      detail: `The current TLS certificate expires in about ${analysis.certificate.daysRemaining} days.`,
      severity: analysis.certificate.daysRemaining <= 14 ? "warning" : "info",
    });
  }

  if (diff?.newThirdPartyProviders.length) {
    alerts.push({
      title: "New third-party provider observed",
      detail: `${diff.newThirdPartyProviders.length} new third-party provider${diff.newThirdPartyProviders.length === 1 ? "" : "s"} appeared since the previous snapshot.`,
      severity: "info",
    });
  }

  if (diff?.wafProviderChanges.newProviders.length) {
    alerts.push({
      title: "Edge or WAF posture changed",
      detail: `New edge-protection signal${diff.wafProviderChanges.newProviders.length === 1 ? "" : "s"} appeared: ${diff.wafProviderChanges.newProviders.join(", ")}.`,
      severity: "info",
    });
  }

  if (diff?.identityProviderChange) {
    alerts.push({
      title: "Identity posture changed",
      detail: `Identity provider changed from ${diff.identityProviderChange.from ?? "none"} to ${diff.identityProviderChange.to ?? "none"}.`,
      severity: "warning",
    });
  }

  if (analysis.publicSignals.hstsPreload.status === "pending") {
    alerts.push({
      title: "HSTS preload submission appears pending",
      detail: "Public preload data suggests the domain may already be in the submission queue.",
      severity: "info",
    });
  }

  return alerts.slice(0, 4);
};
