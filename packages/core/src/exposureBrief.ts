import type {
  AnalysisResult,
  CompromiseIndicator,
  ExposureBrief,
  ExposureBriefCategory,
  ExposureBriefItem,
  ExposureBriefLevel,
  ExposureBriefSource,
  IssueConfidence,
} from "./types.js";

const SEVERITY_ORDER: Record<ExposureBriefItem["severity"], number> = {
  critical: 0,
  warning: 1,
  watch: 2,
  info: 3,
};

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

function cleanEvidence(value: unknown): string[] {
  return normalizeArray(value as string[])
    .filter((item) => typeof item === "string" && item.trim().length > 0)
    .map((item) => item.trim())
    .slice(0, 4);
}

function uniqueByTitle(items: ExposureBriefItem[]): ExposureBriefItem[] {
  const seen = new Set<string>();
  const unique: ExposureBriefItem[] = [];

  for (const item of items) {
    const key = `${item.category}:${item.title.toLowerCase()}:${item.detail.toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(item);
  }

  return unique;
}

function sortItems(items: ExposureBriefItem[]): ExposureBriefItem[] {
  return [...items].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return left.title.localeCompare(right.title);
  });
}

function item({
  title,
  detail,
  severity,
  category,
  confidence = "medium",
  source,
  evidence = [],
  action,
}: {
  title: string;
  detail: string;
  severity: ExposureBriefItem["severity"];
  category: ExposureBriefCategory;
  confidence?: IssueConfidence;
  source: ExposureBriefSource;
  evidence?: string[];
  action: string | null;
}): ExposureBriefItem {
  return {
    title,
    detail,
    severity,
    category,
    confidence,
    source,
    evidence: cleanEvidence(evidence),
    action,
  };
}

function mapCompromiseCategory(indicator: CompromiseIndicator): ExposureBriefCategory {
  if (indicator.category === "credential_collection" || indicator.category === "script_anomaly") {
    return "abuse_signal";
  }
  if (indicator.category === "supply_chain") {
    return "third_party";
  }
  if (indicator.category === "infrastructure") {
    return "infrastructure";
  }
  if (indicator.category === "exposure") {
    return "sensitive_exposure";
  }
  return "abuse_signal";
}

function mapCompromiseSource(indicator: CompromiseIndicator): ExposureBriefSource {
  if (indicator.source === "asset") {
    return "html";
  }
  if (indicator.source === "reputation") {
    return "public_record";
  }
  return indicator.source;
}

function buildSummary(level: ExposureBriefLevel, counts: ExposureBrief["counts"], topRisks: ExposureBriefItem[]) {
  if (level === "unknown") {
    return "Exposure could not be summarized confidently because the passive assessment was limited.";
  }
  if (level === "critical") {
    return "Critical public exposure or abuse indicators need immediate review before treating this target as healthy.";
  }
  if (level === "high") {
    return "Publicly observable exposure is elevated, with multiple items that deserve near-term review.";
  }
  if (level === "medium") {
    return "The target has review-worthy public exposure, but no critical public signal was observed.";
  }
  if (counts.publicEntryPoints > 0) {
    return "Public entry points were observed, with no major exposure signal in the passive checks.";
  }
  if (topRisks.length === 0) {
    return "No notable public exposure signal was observed in the passive checks.";
  }
  return "The passive checks found low-risk public exposure context.";
}

function deriveLevel(
  items: ExposureBriefItem[],
  counts: ExposureBrief["counts"],
  limited: boolean,
): ExposureBriefLevel {
  if (items.some((risk) => risk.severity === "critical")) {
    return "critical";
  }
  const warningCount = items.filter((risk) => risk.severity === "warning").length;
  if (warningCount >= 3 || counts.sensitiveExposures > 0 || counts.highRiskThirdParties > 0) {
    return "high";
  }
  if (warningCount > 0 || items.some((risk) => risk.severity === "watch")) {
    return "medium";
  }
  if (limited && items.length === 0) {
    return "unknown";
  }
  return "low";
}

function pushUnique(actions: string[], value: string | null | undefined) {
  if (!value) {
    return;
  }
  const trimmed = value.trim();
  if (!trimmed || actions.includes(trimmed)) {
    return;
  }
  actions.push(trimmed);
}

export function buildExposureBrief(analysis: AnalysisResult): ExposureBrief {
  const items: ExposureBriefItem[] = [];

  for (const indicator of normalizeArray(analysis.compromiseSignals?.indicators)) {
    items.push(item({
      title: indicator.title,
      detail: indicator.detail,
      severity: indicator.severity,
      category: mapCompromiseCategory(indicator),
      confidence: indicator.confidence,
      source: mapCompromiseSource(indicator),
      evidence: indicator.evidence,
      action: indicator.action,
    }));
  }

  for (const probe of normalizeArray(analysis.exposure?.probes)) {
    if (probe.finding !== "exposed" && probe.finding !== "interesting") {
      continue;
    }
    items.push(item({
      title: probe.finding === "exposed" ? `${probe.label} appears exposed` : `${probe.label} needs review`,
      detail: probe.detail,
      severity: probe.finding === "exposed" ? "warning" : "watch",
      category: "sensitive_exposure",
      confidence: "medium",
      source: "exposure",
      evidence: [`${probe.statusCode} ${probe.finalUrl}`],
      action: "Review whether this path should be publicly reachable and restrict it if it exposes operational detail.",
    }));
  }

  for (const probe of normalizeArray(analysis.apiSurface?.probes)) {
    if (probe.classification !== "public" && probe.classification !== "interesting") {
      continue;
    }
    items.push(item({
      title: probe.classification === "public" ? `${probe.label} is publicly reachable` : `${probe.label} looks like an API surface`,
      detail: probe.detail,
      severity: probe.classification === "public" ? "watch" : "info",
      category: "entry_point",
      confidence: "medium",
      source: "api",
      evidence: [`${probe.statusCode} ${probe.finalUrl}`, probe.contentType ? `Content-Type: ${probe.contentType}` : ""],
      action: "Confirm the endpoint is intentional, authenticated where needed, and covered by monitoring.",
    }));
  }

  for (const host of normalizeArray(analysis.ctDiscovery?.prioritizedHosts).slice(0, 8)) {
    const priority = "priority" in host ? String(host.priority) : "review";
    items.push(item({
      title: `${host.host} is visible in certificate transparency`,
      detail: "Certificate transparency logs expose this related host as part of the public attack surface.",
      severity: priority === "high" ? "watch" : "info",
      category: "entry_point",
      confidence: "high",
      source: "ct",
      evidence: [analysis.ctDiscovery?.sourceUrl || "", priority],
      action: "Confirm this hostname is still owned, intentionally exposed, and included in monitoring.",
    }));
  }

  for (const issue of normalizeArray(analysis.domainSecurity?.issues)) {
    items.push(item({
      title: "Domain trust gap",
      detail: issue,
      severity: "watch",
      category: "trust_gap",
      confidence: "high",
      source: "dns",
      evidence: [analysis.host],
      action: "Review DNS, mail authentication, and domain policy records for the target domain.",
    }));
  }

  for (const issue of normalizeArray(analysis.securityTxt?.issues)) {
    items.push(item({
      title: "Security contact signal gap",
      detail: issue,
      severity: "info",
      category: "trust_gap",
      confidence: "medium",
      source: "public_record",
      evidence: [analysis.securityTxt?.url || analysis.finalUrl],
      action: "Publish or correct security.txt so researchers and vendors know where to report issues.",
    }));
  }

  for (const issue of normalizeArray(analysis.publicSignals?.issues)) {
    items.push(item({
      title: "Public trust signal gap",
      detail: issue,
      severity: "watch",
      category: "trust_gap",
      confidence: "medium",
      source: "public_record",
      evidence: [analysis.publicSignals?.hstsPreload?.sourceUrl || analysis.host],
      action: "Review public trust signals such as HSTS preload eligibility and domain policy posture.",
    }));
  }

  for (const provider of normalizeArray(analysis.thirdPartyTrust?.providers)) {
    if (provider.risk !== "high" && provider.risk !== "medium") {
      continue;
    }
    items.push(item({
      title: `${provider.name} third-party dependency`,
      detail: `${provider.domain} was observed as a ${provider.category} provider with ${provider.risk} passive trust risk.`,
      severity: provider.risk === "high" ? "warning" : "watch",
      category: "third_party",
      confidence: "medium",
      source: "third_party",
      evidence: [provider.evidence],
      action: "Confirm the provider is intentional, documented, and covered by privacy/security review.",
    }));
  }

  for (const vendor of normalizeArray(analysis.aiSurface?.vendors)) {
    items.push(item({
      title: `${vendor.name} AI surface signal`,
      detail: vendor.evidence,
      severity: "info",
      category: "ai",
      confidence: vendor.confidence,
      source: "ai",
      evidence: [vendor.category],
      action: "Confirm AI-assisted surfaces have suitable disclosure, data-handling, and support escalation controls.",
    }));
  }

  const uniqueItems = sortItems(uniqueByTitle(items));
  const publicEntryPoints = uniqueItems.filter((risk) => risk.category === "entry_point").slice(0, 8);
  const trustGaps = uniqueItems.filter((risk) => risk.category === "trust_gap").slice(0, 8);
  const topRisks = uniqueItems.slice(0, 8);
  const counts = {
    publicEntryPoints: publicEntryPoints.length,
    sensitiveExposures: uniqueItems.filter((risk) => risk.category === "sensitive_exposure").length,
    trustGaps: uniqueItems.filter((risk) => risk.category === "trust_gap").length,
    abuseIndicators: uniqueItems.filter((risk) => risk.category === "abuse_signal").length,
    thirdPartyProviders: analysis.thirdPartyTrust?.totalProviders ?? normalizeArray(analysis.thirdPartyTrust?.providers).length,
    highRiskThirdParties: analysis.thirdPartyTrust?.highRiskProviders ?? 0,
    aiVendors: normalizeArray(analysis.aiSurface?.vendors).length,
    ctPriorityHosts: normalizeArray(analysis.ctDiscovery?.prioritizedHosts).length,
  };
  const exposureLevel = deriveLevel(uniqueItems, counts, Boolean(analysis.assessmentLimitation?.limited));
  const nextActions: string[] = [];

  for (const risk of topRisks) {
    pushUnique(nextActions, risk.action);
  }
  for (const action of normalizeArray(analysis.remediationPlan?.items).map((planItem) => planItem.action)) {
    pushUnique(nextActions, action);
  }
  if (nextActions.length === 0) {
    nextActions.push("Keep the target in monitoring and rescan after meaningful deployment, DNS, or vendor changes.");
  }

  return {
    generatedAt: new Date().toISOString(),
    exposureLevel,
    summary: buildSummary(exposureLevel, counts, topRisks),
    counts,
    topRisks,
    publicEntryPoints,
    trustGaps,
    nextActions: nextActions.slice(0, 6),
    collectionBoundary: analysis.compromiseSignals?.collectionBoundary
      || analysis.passiveIntelligence?.collectionBoundary
      || "Passive public evidence only. No credentials, exploitation, intrusive probing, or authenticated access was used.",
    limitation: analysis.assessmentLimitation?.limited ? analysis.assessmentLimitation : null,
  };
}
