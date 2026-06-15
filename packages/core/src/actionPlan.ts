import type {
  ActionPlan,
  ActionPlanItem,
  ActionPlanTheme,
  AnalysisResult,
  ExposureBriefCategory,
  ExposureBriefItem,
  ExposureBriefSource,
  RemediationEffort,
  RemediationImpact,
  RemediationOwner,
  ScanEvidenceKind,
  ScanEvidenceReference,
  ScoreDriver,
  VendorExposureProvider,
} from "./types.js";

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

const IMPACT_RANK: Record<RemediationImpact, number> = {
  high: 0,
  medium: 1,
  low: 2,
};

function evidenceFromText(label: string, observed: string | null, kind: ScanEvidenceKind, source: string): ScanEvidenceReference {
  return {
    kind,
    label,
    observed,
    source: source as ScanEvidenceReference["source"],
  };
}

function evidenceKindForExposure(source: ExposureBriefSource): ScanEvidenceKind {
  if (source === "dns") {
    return "dns";
  }
  if (source === "tls") {
    return "tls";
  }
  if (source === "cookies") {
    return "cookie";
  }
  if (source === "headers") {
    return "header";
  }
  if (source === "html" || source === "third_party" || source === "ai") {
    return "html";
  }
  if (source === "public_record" || source === "ct") {
    return "public_record";
  }
  return "probe";
}

function ownerForExposure(category: ExposureBriefCategory): RemediationOwner {
  if (category === "trust_gap") {
    return "dns";
  }
  if (category === "third_party" || category === "ai") {
    return "third_party";
  }
  if (category === "identity") {
    return "identity";
  }
  if (category === "entry_point" || category === "infrastructure") {
    return "edge";
  }
  return "app";
}

function themeForOwner(owner: RemediationOwner, title: string): ActionPlanTheme {
  const value = title.toLowerCase();
  if (owner === "dns") {
    return "domain_trust";
  }
  if (owner === "third_party") {
    return "vendor_risk";
  }
  if (owner === "identity") {
    return "identity";
  }
  if (value.includes("tls") || value.includes("certificate") || value.includes("https") || value.includes("hsts")) {
    return "transport";
  }
  if (value.includes("monitor") || value.includes("rescan")) {
    return "monitoring";
  }
  if (value.includes("unreachable") || value.includes("timeout") || value.includes("service")) {
    return "availability";
  }
  if (value.includes("header") || value.includes("policy") || value.includes("cookie") || value.includes("csp")) {
    return "browser_hardening";
  }
  return "public_exposure";
}

function themeForExposure(item: ExposureBriefItem): ActionPlanTheme {
  if (item.category === "trust_gap") {
    return "domain_trust";
  }
  if (item.category === "third_party" || item.category === "ai") {
    return "vendor_risk";
  }
  if (item.category === "identity") {
    return "identity";
  }
  if (item.category === "entry_point" || item.category === "infrastructure") {
    return "public_exposure";
  }
  if (item.source === "tls") {
    return "transport";
  }
  return "public_exposure";
}

function impactForExposure(item: ExposureBriefItem): RemediationImpact {
  if (item.severity === "critical" || item.severity === "warning") {
    return "high";
  }
  if (item.severity === "watch") {
    return "medium";
  }
  return "low";
}

function effortForExposure(item: ExposureBriefItem): RemediationEffort {
  if (item.category === "entry_point" || item.category === "trust_gap") {
    return "low";
  }
  if (item.category === "third_party" || item.category === "ai") {
    return "medium";
  }
  return item.severity === "critical" ? "high" : "medium";
}

function scoreDriverAction(driver: ScoreDriver): string {
  if (driver.impact > 0) {
    return `Review and improve ${driver.label} so this score driver no longer reduces the passive posture score.`;
  }
  return `Review ${driver.label} and confirm it is intentionally configured.`;
}

function scoreDriverTheme(driver: ScoreDriver): ActionPlanTheme {
  if (driver.source === "dns" || driver.areaKey === "domain") {
    return "domain_trust";
  }
  if (driver.source === "tls") {
    return "transport";
  }
  if (driver.source === "cookies" || driver.source === "headers") {
    return "browser_hardening";
  }
  if (driver.source === "third_party" || driver.source === "ai") {
    return "vendor_risk";
  }
  return "public_exposure";
}

function scoreDriverOwner(driver: ScoreDriver): RemediationOwner {
  if (driver.source === "dns" || driver.areaKey === "domain") {
    return "dns";
  }
  if (driver.source === "headers" || driver.source === "tls") {
    return "edge";
  }
  if (driver.source === "third_party" || driver.source === "ai") {
    return "third_party";
  }
  if (driver.source === "cookies") {
    return "app";
  }
  return "app";
}

function scoreDriverEvidence(driver: ScoreDriver): ScanEvidenceReference[] {
  return [{
    kind: "score_driver",
    label: driver.label,
    observed: driver.detail,
    source: driver.source,
  }];
}

function vendorEvidence(provider: VendorExposureProvider): ScanEvidenceReference[] {
  return [{
    kind: "html",
    label: provider.domain || provider.name,
    observed: provider.evidence,
    source: "derived",
  }];
}

function actionKey(item: Pick<ActionPlanItem, "title" | "action" | "theme">): string {
  return `${item.theme}:${item.title}:${item.action}`.toLowerCase().replace(/\s+/g, " ").trim();
}

function dedupeItems(items: ActionPlanItem[]): ActionPlanItem[] {
  const seen = new Set<string>();
  const unique: ActionPlanItem[] = [];

  for (const item of items) {
    const key = actionKey(item);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(item);
  }

  return unique;
}

function sortItems(items: ActionPlanItem[]): ActionPlanItem[] {
  return [...items].sort((left, right) => {
    const impactDelta = IMPACT_RANK[left.impact] - IMPACT_RANK[right.impact];
    if (impactDelta !== 0) {
      return impactDelta;
    }
    const priorityDelta = left.priority - right.priority;
    if (priorityDelta !== 0) {
      return priorityDelta;
    }
    return (right.scoreImpact ?? 0) - (left.scoreImpact ?? 0);
  }).map((item, index) => ({
    ...item,
    priority: index + 1,
  }));
}

function buildSummary(analysis: AnalysisResult, items: ActionPlanItem[]): string {
  if (analysis.assessmentLimitation?.limited) {
    return "The assessment was limited, so the first priority is restoring reliable scan coverage before treating the grade as complete.";
  }
  if (items.length === 0) {
    return "No immediate action was identified from the passive evidence. Keep monitoring and rescan after deployment, DNS, or vendor changes.";
  }
  const highImpact = items.filter((item) => item.impact === "high").length;
  if (highImpact > 0) {
    return `${highImpact} high-impact action${highImpact === 1 ? "" : "s"} should move first because they affect the visible security posture most.`;
  }
  return "The next actions are mostly cleanup and monitoring work; no high-impact passive issue is currently leading the posture.";
}

export function buildActionPlan(analysis: AnalysisResult): ActionPlan {
  const items: ActionPlanItem[] = [];

  for (const planItem of normalizeArray(analysis.remediationPlan?.items)) {
    items.push({
      id: `remediation:${planItem.id}`,
      priority: planItem.priority,
      title: planItem.title,
      whyNow: planItem.scoreImpact && planItem.scoreImpact > 0
        ? `This is costing about ${planItem.scoreImpact} point${planItem.scoreImpact === 1 ? "" : "s"} in the passive score.`
        : planItem.detail,
      action: planItem.action,
      verify: planItem.verify,
      owner: planItem.owner,
      effort: planItem.effort,
      impact: planItem.impact,
      scoreImpact: planItem.scoreImpact,
      confidence: "high",
      theme: themeForOwner(planItem.owner, planItem.title),
      evidence: normalizeArray(planItem.evidence).slice(0, 5),
      relatedFindings: normalizeArray(planItem.relatedFindings).slice(0, 5),
      source: "remediation",
    });
  }

  for (const risk of normalizeArray(analysis.exposureBrief?.topRisks)) {
    if (!risk.action) {
      continue;
    }
    const owner = ownerForExposure(risk.category);
    items.push({
      id: `exposure:${risk.category}:${risk.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`,
      priority: 50,
      title: risk.title,
      whyNow: risk.detail,
      action: risk.action,
      verify: "Rescan the target and confirm this exposure brief item is no longer reported as a top risk.",
      owner,
      effort: effortForExposure(risk),
      impact: impactForExposure(risk),
      scoreImpact: null,
      confidence: risk.confidence,
      theme: themeForExposure(risk),
      evidence: normalizeArray(risk.evidence).map((evidence) =>
        evidenceFromText(risk.title, evidence, evidenceKindForExposure(risk.source), risk.source),
      ).slice(0, 5),
      relatedFindings: [risk.detail],
      source: "exposure_brief",
    });
  }

  for (const provider of normalizeArray(analysis.vendorExposure?.highPriorityProviders)) {
    items.push({
      id: `vendor:${provider.domain || provider.name}`.toLowerCase(),
      priority: provider.reviewPriority === "urgent" ? 40 : 60,
      title: `Review ${provider.name} vendor exposure`,
      whyNow: `${provider.domain} is visible as a ${provider.risk}-risk ${provider.category} provider with ${provider.dataFlow.replace(/_/g, " ")} data-flow implications.`,
      action: provider.action,
      verify: "Rescan the target and confirm the provider remains documented, intentionally loaded, or no longer appears.",
      owner: "third_party",
      effort: "medium",
      impact: provider.reviewPriority === "urgent" || provider.risk === "high" ? "high" : "medium",
      scoreImpact: null,
      confidence: "medium",
      theme: "vendor_risk",
      evidence: vendorEvidence(provider),
      relatedFindings: [provider.domain],
      source: "vendor_exposure",
    });
  }

  if (items.length === 0) {
    for (const driver of normalizeArray(analysis.scoreDrivers).filter((driver) => driver.impact > 0).slice(0, 5)) {
      const owner = scoreDriverOwner(driver);
      items.push({
        id: `score:${driver.areaKey}:${driver.label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`,
        priority: 100 - driver.impact,
        title: driver.label,
        whyNow: driver.detail,
        action: scoreDriverAction(driver),
        verify: "Rescan and confirm this score driver is no longer reported as missing or warning.",
        owner,
        effort: driver.impact >= 8 ? "medium" : "low",
        impact: driver.impact >= 10 ? "high" : driver.impact >= 4 ? "medium" : "low",
        scoreImpact: driver.impact,
        confidence: "medium",
        theme: scoreDriverTheme(driver),
        evidence: scoreDriverEvidence(driver),
        relatedFindings: [driver.detail],
        source: "score_driver",
      });
    }
  }

  const sortedItems = sortItems(dedupeItems(items)).slice(0, 8);

  return {
    generatedAt: new Date().toISOString(),
    summary: buildSummary(analysis, sortedItems),
    posture: {
      score: analysis.score,
      grade: analysis.grade,
      limited: Boolean(analysis.assessmentLimitation?.limited),
      mainRisk: sortedItems[0]?.title ?? null,
    },
    totalActions: sortedItems.length,
    highImpactActions: sortedItems.filter((item) => item.impact === "high").length,
    quickWins: sortedItems.filter((item) => item.effort === "low").length,
    items: sortedItems,
    nextReview: analysis.assessmentLimitation?.limited
      ? "Resolve the limited-assessment condition and rerun the scan before relying on the grade."
      : "Rerun after the high-impact actions are complete, and again after deployment, DNS, or vendor changes.",
    limitation: analysis.assessmentLimitation?.limited ? analysis.assessmentLimitation : null,
  };
}
