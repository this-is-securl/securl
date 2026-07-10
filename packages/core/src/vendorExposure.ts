import type {
  AnalysisResult,
  ExternalExposureDataFlow,
  ExternalExposureIntegrity,
  ExternalExposureInventoryItem,
  ExternalExposureReviewPriority,
  ThirdPartyProvider,
  VendorExposureBrief,
  VendorExposureProvider,
  VendorExposureRisk,
} from "./types.js";

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

const priorityRank: Record<ExternalExposureReviewPriority, number> = { urgent: 0, review: 1, routine: 2 };
const riskRank: Record<VendorExposureRisk, number> = { high: 0, medium: 1, low: 2 };
const confidenceRank = { high: 0, medium: 1, low: 2 } as const;
const integrityRank: Record<ExternalExposureIntegrity, number> = { missing: 0, unknown: 1, covered: 2, not_applicable: 3 };

function stablePart(value: string | null | undefined): string {
  return String(value || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64) || "unknown";
}

function inventoryId(item: Pick<ExternalExposureInventoryItem, "role" | "name" | "domain">): string {
  return `exposure:${item.role}:${stablePart(item.name)}:${stablePart(item.domain)}`;
}

function firstHostname(values: Array<string | null | undefined>): string | null {
  for (const value of values) {
    if (!value) continue;
    try {
      return new URL(value).hostname || null;
    } catch {
      continue;
    }
  }
  return null;
}

function uniqueEvidence(values: Array<string | null | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value?.trim())).map((value) => value.trim()))].slice(0, 6);
}

function integrityForProvider(provider: ThirdPartyProvider, analysis: AnalysisResult): ExternalExposureIntegrity {
  const missingSriHosts = normalizeArray(analysis.htmlSecurity?.missingSriScriptUrls)
    .map((value) => firstHostname([value]))
    .filter((value): value is string => Boolean(value));
  if (missingSriHosts.some((host) => host === provider.domain || host.endsWith(`.${provider.domain}`))) {
    return "missing";
  }

  const scriptDomains = normalizeArray(analysis.htmlSecurity?.externalScriptDomains);
  const isScriptProvider = scriptDomains.some((host) => host === provider.domain || host.endsWith(`.${provider.domain}`));
  if (!isScriptProvider) {
    return "not_applicable";
  }
  if ((analysis.htmlSecurity?.sriCoverage?.coveragePercent ?? 0) === 100) {
    return "covered";
  }
  return "unknown";
}

function mergeInventory(items: ExternalExposureInventoryItem[]): ExternalExposureInventoryItem[] {
  const merged = new Map<string, ExternalExposureInventoryItem>();
  for (const item of items) {
    const existing = merged.get(item.id);
    if (!existing) {
      merged.set(item.id, item);
      continue;
    }
    merged.set(item.id, {
      ...existing,
      risk: riskRank[item.risk] < riskRank[existing.risk] ? item.risk : existing.risk,
      confidence: confidenceRank[item.confidence] < confidenceRank[existing.confidence] ? item.confidence : existing.confidence,
      reviewPriority: priorityRank[item.reviewPriority] < priorityRank[existing.reviewPriority]
        ? item.reviewPriority
        : existing.reviewPriority,
      integrity: integrityRank[item.integrity] < integrityRank[existing.integrity] ? item.integrity : existing.integrity,
      evidence: uniqueEvidence([...existing.evidence, ...item.evidence]),
    });
  }
  return [...merged.values()].sort((left, right) => {
    const priorityDelta = priorityRank[left.reviewPriority] - priorityRank[right.reviewPriority];
    if (priorityDelta !== 0) return priorityDelta;
    const riskDelta = riskRank[left.risk] - riskRank[right.risk];
    if (riskDelta !== 0) return riskDelta;
    return left.name.localeCompare(right.name);
  });
}

function dataFlowForCategory(category: ThirdPartyProvider["category"]): VendorExposureProvider["dataFlow"] {
  if (category === "analytics" || category === "ads" || category === "session_replay") {
    return "telemetry";
  }
  if (category === "support" || category === "social" || category === "consent") {
    return "user_interaction";
  }
  if (category === "payments") {
    return "payment";
  }
  if (category === "security") {
    return "security";
  }
  if (category === "ai") {
    return "ai";
  }
  if (category === "cdn") {
    return "content_delivery";
  }
  return "unknown";
}

function reviewPriority(provider: ThirdPartyProvider): VendorExposureProvider["reviewPriority"] {
  if (provider.risk === "high" || provider.category === "session_replay" || provider.category === "payments") {
    return "urgent";
  }
  if (provider.risk === "medium" || provider.category === "ai" || provider.category === "ads") {
    return "review";
  }
  return "routine";
}

function actionForProvider(provider: ThirdPartyProvider): string {
  if (provider.category === "session_replay") {
    return "Confirm session replay masking, consent coverage, retention, and vendor ownership.";
  }
  if (provider.category === "payments") {
    return "Confirm payment provider ownership, PCI scope, and expected public loading paths.";
  }
  if (provider.category === "ai") {
    return "Confirm AI vendor disclosure, data-handling boundaries, and escalation ownership.";
  }
  if (provider.risk === "high") {
    return "Confirm the provider is intentional, documented, and covered by security and privacy review.";
  }
  if (provider.risk === "medium") {
    return "Review whether the provider is still needed and document the data-flow owner.";
  }
  return "Keep the provider in the vendor inventory and monitor for drift.";
}

function rankProvider(provider: VendorExposureProvider): number {
  const priorityWeight = { urgent: 0, review: 1, routine: 2 }[provider.reviewPriority];
  const riskWeight = { high: 0, medium: 1, low: 2 }[provider.risk];
  return priorityWeight * 10 + riskWeight;
}

function summarizeRisk(risk: VendorExposureRisk, counts: VendorExposureBrief["counts"]) {
  if (counts.totalProviders === 0) {
    return "No obvious third-party script or stylesheet providers were observed on the fetched page.";
  }
  if (risk === "high") {
    return "The fetched page exposes high-priority third-party dependencies that deserve explicit ownership and review.";
  }
  if (risk === "medium") {
    return "The fetched page has a visible vendor footprint with review-worthy data-flow or integrity considerations.";
  }
  return "The fetched page uses third-party providers, but the visible footprint is mostly lower-risk delivery or operational tooling.";
}

function deriveRisk(counts: VendorExposureBrief["counts"], issues: string[]): VendorExposureRisk {
  if (
    counts.highRiskProviders > 0 ||
    counts.sessionReplayProviders > 0 ||
    counts.missingSriScripts >= 3 ||
    issues.some((issue) => /session replay|high-trust|high-observability/i.test(issue))
  ) {
    return "high";
  }
  if (counts.mediumRiskProviders > 0 || counts.aiProviders > 0 || counts.paymentProviders > 0 || counts.missingSriScripts > 0 || issues.length > 0) {
    return "medium";
  }
  return "low";
}

function pushUnique(values: string[], value: string | null | undefined) {
  if (!value) {
    return;
  }
  const trimmed = value.trim();
  if (!trimmed || values.includes(trimmed)) {
    return;
  }
  values.push(trimmed);
}

export function buildVendorExposureBrief(analysis: AnalysisResult): VendorExposureBrief {
  const sourceProviders = normalizeArray(analysis.thirdPartyTrust?.providers);
  const providers = sourceProviders
    .map((provider) => ({
      name: provider.name,
      domain: provider.domain,
      category: provider.category,
      risk: provider.risk,
      evidence: provider.evidence,
      reviewPriority: reviewPriority(provider),
      dataFlow: dataFlowForCategory(provider.category),
      action: actionForProvider(provider),
    }))
    .sort((left, right) => {
      const rankDelta = rankProvider(left) - rankProvider(right);
      if (rankDelta !== 0) {
        return rankDelta;
      }
      return left.name.localeCompare(right.name);
    });
  const missingSriScripts = normalizeArray(analysis.htmlSecurity?.missingSriScriptUrls).length;
  const issues = normalizeArray(analysis.thirdPartyTrust?.issues);
  const strengths = normalizeArray(analysis.thirdPartyTrust?.strengths);
  const counts = {
    totalProviders: analysis.thirdPartyTrust?.totalProviders ?? providers.length,
    highRiskProviders: analysis.thirdPartyTrust?.highRiskProviders ?? providers.filter((provider) => provider.risk === "high").length,
    mediumRiskProviders: providers.filter((provider) => provider.risk === "medium").length,
    sessionReplayProviders: providers.filter((provider) => provider.category === "session_replay").length,
    analyticsProviders: providers.filter((provider) => provider.category === "analytics" || provider.category === "ads").length,
    aiProviders: providers.filter((provider) => provider.category === "ai").length + normalizeArray(analysis.aiSurface?.vendors).length,
    paymentProviders: providers.filter((provider) => provider.category === "payments").length,
    supportProviders: providers.filter((provider) => provider.category === "support").length,
    missingSriScripts,
  };
  const risk = deriveRisk(counts, issues);
  const highPriorityProviders = providers.filter((provider) => provider.reviewPriority !== "routine").slice(0, 10);
  const inventoryItems: ExternalExposureInventoryItem[] = sourceProviders.map((provider) => {
    const item = {
      name: provider.name,
      domain: provider.domain,
      role: "third_party" as const,
      category: provider.category,
      risk: provider.risk,
      confidence: "medium" as const,
      evidence: uniqueEvidence([provider.evidence]),
      reviewPriority: reviewPriority(provider),
      dataFlow: dataFlowForCategory(provider.category),
      integrity: integrityForProvider(provider, analysis),
      action: actionForProvider(provider),
    };
    return { id: inventoryId(item), ...item };
  });

  for (const provider of normalizeArray(analysis.infrastructure?.providers)) {
    const item = {
      name: provider.provider,
      domain: null,
      role: "infrastructure" as const,
      category: provider.category,
      risk: "low" as const,
      confidence: provider.confidence,
      evidence: uniqueEvidence([`${provider.source}: ${provider.evidence}`]),
      reviewPriority: "routine" as const,
      dataFlow: "content_delivery" as ExternalExposureDataFlow,
      integrity: "not_applicable" as const,
      action: "Keep the infrastructure provider in the service inventory and monitor unexpected provider drift.",
    };
    inventoryItems.push({ id: inventoryId(item), ...item });
  }

  const waf = analysis.infrastructure?.waf;
  if (waf?.detected && waf.provider) {
    const item = {
      name: waf.provider,
      domain: null,
      role: "infrastructure" as const,
      category: "waf",
      risk: "low" as const,
      confidence: waf.confidence,
      evidence: uniqueEvidence([waf.evidence]),
      reviewPriority: "routine" as const,
      dataFlow: "security" as ExternalExposureDataFlow,
      integrity: "not_applicable" as const,
      action: "Confirm edge protection ownership and monitor for unexpected WAF or edge-provider changes.",
    };
    inventoryItems.push({ id: inventoryId(item), ...item });
  }

  if (analysis.identityProvider?.detected && analysis.identityProvider.provider) {
    const item = {
      name: analysis.identityProvider.provider,
      domain: firstHostname([
        analysis.identityProvider.issuer,
        analysis.identityProvider.openIdConfigurationUrl,
        analysis.identityProvider.authorizationEndpoint,
        ...normalizeArray(analysis.identityProvider.redirectOrigins),
      ]),
      role: "identity" as const,
      category: analysis.identityProvider.protocol || "unknown",
      risk: "medium" as const,
      confidence: analysis.identityProvider.openIdConfigurationUrl ? "high" as const : "medium" as const,
      evidence: uniqueEvidence([
        analysis.identityProvider.openIdConfigurationUrl,
        analysis.identityProvider.issuer,
        ...normalizeArray(analysis.identityProvider.redirectOrigins),
      ]),
      reviewPriority: "review" as const,
      dataFlow: "identity" as ExternalExposureDataFlow,
      integrity: "not_applicable" as const,
      action: "Confirm identity-provider ownership, tenant boundaries, redirect URIs, and change monitoring.",
    };
    inventoryItems.push({ id: inventoryId(item), ...item });
  }

  for (const vendor of normalizeArray(analysis.aiSurface?.vendors)) {
    const item = {
      name: vendor.name,
      domain: null,
      role: "ai_surface" as const,
      category: vendor.category,
      risk: "medium" as const,
      confidence: vendor.confidence,
      evidence: uniqueEvidence([vendor.evidence]),
      reviewPriority: "review" as const,
      dataFlow: "ai" as ExternalExposureDataFlow,
      integrity: "not_applicable" as const,
      action: "Confirm AI vendor disclosure, data-handling boundaries, and escalation ownership.",
    };
    inventoryItems.push({ id: inventoryId(item), ...item });
  }

  const inventory = mergeInventory(inventoryItems);
  const inventoryCounts = {
    total: inventory.length,
    thirdParty: inventory.filter((item) => item.role === "third_party").length,
    infrastructure: inventory.filter((item) => item.role === "infrastructure").length,
    identity: inventory.filter((item) => item.role === "identity").length,
    aiSurface: inventory.filter((item) => item.role === "ai_surface").length,
    urgent: inventory.filter((item) => item.reviewPriority === "urgent").length,
    review: inventory.filter((item) => item.reviewPriority === "review").length,
    telemetryFlows: inventory.filter((item) => item.dataFlow === "telemetry").length,
    unknownFlows: inventory.filter((item) => item.dataFlow === "unknown").length,
    integrityGaps: inventory.filter((item) => item.integrity === "missing").length,
  };
  const nextActions: string[] = [];

  for (const provider of highPriorityProviders) {
    pushUnique(nextActions, provider.action);
  }
  if (missingSriScripts > 0) {
    pushUnique(nextActions, "Add Subresource Integrity for third-party scripts that can be pinned safely, or document why they cannot be pinned.");
  }
  if (counts.totalProviders > 0) {
    pushUnique(nextActions, "Keep a lightweight vendor inventory covering owner, purpose, data handled, and removal criteria.");
  }
  if (nextActions.length === 0) {
    pushUnique(nextActions, "Keep monitoring vendor drift after frontend, analytics, support, payment, or AI changes.");
  }

  return {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    risk,
    summary: summarizeRisk(risk, counts),
    counts,
    providers,
    highPriorityProviders,
    inventory,
    inventoryCounts,
    issues,
    strengths,
    nextActions: nextActions.slice(0, 6),
    collectionBoundary: "Passive public evidence only. Inventory signals are inferred from fetched HTML and assets, redirects, headers, DNS, public identity metadata, and visible provider markers; they do not prove internal dependency or data-flow configuration.",
    limitation: analysis.assessmentLimitation?.limited ? analysis.assessmentLimitation : null,
  };
}

export const buildExternalExposureInventory = buildVendorExposureBrief;
