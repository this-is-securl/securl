import type {
  AnalysisResult,
  ThirdPartyProvider,
  VendorExposureBrief,
  VendorExposureProvider,
  VendorExposureRisk,
} from "./types.js";

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

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
    generatedAt: new Date().toISOString(),
    risk,
    summary: summarizeRisk(risk, counts),
    counts,
    providers,
    highPriorityProviders,
    issues,
    strengths,
    nextActions: nextActions.slice(0, 6),
    collectionBoundary: "Passive public page evidence only. Vendor signals are inferred from fetched HTML, scripts, stylesheets, and visible AI/provider markers.",
    limitation: analysis.assessmentLimitation?.limited ? analysis.assessmentLimitation : null,
  };
}
