import { buildActionPlan } from "./actionPlan.js";
import type {
  ActionPlanItem,
  ActionPlanTheme,
  AnalysisResult,
  PostureInsightAction,
  PostureInsightItem,
  PostureInsights,
  PostureInsightSeverity,
  PostureInsightThemeSummary,
  RemediationOwner,
} from "./types.js";

const SEVERITY_RANK: Record<PostureInsightSeverity, number> = {
  critical: 3,
  warning: 2,
  info: 1,
};

const THEME_LABELS: Record<ActionPlanTheme, string> = {
  browser_hardening: "Browser hardening",
  transport: "Transport security",
  domain_trust: "Domain trust",
  public_exposure: "Public exposure",
  vendor_risk: "Vendor risk",
  identity: "Identity surface",
  availability: "Availability",
  monitoring: "Monitoring",
};

function severityForAction(item: ActionPlanItem): PostureInsightSeverity {
  if (item.impact === "high" || (item.scoreImpact ?? 0) >= 10) {
    return "critical";
  }
  if (item.impact === "medium" || (item.scoreImpact ?? 0) >= 4) {
    return "warning";
  }
  return "info";
}

function highestSeverity(left: PostureInsightSeverity, right: PostureInsightSeverity): PostureInsightSeverity {
  return SEVERITY_RANK[right] > SEVERITY_RANK[left] ? right : left;
}

function buildSummary(analysis: AnalysisResult, insights: PostureInsightItem[]): string {
  if (analysis.assessmentLimitation?.limited) {
    return "The scan was limited, so restore complete scan coverage before treating the posture read as final.";
  }
  if (!insights.length) {
    return "No immediate posture action stands out from the passive evidence. Keep monitoring and rescan after meaningful changes.";
  }
  const critical = insights.filter((insight) => insight.severity === "critical").length;
  if (critical > 0) {
    return `${critical} critical insight${critical === 1 ? "" : "s"} should be reviewed first because ${critical === 1 ? "it carries" : "they carry"} the highest posture impact.`;
  }
  return `${insights.length} actionable insight${insights.length === 1 ? "" : "s"} ${insights.length === 1 ? "is" : "are"} available for follow-up.`;
}

function buildThemeSummaries(items: ActionPlanItem[]): PostureInsightThemeSummary[] {
  const themes = new Map<ActionPlanTheme, PostureInsightThemeSummary>();

  for (const item of items) {
    const severity = severityForAction(item);
    const existing = themes.get(item.theme);
    if (!existing) {
      themes.set(item.theme, {
        theme: item.theme,
        label: THEME_LABELS[item.theme],
        count: 1,
        highestSeverity: severity,
        highImpactActions: item.impact === "high" ? 1 : 0,
        quickWins: item.effort === "low" ? 1 : 0,
        owners: [item.owner],
        scoreImpact: item.scoreImpact ?? 0,
      });
      continue;
    }
    existing.count += 1;
    existing.highestSeverity = highestSeverity(existing.highestSeverity, severity);
    existing.highImpactActions += item.impact === "high" ? 1 : 0;
    existing.quickWins += item.effort === "low" ? 1 : 0;
    existing.scoreImpact += item.scoreImpact ?? 0;
    if (!existing.owners.includes(item.owner)) {
      existing.owners.push(item.owner);
    }
  }

  return [...themes.values()].sort((left, right) => {
    const severityDelta = SEVERITY_RANK[right.highestSeverity] - SEVERITY_RANK[left.highestSeverity];
    if (severityDelta !== 0) return severityDelta;
    const impactDelta = right.highImpactActions - left.highImpactActions;
    if (impactDelta !== 0) return impactDelta;
    return right.scoreImpact - left.scoreImpact;
  });
}

function toInsight(item: ActionPlanItem): PostureInsightItem {
  return {
    id: `insight:${item.id}`,
    title: item.title,
    summary: item.whyNow,
    severity: severityForAction(item),
    theme: item.theme,
    owner: item.owner,
    effort: item.effort,
    impact: item.impact,
    confidence: item.confidence,
    scoreImpact: item.scoreImpact,
    nextAction: item.action,
    verify: item.verify,
    evidence: item.evidence,
    relatedFindings: item.relatedFindings,
    source: item.source,
  };
}

function toNextBestAction(item: ActionPlanItem): PostureInsightAction {
  return {
    id: item.id,
    label: item.action,
    theme: item.theme,
    owner: item.owner,
    effort: item.effort,
    impact: item.impact,
    severity: severityForAction(item),
    verify: item.verify,
  };
}

export function buildPostureInsights(analysis: AnalysisResult): PostureInsights {
  const actionPlan = analysis.actionPlan ?? buildActionPlan(analysis);
  const topItems = actionPlan.items.slice(0, 6);
  const topInsights = topItems.map(toInsight);
  const ownerOrder: RemediationOwner[] = ["edge", "app", "dns", "identity", "third_party"];

  return {
    generatedAt: new Date().toISOString(),
    summary: buildSummary(analysis, topInsights),
    posture: actionPlan.posture,
    themes: buildThemeSummaries(actionPlan.items).map((theme) => ({
      ...theme,
      owners: [...theme.owners].sort((left, right) => ownerOrder.indexOf(left) - ownerOrder.indexOf(right)),
    })),
    topInsights,
    nextBestActions: topItems.slice(0, 3).map(toNextBestAction),
    limitation: actionPlan.limitation,
  };
}
