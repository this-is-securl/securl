import { buildActionPlan } from "./actionPlan.js";
import { buildEvidenceQualitySummary } from "./evidenceQuality.js";
import type {
  ActionPlanItem,
  AnalysisResult,
  EvidenceQualitySignal,
  PostureInsightAction,
  PostureInsightSeverity,
  SignalClaritySignal,
  SignalClaritySummary,
  SignalClarityVerdict,
} from "./types.js";

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

function verdictFor(analysis: AnalysisResult): SignalClarityVerdict {
  if (analysis.assessmentLimitation?.limited) return "limited";
  if (analysis.score >= 85) return "strong";
  if (analysis.score >= 70) return "positive";
  if (analysis.score >= 50) return "mixed";
  return "weak";
}

function severityForImpact(impact: number): PostureInsightSeverity {
  if (impact >= 10) return "critical";
  if (impact >= 4) return "warning";
  return "info";
}

function severityForAction(item: ActionPlanItem): PostureInsightSeverity {
  if (item.impact === "high" || (item.scoreImpact ?? 0) >= 10) return "critical";
  if (item.impact === "medium" || (item.scoreImpact ?? 0) >= 4) return "warning";
  return "info";
}

function headlineFor(analysis: AnalysisResult, verdict: SignalClarityVerdict): string {
  if (verdict === "limited") {
    return `${analysis.host} needs a complete read before the grade should be treated as final.`;
  }
  if (verdict === "strong") {
    return `${analysis.host} presents a strong outside-in security posture.`;
  }
  if (verdict === "positive") {
    return `${analysis.host} looks mostly healthy with a few visible gaps to close.`;
  }
  if (verdict === "mixed") {
    return `${analysis.host} has a mixed posture with material fixes still visible from the outside.`;
  }
  return `${analysis.host} exposes high-impact posture gaps that should be reviewed first.`;
}

function summaryFor(analysis: AnalysisResult, verdict: SignalClarityVerdict, nextBestAction: PostureInsightAction | null): string {
  if (analysis.assessmentLimitation?.limited) {
    return analysis.assessmentLimitation.detail || "The target returned a limited or blocked response, so SecURL could not complete the full passive evidence read.";
  }
  const mainRisk = analysis.executiveSummary?.mainRisk || analysis.summary;
  if (nextBestAction) {
    return `${mainRisk} The clearest next action is: ${nextBestAction.label}`;
  }
  if (verdict === "strong") {
    return `${mainRisk} No urgent follow-up stands out from the passive evidence.`;
  }
  return mainRisk;
}

function negativeDriverSignals(analysis: AnalysisResult): SignalClaritySignal[] {
  return normalizeArray(analysis.scoreDrivers)
    .filter((driver) => driver.impact > 0)
    .sort((left, right) => right.impact - left.impact)
    .slice(0, 5)
    .map((driver) => ({
      id: `score:${driver.areaKey}:${driver.label}`.toLowerCase().replace(/[^a-z0-9:]+/g, "-"),
      label: driver.label,
      detail: driver.detail,
      direction: "negative",
      severity: severityForImpact(driver.impact),
      source: driver.source,
      scoreImpact: driver.impact,
    }));
}

function positiveSignals(strengths: EvidenceQualitySignal[], analysis: AnalysisResult): SignalClaritySignal[] {
  const evidenceSignals = strengths.slice(0, 3).map((signal) => ({
    id: `evidence:${signal.id}`,
    label: signal.label,
    detail: signal.detail,
    direction: "positive" as const,
    severity: "info" as const,
    source: "evidence_quality" as const,
    scoreImpact: null,
  }));

  const postureSignals = normalizeArray(analysis.strengths).slice(0, 2).map((strength, index) => ({
    id: `strength:${index + 1}`,
    label: "Observed strength",
    detail: strength,
    direction: "positive" as const,
    severity: "info" as const,
    source: "action_plan" as const,
    scoreImpact: null,
  }));

  return [...evidenceSignals, ...postureSignals].slice(0, 5);
}

function toNextBestAction(item: ActionPlanItem | null): PostureInsightAction | null {
  if (!item) return null;
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

function caveatsFor(analysis: AnalysisResult, evidenceQuality: ReturnType<typeof buildEvidenceQualitySummary>): string[] {
  return [
    ...(analysis.assessmentLimitation?.limited ? [analysis.assessmentLimitation.detail || "The scan was limited."] : []),
    ...(analysis.scanTiming?.timedOut ? ["Secondary evidence collection timed out before all passive checks completed."] : []),
    ...(evidenceQuality.level === "low" ? ["Evidence quality is low, so verify the highest-impact findings before making irreversible changes."] : []),
    ...normalizeArray(evidenceQuality.recommendedFollowUp).slice(0, 2),
  ].filter((item, index, items) => item && items.indexOf(item) === index);
}

function audienceNotesFor(
  analysis: AnalysisResult,
  verdict: SignalClarityVerdict,
  nextBestAction: PostureInsightAction | null,
): SignalClaritySummary["audienceNotes"] {
  const action = nextBestAction?.label || "keep monitoring and rescan after meaningful changes";
  return {
    developer: verdict === "limited"
      ? "First make the target readable to passive checks, then rerun before tuning application controls."
      : `Start with the highest-impact observable fix: ${action}.`,
    security: `Use the grade ${analysis.grade} / ${analysis.score} as an outside-in triage signal, then validate the supporting evidence before treating it as assurance.`,
    executive: verdict === "strong"
      ? "The public posture looks healthy; the main value is continued monitoring for regressions."
      : "The public posture has visible improvement opportunities that can be prioritized without credentials or intrusive testing.",
  };
}

export function buildSignalClaritySummary(analysis: AnalysisResult): SignalClaritySummary {
  const evidenceQuality = analysis.evidenceQuality ?? buildEvidenceQualitySummary(analysis);
  const actionPlan = analysis.actionPlan ?? buildActionPlan(analysis);
  const nextBestAction = toNextBestAction(actionPlan.items[0] ?? null);
  const verdict = verdictFor(analysis);

  return {
    generatedAt: new Date().toISOString(),
    headline: headlineFor(analysis, verdict),
    verdict,
    summary: summaryFor(analysis, verdict, nextBestAction),
    target: {
      host: analysis.host,
      finalUrl: analysis.finalUrl,
      scannedAt: analysis.scannedAt,
      score: analysis.score,
      grade: analysis.grade,
    },
    confidence: {
      level: evidenceQuality.level,
      score: evidenceQuality.score,
      summary: evidenceQuality.summary,
    },
    score: {
      driversReviewed: normalizeArray(analysis.scoreDrivers).length,
      topNegativeDrivers: negativeDriverSignals(analysis),
      topPositiveSignals: positiveSignals(evidenceQuality.strengths, analysis),
    },
    nextBestAction,
    caveats: caveatsFor(analysis, evidenceQuality),
    audienceNotes: audienceNotesFor(analysis, verdict, nextBestAction),
  };
}
