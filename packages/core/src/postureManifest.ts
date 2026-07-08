import { createHash } from "node:crypto";
import { buildObservationLedger } from "./observations.js";
import {
  DEFAULT_OBSERVATION_POLICY,
  evaluateObservationPolicy,
} from "./observationPolicy.js";
import type {
  AnalysisResult,
  AnalyzeTargetOptions,
  ObservationPolicy,
  ObservationPolicyEvaluation,
  PostureManifest,
  PostureManifestSkippedCheck,
} from "./types.js";

export interface BuildPostureManifestOptions {
  engineVersion?: string | null;
  generatedAt?: string;
  scanMode?: AnalyzeTargetOptions["scanMode"];
  policy?: ObservationPolicy | null;
  policySource?: string;
  policyEvaluation?: ObservationPolicyEvaluation | null;
}

function countIssuesBySeverity(result: AnalysisResult): Record<string, number> {
  return result.issues.reduce<Record<string, number>>((counts, issue) => {
    counts[issue.severity] = (counts[issue.severity] ?? 0) + 1;
    return counts;
  }, {});
}

function buildSkippedChecks(result: AnalysisResult): PostureManifestSkippedCheck[] {
  if (!result.assessmentLimitation?.limited) {
    return [];
  }
  return [{
    id: "complete_assessment",
    category: "assessment",
    reason: result.assessmentLimitation.kind ?? "limited_assessment",
    detail: result.assessmentLimitation.detail ?? null,
  }];
}

function manifestIdFor({
  result,
  policyEvaluation,
}: {
  result: AnalysisResult;
  policyEvaluation: ObservationPolicyEvaluation;
}) {
  const hash = createHash("sha256")
    .update([
      result.finalUrl,
      result.scannedAt,
      String(result.score),
      result.grade,
      policyEvaluation.policy.id,
      policyEvaluation.policy.version,
    ].join("\u0000"))
    .digest("hex")
    .slice(0, 24);
  return `pm_${hash}`;
}

export function buildPostureManifest(
  result: AnalysisResult,
  options: BuildPostureManifestOptions = {},
): PostureManifest {
  const observationLedger = result.observationLedger ?? buildObservationLedger(result);
  const policyEvaluation = options.policyEvaluation ?? evaluateObservationPolicy({
    ledger: observationLedger,
    policy: options.policy ?? DEFAULT_OBSERVATION_POLICY,
  });
  const generatedAt = options.generatedAt ?? result.scannedAt ?? new Date().toISOString();

  return {
    version: "1.0",
    manifestId: manifestIdFor({ result, policyEvaluation }),
    generatedAt,
    engine: {
      name: "securl",
      version: options.engineVersion ?? null,
    },
    target: {
      inputUrl: result.inputUrl,
      normalizedUrl: result.normalizedUrl,
      finalUrl: result.finalUrl,
      host: result.host,
    },
    scan: {
      mode: options.scanMode ?? "standard",
      scannedAt: result.scannedAt,
      responseTimeMs: result.responseTimeMs,
      statusCode: result.statusCode,
      timing: result.scanTiming ?? null,
      assessmentLimitation: result.assessmentLimitation,
    },
    posture: {
      score: result.score,
      grade: result.grade,
      summary: result.summary,
      issueCounts: countIssuesBySeverity(result),
      strengthCount: result.strengths.length,
      scoreDrivers: result.scoreDrivers ?? [],
    },
    checks: {
      observationLedger,
      skipped: buildSkippedChecks(result),
    },
    evidence: {
      evidenceSummary: result.evidenceSummary ?? null,
      evidenceQuality: result.evidenceQuality ?? null,
      signalClarity: result.signalClarity ?? null,
    },
    policy: {
      source: options.policySource ?? "default",
      evaluation: policyEvaluation,
    },
  };
}
