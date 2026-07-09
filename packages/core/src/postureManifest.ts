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

export const POSTURE_MANIFEST_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://securl.online/schemas/posture-manifest-v1.json",
  title: "SecURL Posture Manifest v1",
  description: "Machine-readable external posture recipe card emitted by SecURL.",
  type: "object",
  additionalProperties: false,
  required: [
    "version",
    "manifestId",
    "generatedAt",
    "engine",
    "target",
    "scan",
    "posture",
    "checks",
    "evidence",
    "policy",
  ],
  properties: {
    version: { const: "1.0" },
    manifestId: { type: "string", pattern: "^pm_[a-f0-9]{24}$" },
    generatedAt: { type: "string", format: "date-time" },
    engine: {
      type: "object",
      additionalProperties: false,
      required: ["name", "version"],
      properties: {
        name: { const: "securl" },
        version: { type: ["string", "null"] },
      },
    },
    target: {
      type: "object",
      additionalProperties: false,
      required: ["inputUrl", "normalizedUrl", "finalUrl", "host"],
      properties: {
        inputUrl: { type: "string", minLength: 1 },
        normalizedUrl: { type: "string", minLength: 1 },
        finalUrl: { type: "string", minLength: 1 },
        host: { type: "string", minLength: 1 },
      },
    },
    scan: {
      type: "object",
      additionalProperties: false,
      required: [
        "mode",
        "scannedAt",
        "responseTimeMs",
        "statusCode",
        "timing",
        "assessmentLimitation",
      ],
      properties: {
        mode: { enum: ["standard", "quiet", "deep-passive"] },
        scannedAt: { type: "string", format: "date-time" },
        responseTimeMs: { type: "number", minimum: 0 },
        statusCode: { type: "number", minimum: 0 },
        timing: { type: ["object", "null"], additionalProperties: true },
        assessmentLimitation: { type: "object", additionalProperties: true },
      },
    },
    posture: {
      type: "object",
      additionalProperties: false,
      required: ["score", "grade", "summary", "issueCounts", "strengthCount", "scoreDrivers"],
      properties: {
        score: { type: "number", minimum: 0, maximum: 100 },
        grade: { type: "string", minLength: 1 },
        summary: { type: "string" },
        issueCounts: {
          type: "object",
          additionalProperties: { type: "number", minimum: 0 },
        },
        strengthCount: { type: "number", minimum: 0 },
        scoreDrivers: {
          type: "array",
          items: { type: "object", additionalProperties: true },
        },
      },
    },
    checks: {
      type: "object",
      additionalProperties: false,
      required: ["observationLedger", "skipped"],
      properties: {
        observationLedger: {
          type: "object",
          required: ["version", "generatedAt", "observations"],
          additionalProperties: true,
          properties: {
            version: { type: "string", minLength: 1 },
            generatedAt: { type: "string", format: "date-time" },
            observations: {
              type: "array",
              items: { type: "object", additionalProperties: true },
            },
          },
        },
        skipped: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["id", "category", "reason", "detail"],
            properties: {
              id: { type: "string", minLength: 1 },
              category: { type: "string", minLength: 1 },
              reason: { type: "string", minLength: 1 },
              detail: { type: ["string", "null"] },
            },
          },
        },
      },
    },
    evidence: {
      type: "object",
      additionalProperties: false,
      required: ["evidenceSummary", "evidenceQuality", "signalClarity"],
      properties: {
        evidenceSummary: { type: ["object", "null"], additionalProperties: true },
        evidenceQuality: { type: ["object", "null"], additionalProperties: true },
        signalClarity: { type: ["object", "null"], additionalProperties: true },
      },
    },
    policy: {
      type: "object",
      additionalProperties: false,
      required: ["source", "evaluation"],
      properties: {
        source: { type: "string", minLength: 1 },
        evaluation: {
          type: "object",
          required: ["version", "policy", "passed", "results", "summary"],
          additionalProperties: true,
          properties: {
            version: { type: "string", minLength: 1 },
            policy: { type: "object", additionalProperties: true },
            passed: { type: "boolean" },
            results: {
              type: "array",
              items: { type: "object", additionalProperties: true },
            },
            summary: { type: "object", additionalProperties: true },
          },
        },
      },
    },
  },
} as const;

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
