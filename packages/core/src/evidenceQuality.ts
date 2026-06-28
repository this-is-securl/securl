import type {
  AnalysisResult,
  EvidenceQualityLevel,
  EvidenceQualitySignal,
  EvidenceQualitySummary,
  ScanEvidenceKind,
} from "./types.js";

const OBSERVED_KINDS = new Set<ScanEvidenceKind>(["header", "tls", "cookie", "redirect", "dns", "html", "public_record"]);

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

function clampScore(score: number) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function levelForScore(score: number): EvidenceQualityLevel {
  if (score >= 80) return "high";
  if (score >= 55) return "medium";
  return "low";
}

function pushSignal(
  signals: EvidenceQualitySignal[],
  id: string,
  label: string,
  detail: string,
  impact: EvidenceQualitySignal["impact"],
) {
  signals.push({ id, label, detail, impact });
}

function buildSummary(level: EvidenceQualityLevel, analysis: AnalysisResult, gaps: EvidenceQualitySignal[]) {
  if (analysis.assessmentLimitation?.limited) {
    return "Evidence quality is limited because the target did not return a complete posture read.";
  }
  if (level === "high") {
    return "Evidence quality is high enough to treat the posture result as a solid outside-in read.";
  }
  if (level === "medium") {
    return "Evidence quality is usable, but a few collection gaps should be considered before treating the result as final.";
  }
  if (gaps.length > 0) {
    return "Evidence quality is low, so treat this result as directional until the collection gaps are resolved.";
  }
  return "Evidence quality is low because the scan produced too little structured support for the result.";
}

export function buildEvidenceQualitySummary(analysis: AnalysisResult): EvidenceQualitySummary {
  const evidenceSummary = analysis.evidenceSummary;
  const issues = normalizeArray(analysis.issues);
  const timing = analysis.scanTiming;
  const totalReferences = evidenceSummary?.totalEvidenceReferences ?? 0;
  const observedReferences = evidenceSummary?.observedCount ?? 0;
  const derivedReferences = evidenceSummary?.derivedCount ?? 0;
  const observedRatio = totalReferences > 0 ? observedReferences / totalReferences : 0;
  const kinds = Object.keys(evidenceSummary?.byKind ?? {}) as ScanEvidenceKind[];
  const lowConfidence = issues.filter((issue) => issue.confidence === "low").length;
  const mediumConfidence = issues.filter((issue) => issue.confidence === "medium").length;
  const highConfidence = issues.filter((issue) => issue.confidence === "high").length;
  const strengths: EvidenceQualitySignal[] = [];
  const gaps: EvidenceQualitySignal[] = [];

  let score = 50;

  if (totalReferences >= 12) {
    score += 18;
    pushSignal(strengths, "evidence_volume", "Evidence volume", "The scan produced a broad set of structured evidence references.", "positive");
  } else if (totalReferences >= 5) {
    score += 10;
    pushSignal(strengths, "evidence_volume", "Evidence volume", "The scan produced enough structured evidence for a useful posture read.", "positive");
  } else {
    score -= 18;
    pushSignal(gaps, "low_evidence_volume", "Low evidence volume", "The scan produced fewer structured evidence references than expected.", "negative");
  }

  if (observedRatio >= 0.7) {
    score += 16;
    pushSignal(strengths, "observed_evidence", "Observed evidence", "Most evidence came from directly observed target data rather than derived context.", "positive");
  } else if (observedRatio >= 0.45) {
    score += 6;
  } else {
    score -= 14;
    pushSignal(gaps, "derived_heavy", "Derived-heavy evidence", "The result relies heavily on derived evidence, so direct verification is thinner.", "negative");
  }

  if (kinds.length >= 5) {
    score += 12;
    pushSignal(strengths, "evidence_breadth", "Evidence breadth", "The scan collected evidence across several posture areas.", "positive");
  } else if (kinds.length <= 2) {
    score -= 12;
    pushSignal(gaps, "narrow_evidence", "Narrow evidence", "Evidence came from a small number of source types.", "negative");
  }

  if (analysis.assessmentLimitation?.limited) {
    score -= 35;
    pushSignal(gaps, "limited_assessment", "Limited assessment", analysis.assessmentLimitation.detail ?? "The target response limited collection.", "negative");
  }

  if (timing?.timedOut) {
    score -= 18;
    pushSignal(gaps, "scan_timeout", "Scan timeout", "The scan timed out before all enrichment completed.", "negative");
  }

  if (analysis.statusCode >= 500 || analysis.statusCode === 0) {
    score -= 14;
    pushSignal(gaps, "availability_status", "Availability status", `The target returned HTTP ${analysis.statusCode}, reducing confidence in the observed posture.`, "negative");
  } else if (analysis.statusCode >= 200 && analysis.statusCode < 400) {
    score += 8;
    pushSignal(strengths, "normal_response", "Normal response", `The target returned HTTP ${analysis.statusCode}, supporting a normal posture read.`, "positive");
  }

  if (lowConfidence > 0) {
    score -= Math.min(14, lowConfidence * 4);
    pushSignal(gaps, "low_confidence_findings", "Low-confidence findings", `${lowConfidence} finding${lowConfidence === 1 ? "" : "s"} had low confidence.`, "negative");
  }

  if (highConfidence > 0 && highConfidence >= lowConfidence + mediumConfidence) {
    score += 8;
    pushSignal(strengths, "high_confidence_findings", "High-confidence findings", "Most findings were supported with high-confidence evidence.", "positive");
  }

  if (!normalizeArray(analysis.headers).length) {
    score -= 10;
    pushSignal(gaps, "missing_header_set", "Missing header set", "No response header set was available for the scan.", "negative");
  }

  if (!analysis.certificate?.available) {
    score -= 8;
    pushSignal(gaps, "certificate_unavailable", "Certificate unavailable", "The scan could not read a served TLS certificate.", "negative");
  } else if (analysis.certificate.authorized !== false) {
    score += 6;
    pushSignal(strengths, "certificate_observed", "Certificate observed", "A served TLS certificate was observed during the scan.", "positive");
  }

  const finalScore = clampScore(score);
  const level = levelForScore(finalScore);
  const recommendedFollowUp = [
    ...(analysis.assessmentLimitation?.limited ? ["Restore complete scan coverage and rescan before treating the grade as final."] : []),
    ...(timing?.timedOut ? ["Rerun the scan with a longer timeout or narrower mode to complete enrichment."] : []),
    ...(observedRatio < 0.45 ? ["Verify the top findings manually because direct observed evidence is thin."] : []),
    ...(kinds.length <= 2 ? ["Collect another scan after the target returns normal headers, TLS, DNS, and HTML evidence."] : []),
  ];

  if (recommendedFollowUp.length === 0) {
    recommendedFollowUp.push("Use the score drivers and top insights as the primary follow-up path.");
  }

  return {
    generatedAt: new Date().toISOString(),
    level,
    score: finalScore,
    summary: buildSummary(level, analysis, gaps),
    evidence: {
      totalReferences,
      observedReferences,
      derivedReferences,
      observedRatio: Number(observedRatio.toFixed(2)),
      kinds: kinds.filter((kind) => OBSERVED_KINDS.has(kind) || kind === "probe" || kind === "score_driver"),
    },
    scan: {
      limited: Boolean(analysis.assessmentLimitation?.limited),
      limitedKind: analysis.assessmentLimitation?.kind ?? null,
      timedOut: Boolean(timing?.timedOut),
      statusCode: analysis.statusCode,
      responseTimeMs: analysis.responseTimeMs,
    },
    findings: {
      total: issues.length,
      lowConfidence,
      mediumConfidence,
      highConfidence,
    },
    strengths: strengths.slice(0, 5),
    gaps: gaps.slice(0, 5),
    recommendedFollowUp: recommendedFollowUp.slice(0, 4),
    limitation: analysis.assessmentLimitation?.limited ? analysis.assessmentLimitation : null,
  };
}
