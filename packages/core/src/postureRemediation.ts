import type {
  AnalysisResult,
  RemediationEffort,
  RemediationImpact,
  RemediationOwner,
  RemediationPlan,
  RemediationPlanItem,
  ScanEvidenceKind,
  ScanEvidenceReference,
  ScanIssue,
  ScoreDriver,
  SecurityHeaderResult,
} from "./types.js";

import type {
  PostureEvidenceSummary,
  PostureEvidenceSummaryReference,
} from "./types.js";

const normalizeArray = <T>(value: T[] | undefined | null): T[] => (Array.isArray(value) ? value : []);

const HEADER_AREA_KEYS = new Set(["edge", "content"]);

const slug = (value: string) => {
  let output = "";
  let pendingDash = false;
  for (const char of value.toLowerCase()) {
    const code = char.charCodeAt(0);
    const isAsciiLetter = code >= 97 && code <= 122;
    const isDigit = code >= 48 && code <= 57;
    if (isAsciiLetter || isDigit) {
      if (pendingDash && output.length > 0) output += "-";
      output += char;
      pendingDash = false;
    } else {
      pendingDash = true;
    }
    if (output.length >= 80) break;
  }
  return output || "remediation";
};

function issueSeverityRank(issue: ScanIssue) {
  if (issue.severity === "critical") return 0;
  if (issue.severity === "warning") return 1;
  return 2;
}

function impactFromScore(scoreImpact: number | null, issue?: ScanIssue): RemediationImpact {
  if (scoreImpact !== null && scoreImpact >= 15) return "high";
  if (issue?.severity === "critical") return "high";
  if (scoreImpact !== null && scoreImpact >= 5) return "medium";
  if (issue?.severity === "warning") return "medium";
  return "low";
}

function ownerForArea(areaKey: ScoreDriver["areaKey"] | ScanIssue["area"]): RemediationOwner {
  if (areaKey === "domain") return "dns";
  if (areaKey === "trust" || areaKey === "ai") return "third_party";
  if (areaKey === "headers" || areaKey === "edge" || areaKey === "content") return "edge";
  if (areaKey === "certificate" || areaKey === "transport") return "edge";
  return "app";
}

function effortFor(owner: RemediationOwner, title: string): RemediationEffort {
  const lower = title.toLowerCase();
  if (owner === "dns" || lower.includes("content-security-policy") || lower.includes("csp")) return "medium";
  if (lower.includes("third-party") || lower.includes("identity")) return "medium";
  if (lower.includes("limited assessment") || lower.includes("service unavailable")) return "high";
  return "low";
}

function evidenceKindForScoreSource(source: ScoreDriver["source"]): ScanEvidenceKind {
  if (source === "tls") return "tls";
  if (source === "cookies") return "cookie";
  if (source === "dns") return "dns";
  if (source === "html") return "html";
  if (source === "public_record") return "public_record";
  return "score_driver";
}

function incrementCount<T extends string>(counts: Partial<Record<T, number>>, key: T) {
  counts[key] = (counts[key] ?? 0) + 1;
}

function headerEvidenceForIssue(issue: ScanIssue, headers: SecurityHeaderResult[]): ScanEvidenceReference[] {
  const issueText = `${issue.title} ${issue.detail}`.toLowerCase();
  const matched = headers.find((header) =>
    issueText.includes(header.label.toLowerCase()) || issueText.includes(header.key.toLowerCase()),
  );
  if (!matched) return [];
  return [{
    kind: "header",
    label: matched.label,
    observed: matched.value ?? matched.status,
    expected: matched.recommendation,
    source: issue.source,
  }];
}

function cookieEvidenceForIssue(issue: ScanIssue, analysis: AnalysisResult): ScanEvidenceReference[] {
  const titleLower = issue.title.toLowerCase();
  const prefix = "cookie ";
  const suffix = " needs attention";
  const cookieName = titleLower.startsWith(prefix) && titleLower.endsWith(suffix)
    ? issue.title.slice(prefix.length, issue.title.length - suffix.length).trim() || null
    : null;
  const cookie = cookieName
    ? normalizeArray(analysis.cookies).find((item) => item.name === cookieName)
    : null;
  if (!cookieName && !cookie) return [];
  return [{
    kind: "cookie",
    label: cookieName ?? cookie?.name ?? "Cookie",
    observed: cookie
      ? [
          cookie.secure ? "Secure" : "missing Secure",
          cookie.httpOnly ? "HttpOnly" : "missing HttpOnly",
          cookie.sameSite ? `SameSite=${cookie.sameSite}` : "missing SameSite",
        ].join(", ")
      : issue.detail,
    expected: "Session and authentication cookies should use Secure, HttpOnly, and an appropriate SameSite policy.",
    source: issue.source,
  }];
}

export function buildIssueEvidence(issue: ScanIssue, analysis: AnalysisResult): ScanEvidenceReference[] {
  const evidence: ScanEvidenceReference[] = [
    ...normalizeArray(issue.evidence),
    ...headerEvidenceForIssue(issue, normalizeArray(analysis.headers)),
    ...cookieEvidenceForIssue(issue, analysis),
  ];

  if (issue.area === "transport" && issue.title.toLowerCase().includes("https")) {
    evidence.push({
      kind: "tls",
      label: "Final URL",
      observed: analysis.finalUrl,
      expected: "HTTPS with a trusted certificate chain.",
      url: analysis.finalUrl,
      source: issue.source,
    });
  }

  if (issue.area === "certificate") {
    evidence.push({
      kind: "tls",
      label: analysis.certificate?.subject ?? analysis.host,
      observed: normalizeArray(analysis.certificate?.issues).join("; ") || analysis.certificate?.issuer || null,
      expected: "Valid, trusted certificate with comfortable renewal runway.",
      source: issue.source,
    });
  }

  if (issue.title.toLowerCase().includes("redirect")) {
    evidence.push({
      kind: "redirect",
      label: "Redirect chain",
      observed: `${analysis.redirectChain?.totalHops ?? normalizeArray(analysis.redirects).length} hop(s)`,
      expected: "Short HTTPS-only redirect chain.",
      url: analysis.finalUrl,
      source: issue.source,
    });
  }

  const seen = new Set<string>();
  return evidence.filter((item) => {
    const key = `${item.kind}:${item.label}:${item.observed ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function attachIssueEvidence(analysis: AnalysisResult): AnalysisResult {
  return {
    ...analysis,
    issues: normalizeArray(analysis.issues).map((issue) => ({
      ...issue,
      evidence: buildIssueEvidence(issue, analysis),
    })),
  };
}

function rankEvidence(left: PostureEvidenceSummaryReference, right: PostureEvidenceSummaryReference) {
  const impactDelta = (right.scoreImpact ?? -1) - (left.scoreImpact ?? -1);
  if (impactDelta !== 0) return impactDelta;
  const severityRank = { critical: 0, warning: 1, info: 2 };
  const severityDelta = (severityRank[left.severity ?? "info"] ?? 2) - (severityRank[right.severity ?? "info"] ?? 2);
  if (severityDelta !== 0) return severityDelta;
  return left.label.localeCompare(right.label);
}

export function buildPostureEvidenceSummary(
  analysis: AnalysisResult,
  { limit = 12 } = {},
): PostureEvidenceSummary {
  const scoreDriverEvidence = normalizeArray(analysis.scoreDrivers)
    .filter((driver) => driver.impact > 0)
    .map((driver) => ({
      kind: evidenceKindForScoreSource(driver.source),
      label: driver.label,
      observed: driver.detail,
      source: driver.source,
      areaLabel: driver.areaLabel,
      scoreImpact: driver.impact,
    }));

  const findingEvidence = normalizeArray(analysis.issues).flatMap((issue) => {
    const evidence = normalizeArray(issue.evidence).length ? normalizeArray(issue.evidence) : buildIssueEvidence(issue, analysis);
    return evidence.map((reference) => ({
      ...reference,
      relatedFinding: issue.title,
      severity: issue.severity,
      scoreImpact: null,
    }));
  });

  const allEvidence: PostureEvidenceSummaryReference[] = [
    ...scoreDriverEvidence,
    ...findingEvidence,
  ];
  const byKind: Partial<Record<ScanEvidenceKind, number>> = {};
  const bySource: Record<string, number> = {};

  for (const reference of allEvidence) {
    incrementCount(byKind, reference.kind);
    incrementCount(bySource, String(reference.source ?? "unknown"));
  }

  const observedKinds = new Set<ScanEvidenceKind>(["header", "tls", "cookie", "redirect", "dns", "html", "public_record"]);
  const observedCount = allEvidence.filter((reference) => observedKinds.has(reference.kind)).length;
  const derivedCount = allEvidence.length - observedCount;

  return {
    generatedAt: new Date().toISOString(),
    summary: allEvidence.length
      ? `${allEvidence.length} evidence reference${allEvidence.length === 1 ? "" : "s"} explain the main score drivers and findings.`
      : "No structured evidence references were generated for this scan.",
    totalEvidenceReferences: allEvidence.length,
    byKind,
    bySource,
    observedCount,
    derivedCount,
    topEvidence: [...allEvidence].sort(rankEvidence).slice(0, limit),
    scoreDriverEvidence: scoreDriverEvidence.slice(0, limit),
    findingEvidence: findingEvidence.sort(rankEvidence).slice(0, limit),
    limitation: analysis.assessmentLimitation ?? null,
  };
}

function relatedFindingsForDriver(driver: ScoreDriver, issues: ScanIssue[]) {
  const driverText = `${driver.areaKey} ${driver.label} ${driver.detail}`.toLowerCase();
  return issues
    .filter((issue) => {
      if (HEADER_AREA_KEYS.has(driver.areaKey) && issue.area === "headers") return true;
      if (driver.source === "cookies" && issue.area === "cookies") return true;
      if (driver.source === "tls" && (issue.area === "certificate" || issue.area === "transport")) return true;
      return driverText.includes(issue.title.toLowerCase());
    })
    .sort((left, right) => issueSeverityRank(left) - issueSeverityRank(right))
    .slice(0, 4)
    .map((issue) => issue.title);
}

function actionFor(owner: RemediationOwner, title: string, detail: string) {
  const lower = `${title} ${detail}`.toLowerCase();
  if (lower.includes("content-security-policy") || lower.includes("csp")) {
    return "Define a deployable CSP baseline, test it in report-only mode if needed, then enforce it on the edge or app response.";
  }
  if (lower.includes("header")) {
    return "Set the missing or weak browser security headers at the edge, reverse proxy, or application response layer.";
  }
  if (owner === "dns") {
    return "Update DNS/provider configuration, then rescan once records have propagated.";
  }
  if (lower.includes("cookie")) {
    return "Adjust application cookie attributes for session-sensitive cookies and verify the Set-Cookie response.";
  }
  if (lower.includes("certificate") || lower.includes("tls")) {
    return "Review certificate issuance, renewal, and TLS termination configuration on the serving edge.";
  }
  if (owner === "third_party") {
    return "Confirm ownership, data handling, and necessity for the observed third-party surface.";
  }
  return "Review the finding, apply the smallest safe configuration change, then rescan the same URL.";
}

function verifyFor(owner: RemediationOwner) {
  if (owner === "dns") return "Rescan after DNS propagation and confirm Domain & Trust findings are reduced.";
  if (owner === "third_party") return "Rescan and confirm the vendor signal is either disclosed, justified, or removed.";
  return "Rescan the target and confirm the related finding is resolved or downgraded.";
}

function itemFromDriver(driver: ScoreDriver, analysis: AnalysisResult, priority: number): RemediationPlanItem {
  const issues = normalizeArray(analysis.issues);
  const owner = ownerForArea(driver.areaKey);
  const relatedFindings = relatedFindingsForDriver(driver, issues);
  return {
    id: slug(`${driver.areaKey}-${driver.label}`),
    priority,
    title: driver.label,
    detail: driver.detail,
    owner,
    effort: effortFor(owner, driver.label),
    impact: impactFromScore(driver.impact),
    action: actionFor(owner, driver.label, driver.detail),
    verify: verifyFor(owner),
    scoreImpact: driver.impact,
    relatedFindings,
    evidence: [{
      kind: evidenceKindForScoreSource(driver.source),
      label: driver.areaLabel,
      observed: driver.detail,
      source: driver.source,
    }],
  };
}

function itemFromIssue(issue: ScanIssue, analysis: AnalysisResult, priority: number): RemediationPlanItem {
  const owner = ownerForArea(issue.area);
  return {
    id: slug(`${issue.area}-${issue.title}`),
    priority,
    title: issue.title,
    detail: issue.detail,
    owner,
    effort: effortFor(owner, issue.title),
    impact: impactFromScore(null, issue),
    action: actionFor(owner, issue.title, issue.detail),
    verify: verifyFor(owner),
    scoreImpact: null,
    relatedFindings: [issue.title],
    evidence: buildIssueEvidence(issue, analysis),
  };
}

export function buildPostureRemediationPlan(analysis: AnalysisResult, { limit = 10 } = {}): RemediationPlan {
  const issues = normalizeArray(analysis.issues);
  const driverItems = normalizeArray(analysis.scoreDrivers)
    .filter((driver) => driver.impact > 0)
    .map((driver, index) => itemFromDriver(driver, analysis, index + 1));

  const existingTitles = new Set(driverItems.map((item) => item.title.toLowerCase()));
  const issueItems = issues
    .filter((issue) => !existingTitles.has(issue.title.toLowerCase()))
    .sort((left, right) => issueSeverityRank(left) - issueSeverityRank(right) || left.title.localeCompare(right.title))
    .map((issue, index) => itemFromIssue(issue, analysis, driverItems.length + index + 1));

  const deduped: RemediationPlanItem[] = [];
  const seen = new Set<string>();
  for (const item of [...driverItems, ...issueItems]) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    deduped.push({ ...item, priority: deduped.length + 1 });
    if (deduped.length >= limit) break;
  }

  const highImpactActions = deduped.filter((item) => item.impact === "high").length;
  const quickWins = deduped.filter((item) => item.effort === "low").length;

  return {
    generatedAt: new Date().toISOString(),
    summary: deduped.length
      ? `${deduped.length} prioritized remediation action${deduped.length === 1 ? "" : "s"} generated from score drivers and findings.`
      : "No remediation actions were generated from the current passive evidence.",
    totalActions: deduped.length,
    highImpactActions,
    quickWins,
    items: deduped,
  };
}
