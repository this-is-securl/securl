import type { AnalysisResult, CertificateResult, CookieResult, RedirectHop, ScoreDriver, SecurityHeaderResult } from "./types.js";

export type PostureAreaKey = "edge" | "content" | "domain" | "exposure" | "api" | "trust" | "ai";

export interface PostureAreaScore {
  key: PostureAreaKey;
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
}

type PostureScoringInput = Omit<AnalysisResult, "executiveSummary"> & {
  executiveSummary?: AnalysisResult["executiveSummary"];
};

const HEADER_PENALTY: Record<string, { missing: number; warning: number }> = {
  "strict-transport-security": { missing: 10, warning: 4 },
  "content-security-policy": { missing: 12, warning: 4 },
  "x-frame-options": { missing: 3, warning: 2 },
  "x-content-type-options": { missing: 4, warning: 2 },
  "referrer-policy": { missing: 3, warning: 2 },
  "permissions-policy": { missing: 1, warning: 1 },
  "cross-origin-opener-policy": { missing: 1, warning: 1 },
  "cross-origin-resource-policy": { missing: 1, warning: 1 },
};

const POSTURE_WEIGHTS: Record<PostureAreaKey, number> = {
  edge: 0.25,
  content: 0.2,
  domain: 0.2,
  exposure: 0.15,
  api: 0.1,
  trust: 0.05,
  ai: 0.05,
};
// A site with no public AI/automation surface has no AI weakness to score, so
// the AI area is treated as fully neutral (no penalty) when nothing is detected.
const AI_NEUTRAL_NO_SURFACE_PENALTY = 0;
// Cap the per-area contribution of fetched-page (HTML) findings so a handful of
// common low-severity findings (inline scripts, partial SRI) can't zero out the
// whole content area. CSP remains the dominant content-security driver.
const HTML_FINDINGS_PENALTY_CAP = 30;

// Penalty for the non-CSP "edge" headers, weighted by the per-header severity the
// codebase already declares in HEADER_PENALTY. This keeps the posture scorer
// consistent with scoreAnalysis: universally-omitted low-value headers
// (COOP/CORP/Permissions-Policy = 1 each) cost far less than genuinely important
// ones (HSTS = 10), instead of a flat rate that punished every site equally.
const edgeHeaderPenaltyFor = (
  findings: SecurityHeaderResult[],
  status: "missing" | "warning",
) =>
  findings
    .filter((header) => header.status === status)
    .reduce((sum, header) => {
      const weights = HEADER_PENALTY[header.key] ?? { missing: 4, warning: 2 };
      return sum + (status === "missing" ? weights.missing : weights.warning);
    }, 0);

const HOSTED_PLATFORM_SUFFIXES = [
  ".up.railway.app",
  ".vercel.app",
  ".netlify.app",
  ".pages.dev",
  ".onrender.com",
  ".fly.dev",
  ".herokuapp.com",
  ".github.io",
];

const clamp = (value: number) => Math.max(0, Math.min(100, value));

const isHostedPlatformTarget = (analysis: PostureScoringInput) => {
  let hostname = "";
  try {
    hostname = new URL(analysis.finalUrl).hostname.toLowerCase();
  } catch {
    return false;
  }

  if (HOSTED_PLATFORM_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    return true;
  }

  return analysis.infrastructure?.providers?.some((provider) =>
    provider.category === "paas"
    && ["Vercel", "Netlify", "Heroku"].includes(provider.provider),
  ) ?? false;
};

const severeAssessmentCaps: Record<
  NonNullable<PostureScoringInput["assessmentLimitation"]["kind"]>,
  { default: number; domain: number }
> = {
  blocked_edge_response: { default: 59, domain: 78 },
  auth_required: { default: 59, domain: 78 },
  rate_limited: { default: 54, domain: 74 },
  service_unavailable: { default: 35, domain: 72 },
  other: { default: 59, domain: 74 },
};

const statusAvailabilityPenalty = (statusCode?: number) => {
  if (!statusCode) return 0;
  if (statusCode >= 500) return 35;
  if (statusCode === 429) return 20;
  return 0;
};

const limitedAssessmentScoreCap = (kind: PostureScoringInput["assessmentLimitation"]["kind"]) => {
  if (kind === "service_unavailable") return 49;
  if (kind === "rate_limited") return 59;
  return 64;
};

const trustWeaknessScoreCap = (areaScores: PostureAreaScore[]) => {
  const domainArea = areaScores.find((area) => area.key === "domain");
  if (!domainArea || domainArea.score >= 65) {
    return null;
  }

  return {
    cap: domainArea.score < 45 ? 79 : 89,
  };
};

const cappedAreaScore = (
  areaKey: PostureAreaKey,
  score: number,
  assessmentLimitation: PostureScoringInput["assessmentLimitation"],
) => {
  if (!assessmentLimitation.limited || !assessmentLimitation.kind) {
    return score;
  }

  const caps = severeAssessmentCaps[assessmentLimitation.kind];
  return Math.min(score, areaKey === "domain" ? caps.domain : caps.default);
};

const statusForScore = (score: number): PostureAreaScore["status"] => {
  if (score >= 85) return "strong";
  if (score >= 65) return "watch";
  return "weak";
};

const AREA_LABELS: Record<PostureAreaKey | "overall", string> = {
  edge: "Edge Security",
  content: "Content Security",
  domain: "Domain & Trust",
  exposure: "Exposure Control",
  api: "API Surface",
  trust: "Third-Party Trust",
  ai: "AI & Automation",
  overall: "Overall posture",
};

const scoreDriver = (
  areaKey: ScoreDriver["areaKey"],
  impact: number,
  label: string,
  detail: string,
  source: ScoreDriver["source"],
): ScoreDriver | null => {
  if (impact <= 0) {
    return null;
  }

  return {
    areaKey,
    areaLabel: AREA_LABELS[areaKey],
    impact,
    label,
    detail,
    source,
  };
};

export function gradeForScore(score: number): string {
  if (score >= 97) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function gradeForPostureScore(
  score: number,
  assessmentLimitation: PostureScoringInput["assessmentLimitation"],
): string {
  if (assessmentLimitation.limited) {
    return "U";
  }

  return gradeForScore(score);
}

export function scoreAnalysis({
  isHttps,
  headerResults,
  certificate,
  cookies,
  redirects,
  limitedResponse = false,
}: {
  isHttps: boolean;
  headerResults: SecurityHeaderResult[];
  certificate: CertificateResult;
  cookies: CookieResult[];
  redirects: RedirectHop[];
  limitedResponse?: boolean;
}): { score: number; grade: string } {
  let score = 100;

  if (!isHttps) {
    score -= 35;
  }

  for (const header of headerResults) {
    const weights = HEADER_PENALTY[header.key] || { missing: 4, warning: 2 };
    if (header.status === "missing") {
      if (!limitedResponse) {
        score -= weights.missing;
      }
    }
    if (header.status === "warning") {
      score -= weights.warning;
    }
  }

  if (certificate.available) {
    if (!certificate.valid) {
      score -= 25;
    }
    if (certificate.protocol && /tlsv1(\.0|\.1)?$/i.test(certificate.protocol)) {
      score -= 15;
    }
    if ((certificate.daysRemaining ?? 365) <= 14) {
      score -= 10;
    }
  }

  const scoredCookies = new Map<string, { secure: boolean; httpOnly: boolean; sameSite: string | null }>();
  for (const cookie of cookies) {
    const expiresAt = cookie.expires ? Date.parse(cookie.expires) : NaN;
    if (!Number.isNaN(expiresAt) && expiresAt <= Date.now()) {
      continue;
    }

    const cookieKey = cookie.name.toLowerCase();
    const existing = scoredCookies.get(cookieKey);
    scoredCookies.set(cookieKey, existing
      ? { secure: existing.secure && cookie.secure, httpOnly: existing.httpOnly && cookie.httpOnly, sameSite: existing.sameSite && cookie.sameSite }
      : { secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite },
    );
  }

  let cookiePenalty = 0;
  if (!limitedResponse) {
    for (const [name, cookie] of scoredCookies.entries()) {
      const isLikelyPreferenceCookie = /(locale|lang|language|country|theme|consent|prefs?|preference|visitor|device|did)/i.test(name);
      let perCookiePenalty = 0;
      if (!cookie.secure) perCookiePenalty += 1;
      if (!cookie.httpOnly && !isLikelyPreferenceCookie) perCookiePenalty += 1;
      if (!cookie.sameSite) perCookiePenalty += 1;
      cookiePenalty += Math.min(perCookiePenalty, 4);
    }
  }
  score -= Math.min(cookiePenalty, 8);

  if (redirects.length > 1) {
    score -= Math.min(redirects.length - 1, 4) * 2;
  }

  if (limitedResponse) {
    score = Math.min(score, 84);
  }

  score = Math.max(0, Math.min(100, score));

  return { score, grade: gradeForScore(score) };
}

export function getPostureAreaScores(analysis: PostureScoringInput): PostureAreaScore[] {
  const hostedPlatformTarget = isHostedPlatformTarget(analysis);
  const cspHeaderFindings = analysis.headers.filter(
    (header) => header.key === "content-security-policy" && header.status !== "present",
  );
  const edgeHeaderFindings = analysis.headers.filter(
    (header) => header.key !== "content-security-policy" && header.status !== "present",
  );
  const edgeMissingPenalty = edgeHeaderPenaltyFor(edgeHeaderFindings, "missing");
  const edgeWarningPenalty = edgeHeaderPenaltyFor(edgeHeaderFindings, "warning");
  const cspHeaderIssueCount = cspHeaderFindings.length;
  const cookieIssueCount = analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0);
  const htmlPenalty = Math.min(analysis.htmlSecurity.issues.length * 10, HTML_FINDINGS_PENALTY_CAP);
  const redirectPenalty = analysis.redirects.length > 1 ? Math.max(analysis.redirects.length - 1, 0) * 2 : 0;
  const availabilityPenalty = statusAvailabilityPenalty(analysis.statusCode);
  const transportPenalty = new URL(analysis.finalUrl).protocol === "https:" ? 0 : 35;
  const certificatePenalty =
    analysis.certificate.available && !analysis.certificate.valid
      ? 25
      : analysis.certificate.protocol && /tlsv1(\.0|\.1)?$/i.test(analysis.certificate.protocol)
        ? 15
        : (analysis.certificate.daysRemaining ?? 365) <= 14
          ? 10
          : 0;

  const edgePenalty =
    transportPenalty +
    certificatePenalty +
    edgeMissingPenalty +
    edgeWarningPenalty +
    analysis.corsSecurity.issues.length * 8 +
    availabilityPenalty +
    redirectPenalty;

  const contentPenalty =
    cspHeaderIssueCount * 18 +
    htmlPenalty +
    cookieIssueCount * 6;

  const domainPenaltyRaw =
    analysis.domainSecurity.issues.length * 8 +
    analysis.securityTxt.issues.length * 5 +
    analysis.publicSignals.issues.length * 4;
  const domainPenalty = hostedPlatformTarget ? Math.min(domainPenaltyRaw, 30) : domainPenaltyRaw;

  const exposurePenalty =
    analysis.exposure.issues.length * 20 +
    analysis.exposure.probes.filter((probe) => probe.finding === "interesting").length * 4;

  const apiPenalty =
    analysis.apiSurface.issues.length * 15 +
    analysis.apiSurface.probes.filter((probe) => probe.classification === "interesting").length * 4;

  const trustPenalty =
    analysis.thirdPartyTrust.highRiskProviders * 10 +
    analysis.thirdPartyTrust.issues.length * 6;

  const aiPenalty =
    (!analysis.aiSurface.detected ? AI_NEUTRAL_NO_SURFACE_PENALTY : 0) +
    analysis.aiSurface.issues.length * 12 +
    (analysis.aiSurface.detected && !analysis.aiSurface.disclosures.length ? 8 : 0);

  const areas: Array<Omit<PostureAreaScore, "status">> = [
    { key: "edge", label: "Edge Security", score: cappedAreaScore("edge", clamp(100 - edgePenalty), analysis.assessmentLimitation) },
    { key: "content", label: "Content Security", score: cappedAreaScore("content", clamp(100 - contentPenalty), analysis.assessmentLimitation) },
    { key: "domain", label: "Domain & Trust", score: cappedAreaScore("domain", clamp(100 - domainPenalty), analysis.assessmentLimitation) },
    { key: "exposure", label: "Exposure Control", score: cappedAreaScore("exposure", clamp(100 - exposurePenalty), analysis.assessmentLimitation) },
    { key: "api", label: "API Surface", score: cappedAreaScore("api", clamp(100 - apiPenalty), analysis.assessmentLimitation) },
    { key: "trust", label: "Third-Party Trust", score: cappedAreaScore("trust", clamp(100 - trustPenalty), analysis.assessmentLimitation) },
    { key: "ai", label: "AI & Automation", score: cappedAreaScore("ai", clamp(100 - aiPenalty), analysis.assessmentLimitation) },
  ];

  return areas.map((area) => ({
    ...area,
    status: statusForScore(area.score),
  }));
}

export function getPostureScoreDrivers(analysis: PostureScoringInput): ScoreDriver[] {
  const hostedPlatformTarget = isHostedPlatformTarget(analysis);
  const cspHeaderFindings = analysis.headers.filter(
    (header) => header.key === "content-security-policy" && header.status !== "present",
  );
  const edgeHeaderFindings = analysis.headers.filter(
    (header) => header.key !== "content-security-policy" && header.status !== "present",
  );
  const missingHeaderCount = edgeHeaderFindings.filter((header) => header.status === "missing").length;
  const warningHeaderCount = edgeHeaderFindings.filter((header) => header.status === "warning").length;
  const edgeMissingPenalty = edgeHeaderPenaltyFor(edgeHeaderFindings, "missing");
  const edgeWarningPenalty = edgeHeaderPenaltyFor(edgeHeaderFindings, "warning");
  const htmlPenalty = Math.min(analysis.htmlSecurity.issues.length * 10, HTML_FINDINGS_PENALTY_CAP);
  const cookieIssueCount = analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0);
  const redirectPenalty = analysis.redirects.length > 1 ? Math.max(analysis.redirects.length - 1, 0) * 2 : 0;
  const availabilityPenalty = statusAvailabilityPenalty(analysis.statusCode);
  const transportPenalty = new URL(analysis.finalUrl).protocol === "https:" ? 0 : 35;
  const certificatePenalty =
    analysis.certificate.available && !analysis.certificate.valid
      ? 25
      : analysis.certificate.protocol && /tlsv1(\.0|\.1)?$/i.test(analysis.certificate.protocol)
        ? 15
        : (analysis.certificate.daysRemaining ?? 365) <= 14
          ? 10
          : 0;
  const domainPenaltyRaw =
    analysis.domainSecurity.issues.length * 8 +
    analysis.securityTxt.issues.length * 5 +
    analysis.publicSignals.issues.length * 4;
  const domainPenalty = hostedPlatformTarget ? Math.min(domainPenaltyRaw, 30) : domainPenaltyRaw;
  const highRiskThirdPartyPenalty = analysis.thirdPartyTrust.highRiskProviders * 10;
  const thirdPartyIssuePenalty = analysis.thirdPartyTrust.issues.length * 6;
  const absentAiPenalty = !analysis.aiSurface.detected ? AI_NEUTRAL_NO_SURFACE_PENALTY : 0;
  const missingAiDisclosurePenalty = analysis.aiSurface.detected && !analysis.aiSurface.disclosures.length ? 8 : 0;

  return [
    scoreDriver("edge", transportPenalty, "Plain HTTP final URL", "The final URL did not use HTTPS, which heavily reduces edge-security confidence.", "tls"),
    scoreDriver("edge", certificatePenalty, "TLS certificate or protocol issue", "The observed TLS posture was invalid, outdated, or close to expiry.", "tls"),
    scoreDriver("edge", edgeMissingPenalty, "Missing edge headers", `${missingHeaderCount} non-CSP browser-facing protection${missingHeaderCount === 1 ? " is" : "s are"} missing.`, "headers"),
    scoreDriver("edge", edgeWarningPenalty, "Weak edge header values", `${warningHeaderCount} non-CSP browser-facing protection${warningHeaderCount === 1 ? " has" : "s have"} warning-level configuration.`, "headers"),
    scoreDriver("edge", analysis.corsSecurity.issues.length * 8, "CORS configuration findings", `${analysis.corsSecurity.issues.length} CORS finding${analysis.corsSecurity.issues.length === 1 ? "" : "s"} reduced edge confidence.`, "headers"),
    scoreDriver("edge", availabilityPenalty, "Availability status penalty", `The target returned HTTP ${analysis.statusCode}, limiting confidence in the observed posture.`, "availability"),
    scoreDriver("edge", redirectPenalty, "Redirect chain penalty", `The scan followed ${analysis.redirects.length - 1} redirect${analysis.redirects.length === 2 ? "" : "s"} before the final response.`, "headers"),
    scoreDriver("content", cspHeaderFindings.length * 18, "Content-Security-Policy gap", "CSP is missing or weak, which is the largest content-security driver.", "headers"),
    scoreDriver("content", htmlPenalty, "HTML security findings", `${analysis.htmlSecurity.issues.length} fetched-page finding${analysis.htmlSecurity.issues.length === 1 ? "" : "s"} affected content-security confidence.`, "html"),
    scoreDriver("content", cookieIssueCount * 6, "Cookie attribute findings", `${cookieIssueCount} cookie attribute finding${cookieIssueCount === 1 ? "" : "s"} affected content-security confidence.`, "cookies"),
    scoreDriver("domain", domainPenalty, "Domain and public-trust findings", `${analysis.domainSecurity.issues.length + analysis.securityTxt.issues.length + analysis.publicSignals.issues.length} domain, disclosure, or public-trust signal${analysis.domainSecurity.issues.length + analysis.securityTxt.issues.length + analysis.publicSignals.issues.length === 1 ? "" : "s"} reduced trust confidence${hostedPlatformTarget && domainPenaltyRaw > domainPenalty ? " after hosted-platform softening" : ""}.`, "dns"),
    scoreDriver("exposure", analysis.exposure.issues.length * 20, "Exposed sensitive path findings", `${analysis.exposure.issues.length} exposure finding${analysis.exposure.issues.length === 1 ? "" : "s"} had high score impact.`, "public_record"),
    scoreDriver("exposure", analysis.exposure.probes.filter((probe) => probe.finding === "interesting").length * 4, "Interesting exposure probes", "Public discovery or sensitive-looking paths produced review-worthy responses.", "public_record"),
    scoreDriver("api", analysis.apiSurface.issues.length * 15, "API surface findings", `${analysis.apiSurface.issues.length} API surface finding${analysis.apiSurface.issues.length === 1 ? "" : "s"} reduced API confidence.`, "public_record"),
    scoreDriver("api", analysis.apiSurface.probes.filter((probe) => probe.classification === "interesting").length * 4, "Interesting API probes", "API-like paths produced review-worthy responses.", "public_record"),
    scoreDriver("trust", highRiskThirdPartyPenalty, "High-risk third-party providers", `${analysis.thirdPartyTrust.highRiskProviders} higher-risk third-party integration${analysis.thirdPartyTrust.highRiskProviders === 1 ? "" : "s"} affected trust confidence.`, "third_party"),
    scoreDriver("trust", thirdPartyIssuePenalty, "Third-party trust findings", `${analysis.thirdPartyTrust.issues.length} third-party trust finding${analysis.thirdPartyTrust.issues.length === 1 ? "" : "s"} affected trust confidence.`, "third_party"),
    scoreDriver("ai", absentAiPenalty, "No visible AI surface", "No public AI or automation surface was detected; this is scored as strong-neutral rather than perfect assurance.", "ai"),
    scoreDriver("ai", analysis.aiSurface.issues.length * 12, "AI and automation findings", `${analysis.aiSurface.issues.length} AI or automation finding${analysis.aiSurface.issues.length === 1 ? "" : "s"} reduced confidence.`, "ai"),
    scoreDriver("ai", missingAiDisclosurePenalty, "AI disclosure gap", "AI or automation signals were detected without obvious disclosure language.", "ai"),
  ]
    .filter((driver): driver is ScoreDriver => Boolean(driver))
    .sort((left, right) => right.impact - left.impact)
    .slice(0, 8);
}

export function scorePostureAnalysis(analysis: PostureScoringInput): { score: number; grade: string; scoreDrivers: ScoreDriver[] } {
  const areaScores = getPostureAreaScores(analysis);
  const weakAreaCount = areaScores.filter((area) => area.score < 65).length;
  const watchAreaCount = areaScores.filter((area) => area.score >= 65 && area.score < 85).length;
  const breadthPenalty = Math.max(0, weakAreaCount - 1) * 4 + Math.min(watchAreaCount, 2) * 2;
  const weightedScore = Math.round(
    areaScores.reduce((total, area) => total + area.score * POSTURE_WEIGHTS[area.key], 0),
  );
  const adjustedScore = clamp(weightedScore - breadthPenalty);
  const trustCap = trustWeaknessScoreCap(areaScores);
  const cappedScore = trustCap ? Math.min(adjustedScore, trustCap.cap) : adjustedScore;
  const score = analysis.assessmentLimitation.limited
    ? Math.min(cappedScore, limitedAssessmentScoreCap(analysis.assessmentLimitation.kind))
    : cappedScore;
  const drivers = getPostureScoreDrivers(analysis);
  const breadthDriver = scoreDriver(
    "overall",
    breadthPenalty,
    "Multiple weak or watch areas",
    "The final score includes a breadth penalty because findings are spread across several posture areas.",
    "breadth",
  );
  const limitedDriver = analysis.assessmentLimitation.limited
    ? scoreDriver(
        "overall",
        Math.max(1, adjustedScore - score),
        "Limited assessment score cap",
        "The target could not be assessed cleanly, so the score is capped and the grade is marked unscored.",
        "assessment_limit",
      )
    : null;
  const trustCapDriver = trustCap && adjustedScore > trustCap.cap
    ? scoreDriver(
        "overall",
        adjustedScore - trustCap.cap,
        "Weak domain trust score cap",
        "Domain & Trust is weak, so the overall posture cannot be graded as A-level even when browser-facing headers are strong.",
        "dns",
      )
    : null;

  return {
    score,
    grade: gradeForPostureScore(score, analysis.assessmentLimitation),
    scoreDrivers: [...drivers, breadthDriver, trustCapDriver, limitedDriver]
      .filter((driver): driver is ScoreDriver => Boolean(driver))
      .sort((left, right) => right.impact - left.impact)
      .slice(0, 8),
  };
}

export function summarizePostureGrade(grade: string): string {
  if (grade === "U") {
    return "Assessment confidence is limited, so this result should be treated as directional rather than a full posture read.";
  }
  if (grade === "A+" || grade === "A") {
    return "External posture looks strong across the main passive checks.";
  }
  if (grade === "B") {
    return "External posture is broadly sound, with a few posture areas still worth tightening.";
  }
  if (grade === "C") {
    return "External posture is mixed, with meaningful gaps across one or more posture areas.";
  }
  return "External posture needs work before this would count as well hardened.";
}
