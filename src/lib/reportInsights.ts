import { AnalysisResult, MitreRelevance, OwaspCategory } from "@/types/analysis";

export interface InsightBucket<T extends string> {
  label: T;
  count: number;
}

export interface ThemeDetail<T extends string> extends InsightBucket<T> {
  summary: string;
  whyItMatters: string;
  examples: string[];
}

export interface DisclosurePosture {
  summary: string;
  strengths: string[];
  issues: string[];
  discoveredPages: string[];
}

const PATH_LABELS = [
  { pattern: /\/privacy/i, label: "Privacy" },
  { pattern: /\/terms|\/legal|\/acceptable-use/i, label: "Terms" },
  { pattern: /\/security|\/trust|\/responsible-ai/i, label: "Security" },
  { pattern: /\/contact|\/support/i, label: "Contact" },
  { pattern: /\/accessibility/i, label: "Accessibility" },
] as const;

const countByLabel = <T extends string>(labels: T[]) => {
  const counts = new Map<T, number>();
  for (const label of labels) {
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([label, count]) => ({ label, count }));
};

const OWASP_EXPLAINERS: Record<
  OwaspCategory,
  {
    summary: string;
    whyItMatters: string;
  }
> = {
  "A01 Broken Access Control": {
    summary: "The visible surface suggests some publicly reachable or overexposed routes and resources deserve boundary review.",
    whyItMatters: "Even passive exposure clues can point to routes or assets that should be more tightly constrained before deeper testing starts.",
  },
  "A02 Cryptographic Failures": {
    summary: "Transport and trust controls are showing weakness through TLS, HTTPS, certificate, or secure-cookie posture.",
    whyItMatters: "Weak transport controls can expose sessions, weaken browser trust, and make downstream application protections less meaningful.",
  },
  "A03 Injection": {
    summary: "Browser-side content controls are permissive enough that injection resistance may be weaker than it should be.",
    whyItMatters: "Loose CSP or inline execution patterns increase the blast radius if any script-injection issue exists elsewhere in the stack.",
  },
  "A05 Security Misconfiguration": {
    summary: "Most visible issues are hardening or configuration gaps rather than evidence of an application-specific exploit path.",
    whyItMatters: "This is often the fastest class of weakness to improve and usually gives the biggest posture lift for the least engineering effort.",
  },
  "A06 Vulnerable and Outdated Components": {
    summary: "Visible client-side libraries or dependency clues suggest a component hygiene issue that deserves version and advisory review.",
    whyItMatters: "Publicly fingerprintable outdated components can turn passive surface intelligence into very actionable attacker guidance.",
  },
  "A07 Identification and Authentication Failures": {
    summary: "Session, cookie, and authentication-adjacent behavior is more exposed or weaker than ideal.",
    whyItMatters: "Authentication posture shapes how much confidence you can place in session integrity and user-boundary controls.",
  },
};

const MITRE_EXPLAINERS: Record<
  MitreRelevance,
  {
    summary: string;
    whyItMatters: string;
  }
> = {
  Reconnaissance: {
    summary: "The site exposes information that makes external mapping and fingerprinting easier.",
    whyItMatters: "Attackers usually start by learning the shape of the surface; reducing public clues lowers that early advantage.",
  },
  "Initial Access": {
    summary: "Some findings could make the external surface easier to approach or abuse as a first foothold.",
    whyItMatters: "These are the signals most likely to matter before authentication or deeper exploitation even begins.",
  },
  "Credential Access": {
    summary: "The visible surface includes session, password, or cookie clues that relate to how credentials could be exposed or mishandled.",
    whyItMatters: "Anything that weakens session or credential handling tends to have outsized operational impact.",
  },
  Collection: {
    summary: "Some browser or page behaviors could increase unintended data leakage or collection opportunities.",
    whyItMatters: "These issues often matter for privacy, telemetry, and post-auth data handling even when they are not headline security bugs.",
  },
  "Defense Evasion": {
    summary: "Certain controls are weak or absent in ways that could make abusive behavior harder to contain or detect at the browser boundary.",
    whyItMatters: "Easier evasion means other controls may need to work harder to compensate for weaker client-facing safeguards.",
  },
};

export const getOwaspSummary = (analysis: AnalysisResult): InsightBucket<OwaspCategory>[] =>
  countByLabel(analysis.issues.flatMap((issue) => issue.owasp)) as InsightBucket<OwaspCategory>[];

export const getMitreSummary = (analysis: AnalysisResult): InsightBucket<MitreRelevance>[] =>
  countByLabel(analysis.issues.flatMap((issue) => issue.mitre)) as InsightBucket<MitreRelevance>[];

const buildThemeDetails = <T extends string>(
  buckets: InsightBucket<T>[],
  analysis: AnalysisResult,
  explainers: Record<string, { summary: string; whyItMatters: string }>,
  matcher: (label: T) => (issue: AnalysisResult["issues"][number]) => boolean,
): ThemeDetail<T>[] =>
  buckets.map((bucket) => {
    const explainer = explainers[bucket.label] || {
      summary: "This theme was inferred from the current finding set.",
      whyItMatters: "It helps group related issues into a more operational posture readout.",
    };
    const examples = analysis.issues
      .filter(matcher(bucket.label))
      .slice(0, 3)
      .map((issue) => issue.title);

    return {
      ...bucket,
      summary: explainer.summary,
      whyItMatters: explainer.whyItMatters,
      examples,
    };
  });

export const getDominantThemes = (analysis: AnalysisResult) => {
  const owaspBuckets = getOwaspSummary(analysis).slice(0, 3);
  const mitreBuckets = getMitreSummary(analysis).slice(0, 3);
  const owasp = buildThemeDetails(
    owaspBuckets,
    analysis,
    OWASP_EXPLAINERS,
    (label) => (issue) => issue.owasp.includes(label),
  );
  const mitre = buildThemeDetails(
    mitreBuckets,
    analysis,
    MITRE_EXPLAINERS,
    (label) => (issue) => issue.mitre.includes(label),
  );
  const dominantOwasp = owasp[0]?.label || "A05 Security Misconfiguration";

  const summary =
    dominantOwasp === "A05 Security Misconfiguration"
      ? "Most visible issues are configuration and hardening gaps rather than application-specific exploit signals."
      : dominantOwasp === "A02 Cryptographic Failures"
        ? "Transport and cryptographic posture is the main visible weakness."
        : dominantOwasp === "A07 Identification and Authentication Failures"
          ? "Session and authentication-adjacent signals are more prominent than average."
          : "The visible issue mix spans several classes rather than one obvious dominant theme.";

  return {
    summary,
    owasp,
    mitre,
  };
};

export const getDisclosurePosture = (analysis: AnalysisResult): DisclosurePosture => {
  const firstPartyPaths = analysis.htmlSecurity.firstPartyPaths || [];
  const discoveredPages = PATH_LABELS.filter((item) =>
    firstPartyPaths.some((path) => item.pattern.test(path)),
  ).map((item) => item.label);

  const strengths: string[] = [];
  const issues: string[] = [];

  if (analysis.securityTxt.status === "present_valid") {
    strengths.push("A valid security.txt disclosure route is published.");
  } else {
    issues.push("No valid security.txt disclosure route was detected.");
  }

  if (discoveredPages.includes("Privacy")) {
    strengths.push("A privacy-related page was discovered passively.");
  } else {
    issues.push("No obvious privacy-policy page was discovered from the fetched page.");
  }

  if (discoveredPages.includes("Terms")) {
    strengths.push("A terms or legal page was discovered passively.");
  }

  if (discoveredPages.includes("Contact")) {
    strengths.push("A contact or support path was discovered passively.");
  }

  if (analysis.aiSurface.detected) {
    if (analysis.aiSurface.privacySignals.length || analysis.aiSurface.governanceSignals.length || analysis.aiSurface.disclosures.length) {
      strengths.push("AI-related disclosure or governance language is visible.");
    } else {
      issues.push("AI or automation signals are visible without much supporting disclosure language.");
    }
  }

  const summary =
    strengths.length >= 3 && issues.length <= 1
      ? "Disclosure and trust posture looks relatively transparent from passive signals."
      : strengths.length >= 1
        ? "Some trust and disclosure signals are present, but the public-facing guidance still feels partial."
        : "Public trust and disclosure posture looks thin from passive signals.";

  return {
    summary,
    strengths,
    issues,
    discoveredPages,
  };
};
