import { getAiSurfaceClassificationSummary } from "@/lib/aiSurface";
import { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";
import { getAuthSurfaceSummary, getDataCollectionSummary } from "@/lib/passiveSurface";
import { getPriorityActions } from "@/lib/priorities";
import { getDisclosurePosture, getDominantThemes } from "@/lib/reportInsights";

const escapeHtml = (value: unknown) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const buildExposureLines = (analysis: AnalysisResult) =>
  analysis.exposure.probes.map(
    (probe) => `- ${probe.label} (${probe.path}): ${probe.finding} (${probe.statusCode}) - ${probe.detail}`,
  );

const buildTechnologyLines = (analysis: AnalysisResult) =>
  analysis.technologies.length
    ? analysis.technologies.map(
        (tech) =>
          `- ${tech.name} (${tech.category}, ${tech.detection}, ${tech.confidence} confidence)${tech.evidence ? `: ${tech.evidence}` : ""}`,
      )
    : ["- No stack signals recorded."];

const buildDiscoveryLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.firstPartyPaths.length
    ? analysis.htmlSecurity.firstPartyPaths.map((path) => `- Path: ${path}`)
    : ["- No same-origin paths discovered from the fetched page."];

const buildSameSiteHostLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.sameSiteHosts.length
    ? analysis.htmlSecurity.sameSiteHosts.map((host) => `- Host: ${host}`)
    : ["- No sibling same-site hosts were referenced by the fetched page."];

const buildPassiveLeakLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.passiveLeakSignals.length
    ? analysis.htmlSecurity.passiveLeakSignals.map(
        (signal) => `- [${signal.severity}] ${signal.title}: ${signal.detail}${signal.evidence.length ? ` Evidence: ${signal.evidence.join(", ")}` : ""}`,
      )
    : ["- No passive leak or fingerprinting signals recorded."];

const buildLibraryRiskLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.libraryRiskSignals.length
    ? analysis.htmlSecurity.libraryRiskSignals.flatMap((signal) => [
        `- ${signal.packageName} ${signal.version} (${signal.confidence} confidence)`,
        `  Source: ${signal.sourceUrl}`,
        ...signal.vulnerabilities.map(
          (item) =>
            `  - ${item.id}${item.aliases.length ? ` [${item.aliases.join(", ")}]` : ""} (${item.severity}): ${item.summary}`,
        ),
      ])
    : analysis.htmlSecurity.libraryFingerprints.length
      ? ["- Explicitly versioned client libraries were detected, but no OSV advisory matches were returned."]
      : ["- No explicit versioned client-library fingerprints were detected."];

const buildThirdPartyLines = (analysis: AnalysisResult) =>
  analysis.thirdPartyTrust.providers.length
    ? analysis.thirdPartyTrust.providers.map(
        (provider) => `- ${provider.name} [${provider.category} | ${provider.risk} risk] ${provider.domain}`,
      )
    : ["- No third-party providers recorded."];

const buildCtLines = (analysis: AnalysisResult) =>
  analysis.ctDiscovery.subdomains.length
    ? analysis.ctDiscovery.subdomains.map((host) => `- ${host}`)
    : ["- No CT-discovered subdomains recorded."];

const buildCtSampleLines = (analysis: AnalysisResult) =>
  analysis.ctDiscovery.sampledHosts.length
    ? analysis.ctDiscovery.sampledHosts.map(
        (host) =>
          `- ${host.host} [${host.priority} ${host.category}] ${host.reachable ? `${host.statusCode} ${host.responseKind}` : "unreachable"}: ${host.note}`,
      )
    : ["- No CT sampled hosts recorded."];

const buildWafLines = (analysis: AnalysisResult) =>
  analysis.wafFingerprint.providers.length
    ? analysis.wafFingerprint.providers.map(
        (provider) => `- ${provider.name} (${provider.detection}, ${provider.confidence} confidence): ${provider.evidence}`,
      )
    : ["- No branded WAF or edge provider was conclusively identified."];

const buildThemeMarkdownLines = (
  labelPrefix: "OWASP" | "MITRE",
  themes: Array<{ label: string; count: number; summary: string; whyItMatters: string; examples: string[] }>,
) =>
  themes.length
    ? themes.flatMap((item) => [
        `- ${labelPrefix}: ${item.label} (${item.count})`,
        `  Summary: ${item.summary}`,
        `  Why it matters: ${item.whyItMatters}`,
        ...(item.examples.length ? [`  Driving findings: ${item.examples.join("; ")}`] : []),
      ])
    : [`- No ${labelPrefix}-aligned themes recorded.`];

const severityRank = {
  critical: 0,
  warning: 1,
  info: 2,
} as const;

const sentenceJoin = (items: string[]) => {
  if (items.length <= 1) return items[0] ?? "";
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
};

const shortenEvidence = (value: string, maxLength = 140) =>
  value.length > maxLength ? `${value.slice(0, maxLength - 1).trimEnd()}…` : value;

const getWeakestAreas = (analysis: AnalysisResult, limit = 3) =>
  [...getAreaScores(analysis)]
    .sort((left, right) => left.score - right.score)
    .slice(0, limit);

const getStrongestAreas = (analysis: AnalysisResult, limit = 2) =>
  [...getAreaScores(analysis)]
    .filter((area) => area.score >= 85)
    .sort((left, right) => right.score - left.score)
    .slice(0, limit);

const getTopFindings = (analysis: AnalysisResult, limit = 5) =>
  [...analysis.issues]
    .sort((left, right) => {
      const severityDelta = severityRank[left.severity] - severityRank[right.severity];
      if (severityDelta !== 0) return severityDelta;
      return left.title.localeCompare(right.title);
    })
    .slice(0, limit);

const buildPostureNarrative = (analysis: AnalysisResult, diff: HistoryDiff | null) => {
  const weakestAreas = getWeakestAreas(analysis);
  const strongestAreas = getStrongestAreas(analysis);
  const weakAreaText = weakestAreas.length
    ? sentenceJoin(weakestAreas.map((area) => `${area.label} (${area.score}/100)`))
    : "no obviously weak category";
  const strongAreaText = strongestAreas.length
    ? sentenceJoin(strongestAreas.map((area) => `${area.label} (${area.score}/100)`))
    : "no category that is clearly strong enough to treat as a durable compensating strength";
  const changeText = diff
    ? `Compared with the previous local snapshot, the score moved ${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}; ${diff.newIssues.length} issue${diff.newIssues.length === 1 ? "" : "s"} appeared and ${diff.resolvedIssues.length} resolved.`
    : "No previous local snapshot was available, so this report should be treated as a baseline rather than a trend statement.";

  return [
    `${analysis.host} currently scores ${analysis.grade} (${analysis.score}/100). The clearest visible weakness sits in ${weakAreaText}.`,
    `In practical terms, the current posture suggests ${analysis.executiveSummary.mainRisk.charAt(0).toLowerCase()}${analysis.executiveSummary.mainRisk.slice(1)}`,
    `The stronger areas are ${strongAreaText}. ${changeText}`,
  ];
};

const buildStakeholderQuestions = (analysis: AnalysisResult) => {
  const questions = [
    "Are the missing or weak browser protections intentionally omitted, or should they be enforced at the edge/framework layer?",
  ];

  if (analysis.thirdPartyTrust.totalProviders > 0) {
    questions.push("Are the observed third-party providers covered by vendor review, privacy notice, and change-control expectations?");
  }

  if (analysis.htmlSecurity.forms.length > 0) {
    questions.push("Do the observed forms collect personal, credential, or regulated data, and are their submission paths documented?");
  }

  if (analysis.domainSecurity.issues.length > 0 || analysis.securityTxt.status !== "present") {
    questions.push("Does domain ownership include mail/disclosure controls, or is this target purely web-facing?");
  }

  if (analysis.assessmentLimitation.limited) {
    questions.push("What controls blocked or limited the read, and should the assessment be repeated from an approved user-agent or network?");
  }

  return questions.slice(0, 4);
};

const buildEvidenceForAction = (analysis: AnalysisResult, actionTitle: string) => {
  const normalized = actionTitle.toLowerCase();
  if (normalized.includes("https") || normalized.includes("hsts")) {
    const hsts = analysis.headers.find((header) => header.key === "strict-transport-security");
    return hsts?.value ? `Observed HSTS value: ${shortenEvidence(hsts.value)}` : "Strict-Transport-Security was not present on the scanned response.";
  }
  if (normalized.includes("content security") || normalized.includes("csp")) {
    const csp = analysis.headers.find((header) => header.key === "content-security-policy");
    return csp?.value ? `Observed CSP value: ${shortenEvidence(csp.value)}` : "Content-Security-Policy was not present on the scanned response.";
  }
  if (normalized.includes("third-party")) {
    return `${analysis.thirdPartyTrust.totalProviders} provider${analysis.thirdPartyTrust.totalProviders === 1 ? "" : "s"} detected; ${analysis.thirdPartyTrust.highRiskProviders} marked higher risk.`;
  }
  if (normalized.includes("security.txt")) {
    return `security.txt status: ${analysis.securityTxt.status}.`;
  }
  if (normalized.includes("email") || normalized.includes("dmarc")) {
    const spfPresent = Boolean(analysis.domainSecurity.spf);
    const dmarcPresent = Boolean(analysis.domainSecurity.dmarc);
    const mtaStsPresent = analysis.domainSecurity.mtaSts.dns !== null;
    return `SPF ${spfPresent ? "is present" : "was not found"}, DMARC ${dmarcPresent ? "is present" : "was not found"}, and MTA-STS ${mtaStsPresent ? "is published" : "was not observed"}.`;
  }
  if (normalized.includes("api")) {
    return `${analysis.apiSurface.probes.filter((probe) => probe.classification !== "absent").length} API-style probe${analysis.apiSurface.probes.length === 1 ? "" : "s"} returned a non-absent classification.`;
  }
  if (normalized.includes("leak")) {
    return `${analysis.htmlSecurity.passiveLeakSignals.length} passive leak signal${analysis.htmlSecurity.passiveLeakSignals.length === 1 ? "" : "s"} observed.`;
  }
  return `Related area evidence is included in the detailed sections below.`;
};

const buildAssessmentLimits = (analysis: AnalysisResult) => {
  const limits = [
    "This report is based on an external, unauthenticated, passive-first read. It is useful for posture and governance, but it does not replace authenticated testing or exploitation work.",
  ];

  if (analysis.assessmentLimitation.limited) {
    limits.push(`${analysis.assessmentLimitation.title ?? "The assessment was limited"}: ${analysis.assessmentLimitation.detail ?? "some target responses could not be read cleanly."}`);
  }

  if (!analysis.htmlSecurity.fetched) {
    limits.push("The fetched page body was not available, so client-side and form observations are incomplete.");
  }

  if (!analysis.ctDiscovery.subdomains.length && analysis.ctDiscovery.issues.length > 0) {
    limits.push("Certificate Transparency coverage was incomplete or timed out, so subdomain observations may be understated.");
  }

  return limits;
};

const buildFormLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.forms.length
    ? analysis.htmlSecurity.forms.map((form, index) => {
        const target = form.action || "current page / unspecified action";
        const riskSignals = [
          form.hasPasswordField ? "password field" : null,
          form.insecureSubmission ? "insecure submission" : null,
          /^https?:\/\//i.test(target) && !target.startsWith(new URL(analysis.finalUrl).origin) ? "external target" : null,
        ].filter(Boolean);
        return `- Form ${index + 1}: ${form.method.toUpperCase()} to ${target}${riskSignals.length ? ` (${riskSignals.join(", ")})` : ""}`;
      })
    : ["- No forms were observed on the fetched page."];

const getChangeHeadline = (diff: HistoryDiff | null) =>
  diff
    ? `Score ${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}; ${diff.newIssues.length} new issue${diff.newIssues.length === 1 ? "" : "s"} and ${diff.resolvedIssues.length} resolved.`
    : "No previous local snapshot was available, so this report should be treated as a baseline.";

const buildCategoryTableMarkdown = (areas: ReturnType<typeof getAreaScores>) => [
  "| Area | Score | Status |",
  "| --- | ---: | --- |",
  ...areas.map((area) => `| ${area.label} | ${area.score}/100 | ${area.status} |`),
];

const buildMetricLinesMarkdown = (
  analysis: AnalysisResult,
  diff: HistoryDiff | null,
  summary: ReturnType<typeof getUnifiedIssueSummary>,
  weakestAreas: ReturnType<typeof getWeakestAreas>,
  strongestAreas: ReturnType<typeof getStrongestAreas>,
) => [
  `- Grade: **${analysis.grade}**`,
  `- Score: **${analysis.score}/100**`,
  `- Main visible risk: ${analysis.executiveSummary.mainRisk}`,
  `- Weakest areas: ${weakestAreas.length ? weakestAreas.map((area) => `${area.label} (${area.score}/100)`).join(", ") : "No obvious weak cluster recorded."}`,
  `- Strongest areas: ${strongestAreas.length ? strongestAreas.map((area) => `${area.label} (${area.score}/100)`).join(", ") : "No obviously compensating strengths recorded."}`,
  `- Findings mix: ${summary.critical} critical, ${summary.priorityWarnings} priority warning, ${summary.supportingWatchItems} watch, ${summary.observedSignals} informational signals`,
  `- Change headline: ${getChangeHeadline(diff)}`,
];

const buildDecisionMarkdown = (analysis: AnalysisResult, priorityActions: ReturnType<typeof getPriorityActions>) => [
  "## What to do next",
  "",
  ...(priorityActions.length
    ? priorityActions.flatMap((action, index) => [
        `${index + 1}. **${action.title}**`,
        `   Why it matters: ${action.detail}`,
        `   Evidence: ${buildEvidenceForAction(analysis, action.title)}`,
        ...(action.priorityReason ? [`   Priority rationale: ${action.priorityReason}`] : []),
      ])
    : ["1. No high-priority remediation actions were generated from this scan."]),
  "",
];

const buildNarrativeMarkdown = (
  analysis: AnalysisResult,
  diff: HistoryDiff | null,
  priorityActions: ReturnType<typeof getPriorityActions>,
  areas: ReturnType<typeof getAreaScores>,
  summary: ReturnType<typeof getUnifiedIssueSummary>,
) => {
  const weakestAreas = getWeakestAreas(analysis);
  const strongestAreas = getStrongestAreas(analysis);

  return [
    "## At a glance",
    "",
    ...buildMetricLinesMarkdown(analysis, diff, summary, weakestAreas, strongestAreas),
    "",
    ...buildDecisionMarkdown(analysis, priorityActions),
    "## Why this matters",
    "",
    ...buildPostureNarrative(analysis, diff).map((line) => `- ${line}`),
    "",
    "## Top findings",
    "",
    ...(getTopFindings(analysis).length
      ? getTopFindings(analysis).map((issue) => `- [${issue.severity}] ${issue.title}: ${issue.detail}`)
      : ["- No core findings were recorded."]),
    "",
    "## Analyst prompts",
    "",
    ...buildStakeholderQuestions(analysis).map((question) => `- ${question}`),
    "",
    "## Assessment boundaries",
    "",
    ...buildAssessmentLimits(analysis).map((limit) => `- ${limit}`),
    "",
    "## Category posture",
    "",
    ...buildCategoryTableMarkdown(areas),
    "",
  ];
};

export const buildMarkdownReport = (analysis: AnalysisResult, diff: HistoryDiff | null = null) => {
  const areas = getAreaScores(analysis);
  const summary = getUnifiedIssueSummary(analysis);
  const priorityActions = getPriorityActions(analysis);
  const aiSummary = getAiSurfaceClassificationSummary(analysis.aiSurface);
  const taxonomy = getDominantThemes(analysis);
  const disclosure = getDisclosurePosture(analysis);
  const authSurface = getAuthSurfaceSummary(analysis.htmlSecurity);
  const dataCollection = getDataCollectionSummary(analysis.htmlSecurity);

  return [
    `# Security Report: ${analysis.host}`,
    "",
    `- Final URL: ${analysis.finalUrl}`,
    `- Scanned: ${new Date(analysis.scannedAt).toLocaleString()}`,
    `- Status: ${analysis.statusCode}`,
    "",
    ...buildNarrativeMarkdown(analysis, diff, priorityActions, areas, summary),
    "## Executive readout",
    "",
    `- Overview: ${analysis.executiveSummary.overview}`,
    ...analysis.executiveSummary.takeaways.map((takeaway) => `- ${takeaway}`),
    "",
    "## Findings mix",
    "",
    `- Critical findings: ${summary.critical}`,
    `- Priority warning findings: ${summary.priorityWarnings}`,
    `- Supporting watch items: ${summary.supportingWatchItems}`,
    `- Observed signals: ${summary.observedSignals}`,
    "",
    "## Risk Themes",
    "",
    `- Summary: ${taxonomy.summary}`,
    ...buildThemeMarkdownLines("OWASP", taxonomy.owasp),
    ...buildThemeMarkdownLines("MITRE", taxonomy.mitre),
    "",
    "## Key Findings",
    "",
    ...(analysis.issues.length
      ? analysis.issues.map(
          (issue) =>
            `- [${issue.severity} | ${issue.confidence} confidence | ${issue.source}${issue.owasp.length ? ` | OWASP: ${issue.owasp.join(", ")}` : ""}${issue.mitre.length ? ` | MITRE: ${issue.mitre.join(", ")}` : ""}] ${issue.title}: ${issue.detail}`,
        )
      : ["- No core findings recorded."]),
    "",
    "## Priority Actions for This Target",
    "",
    ...(priorityActions.length
      ? priorityActions.flatMap((action, index) => [
          `- ${index + 1}. [${action.severity}] ${action.title}: ${action.detail}`,
          ...(action.priorityReason ? [`  ${action.priorityReason}`] : []),
        ])
      : ["- No priority actions generated."]),
    "",
    "## Changes since last scan",
    "",
    ...(diff
      ? [
          `- Score delta: ${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}`,
          `- New issues: ${diff.newIssues.length}`,
          `- Resolved issues: ${diff.resolvedIssues.length}`,
          `- Header changes: ${diff.headerChanges.length}`,
          `- New third parties: ${diff.newThirdPartyProviders.length}`,
          `- New AI vendors: ${diff.newAiVendors.length}`,
          `- New WAF signals: ${diff.wafProviderChanges.newProviders.length}`,
          ...(diff.summary.length ? diff.summary.map((item) => `- ${item}`) : ["- No material posture changes summarized."]),
        ]
      : ["- No previous local snapshot available for comparison."]),
    "",
    "## Analyst workbook",
    "",
    "### security.txt",
    "",
    `- Status: ${analysis.securityTxt.status}`,
    ...(analysis.securityTxt.url ? [`- URL: ${analysis.securityTxt.url}`] : []),
    ...(analysis.securityTxt.issues.length ? analysis.securityTxt.issues.map((issue) => `- ${issue}`) : ["- No security.txt issues recorded."]),
    "",
    "### Domain & Email Security",
    "",
    `- SPF: ${analysis.domainSecurity.spf ?? "Not found"}`,
    `- DMARC: ${analysis.domainSecurity.dmarc ?? "Not found"}`,
    `- DNSSEC: ${analysis.domainSecurity.dnssec.status}`,
    `- MX count: ${analysis.domainSecurity.mxRecords.length}`,
    `- CAA count: ${analysis.domainSecurity.caaRecords.length}`,
    "",
    "### Identity Provider & OAuth Surface",
    "",
    `- Detected: ${analysis.identityProvider.detected ? "Yes" : "No"}`,
    `- Provider: ${analysis.identityProvider.provider ?? "Not identified"}`,
    `- Protocol: ${analysis.identityProvider.protocol ?? "Not inferred"}`,
    `- OIDC config: ${analysis.identityProvider.openIdConfigurationUrl ?? "Not observed"}`,
    `- Redirect origins: ${analysis.identityProvider.redirectOrigins.length ? analysis.identityProvider.redirectOrigins.join(", ") : "None recorded"}`,
    `- Auth-like hosts: ${analysis.identityProvider.authHostCandidates.length ? analysis.identityProvider.authHostCandidates.join(", ") : "None recorded"}`,
    `- Login paths: ${analysis.identityProvider.loginPaths.length ? analysis.identityProvider.loginPaths.join(", ") : "None recorded"}`,
    `- Tenant clues: ${analysis.identityProvider.tenantSignals.length ? analysis.identityProvider.tenantSignals.join(", ") : "None recorded"}`,
    ...(analysis.identityProvider.redirectUriSignals.length
      ? analysis.identityProvider.redirectUriSignals.map((signal) => `- Review redirect URI signal: ${signal}`)
      : ["- No public redirect_uri-style parameters were recorded."]),
    "",
    "### Certificate Transparency",
    "",
    `- Queried domain: ${analysis.ctDiscovery.queriedDomain}`,
    `- Coverage summary: ${analysis.ctDiscovery.coverageSummary}`,
    `- Subdomains discovered: ${analysis.ctDiscovery.subdomains.length}`,
    `- Wildcard entries: ${analysis.ctDiscovery.wildcardEntries.length}`,
    ...buildCtLines(analysis),
    ...buildCtSampleLines(analysis),
    ...(analysis.ctDiscovery.sampledHosts.some((host) => host.suspectedTakeover)
      ? analysis.ctDiscovery.sampledHosts
          .filter((host) => host.suspectedTakeover)
          .map((host) => `- Possible takeover: ${host.host} via ${host.suspectedTakeover?.provider} (${host.suspectedTakeover?.confidence} confidence)`)
      : ["- No takeover-style signatures were observed in the sampled CT hosts."]),
    "",
    "### WAF & Edge Fingerprint",
    "",
    `- Summary: ${analysis.wafFingerprint.summary}`,
    ...buildWafLines(analysis),
    ...(analysis.wafFingerprint.edgeSignals.length
      ? analysis.wafFingerprint.edgeSignals.map((signal) => `- Edge evidence: ${signal}`)
      : ["- No extra edge evidence recorded."]),
    "",
    "### Public Trust Signals",
    "",
    `- HSTS preload status: ${analysis.publicSignals.hstsPreload.status}`,
    `- HSTS preload note: ${analysis.publicSignals.hstsPreload.summary}`,
    "",
    "### Disclosure & Trust",
    "",
    `- Summary: ${disclosure.summary}`,
    ...(disclosure.discoveredPages.length
      ? disclosure.discoveredPages.map((page) => `- Discovered page: ${page}`)
      : ["- No obvious trust or policy pages discovered."]),
    ...disclosure.strengths.map((item) => `- ${item}`),
    ...disclosure.issues.map((item) => `- ${item}`),
    "",
    "### Passive Discovery",
    "",
    `- Page title: ${analysis.htmlSecurity.pageTitle ?? "Unavailable"}`,
    `- Discovery sources: ${analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded"}`,
    `- Same-origin paths discovered: ${analysis.htmlSecurity.firstPartyPaths.length}`,
    `- Same-site hosts referenced: ${analysis.htmlSecurity.sameSiteHosts.length}`,
    ...buildDiscoveryLines(analysis),
    ...buildSameSiteHostLines(analysis),
    ...buildPassiveLeakLines(analysis),
    ...buildLibraryRiskLines(analysis),
    "",
    "### Auth Surface",
    "",
    `- Summary: ${authSurface.summary}`,
    `- Auth paths: ${authSurface.authPaths.length}`,
    `- Password forms: ${authSurface.passwordFormCount}`,
    `- External password form targets: ${authSurface.externalPasswordForms.length}`,
    ...(authSurface.authPaths.length
      ? authSurface.authPaths.map((item) => `- ${item.path} (${item.category})`)
      : ["- No auth-adjacent paths discovered passively."]),
    "",
    "### Data Collection Surface",
    "",
    `- Summary: ${dataCollection.summary}`,
    `- Public forms: ${dataCollection.totalForms}`,
    `- POST forms: ${dataCollection.postForms}`,
    `- External form targets: ${dataCollection.externalForms.length}`,
    `- Insecure form submits: ${dataCollection.insecureForms}`,
    ...buildFormLines(analysis),
    ...(dataCollection.externalForms.length
      ? dataCollection.externalForms.map((target) => `- External target: ${target}`)
      : ["- No external form targets were detected."]),
    "",
    "### Detected Stack",
    "",
    ...buildTechnologyLines(analysis),
    "",
    "### Third-Party Trust",
    "",
    `- Providers detected: ${analysis.thirdPartyTrust.totalProviders}`,
    `- Higher-risk providers: ${analysis.thirdPartyTrust.highRiskProviders}`,
    `- Summary: ${analysis.thirdPartyTrust.summary}`,
    ...buildThirdPartyLines(analysis),
    ...(analysis.thirdPartyTrust.issues.length
      ? analysis.thirdPartyTrust.issues.map((issue) => `- ${issue}`)
      : ["- No third-party trust issues recorded."]),
    "",
    "### AI Surface",
    "",
    `- Classification: ${aiSummary}`,
    `- AI detected: ${analysis.aiSurface.detected ? "Yes" : "No"}`,
    `- Assistant visible: ${analysis.aiSurface.assistantVisible ? "Yes" : "No"}`,
    `- Vendors: ${analysis.aiSurface.vendors.length ? analysis.aiSurface.vendors.map((vendor) => vendor.name).join(", ") : "None detected"}`,
    `- AI paths: ${analysis.aiSurface.discoveredPaths.length ? analysis.aiSurface.discoveredPaths.join(", ") : "None detected"}`,
    ...(analysis.aiSurface.privacySignals.length ? analysis.aiSurface.privacySignals.map((signal) => `- ${signal}`) : ["- No explicit AI privacy guidance detected."]),
    ...(analysis.aiSurface.governanceSignals.length ? analysis.aiSurface.governanceSignals.map((signal) => `- ${signal}`) : ["- No explicit AI governance language detected."]),
    ...(analysis.aiSurface.issues.length ? analysis.aiSurface.issues.map((issue) => `- ${issue}`) : ["- No AI-surface issues recorded."]),
    "",
    "### Low-Noise Exposure Checks",
    "",
    ...buildExposureLines(analysis),
    "",
  ].join("\n");
};

export const buildHtmlReport = (analysis: AnalysisResult, diff: HistoryDiff | null = null) => {
  const areas = getAreaScores(analysis);
  const priorityActions = getPriorityActions(analysis);
  const aiSummary = getAiSurfaceClassificationSummary(analysis.aiSurface);
  const disclosure = getDisclosurePosture(analysis);
  const weakestAreas = getWeakestAreas(analysis);
  const strongestAreas = getStrongestAreas(analysis);
  const topFindings = getTopFindings(analysis);
  const changeHeadline = getChangeHeadline(diff);

  const generatedAt = new Date().toLocaleDateString(undefined, { day: "2-digit", month: "long", year: "numeric" });
  const scanDate = new Date(analysis.scannedAt).toLocaleDateString(undefined, { day: "2-digit", month: "long", year: "numeric" });

  const gradeColor =
    analysis.grade === "A+" || analysis.grade === "A" ? "#16a34a"
    : analysis.grade === "B" ? "#2563eb"
    : analysis.grade === "C" ? "#d97706"
    : analysis.grade === "D" ? "#ea580c"
    : analysis.grade === "F" ? "#dc2626"
    : "#94a3b8";

  const gradeFontSize = analysis.grade.length > 1 ? 50 : 66;

  const ringCirc = parseFloat((2 * Math.PI * 90).toFixed(2));
  const ringOffset = parseFloat((ringCirc * (1 - analysis.score / 100)).toFixed(2));

  const overallPostureLabel =
    analysis.grade === "A+" ? "Excellent Posture"
    : analysis.grade === "A" ? "Strong Posture"
    : analysis.grade === "B" ? "Good Posture"
    : analysis.grade === "C" ? "Mixed Posture"
    : analysis.grade === "D" ? "Weak Posture"
    : analysis.grade === "F" ? "Needs Immediate Attention"
    : "Assessment Limited";

  const fixNow = priorityActions.slice(0, 2);
  const fixNext = priorityActions.slice(2, 4);
  const keepWatching = weakestAreas.slice(0, 2);

  const weakestAreaText = weakestAreas.length
    ? weakestAreas.map((a) => `${a.label} (${a.score}/100)`).join(", ")
    : "no obvious weak cluster";

  const strongestAreaText = strongestAreas.length
    ? strongestAreas.map((a) => a.label).join(", ")
    : "no clearly compensating strengths recorded";

  const reportLimits = buildAssessmentLimits(analysis);

  const severityBadge = (severity: string) => {
    const styleMap: Record<string, string> = {
      critical: "background:#fef2f2;color:#dc2626;border-color:#fca5a5",
      warning:  "background:#fffbeb;color:#d97706;border-color:#fcd34d",
      info:     "background:#f8fafc;color:#64748b;border-color:#e2e8f0",
    };
    return `<span class="badge" style="${styleMap[severity] ?? styleMap.info}">${escapeHtml(severity)}</span>`;
  };

  const statusBadge = (status: string) => {
    const styleMap: Record<string, string> = {
      strong:  "background:#f0fdf4;color:#16a34a",
      watch:   "background:#fffbeb;color:#d97706",
      weak:    "background:#fef2f2;color:#dc2626",
      limited: "background:#f1f5f9;color:#64748b",
    };
    return `<span class="status-pill" style="${styleMap[status] ?? styleMap.watch}">${escapeHtml(status)}</span>`;
  };

  const barFill = (status: string) =>
    status === "strong" ? "#16a34a" : status === "watch" ? "#d97706" : "#dc2626";

  const areaExplain = (label: string) => {
    const map: Record<string, string> = {
      "Edge Security":    "Controls how browsers enforce communication rules, including HSTS, framing, and redirect hygiene.",
      "Domain & Trust":   "Covers email authentication (SPF, DMARC, MTA-STS), CAA constraints, and domain ownership signals.",
      "Content Security": "Reflects Content Security Policy strength and browser sandbox controls.",
      "Exposure Control": "Based on passive probes for unintended public-facing endpoints and information disclosure.",
      "API Surface":      "Derived from passive probes for exposed API paths and machine-readable interfaces.",
      "Third-Party Trust": "Accounts for the number and risk profile of external script and data providers.",
      "AI & Automation":  "Reflects visibility into AI vendors, assistants, and automation surfaces.",
    };
    return map[label] ?? `${label} was assessed as part of the external posture read.`;
  };

  const renderPriorityList = (actions: ReturnType<typeof getPriorityActions>) =>
    actions.length
      ? `<ul class="plist">${actions.map((a) => `
          <li class="plist-item">
            <div class="plist-title">${escapeHtml(a.title)}</div>
            <div class="plist-detail">${escapeHtml(a.detail)}</div>
            ${a.priorityReason ? `<div class="plist-reason">${escapeHtml(a.priorityReason)}</div>` : ""}
          </li>`).join("")}</ul>`
      : `<p class="p-muted">No items in this category.</p>`;

  const postureRows = areas.map((area) => `
    <div class="posture-row">
      <div class="posture-row-top">
        <div class="posture-label-wrap">
          <span class="posture-label">${escapeHtml(area.label)}</span>
          ${statusBadge(area.status)}
        </div>
        <span class="posture-score">${area.score}<span class="posture-score-denom">/100</span></span>
      </div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, area.score)}%;background:${barFill(area.status)}"></div></div>
      <p class="posture-explain">${escapeHtml(areaExplain(area.label))}</p>
    </div>`).join("");

  const findingCards = topFindings.slice(0, 6).map((issue) => {
    const tags = [...issue.owasp.slice(0, 2), ...issue.mitre.slice(0, 1)]
      .map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("");
    return `
      <div class="finding-card">
        <div class="finding-top">
          <h3 class="finding-title">${escapeHtml(issue.title)}</h3>
          ${severityBadge(issue.severity)}
        </div>
        <p class="finding-body">${escapeHtml(issue.detail)}</p>
        ${tags ? `<div class="tag-row">${tags}</div>` : ""}
      </div>`;
  }).join("") || `<div class="finding-card"><p class="p-muted">No findings recorded from this scan.</p></div>`;

  const issueTableRows = analysis.issues.length
    ? analysis.issues.map((issue) => `
        <tr>
          <td style="font-weight:600;color:#0f172a">${escapeHtml(issue.title)}</td>
          <td>${severityBadge(issue.severity)}</td>
          <td class="td-muted">${escapeHtml(issue.source)}</td>
          <td class="td-muted">${escapeHtml(issue.detail.length > 110 ? issue.detail.slice(0, 109) + "…" : issue.detail)}</td>
        </tr>`).join("")
    : `<tr><td colspan="4" class="td-muted">No findings recorded.</td></tr>`;

  const strengthRows = analysis.strengths.slice(0, 6).length
    ? analysis.strengths.slice(0, 6).map((s) => `
        <div class="strength-row">
          <div class="strength-dot"></div>
          <div>${escapeHtml(s)}</div>
        </div>`).join("")
    : `<p class="p-muted">No explicit strengths were recorded from this scan.</p>`;

  const ctHtml = analysis.ctDiscovery.subdomains.slice(0, 12).length
    ? analysis.ctDiscovery.subdomains.slice(0, 12).map((h) => `<li>${escapeHtml(h)}</li>`).join("")
    : "<li>No CT-discovered subdomains recorded.</li>";

  const thirdPartyRows = analysis.thirdPartyTrust.providers.length
    ? analysis.thirdPartyTrust.providers.map((p) => {
        const riskStyle = p.risk === "high"
          ? "background:#fef2f2;color:#dc2626;border-color:#fca5a5"
          : "background:#f8fafc;color:#64748b;border-color:#e2e8f0";
        return `
          <tr>
            <td style="font-weight:600;color:#0f172a">${escapeHtml(p.name)}</td>
            <td class="td-muted">${escapeHtml(p.category)}</td>
            <td class="td-muted">${escapeHtml(p.domain)}</td>
            <td><span class="badge" style="${riskStyle}">${escapeHtml(p.risk)}</span></td>
          </tr>`;
      }).join("")
    : `<tr><td colspan="4" class="td-muted">No third-party providers recorded.</td></tr>`;

  const roadmapItems = priorityActions.length
    ? priorityActions.map((a, i) => `
        <div class="roadmap-row">
          <div class="roadmap-num">${i + 1}</div>
          <div class="roadmap-content">
            <div class="roadmap-title">${escapeHtml(a.title)}</div>
            <div class="roadmap-detail">${escapeHtml(a.detail)}</div>
            <div class="roadmap-evidence">${escapeHtml(buildEvidenceForAction(analysis, a.title))}</div>
          </div>
        </div>`).join("")
    : `<p class="p-muted">No priority actions were generated from this scan.</p>`;

  const limitItems = reportLimits
    .map((l) => `<div class="limit-item">${escapeHtml(l)}</div>`).join("");

  const pageFooter = `
    <div class="page-footer">
      <span>${escapeHtml(analysis.host)}</span>
      <span>SecURL · External Security Posture Report · ${escapeHtml(generatedAt)}</span>
    </div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Security Report – ${escapeHtml(analysis.host)}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,400;0,500;0,600;0,700;0,800;1,400&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    @page { margin: 14mm 16mm; size: A4; }

    :root {
      --text:    #0f172a;
      --text-2:  #334155;
      --muted:   #64748b;
      --subtle:  #94a3b8;
      --border:  #e2e8f0;
      --surface: #f8fafc;
      --sf2:     #f1f5f9;
      --white:   #ffffff;
      --grade:   ${gradeColor};
    }

    body {
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.65;
      color: var(--text);
      background: var(--white);
    }
    h1, h2, h3 { line-height: 1.25; color: var(--text); font-weight: 700; }
    p { color: var(--text-2); }
    ul { padding-left: 18px; }
    li + li { margin-top: 5px; }

    /* ─ COVER ───────────────────────────────────────────────────────── */
    .cover {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      break-after: page;
      page-break-after: always;
    }
    .cover-head {
      padding: 22px 52px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .cover-wordmark {
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--text);
    }
    .cover-type {
      font-size: 11px;
      font-weight: 500;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .cover-body {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 52px 52px 40px;
      text-align: center;
      gap: 26px;
    }
    .cover-url {
      font-size: 36px;
      font-weight: 800;
      letter-spacing: -0.04em;
      color: var(--text);
      word-break: break-all;
      max-width: 620px;
      line-height: 1.1;
    }
    .cover-ring-wrap { position: relative; width: 220px; height: 220px; }
    .cover-ring-svg  { width: 220px; height: 220px; }
    .cover-ring-inner {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 1px;
    }
    .cover-grade {
      font-size: ${gradeFontSize}px;
      font-weight: 800;
      line-height: 1;
      color: var(--grade);
      letter-spacing: -0.04em;
    }
    .cover-score-label { font-size: 14px; font-weight: 600; color: var(--muted); }
    .cover-posture {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--grade);
    }
    .cover-verdict { font-size: 16px; line-height: 1.6; color: var(--text-2); max-width: 480px; }
    .cover-foot {
      padding: 20px 52px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      color: var(--muted);
    }
    .cover-foot-items { display: flex; gap: 28px; }
    .cover-foot-brand {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--subtle);
    }

    /* ─ REPORT PAGES ─────────────────────────────────────────────────── */
    .rpage {
      max-width: 900px;
      margin: 0 auto;
      padding: 44px 44px 52px;
      break-before: page;
      page-break-before: always;
    }
    .section-head { margin-bottom: 26px; padding-bottom: 16px; border-bottom: 1.5px solid var(--border); }
    .eyebrow {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.24em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 7px;
    }
    .section-title { font-size: 24px; font-weight: 800; letter-spacing: -0.02em; color: var(--text); }

    /* ─ PRIORITY CARDS ────────────────────────────────────────────────── */
    .priority-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
    .pcard { border: 1px solid var(--border); border-left-width: 4px; border-radius: 10px; padding: 22px 20px; }
    .pcard-now   { border-left-color: #dc2626; background: #fff5f5; }
    .pcard-next  { border-left-color: #d97706; background: #fffcf0; }
    .pcard-watch { border-left-color: #475569; background: var(--surface); }
    .pcard-label { font-size: 10px; font-weight: 700; letter-spacing: 0.2em; text-transform: uppercase; margin-bottom: 5px; }
    .pcard-now   .pcard-label { color: #dc2626; }
    .pcard-next  .pcard-label { color: #d97706; }
    .pcard-watch .pcard-label { color: #475569; }
    .pcard-count { font-size: 48px; font-weight: 800; line-height: 1; color: var(--text); margin-bottom: 14px; }
    .plist { list-style: none; padding: 0; }
    .plist-item { padding: 10px 0; border-top: 1px solid var(--border); }
    .plist-item:first-child { border-top: none; padding-top: 0; }
    .plist-title  { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 3px; }
    .plist-detail { font-size: 12px; color: var(--muted); line-height: 1.5; }
    .plist-reason { font-size: 11px; color: var(--subtle); margin-top: 3px; font-style: italic; }
    .p-muted { font-size: 13px; color: var(--muted); }

    /* ─ POSTURE OVERVIEW ──────────────────────────────────────────────── */
    .posture-row { padding: 16px 0; border-bottom: 1px solid var(--border); }
    .posture-row:last-child { border-bottom: none; }
    .posture-row-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .posture-label-wrap { display: flex; align-items: center; gap: 10px; }
    .posture-label { font-size: 15px; font-weight: 700; color: var(--text); }
    .status-pill { font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; }
    .posture-score { font-size: 22px; font-weight: 800; color: var(--text); }
    .posture-score-denom { font-size: 13px; font-weight: 500; color: var(--muted); }
    .bar-track { height: 6px; background: var(--sf2); border-radius: 999px; overflow: hidden; margin-bottom: 8px; }
    .bar-fill  { height: 100%; border-radius: 999px; }
    .posture-explain { font-size: 13px; color: var(--muted); line-height: 1.5; }

    /* ─ FINDING CARDS ─────────────────────────────────────────────────── */
    .findings-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .finding-card  { border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; background: var(--white); }
    .finding-top   { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 8px; }
    .finding-title { font-size: 14px; font-weight: 700; color: var(--text); flex: 1; line-height: 1.35; }
    .finding-body  { font-size: 13px; color: var(--muted); line-height: 1.55; }
    .tag-row { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 10px; }
    .badge {
      display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px;
      font-size: 10px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
      border: 1px solid; white-space: nowrap; flex-shrink: 0;
    }
    .tag { font-size: 10px; padding: 2px 6px; background: var(--sf2); color: var(--muted); border-radius: 4px; }

    /* ─ STRENGTHS ─────────────────────────────────────────────────────── */
    .strength-row { display: flex; align-items: flex-start; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--text-2); line-height: 1.5; }
    .strength-row:last-child { border-bottom: none; }
    .strength-dot { width: 7px; height: 7px; border-radius: 50%; background: #16a34a; flex-shrink: 0; margin-top: 4px; }

    /* ─ INFO CARDS ────────────────────────────────────────────────────── */
    .two-col { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
    .info-card { border: 1px solid var(--border); border-radius: 10px; padding: 20px; background: var(--white); }
    .info-title { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
    .info-card p  { font-size: 13px; color: var(--muted); margin-top: 5px; }
    .info-card li { font-size: 13px; color: var(--muted); }

    /* ─ DATA TABLES ───────────────────────────────────────────────────── */
    .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .data-table th { text-align: left; padding: 8px 10px; background: var(--surface); font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--border); font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; }
    .data-table td { padding: 9px 10px; border-bottom: 1px solid var(--border); color: var(--text-2); vertical-align: top; }
    .data-table tr:last-child td { border-bottom: none; }
    .td-muted { color: var(--muted) !important; }

    /* ─ ROADMAP ───────────────────────────────────────────────────────── */
    .roadmap-row { display: flex; gap: 16px; padding: 14px 0; border-bottom: 1px solid var(--border); }
    .roadmap-row:last-child { border-bottom: none; }
    .roadmap-num { width: 28px; height: 28px; border-radius: 50%; background: var(--text); color: #fff; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 800; flex-shrink: 0; margin-top: 2px; }
    .roadmap-content { flex: 1; }
    .roadmap-title    { font-size: 14px; font-weight: 700; color: var(--text); margin-bottom: 4px; }
    .roadmap-detail   { font-size: 13px; color: var(--muted); margin-bottom: 4px; line-height: 1.5; }
    .roadmap-evidence { font-size: 12px; color: var(--subtle); font-style: italic; }

    /* ─ NOTE BOX ──────────────────────────────────────────────────────── */
    .note-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; font-size: 13px; color: var(--muted); margin-top: 14px; line-height: 1.55; }

    /* ─ APPENDIX ──────────────────────────────────────────────────────── */
    .limit-item { padding: 11px 0; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--muted); line-height: 1.55; }
    .limit-item:last-child { border-bottom: none; }

    /* ─ PAGE FOOTER ───────────────────────────────────────────────────── */
    .page-footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; font-size: 11px; color: var(--subtle); }

    /* Responsive collapse is screen-only — never fires during print */
    @media screen and (max-width: 680px) {
      .priority-grid, .findings-grid, .two-col { grid-template-columns: 1fr; }
      .cover-url { font-size: 26px; }
      .cover-body, .cover-head, .cover-foot, .rpage { padding-left: 24px; padding-right: 24px; }
    }

    /* Print-specific: lock every multi-column grid and fix the cover page */
    @media print {
      /* Suppress browser-added URL / date header and footer lines */
      @page { margin: 0; size: A4; }

      /* Compensate for zero @page margin with internal padding */
      .cover-head, .cover-foot { padding-left: 18mm; padding-right: 18mm; }
      .cover-body { padding-left: 18mm; padding-right: 18mm; }
      .rpage { padding-left: 18mm; padding-right: 18mm; }

      /* Ensure cover fills exactly one page */
      .cover { min-height: 100vh; page-break-after: always; break-after: page; }

      /* Lock all multi-column layouts — never collapse regardless of viewport */
      .priority-grid { grid-template-columns: repeat(3, 1fr) !important; }
      .findings-grid { grid-template-columns: repeat(2, 1fr) !important; }
      .two-col       { grid-template-columns: repeat(2, 1fr) !important; }
    }
  </style>
</head>
<body>

<!-- ══ 01 COVER ════════════════════════════════════════════════════════════ -->
<div class="cover">
  <header class="cover-head">
    <div class="cover-wordmark">SecURL</div>
    <div class="cover-type">External Security Posture Report</div>
  </header>

  <main class="cover-body">
    <div class="cover-url">${escapeHtml(analysis.finalUrl)}</div>

    <div class="cover-ring-wrap">
      <svg class="cover-ring-svg" viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg">
        <circle cx="110" cy="110" r="90" fill="none" stroke="#e2e8f0" stroke-width="14"/>
        <circle cx="110" cy="110" r="90" fill="none" stroke="${gradeColor}" stroke-width="14"
                stroke-linecap="round"
                stroke-dasharray="${ringCirc}"
                stroke-dashoffset="${ringOffset}"
                transform="rotate(-90 110 110)"/>
      </svg>
      <div class="cover-ring-inner">
        <div class="cover-grade">${escapeHtml(analysis.grade)}</div>
        <div class="cover-score-label">${analysis.score}/100</div>
      </div>
    </div>

    <div class="cover-posture">${escapeHtml(overallPostureLabel)}</div>
    <p class="cover-verdict">${escapeHtml(analysis.executiveSummary.mainRisk)}</p>
  </main>

  <footer class="cover-foot">
    <div class="cover-foot-items">
      <span>Generated: ${escapeHtml(generatedAt)}</span>
      <span>Scan date: ${escapeHtml(scanDate)}</span>
      <span>Status: ${escapeHtml(String(analysis.statusCode))}</span>
    </div>
    <div class="cover-foot-brand">Prepared by SecURL</div>
  </footer>
</div>

<!-- ══ 02 PRIORITY ACTIONS ══════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">02 — Priority Actions</div>
    <h2 class="section-title">Where attention should go first</h2>
  </div>

  <div class="priority-grid">
    <div class="pcard pcard-now">
      <div class="pcard-label">Fix Now</div>
      <div class="pcard-count">${fixNow.length}</div>
      ${renderPriorityList(fixNow)}
    </div>
    <div class="pcard pcard-next">
      <div class="pcard-label">Fix Next</div>
      <div class="pcard-count">${fixNext.length}</div>
      ${renderPriorityList(fixNext)}
    </div>
    <div class="pcard pcard-watch">
      <div class="pcard-label">Keep Watching</div>
      <div class="pcard-count">${keepWatching.length}</div>
      <ul class="plist">
        ${keepWatching.length
          ? keepWatching.map((a) => `
              <li class="plist-item">
                <div class="plist-title">${escapeHtml(a.label)}</div>
                <div class="plist-detail">${a.score}/100 — ${escapeHtml(a.status)}</div>
              </li>`).join("")
          : `<li class="plist-item"><div class="plist-detail">Monitor posture over time and revisit after addressing Fix Now items.</div></li>`}
        <li class="plist-item"><div class="plist-detail">${escapeHtml(changeHeadline)}</div></li>
      </ul>
    </div>
  </div>
  ${pageFooter}
</div>

<!-- ══ 03 POSTURE OVERVIEW ══════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">03 — Posture Overview</div>
    <h2 class="section-title">Category scores at a glance</h2>
  </div>
  <div>${postureRows}</div>
  ${pageFooter}
</div>

<!-- ══ 04 KEY FINDINGS ══════════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">04 — Key Findings</div>
    <h2 class="section-title">Top risks explained plainly</h2>
  </div>
  <div class="findings-grid">${findingCards}</div>
  ${pageFooter}
</div>

<!-- ══ 05 STRENGTHS ═════════════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">05 — Strengths &amp; Positive Signals</div>
    <h2 class="section-title">What is already working well</h2>
  </div>
  <div class="two-col">
    <div class="info-card">
      <div class="info-title">Positive Signals</div>
      ${strengthRows}
    </div>
    <div class="info-card">
      <div class="info-title">Most Reassuring Areas</div>
      <p>${escapeHtml(strongestAreaText)}</p>
      <div class="note-box">${escapeHtml(analysis.executiveSummary.overview)}</div>
      ${analysis.executiveSummary.takeaways.length ? `
        <ul style="margin-top:14px;padding-left:16px">
          ${analysis.executiveSummary.takeaways.slice(0, 3).map((t) => `<li style="font-size:13px;color:var(--muted)">${escapeHtml(t)}</li>`).join("")}
        </ul>` : ""}
    </div>
  </div>
  ${pageFooter}
</div>

<!-- ══ 06 TECHNICAL DETAILS ═════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">06 — Technical Details</div>
    <h2 class="section-title">Evidence for the security team</h2>
  </div>

  <div style="margin-bottom:20px">
    <table class="data-table">
      <thead>
        <tr><th>Finding</th><th>Severity</th><th>Source</th><th>Detail</th></tr>
      </thead>
      <tbody>${issueTableRows}</tbody>
    </table>
  </div>

  <div class="two-col">
    <div class="info-card">
      <div class="info-title">Domain &amp; Email Trust</div>
      <p>SPF: ${escapeHtml(analysis.domainSecurity.spf ?? "Not found")}</p>
      <p>DMARC: ${escapeHtml(analysis.domainSecurity.dmarc ?? "Not found")}</p>
      <p>DNSSEC: ${escapeHtml(analysis.domainSecurity.dnssec.status)}</p>
      <p>MX records: ${analysis.domainSecurity.mxRecords.length}</p>
      <p>CAA records: ${analysis.domainSecurity.caaRecords.length}</p>
      <div class="note-box">${escapeHtml(disclosure.summary)}</div>
    </div>
    <div class="info-card">
      <div class="info-title">Certificate Transparency</div>
      <p>${escapeHtml(analysis.ctDiscovery.coverageSummary)}</p>
      <p style="margin-top:8px">Subdomains: ${analysis.ctDiscovery.subdomains.length}</p>
      <p>Wildcard entries: ${analysis.ctDiscovery.wildcardEntries.length}</p>
      <ul style="margin-top:10px;font-size:13px;color:var(--muted)">${ctHtml}</ul>
    </div>
    <div class="info-card">
      <div class="info-title">Third-Party Providers</div>
      <table class="data-table">
        <thead><tr><th>Name</th><th>Category</th><th>Domain</th><th>Risk</th></tr></thead>
        <tbody>${thirdPartyRows}</tbody>
      </table>
    </div>
    <div class="info-card">
      <div class="info-title">WAF &amp; Edge</div>
      <p>${escapeHtml(analysis.wafFingerprint.summary)}</p>
      ${analysis.wafFingerprint.providers.length ? `
        <ul style="margin-top:10px;font-size:13px;color:var(--muted)">
          ${analysis.wafFingerprint.providers.map((p) => `<li><strong>${escapeHtml(p.name)}</strong> (${escapeHtml(p.confidence)} confidence): ${escapeHtml(p.evidence)}</li>`).join("")}
        </ul>` : ""}
    </div>
    <div class="info-card">
      <div class="info-title">AI &amp; Automation Surface</div>
      <p>${escapeHtml(aiSummary)}</p>
      <p style="margin-top:6px">Detected: ${analysis.aiSurface.detected ? "Yes" : "No"} · Assistant visible: ${analysis.aiSurface.assistantVisible ? "Yes" : "No"}</p>
      ${analysis.aiSurface.vendors.length ? `<p style="margin-top:6px">Vendors: ${escapeHtml(analysis.aiSurface.vendors.map((v) => v.name).join(", "))}</p>` : ""}
    </div>
    <div class="info-card">
      <div class="info-title">Detected Stack</div>
      ${analysis.technologies.length ? `
        <ul style="padding-left:16px">
          ${analysis.technologies.map((t) => `<li style="font-size:13px;color:var(--muted)"><strong style="color:var(--text-2)">${escapeHtml(t.name)}</strong> — ${escapeHtml(t.category)}, ${escapeHtml(t.confidence)} confidence</li>`).join("")}
        </ul>` : `<p class="p-muted">No stack signals recorded.</p>`}
    </div>
  </div>
  ${pageFooter}
</div>

<!-- ══ 07 RECOMMENDATIONS ════════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">07 — Recommendations &amp; Next Steps</div>
    <h2 class="section-title">Prioritised roadmap</h2>
  </div>

  <div style="margin-bottom:24px">${roadmapItems}</div>

  <div class="two-col">
    <div class="info-card">
      <div class="info-title">Monitoring Suggestion</div>
      <p>Track ${escapeHtml(weakestAreaText)} over time. Watch for changes in the findings count, header configuration, and trust signals.</p>
      <div class="note-box">
        ${diff ? escapeHtml(changeHeadline) : "This report is a baseline. The next saved scan will show whether posture is improving, stable, or regressing."}
      </div>
    </div>
    <div class="info-card">
      <div class="info-title">Questions for the Security Team</div>
      <ul style="padding-left:16px">
        ${buildStakeholderQuestions(analysis).map((q) => `<li style="font-size:13px;color:var(--muted)">${escapeHtml(q)}</li>`).join("")}
      </ul>
    </div>
  </div>
  ${pageFooter}
</div>

<!-- ══ 08 APPENDIX ══════════════════════════════════════════════════════════ -->
<div class="rpage">
  <div class="section-head">
    <div class="eyebrow">08 — Appendix / Limitations</div>
    <h2 class="section-title">How to read this report</h2>
  </div>
  <div class="two-col">
    <div class="info-card">
      <div class="info-title">Assessment Limits</div>
      ${limitItems}
    </div>
    <div class="info-card">
      <div class="info-title">Method Notes</div>
      <div class="limit-item">This report is based on an external, unauthenticated, passive-first assessment. It captures observable signals from the public surface of the target.</div>
      <div class="limit-item">It is intended to support posture review, triage, and follow-up planning — not to replace authenticated testing, configuration review, or exploitation work.</div>
      <div class="limit-item">Scores reflect weighted evidence across multiple categories. Absence of a finding is not a guarantee of correct configuration.</div>
    </div>
  </div>
  ${pageFooter}
</div>

</body>
</html>`;
};
