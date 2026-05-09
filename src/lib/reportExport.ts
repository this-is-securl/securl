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

const buildThemeHtmlItems = (
  themes: Array<{ label: string; count: number; summary: string; whyItMatters: string; examples: string[] }>,
) =>
  themes.length
    ? themes
        .map(
          (item) =>
            `<li><strong>${escapeHtml(item.label)}</strong> (${item.count})<br>${escapeHtml(item.summary)}<br><em>Why it matters:</em> ${escapeHtml(item.whyItMatters)}${item.examples.length ? `<br><em>Driving findings:</em> ${escapeHtml(item.examples.join("; "))}` : ""}</li>`,
        )
        .join("")
    : "<li>No taxonomy themes recorded.</li>";

const severityRank = {
  critical: 0,
  warning: 1,
  info: 2,
} as const;

const sentenceJoin = (items: string[]) => {
  if (items.length <= 1) return items[0] ?? "";
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items.at(-1)}`;
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
  const warningCount = analysis.issues.filter((issue) => issue.severity === "warning").length;
  const criticalCount = analysis.issues.filter((issue) => issue.severity === "critical").length;
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
    const mtaStsPresent = analysis.domainSecurity.mtaSts.status === "present";
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

const buildSeverityTone = (analysis: AnalysisResult) => {
  if (analysis.assessmentLimitation.limited) return "limited";
  if (analysis.grade === "A" || analysis.grade === "B") return "strong";
  if (analysis.grade === "C") return "watch";
  return "weak";
};

const buildCategoryBarsHtml = (areas: ReturnType<typeof getAreaScores>) =>
  areas
    .map(
      (area) => `
        <div class="bar-row">
          <div class="bar-copy">
            <strong>${escapeHtml(area.label)}</strong>
            <span>${escapeHtml(area.status)}</span>
          </div>
          <div class="bar-track"><span style="width:${Math.max(6, area.score)}%"></span></div>
          <div class="bar-score">${area.score}</div>
        </div>`,
    )
    .join("");

const buildCompactListHtml = (items: string[]) =>
  items.length ? `<ul class="compact-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : "<p class=\"muted\">No additional items recorded.</p>";

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
  const summary = getUnifiedIssueSummary(analysis);
  const priorityActions = getPriorityActions(analysis);
  const aiSummary = getAiSurfaceClassificationSummary(analysis.aiSurface);
  const taxonomy = getDominantThemes(analysis);
  const disclosure = getDisclosurePosture(analysis);
  const authSurface = getAuthSurfaceSummary(analysis.htmlSecurity);
  const dataCollection = getDataCollectionSummary(analysis.htmlSecurity);
  const weakestAreas = getWeakestAreas(analysis);
  const strongestAreas = getStrongestAreas(analysis);
  const severityTone = buildSeverityTone(analysis);
  const issueItems = analysis.issues.length
    ? analysis.issues
        .map(
          (issue) =>
            `<li><strong>[${escapeHtml(issue.severity)} | ${escapeHtml(issue.confidence)} confidence | ${escapeHtml(issue.source)}${issue.owasp.length ? ` | OWASP: ${escapeHtml(issue.owasp.join(", "))}` : ""}${issue.mitre.length ? ` | MITRE: ${escapeHtml(issue.mitre.join(", "))}` : ""}] ${escapeHtml(issue.title)}</strong><br>${escapeHtml(issue.detail)}</li>`,
        )
        .join("")
    : "<li>No core findings recorded.</li>";
  const areaItems = areas
    .map((area) => `<li><strong>${escapeHtml(area.label)}</strong>: ${area.score}/100 (${escapeHtml(area.status)})</li>`)
    .join("");
  const priorityItems = priorityActions.length
    ? priorityActions
        .map((action) => `<li><strong>[${escapeHtml(action.severity)}] ${escapeHtml(action.title)}</strong><br>${escapeHtml(action.detail)}${action.priorityReason ? `<br><em>${escapeHtml(action.priorityReason)}</em>` : ""}</li>`)
        .join("")
    : "<li>No priority actions generated.</li>";
  const exposureItems = buildExposureLines(analysis)
    .map((line) => `<li>${escapeHtml(line.slice(2))}</li>`)
    .join("");
  const technologyItems = analysis.technologies.length
    ? analysis.technologies
        .map(
          (tech) =>
            `<li><strong>${escapeHtml(tech.name)}</strong> (${escapeHtml(tech.category)}, ${escapeHtml(tech.detection)}, ${escapeHtml(tech.confidence)} confidence)<br>${escapeHtml(tech.evidence)}</li>`,
        )
        .join("")
    : "<li>No stack signals recorded.</li>";
  const discoveryItems = analysis.htmlSecurity.firstPartyPaths.length
    ? analysis.htmlSecurity.firstPartyPaths.map((path) => `<li>${escapeHtml(path)}</li>`).join("")
    : "<li>No same-origin paths discovered from the fetched page.</li>";
  const sameSiteHostItems = analysis.htmlSecurity.sameSiteHosts.length
    ? analysis.htmlSecurity.sameSiteHosts.map((host) => `<li>${escapeHtml(host)}</li>`).join("")
    : "<li>No sibling same-site hosts were referenced by the fetched page.</li>";
  const passiveLeakItems = buildPassiveLeakLines(analysis)
    .map((line) => `<li>${escapeHtml(line.slice(2))}</li>`)
    .join("");
  const libraryRiskItems = buildLibraryRiskLines(analysis)
    .map((line) => `<li>${escapeHtml(line.slice(2))}</li>`)
    .join("");
  const ctItems = buildCtLines(analysis)
    .map((line) => `<li>${escapeHtml(line.slice(2))}</li>`)
    .join("");
  const owaspThemeItems = buildThemeHtmlItems(taxonomy.owasp);
  const mitreThemeItems = buildThemeHtmlItems(taxonomy.mitre);
  const changeHeadline = getChangeHeadline(diff);
  const topFindings = getTopFindings(analysis);
  const topFindingItems = topFindings.length
    ? topFindings.map((issue) => `<li><strong>[${escapeHtml(issue.severity)}] ${escapeHtml(issue.title)}</strong><br>${escapeHtml(issue.detail)}</li>`).join("")
    : "<li>No core findings were recorded.</li>";
  const weakestAreaText = weakestAreas.length
    ? weakestAreas.map((area) => `${area.label} (${area.score}/100)`).join(", ")
    : "No obvious weak cluster recorded.";
  const strongestAreaText = strongestAreas.length
    ? strongestAreas.map((area) => `${area.label} (${area.score}/100)`).join(", ")
    : "No clearly compensating strengths recorded.";
  const executiveTakeawayItems = analysis.executiveSummary.takeaways.length
    ? analysis.executiveSummary.takeaways.slice(0, 3).map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No extra executive takeaways were generated from this scan.</li>";
  const strengthItems = analysis.strengths.length
    ? analysis.strengths.slice(0, 4).map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No explicit strengths were recorded.</li>";
  const generatedAt = new Date().toLocaleString();
  const donutDegrees = Math.round((analysis.score / 100) * 360);
  const urgentActionCount = Math.min(priorityActions.length, 2);
  const nextActionCount = Math.max(Math.min(priorityActions.length - urgentActionCount, 2), 0);
  const followUpCount = buildAssessmentLimits(analysis).length;
  const triageCards = [
    {
      label: "Fix now",
      count: urgentActionCount,
      detail: priorityActions.length
        ? priorityActions
            .slice(0, 2)
            .map((action) => action.title)
            .join(" • ")
        : "No urgent remediation items were generated from this scan.",
    },
    {
      label: "Fix next",
      count: nextActionCount,
      detail:
        priorityActions.length > 2
          ? priorityActions
              .slice(2, 4)
              .map((action) => action.title)
              .join(" • ")
          : "After the first fixes land, review the remaining hardening and trust gaps.",
    },
    {
      label: "Keep watching",
      count: followUpCount,
      detail: analysis.assessmentLimitation.limited
        ? "Some parts of the target could not be read cleanly, so a follow-up assessment is still worth scheduling."
        : `Monitor ${weakestAreaText} over time to check whether posture is improving or drifting.`,
    },
  ];
  const triageItems = triageCards
    .map(
      (item) => `
        <div class="triage-card">
          <span class="triage-label">${escapeHtml(item.label)}</span>
          <strong>${item.count}</strong>
          <p>${escapeHtml(item.detail)}</p>
        </div>`,
    )
    .join("");
  const priorityBriefItems = priorityActions.length
    ? priorityActions
        .slice(0, 3)
        .map(
          (action) => `
            <li>
              <strong>${escapeHtml(action.title)}</strong><br>
              ${escapeHtml(action.detail)}
            </li>`,
        )
        .join("")
    : "<li>No urgent remediation items were generated from this scan.</li>";

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Security Report - ${escapeHtml(analysis.host)}</title>
    <style>
      :root { color-scheme: dark; --bg:#09111f; --bg-soft:#111c2d; --panel:#172335; --panel-2:#1d2b40; --line:rgba(148, 163, 184, 0.18); --text:#e8edf7; --muted:#9aa8bf; --accent:#cf7a36; --good:#c6d4e6; --watch:#d0a56e; --limited:#d5b786; }
      * { box-sizing: border-box; }
      body { font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: linear-gradient(180deg, #07111d 0%, #0f1624 100%); color: var(--text); }
      .page { max-width: 1240px; margin: 0 auto; padding: 40px 28px 64px; }
      h1, h2, h3 { margin: 0; }
      p { margin: 0; line-height: 1.65; }
      ul { margin: 0; padding-left: 18px; line-height: 1.65; }
      li + li { margin-top: 8px; }
      .cover-sheet { min-height: calc(100vh - 104px); display:grid; align-items:center; margin-bottom: 24px; }
      .cover-frame { display:grid; grid-template-columns: minmax(0, 1.4fr) 280px; gap: 24px; align-items:start; padding: 30px 0; }
      .cover-kicker { font-size: 12px; letter-spacing: .28em; text-transform: uppercase; color: var(--muted); margin-bottom: 18px; }
      .cover-target { font-size: clamp(42px, 7vw, 76px); line-height: .95; letter-spacing: -.06em; font-weight: 800; margin-bottom: 14px; word-break: break-word; }
      .cover-url { color: var(--muted); font-size: 24px; line-height: 1.45; word-break: break-word; max-width: 28ch; }
      .cover-score { align-self:start; padding: 28px 24px; border-radius: 28px; background: linear-gradient(180deg, rgba(207,122,54,.92), rgba(166,94,43,.96)); color: #fff8f0; box-shadow: 0 18px 44px rgba(89, 44, 16, 0.32); }
      .cover-score span { display:block; font-size: 11px; letter-spacing: .24em; text-transform: uppercase; opacity: .86; margin-bottom: 14px; }
      .cover-score strong { display:block; font-size: 76px; line-height: .9; letter-spacing: -.05em; margin-bottom: 8px; }
      .cover-score p { font-size: 20px; line-height: 1.3; }
      .hero { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(340px, .95fr); gap: 22px; margin-bottom: 24px; align-items: start; }
      .panel { background: linear-gradient(180deg, rgba(17,28,45,.96), rgba(11,20,34,.96)); border: 1px solid var(--line); border-radius: 28px; padding: 28px; box-shadow: 0 14px 36px rgba(3, 8, 20, 0.34); }
      .hero-panel { position: relative; overflow: hidden; }
      .hero-panel::after { content:""; position:absolute; inset:auto -60px -100px auto; width:220px; height:220px; background: radial-gradient(circle, rgba(207,122,54,0.28), transparent 70%); pointer-events:none; }
      .eyebrow { font-size: 12px; letter-spacing: .28em; text-transform: uppercase; color: var(--muted); margin-bottom: 12px; }
      .hero-title { font-size: 15px; color: var(--muted); margin-bottom: 10px; }
      .hero-host { font-size: clamp(34px, 5vw, 42px); line-height: 1.08; font-weight: 800; margin-bottom: 10px; word-break: break-word; }
      .hero-url { color: var(--muted); font-size: 18px; margin-bottom: 22px; word-break: break-word; }
      .hero-risk { max-width: 58ch; color: #f3f6fb; font-size: 21px; line-height: 1.45; }
      .grade-chip { display:inline-flex; align-items:center; gap: 12px; padding: 10px 14px; border-radius: 999px; border: 1px solid var(--line); background: rgba(255,255,255,.03); margin-bottom: 22px; }
      .grade-chip strong { font-size: 28px; line-height: 1; }
      .grade-chip span { color: var(--muted); font-size: 13px; letter-spacing: .18em; text-transform: uppercase; }
      .tone-strong strong { color: #dbe7f5; }
      .tone-watch strong { color: var(--watch); }
      .tone-weak strong, .tone-limited strong { color: var(--accent); }
      .hero-facts { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 26px; }
      .fact { padding: 16px 18px; border-radius: 20px; background: rgba(255,255,255,.03); border: 1px solid var(--line); min-height: 98px; }
      .fact-label { display:block; font-size: 11px; letter-spacing: .24em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }
      .fact strong { display:block; font-size: 30px; line-height: 1.1; margin-bottom: 4px; }
      .fact span { color: var(--muted); }
      .sidebar-stack { display:grid; gap: 18px; }
      .summary-band { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
      .summary-card { padding: 18px 20px; border-radius: 20px; border: 1px solid var(--line); background: rgba(255,255,255,.03); }
      .summary-card strong { display:block; margin-bottom: 8px; font-size: 14px; letter-spacing: .18em; text-transform: uppercase; color: var(--muted); }
      .summary-card p { font-size: 16px; }
      .brief-list { margin: 0; padding-left: 18px; }
      .brief-list li { color: var(--text); line-height: 1.55; }
      .triage-grid { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap:14px; margin-top: 14px; }
      .triage-card { padding: 18px 20px; border-radius: 20px; border: 1px solid var(--line); background: rgba(255,255,255,.03); min-height: 150px; }
      .triage-label { display:block; margin-bottom: 10px; font-size: 12px; letter-spacing: .22em; text-transform: uppercase; color: var(--muted); }
      .triage-card strong { display:block; font-size: 34px; line-height: 1; margin-bottom: 10px; color: #f0d5bc; }
      .triage-card p { color: var(--muted); font-size: 15px; line-height: 1.55; }
      .page-break { margin: 0 0 18px; }
      .summary-page { display:grid; gap: 22px; }
      .visual-grid { display:grid; grid-template-columns: minmax(280px, .78fr) minmax(0, 1.22fr); gap: 18px; }
      .donut-panel { display:grid; grid-template-columns: 168px minmax(0, 1fr); gap: 18px; align-items:center; }
      .donut-ring { width: 168px; height: 168px; border-radius: 999px; background: conic-gradient(#cf7a36 0deg ${donutDegrees}deg, rgba(207,122,54,.18) ${donutDegrees}deg 360deg); display:grid; place-items:center; }
      .donut-inner { width: 120px; height: 120px; border-radius: 999px; background: #0f1624; display:grid; place-items:center; text-align:center; }
      .donut-inner strong { display:block; font-size: 54px; line-height: .9; color: #f0d5bc; }
      .donut-inner span { display:block; font-size: 13px; letter-spacing: .18em; text-transform: uppercase; color: var(--muted); margin-top: 6px; }
      .visual-copy h3 { font-size: 22px; margin-bottom: 10px; }
      .visual-copy p { color: var(--muted); }
      .content-grid { display:grid; grid-template-columns: minmax(0, 1.35fr) minmax(300px, .95fr); gap: 22px; margin-bottom: 22px; align-items: start; }
      .stack { display:grid; gap: 18px; }
      .section-title { font-size: 22px; margin-bottom: 14px; }
      .callout-list li + li, .compact-list li + li { margin-top: 8px; }
      .action-card { padding: 16px 18px; border-radius: 18px; background: rgba(255,255,255,.03); border: 1px solid var(--line); }
      .action-card + .action-card { margin-top: 12px; }
      .action-card h3 { font-size: 17px; margin-bottom: 8px; }
      .action-card p + p { margin-top: 8px; }
      .muted { color: var(--muted); }
      .bar-list { display:grid; gap: 12px; }
      .bar-row { display:grid; grid-template-columns: 1.2fr 1.8fr 54px; gap: 12px; align-items:center; }
      .bar-copy { display:grid; gap: 2px; }
      .bar-copy span { color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: .18em; }
      .bar-track { height: 10px; background: rgba(255,255,255,.08); border-radius: 999px; overflow:hidden; }
      .bar-track span { display:block; height:100%; border-radius:999px; background: linear-gradient(90deg, #a55e2b, #d48a48); }
      .bar-score { text-align:right; font-weight: 700; color: #f1d0ae; }
      .appendix { display:grid; gap: 18px; }
      .appendix-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
      .kpi-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
      .kpi { padding: 16px 18px; border-radius: 18px; background: rgba(255,255,255,.03); border: 1px solid var(--line); }
      .kpi strong { display:block; font-size: 26px; margin-bottom: 4px; }
      .kpi span { color: var(--muted); }
      .chapter { display:grid; gap: 18px; margin: 24px 0 18px; }
      .chapter-header { display:flex; align-items:flex-end; justify-content:space-between; gap:16px; padding:0 4px; }
      .chapter-header h2 { font-size: 28px; letter-spacing: -.04em; }
      .chapter-header p { max-width: 60ch; color: var(--muted); }
      .chapter-kicker { font-size: 12px; letter-spacing: .28em; text-transform: uppercase; color: var(--muted); }
      @media (max-width: 1120px) {
        .cover-frame,
        .hero, .content-grid, .visual-grid, .donut-panel { grid-template-columns: 1fr; }
      }
      @media (max-width: 780px) {
        .page { padding: 20px 16px 40px; }
        .panel { padding: 22px; border-radius: 24px; }
        .hero-risk { font-size: 19px; }
        .summary-band, .appendix-grid, .triage-grid { grid-template-columns: 1fr; }
      }
      @media (max-width: 640px) {
        .hero-facts, .kpi-grid { grid-template-columns: 1fr; }
        .grade-chip { margin-bottom: 18px; }
        .bar-row { grid-template-columns: 1fr; gap: 8px; }
        .bar-score { text-align: left; }
      }
      @page { margin: 12mm; }
      @media print { body { background: #fff; color: #0f172a; } .page { max-width: none; padding: 0; } .panel, .fact, .summary-card, .action-card, .kpi, .triage-card { background: #f8fafc; color: #0f172a; box-shadow: none; } .cover-score { box-shadow: none; } .donut-inner { background: #fff; } .muted, .eyebrow, .summary-card strong, .fact span, .fact-label, .bar-copy span, .kpi span, .triage-label, .chapter-kicker, .cover-kicker, .cover-url, .visual-copy p, .donut-inner span { color: #475569; } .bar-track { background: #e2e8f0; } .summary-band, .triage-grid, .visual-grid { break-inside: avoid; page-break-inside: avoid; } .page-break { page-break-before: always; break-before: page; } }
    </style>
  </head>
  <body>
    <div class="page">
      <section class="cover-sheet">
        <div class="cover-frame">
          <div>
            <div class="cover-kicker">External security posture report</div>
            <h1 class="cover-target">${escapeHtml(analysis.finalUrl)}</h1>
          </div>
          <div class="cover-score">
            <span>Overall score</span>
            <strong>${analysis.score}</strong>
            <p>${escapeHtml(analysis.grade)} posture grade</p>
          </div>
        </div>
      </section>
      <section class="page-break summary-page">
        <div class="summary-band">
          <div class="summary-card"><strong>Generated</strong><p>${escapeHtml(generatedAt)}<br><span class="muted">Scan captured ${escapeHtml(new Date(analysis.scannedAt).toLocaleString())}</span></p></div>
          <div class="summary-card"><strong>Overall finding</strong><p>${escapeHtml(analysis.executiveSummary.overview)}</p></div>
          <div class="summary-card"><strong>Most exposed areas</strong><p>${escapeHtml(weakestAreaText)}</p></div>
          <div class="summary-card"><strong>Most reassuring areas</strong><p>${escapeHtml(strongestAreaText)}</p></div>
        </div>
        <div class="visual-grid">
          <div class="panel donut-panel">
            <div class="donut-ring">
              <div class="donut-inner">
                <div>
                  <strong>${escapeHtml(analysis.grade)}</strong>
                  <span>${analysis.score}/100</span>
                </div>
              </div>
            </div>
            <div class="visual-copy">
              <div class="eyebrow">Overall posture</div>
              <h3>${analysis.score}/100</h3>
              <p>${escapeHtml(analysis.executiveSummary.mainRisk)}</p>
            </div>
          </div>
          <div class="panel">
            <div class="eyebrow">Category scores</div>
            <h2 class="section-title">Where the score is being shaped</h2>
            <div class="bar-list">
              ${buildCategoryBarsHtml(areas)}
            </div>
          </div>
        </div>
      </section>
      <section class="panel page-break" style="margin-bottom:22px;">
        <div class="eyebrow">Action map</div>
        <h2 class="section-title">Where attention should go first</h2>
        <div class="triage-grid">${triageItems}</div>
        <div class="panel" style="margin-top:18px; padding:22px;">
          <div class="eyebrow">Immediate action</div>
          <h2 class="section-title">What to do next</h2>
          <ul class="brief-list">${priorityBriefItems}</ul>
        </div>
      </section>
      <section class="chapter page-break">
        <div class="chapter-header">
          <div>
            <div class="chapter-kicker">Detailed review</div>
            <h2>Why this matters and what supports it</h2>
          </div>
          <p>
            The rest of this report explains why the score landed where it did
            and shows the evidence behind the recommended actions.
          </p>
        </div>
      </section>
      <section class="content-grid">
        <div class="stack">
          <div class="panel">
            <div class="eyebrow">Plain-language summary</div>
            <h2 class="section-title">Why this matters</h2>
            ${buildPostureNarrative(analysis, diff).map((line) => `<p>${escapeHtml(line)}</p>`).join("<div style=\"height:10px\"></div>")}
          </div>
          <div class="panel">
            <div class="eyebrow">Key messages</div>
            <h2 class="section-title">What stands out</h2>
            <div class="appendix-grid">
              <div>
                <h3 style="margin-bottom:10px;">What stands out</h3>
                <ul>${executiveTakeawayItems}</ul>
              </div>
              <div>
                <h3 style="margin-bottom:10px;">What is already working well</h3>
                <ul>${strengthItems}</ul>
              </div>
            </div>
          </div>
          <div class="panel">
            <div class="eyebrow">Key findings</div>
            <h2 class="section-title">Most important issues seen from the outside</h2>
            <ul class="callout-list">${topFindingItems}</ul>
          </div>
          <div class="panel">
            <div class="eyebrow">Pattern of risk</div>
            <h2 class="section-title">Where the issues cluster</h2>
            <p class="muted" style="margin-bottom:14px;">${escapeHtml(taxonomy.summary)}</p>
            <div class="appendix-grid">
              <div>
                <h3 style="margin-bottom:10px;">OWASP alignment</h3>
                <ul>${owaspThemeItems}</ul>
              </div>
              <div>
                <h3 style="margin-bottom:10px;">MITRE relevance</h3>
                <ul>${mitreThemeItems}</ul>
              </div>
            </div>
          </div>
        </div>
        <div class="stack">
          <div class="panel">
            <div class="eyebrow">Score breakdown</div>
            <h2 class="section-title">How the score is being shaped</h2>
            <div class="bar-list">
              ${buildCategoryBarsHtml(areas)}
            </div>
          </div>
          <div class="panel">
            <div class="eyebrow">Follow-up questions</div>
            <h2 class="section-title">What still needs confirming</h2>
            ${buildCompactListHtml(buildStakeholderQuestions(analysis))}
          </div>
          <div class="panel">
            <div class="eyebrow">Report limits</div>
            <h2 class="section-title">How to read this report</h2>
            ${buildCompactListHtml(buildAssessmentLimits(analysis))}
          </div>
          <div class="panel">
            <div class="eyebrow">Change over time</div>
            <h2 class="section-title">What changed</h2>
            <div class="kpi-grid">
              <div class="kpi"><strong>${diff ? `${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}` : "—"}</strong><span>Score delta</span></div>
              <div class="kpi"><strong>${diff ? diff.newIssues.length : 0}</strong><span>New issues</span></div>
              <div class="kpi"><strong>${diff ? diff.resolvedIssues.length : 0}</strong><span>Resolved issues</span></div>
              <div class="kpi"><strong>${diff ? diff.headerChanges.length : 0}</strong><span>Header changes</span></div>
            </div>
            ${diff ? buildCompactListHtml(diff.summary.length ? diff.summary : ["No material posture changes summarized."]) : "<p class=\"muted\" style=\"margin-top:14px;\">No previous local snapshot available for comparison.</p>"}
          </div>
        </div>
      </section>
      <section class="chapter">
        <div class="chapter-header">
          <div>
            <div class="chapter-kicker">Detailed evidence</div>
            <h2>Technical detail and supporting evidence</h2>
          </div>
          <p>
            This section keeps the raw posture detail, mapped themes, and
            supporting evidence for technical review, remediation planning, or
            later audit follow-up.
          </p>
        </div>
      </section>
      <section class="appendix">
        <div class="panel">
          <div class="eyebrow">Detailed evidence</div>
          <h2 class="section-title">Full findings and evidence</h2>
          <ul>${issueItems}</ul>
        </div>
        <div class="appendix-grid">
          <div class="panel">
            <h2 class="section-title">Domain &amp; Email Security</h2>
            <p>SPF: ${escapeHtml(analysis.domainSecurity.spf ?? "Not found")}</p>
            <p>DMARC: ${escapeHtml(analysis.domainSecurity.dmarc ?? "Not found")}</p>
            <p>DNSSEC: ${escapeHtml(analysis.domainSecurity.dnssec.status)}</p>
            <p>MX count: ${analysis.domainSecurity.mxRecords.length}</p>
            <p>CAA count: ${analysis.domainSecurity.caaRecords.length}</p>
          </div>
          <div class="panel">
            <h2 class="section-title">Disclosure &amp; Public Trust</h2>
            <p>${escapeHtml(disclosure.summary)}</p>
            <ul>
              ${disclosure.discoveredPages.length ? disclosure.discoveredPages.map((item) => `<li>Discovered page: ${escapeHtml(item)}</li>`).join("") : "<li>No obvious trust or policy pages discovered.</li>"}
              ${disclosure.strengths.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
              ${disclosure.issues.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
            </ul>
          </div>
          <div class="panel">
            <h2 class="section-title">Identity Provider &amp; OAuth Surface</h2>
            <p>Detected: ${analysis.identityProvider.detected ? "Yes" : "No"}</p>
            <p>Provider: ${escapeHtml(analysis.identityProvider.provider ?? "Not identified")}</p>
            <p>Protocol: ${escapeHtml(analysis.identityProvider.protocol ?? "Not inferred")}</p>
            <p>OIDC config: ${escapeHtml(analysis.identityProvider.openIdConfigurationUrl ?? "Not observed")}</p>
            <ul>${analysis.identityProvider.redirectUriSignals.length
              ? analysis.identityProvider.redirectUriSignals.map((signal) => `<li>Review redirect URI signal: ${escapeHtml(signal)}</li>`).join("")
              : "<li>No public redirect_uri-style parameters were recorded.</li>"}</ul>
          </div>
          <div class="panel">
            <h2 class="section-title">Passive Discovery</h2>
            <p>Page title: ${escapeHtml(analysis.htmlSecurity.pageTitle ?? "Unavailable")}</p>
            <p>Discovery sources: ${escapeHtml(analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded")}</p>
            <ul>${discoveryItems}</ul>
            <ul>${sameSiteHostItems}</ul>
            <ul>${passiveLeakItems}</ul>
            <ul>${libraryRiskItems}</ul>
          </div>
          <div class="panel">
            <h2 class="section-title">Auth &amp; Data Collection Surface</h2>
            <p>${escapeHtml(authSurface.summary)}</p>
            <p>${escapeHtml(dataCollection.summary)}</p>
            <ul>${authSurface.authPaths.length
              ? authSurface.authPaths.map((item) => `<li>${escapeHtml(item.path)} (${escapeHtml(item.category)})</li>`).join("")
              : "<li>No auth-adjacent paths discovered passively.</li>"}</ul>
            <ul>${buildFormLines(analysis).map((line) => `<li>${escapeHtml(line.slice(2))}</li>`).join("")}</ul>
          </div>
          <div class="panel">
            <h2 class="section-title">Detected Stack &amp; Third Parties</h2>
            <ul>${technologyItems}</ul>
            <ul>${analysis.thirdPartyTrust.providers.length
              ? analysis.thirdPartyTrust.providers.map((provider) => `<li><strong>${escapeHtml(provider.name)}</strong> [${escapeHtml(provider.category)} | ${escapeHtml(provider.risk)} risk] ${escapeHtml(provider.domain)}<br>${escapeHtml(provider.evidence)}</li>`).join("")
              : "<li>No third-party providers recorded.</li>"}</ul>
          </div>
          <div class="panel">
            <h2 class="section-title">Certificate Transparency &amp; Edge</h2>
            <p>Queried domain: ${escapeHtml(analysis.ctDiscovery.queriedDomain)}</p>
            <p>${escapeHtml(analysis.ctDiscovery.coverageSummary)}</p>
            <ul>${ctItems}</ul>
            <ul>${buildCtSampleLines(analysis).map((line) => `<li>${escapeHtml(line.slice(2))}</li>`).join("")}</ul>
            <ul>${analysis.ctDiscovery.sampledHosts.some((host) => host.suspectedTakeover)
              ? analysis.ctDiscovery.sampledHosts
                  .filter((host) => host.suspectedTakeover)
                  .map((host) => `<li>Possible takeover: ${escapeHtml(host.host)} via ${escapeHtml(host.suspectedTakeover?.provider)} (${escapeHtml(host.suspectedTakeover?.confidence)} confidence)</li>`)
                  .join("")
              : "<li>No takeover-style signatures were observed in the sampled CT hosts.</li>"}</ul>
            <ul>${buildWafLines(analysis).map((line) => `<li>${escapeHtml(line.slice(2))}</li>`).join("")}</ul>
          </div>
          <div class="panel">
            <h2 class="section-title">AI Surface &amp; Exposure Checks</h2>
            <p>Classification: ${escapeHtml(aiSummary)}</p>
            <p>Vendors: ${escapeHtml(analysis.aiSurface.vendors.length ? analysis.aiSurface.vendors.map((vendor) => vendor.name).join(", ") : "None detected")}</p>
            <ul>${analysis.aiSurface.privacySignals.length ? analysis.aiSurface.privacySignals.map((signal) => `<li>${escapeHtml(signal)}</li>`).join("") : "<li>No explicit AI privacy guidance detected.</li>"}</ul>
            <ul>${analysis.aiSurface.governanceSignals.length ? analysis.aiSurface.governanceSignals.map((signal) => `<li>${escapeHtml(signal)}</li>`).join("") : "<li>No explicit AI governance language detected.</li>"}</ul>
            <ul>${exposureItems}</ul>
          </div>
        </div>
      </section>
    </div>
  </body>
</html>`;
};
