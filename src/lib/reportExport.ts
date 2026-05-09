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
  const generatedAt = new Date().toLocaleDateString(undefined, {
    day: "2-digit",
    month: "long",
    year: "numeric",
  });
  const scanDate = new Date(analysis.scannedAt).toLocaleDateString(undefined, {
    day: "2-digit",
    month: "long",
    year: "numeric",
  });
  const donutDegrees = Math.round((analysis.score / 100) * 360);
  const overallPostureLabel =
    analysis.grade === "A" || analysis.grade === "B"
      ? "Good"
      : analysis.grade === "C"
        ? "Mixed"
        : "Needs attention";
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
  const actionBuckets = {
    fixNow: priorityActions.slice(0, 2),
    fixNext: priorityActions.slice(2, 4),
    keepWatching: weakestAreas.slice(0, 2),
  };
  const postureBreakdownItems = areas
    .map((area) => {
      const explanation =
        area.label === "Edge Security"
          ? "Missing or weak browser protections still shape the external read."
          : area.label === "Domain & Trust"
            ? "Email and ownership signals still have room to improve."
            : area.label === "Content Security"
              ? "The content policy baseline is useful, but browser hardening is incomplete."
              : area.label === "Exposure Control"
                ? "Low-noise probes found relatively little unexpected public exposure."
                : area.label === "API Surface"
                  ? "No obvious API posture concerns were surfaced from the passive checks."
                  : area.label === "Third-Party Trust"
                    ? "Provider exposure looked comparatively controlled on this scan."
                    : area.label === "AI & Automation"
                      ? "No significant AI-surface concern dominated this assessment."
                      : `${area.label} was scored as ${area.status}.`;
      const toneClass =
        area.status === "strong" ? "tone-strong" : area.status === "watch" ? "tone-watch" : "tone-weak";
      return `
        <div class="overview-row">
          <div>
            <p class="overview-area">${escapeHtml(area.label)}</p>
            <p class="overview-explainer">${escapeHtml(explanation)}</p>
          </div>
          <div class="overview-bar-wrap">
            <div class="overview-bar"><span class="${toneClass}" style="width:${Math.max(8, area.score)}%"></span></div>
          </div>
          <div class="overview-score">${area.score}/100</div>
        </div>`;
    })
    .join("");
  const topStrengths = analysis.strengths.slice(0, 5);
  const strengthsHtml = topStrengths.length
    ? topStrengths.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No explicit strengths were recorded from this scan.</li>";
  const reportLimitItems = buildAssessmentLimits(analysis)
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Security Report - ${escapeHtml(analysis.host)}</title>
    <style>
      :root { color-scheme: light; --text:#0f172a; --muted:#475569; --line:#dbe3ef; --panel:#ffffff; --panel-soft:#f8fafc; --accent:#cf7a36; --accent-soft:#f3d7bd; --danger:#8e5c3b; --ok:#dbe7f5; --watch:#d0a56e; }
      * { box-sizing: border-box; }
      body { margin:0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color:var(--text); background:#fff; }
      h1,h2,h3,p,ul { margin:0; }
      ul { padding-left:18px; line-height:1.6; }
      li + li { margin-top:8px; }
      .page { width:100%; max-width:1040px; margin:0 auto; padding:34px 28px 40px; }
      .page-break { break-before: page; page-break-before: always; }
      .section { margin-top: 24px; }
      .eyebrow { font-size:12px; letter-spacing:.24em; text-transform:uppercase; color:var(--muted); margin-bottom:10px; }
      .panel { background:var(--panel); border:1px solid var(--line); border-radius:28px; padding:24px; }
      .cover { display:grid; grid-template-columns:minmax(0,1fr) 220px; gap:28px; align-items:start; min-height:220px; }
      .cover-title { font-size:18px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; color:#334155; }
      .cover-target { margin-top:26px; font-size:64px; line-height:.94; letter-spacing:-.06em; font-weight:800; word-break:break-word; }
      .cover-meta { margin-top:26px; display:grid; gap:6px; color:var(--muted); font-size:15px; }
      .cover-score { display:grid; place-items:center; border-radius:28px; background:linear-gradient(180deg,#f3d7bd,#f7e6d5); padding:18px; }
      .cover-donut { width:160px; height:160px; border-radius:999px; display:grid; place-items:center; background:conic-gradient(var(--accent) 0deg ${donutDegrees}deg, rgba(207,122,54,.15) ${donutDegrees}deg 360deg); }
      .cover-donut-inner { width:114px; height:114px; border-radius:999px; background:#fff; display:grid; place-items:center; text-align:center; }
      .cover-donut-inner strong { display:block; font-size:54px; line-height:.9; color:var(--accent); }
      .cover-donut-inner span { display:block; margin-top:8px; font-size:20px; font-weight:700; color:#334155; }
      .cover-verdict { margin-top:22px; font-size:20px; font-weight:700; color:#111827; }
      .cover-risk { margin-top:8px; font-size:20px; line-height:1.45; color:#1f2937; max-width:38ch; }
      .action-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }
      .action-card { border:1px solid var(--line); border-radius:24px; padding:22px; background:var(--panel-soft); min-height:220px; }
      .action-card strong { display:block; font-size:18px; margin-bottom:14px; }
      .action-card ul { padding-left:18px; }
      .action-card.fix-now { border-color:#e5c8ab; background:#fff7ef; }
      .action-card.fix-next { border-color:#e6ddce; background:#fcfaf7; }
      .action-card.keep-watching { border-color:#d9e0ea; background:#f8fafc; }
      .overview-block { display:grid; gap:18px; }
      .overview-row { display:grid; grid-template-columns:minmax(0,1.2fr) 1fr 80px; gap:16px; align-items:center; }
      .overview-area { font-size:17px; font-weight:700; }
      .overview-explainer { margin-top:6px; color:var(--muted); font-size:14px; line-height:1.55; }
      .overview-bar { height:12px; background:#e9eef5; border-radius:999px; overflow:hidden; }
      .overview-bar span { display:block; height:100%; border-radius:999px; background:linear-gradient(90deg,#9d5a28,#d08a4b); }
      .overview-bar span.tone-strong { background:linear-gradient(90deg,#c6d4e6,#e2e8f0); }
      .overview-bar span.tone-watch { background:linear-gradient(90deg,#b56a2c,#d89a63); }
      .overview-bar span.tone-weak { background:linear-gradient(90deg,#8e5c3b,#b56a2c); }
      .overview-score { text-align:right; font-size:16px; font-weight:800; color:#1f2937; }
      .cards-2 { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }
      .cards-3 { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }
      .finding-card, .info-card { border:1px solid var(--line); border-radius:24px; padding:22px; background:var(--panel); }
      .finding-head { display:flex; justify-content:space-between; gap:12px; align-items:start; }
      .finding-pill { display:inline-flex; align-items:center; border-radius:999px; padding:6px 10px; font-size:11px; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
      .finding-pill.critical { background:#fff1e8; color:#8e5c3b; border:1px solid #f0cfb3; }
      .finding-pill.warning { background:#fff7ef; color:#b56a2c; border:1px solid #ebd1b5; }
      .finding-pill.info { background:#f8fafc; color:#475569; border:1px solid #dce4ef; }
      .finding-card h3 { font-size:20px; line-height:1.3; margin-bottom:10px; }
      .finding-card p { color:var(--muted); line-height:1.65; }
      .plain-list li { margin-top:10px; }
      .small-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }
      .note-box { border:1px solid var(--line); border-radius:20px; padding:18px; background:var(--panel-soft); }
      .note-box p { color:var(--muted); line-height:1.6; }
      .footer-cta { border-top:1px solid var(--line); margin-top:20px; padding-top:16px; font-size:14px; color:var(--muted); }
      .muted { color:var(--muted); }
      @media (max-width: 920px) {
        .cover, .action-grid, .cards-2, .cards-3, .small-grid, .overview-row { grid-template-columns:1fr; }
        .cover-target { font-size:46px; }
        .overview-score { text-align:left; }
      }
      @page { margin: 12mm; }
    </style>
  </head>
  <body>
    <div class="page">
      <section class="cover">
        <div>
          <div class="cover-title">External Security Posture Report</div>
          <h1 class="cover-target">${escapeHtml(analysis.finalUrl)}</h1>
          <div class="cover-meta">
            <div>Generated: ${escapeHtml(generatedAt)}</div>
            <div>Scan Date: ${escapeHtml(scanDate)}</div>
            <div>Prepared by SecURL</div>
          </div>
          <p class="cover-verdict">Overall Posture: ${escapeHtml(overallPostureLabel)}</p>
          <p class="cover-risk">${escapeHtml(analysis.executiveSummary.mainRisk)}</p>
        </div>
        <div class="cover-score">
          <div class="cover-donut">
            <div class="cover-donut-inner">
              <div>
                <strong>${escapeHtml(analysis.grade)}</strong>
                <span>${analysis.score}/100</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Priority actions</div>
        <h2>Where attention should go first</h2>
        <div class="action-grid" style="margin-top:18px;">
          <div class="action-card fix-now">
            <strong>Fix Now</strong>
            <ul class="plain-list">
              ${(actionBuckets.fixNow.length
                ? actionBuckets.fixNow.map((action) => `<li><strong>${escapeHtml(action.title)}</strong><br>${escapeHtml(action.detail)}</li>`).join("")
                : "<li>No immediate high-impact action was generated from this scan.</li>")}
            </ul>
          </div>
          <div class="action-card fix-next">
            <strong>Fix Next</strong>
            <ul class="plain-list">
              ${(actionBuckets.fixNext.length
                ? actionBuckets.fixNext.map((action) => `<li><strong>${escapeHtml(action.title)}</strong><br>${escapeHtml(action.detail)}</li>`).join("")
                : "<li>After the immediate fixes land, address the remaining hardening and trust gaps.</li>")}
            </ul>
          </div>
          <div class="action-card keep-watching">
            <strong>Keep Watching</strong>
            <ul class="plain-list">
              ${(actionBuckets.keepWatching.length
                ? actionBuckets.keepWatching.map((area) => `<li><strong>${escapeHtml(area.label)}</strong> (${area.score}/100)</li>`).join("")
                : "<li>No weak posture areas dominated this scan.</li>")}
              <li>${escapeHtml(changeHeadline)}</li>
            </ul>
          </div>
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Posture overview</div>
        <h2>Category scores</h2>
        <div class="panel overview-block" style="margin-top:18px;">
          ${postureBreakdownItems}
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Key findings</div>
        <h2>Top risks explained plainly</h2>
        <div class="cards-2" style="margin-top:18px;">
          ${topFindings
            .slice(0, 6)
            .map(
              (issue) => `
                <div class="finding-card">
                  <div class="finding-head">
                    <h3>${escapeHtml(issue.title)}</h3>
                    <span class="finding-pill ${escapeHtml(issue.severity)}">${escapeHtml(issue.severity)}</span>
                  </div>
                  <p>${escapeHtml(issue.detail)}</p>
                </div>`,
            )
            .join("")}
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Strengths &amp; positive signals</div>
        <h2>What is already working well</h2>
        <div class="cards-2" style="margin-top:18px;">
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Positive signals</h3>
            <ul class="plain-list">${strengthsHtml}</ul>
          </div>
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Most reassuring areas</h3>
            <p class="muted">${escapeHtml(strongestAreaText)}</p>
            <div class="note-box" style="margin-top:16px;">
              <p>${escapeHtml(analysis.executiveSummary.overview)}</p>
            </div>
          </div>
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Technical details</div>
        <h2>Evidence for the security team</h2>
        <div class="cards-2" style="margin-top:18px;">
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Full findings</h3>
            <ul>${issueItems}</ul>
          </div>
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Domain &amp; email trust</h3>
            <p>SPF: ${escapeHtml(analysis.domainSecurity.spf ?? "Not found")}</p>
            <p>DMARC: ${escapeHtml(analysis.domainSecurity.dmarc ?? "Not found")}</p>
            <p>DNSSEC: ${escapeHtml(analysis.domainSecurity.dnssec.status)}</p>
            <p>MX count: ${analysis.domainSecurity.mxRecords.length}</p>
            <p>CAA count: ${analysis.domainSecurity.caaRecords.length}</p>
            <div class="note-box" style="margin-top:16px;">
              <p>${escapeHtml(disclosure.summary)}</p>
            </div>
          </div>
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Infrastructure &amp; edge</h3>
            <p>Queried domain: ${escapeHtml(analysis.ctDiscovery.queriedDomain)}</p>
            <p class="muted" style="margin-top:8px;">${escapeHtml(analysis.ctDiscovery.coverageSummary)}</p>
            <ul style="margin-top:14px;">${ctItems}</ul>
          </div>
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Third-party &amp; AI surface</h3>
            <p>Classification: ${escapeHtml(aiSummary)}</p>
            <p class="muted" style="margin-top:8px;">Vendors: ${escapeHtml(analysis.aiSurface.vendors.length ? analysis.aiSurface.vendors.map((vendor) => vendor.name).join(", ") : "None detected")}</p>
            <ul style="margin-top:14px;">${analysis.thirdPartyTrust.providers.length
              ? analysis.thirdPartyTrust.providers.map((provider) => `<li><strong>${escapeHtml(provider.name)}</strong> [${escapeHtml(provider.category)} | ${escapeHtml(provider.risk)} risk] ${escapeHtml(provider.domain)}</li>`).join("")
              : "<li>No third-party providers recorded.</li>"}</ul>
          </div>
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Recommendations &amp; next steps</div>
        <h2>What to do next</h2>
        <div class="cards-2" style="margin-top:18px;">
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Prioritised roadmap</h3>
            <ul>${priorityItems}</ul>
          </div>
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Monitoring suggestion</h3>
            <p class="muted">Track ${escapeHtml(weakestAreaText)} over time and watch for movement in the findings count, header changes, and trust signals.</p>
            <div class="note-box" style="margin-top:16px;">
              <p>${diff ? escapeHtml(changeHeadline) : "This report is a baseline. The next saved scan will tell you whether the posture is improving, stable, or regressing."}</p>
            </div>
            <div class="footer-cta">SecURL monitoring helps turn one-time posture reads into a recurring external assurance view.</div>
          </div>
        </div>
      </section>

      <section class="section page-break">
        <div class="eyebrow">Appendix / limitations</div>
        <h2>How to read this report</h2>
        <div class="small-grid" style="margin-top:18px;">
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Limits of this assessment</h3>
            <ul>${reportLimitItems}</ul>
          </div>
          <div class="info-card">
            <h3 style="margin-bottom:12px;">Method notes</h3>
            <ul>
              <li>This report is based on an external, unauthenticated, passive-first assessment.</li>
              <li>It is intended to support posture review, triage, and follow-up planning.</li>
              <li>It does not replace authenticated testing, configuration review, or exploitation work.</li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  </body>
</html>`;
};
