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
    `This scan grades ${analysis.host} as ${analysis.grade} (${analysis.score}/100). The main concentration of risk is ${weakAreaText}.`,
    `The finding mix is ${criticalCount} critical, ${warningCount} warning, and ${analysis.issues.length - criticalCount - warningCount} informational item${analysis.issues.length - criticalCount - warningCount === 1 ? "" : "s"}. ${analysis.executiveSummary.mainRisk}`,
    `The strongest visible posture area is ${strongAreaText}. ${changeText}`,
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
    return hsts?.value ? `Observed HSTS value: ${hsts.value}` : "Strict-Transport-Security was not present on the scanned response.";
  }
  if (normalized.includes("content security") || normalized.includes("csp")) {
    const csp = analysis.headers.find((header) => header.key === "content-security-policy");
    return csp?.value ? `Observed CSP value: ${csp.value}` : "Content-Security-Policy was not present on the scanned response.";
  }
  if (normalized.includes("third-party")) {
    return `${analysis.thirdPartyTrust.totalProviders} provider${analysis.thirdPartyTrust.totalProviders === 1 ? "" : "s"} detected; ${analysis.thirdPartyTrust.highRiskProviders} marked higher risk.`;
  }
  if (normalized.includes("security.txt")) {
    return `security.txt status: ${analysis.securityTxt.status}.`;
  }
  if (normalized.includes("email") || normalized.includes("dmarc")) {
    return `SPF: ${analysis.domainSecurity.spf ?? "not found"}; DMARC: ${analysis.domainSecurity.dmarc ?? "not found"}.`;
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
    "This is an external, unauthenticated, passive-first read. It does not prove exploitability or replace authenticated application testing.",
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

const buildNarrativeMarkdown = (analysis: AnalysisResult, diff: HistoryDiff | null, priorityActions: ReturnType<typeof getPriorityActions>) => [
  "## What This Means",
  "",
  ...buildPostureNarrative(analysis, diff).map((line) => `- ${line}`),
  "",
  "## Most Important Observed Findings",
  "",
  ...(getTopFindings(analysis).length
    ? getTopFindings(analysis).map((issue) => `- [${issue.severity}] ${issue.title}: ${issue.detail}`)
    : ["- No core findings were recorded."]),
  "",
  "## Decision View",
  "",
  ...(priorityActions.length
    ? priorityActions.flatMap((action, index) => [
        `### ${index + 1}. ${action.title}`,
        "",
        `- Why it matters: ${action.detail}`,
        `- Evidence: ${buildEvidenceForAction(analysis, action.title)}`,
        ...(action.priorityReason ? [`- Priority rationale: ${action.priorityReason}`] : []),
        "",
      ])
    : ["- No high-priority remediation actions were generated from this scan.", ""]),
  "## Questions To Resolve",
  "",
  ...buildStakeholderQuestions(analysis).map((question) => `- ${question}`),
  "",
  "## Assessment Boundaries",
  "",
  ...buildAssessmentLimits(analysis).map((limit) => `- ${limit}`),
  "",
];

const buildNarrativeHtml = (analysis: AnalysisResult, diff: HistoryDiff | null, priorityActions: ReturnType<typeof getPriorityActions>) => `
    <div class="card insight">
      <h2>What This Means</h2>
      ${buildPostureNarrative(analysis, diff).map((line) => `<p>${escapeHtml(line)}</p>`).join("")}
    </div>
    <div class="card">
      <h2>Most Important Observed Findings</h2>
      <ul>${getTopFindings(analysis).length
        ? getTopFindings(analysis).map((issue) => `<li><strong>[${escapeHtml(issue.severity)}] ${escapeHtml(issue.title)}</strong><br>${escapeHtml(issue.detail)}</li>`).join("")
        : "<li>No core findings were recorded.</li>"}</ul>
    </div>
    <div class="card">
      <h2>Decision View</h2>
      ${priorityActions.length
        ? priorityActions
            .map(
              (action, index) => `
      <div class="action">
        <h3>${index + 1}. ${escapeHtml(action.title)}</h3>
        <p><strong>Why it matters:</strong> ${escapeHtml(action.detail)}</p>
        <p><strong>Evidence:</strong> ${escapeHtml(buildEvidenceForAction(analysis, action.title))}</p>
        ${action.priorityReason ? `<p class="muted">${escapeHtml(action.priorityReason)}</p>` : ""}
      </div>`,
            )
            .join("")
        : "<p>No high-priority remediation actions were generated from this scan.</p>"}
    </div>
    <div class="card">
      <h2>Questions To Resolve</h2>
      <ul>${buildStakeholderQuestions(analysis).map((question) => `<li>${escapeHtml(question)}</li>`).join("")}</ul>
    </div>
    <div class="card">
      <h2>Assessment Boundaries</h2>
      <ul>${buildAssessmentLimits(analysis).map((limit) => `<li>${escapeHtml(limit)}</li>`).join("")}</ul>
    </div>`;

const buildExportHeadlineMarkdown = (diff: HistoryDiff | null) =>
  diff
    ? [
        `- Change headline: score ${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}, ${diff.newIssues.length} new issue${diff.newIssues.length === 1 ? "" : "s"}, ${diff.resolvedIssues.length} resolved.`,
        "- Category deltas are intentionally omitted from the export headline because per-category baseline snapshots are not embedded in exported reports.",
      ]
    : ["- Change headline: no previous local snapshot was available for comparison."];

const buildExportHeadlineHtml = (diff: HistoryDiff | null) =>
  diff
    ? [
        `<p>Change headline: score ${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}, ${diff.newIssues.length} new issue${diff.newIssues.length === 1 ? "" : "s"}, ${diff.resolvedIssues.length} resolved.</p>`,
        "<p>Category deltas are intentionally omitted from the export headline because per-category baseline snapshots are not embedded in exported reports.</p>",
      ].join("")
    : "<p>Change headline: no previous local snapshot was available for comparison.</p>";

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
    `- Grade: ${analysis.grade}`,
    `- Score: ${analysis.score}/100`,
    `- Status: ${analysis.statusCode}`,
    ...buildExportHeadlineMarkdown(diff),
    "",
    "## Executive Readout",
    "",
    `- Overview: ${analysis.executiveSummary.overview}`,
    `- Main risk: ${analysis.executiveSummary.mainRisk}`,
    ...analysis.executiveSummary.takeaways.map((takeaway) => `- ${takeaway}`),
    "",
    ...buildNarrativeMarkdown(analysis, diff, priorityActions),
    "## Summary",
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
    "## Category Scores",
    "",
    "- These category scores are directional breakdowns by posture area. They explain where risk is concentrated, but they are not intended to exactly match the single overall score.",
    "",
    ...areas.map((area) => `- ${area.label}: ${area.score}/100 (${area.status})`),
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
    "## Changes Since Last Scan",
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
    "## security.txt",
    "",
    `- Status: ${analysis.securityTxt.status}`,
    ...(analysis.securityTxt.url ? [`- URL: ${analysis.securityTxt.url}`] : []),
    ...(analysis.securityTxt.issues.length ? analysis.securityTxt.issues.map((issue) => `- ${issue}`) : ["- No security.txt issues recorded."]),
    "",
    "## Domain & Email Security",
    "",
    `- SPF: ${analysis.domainSecurity.spf ?? "Not found"}`,
    `- DMARC: ${analysis.domainSecurity.dmarc ?? "Not found"}`,
    `- DNSSEC: ${analysis.domainSecurity.dnssec.status}`,
    `- MX count: ${analysis.domainSecurity.mxRecords.length}`,
    `- CAA count: ${analysis.domainSecurity.caaRecords.length}`,
    "",
    "## Identity Provider & OAuth Surface",
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
    "## Certificate Transparency",
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
    "## WAF & Edge Fingerprint",
    "",
    `- Summary: ${analysis.wafFingerprint.summary}`,
    ...buildWafLines(analysis),
    ...(analysis.wafFingerprint.edgeSignals.length
      ? analysis.wafFingerprint.edgeSignals.map((signal) => `- Edge evidence: ${signal}`)
      : ["- No extra edge evidence recorded."]),
    "",
    "## Public Trust Signals",
    "",
    `- HSTS preload status: ${analysis.publicSignals.hstsPreload.status}`,
    `- HSTS preload note: ${analysis.publicSignals.hstsPreload.summary}`,
    "",
    "## Disclosure & Trust",
    "",
    `- Summary: ${disclosure.summary}`,
    ...(disclosure.discoveredPages.length
      ? disclosure.discoveredPages.map((page) => `- Discovered page: ${page}`)
      : ["- No obvious trust or policy pages discovered."]),
    ...disclosure.strengths.map((item) => `- ${item}`),
    ...disclosure.issues.map((item) => `- ${item}`),
    "",
    "## Passive Discovery",
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
    "## Auth Surface",
    "",
    `- Summary: ${authSurface.summary}`,
    `- Auth paths: ${authSurface.authPaths.length}`,
    `- Password forms: ${authSurface.passwordFormCount}`,
    `- External password form targets: ${authSurface.externalPasswordForms.length}`,
    ...(authSurface.authPaths.length
      ? authSurface.authPaths.map((item) => `- ${item.path} (${item.category})`)
      : ["- No auth-adjacent paths discovered passively."]),
    "",
    "## Data Collection Surface",
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
    "## Detected Stack",
    "",
    ...buildTechnologyLines(analysis),
    "",
    "## Third-Party Trust",
    "",
    `- Providers detected: ${analysis.thirdPartyTrust.totalProviders}`,
    `- Higher-risk providers: ${analysis.thirdPartyTrust.highRiskProviders}`,
    `- Summary: ${analysis.thirdPartyTrust.summary}`,
    ...buildThirdPartyLines(analysis),
    ...(analysis.thirdPartyTrust.issues.length
      ? analysis.thirdPartyTrust.issues.map((issue) => `- ${issue}`)
      : ["- No third-party trust issues recorded."]),
    "",
    "## AI Surface",
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
    "## Low-Noise Exposure Checks",
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

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Security Report - ${escapeHtml(analysis.host)}</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 40px; color: #0f172a; }
      h1, h2 { margin-bottom: 8px; }
      h3 { margin: 16px 0 6px; }
      .meta, .card { margin-bottom: 24px; }
      .card { border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; background: #f8fafc; }
      .insight { background: #eef6ff; border-color: #bfdbfe; }
      .action { border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 12px; }
      .action:first-of-type { border-top: 0; padding-top: 0; margin-top: 0; }
      .muted { color: #475569; }
      ul { line-height: 1.6; }
    </style>
  </head>
  <body>
    <h1>Security Report: ${escapeHtml(analysis.host)}</h1>
    <div class="meta">
      <p>Final URL: ${escapeHtml(analysis.finalUrl)}</p>
      <p>Scanned: ${escapeHtml(new Date(analysis.scannedAt).toLocaleString())}</p>
      <p>Grade: ${escapeHtml(analysis.grade)}</p>
      <p>Score: ${analysis.score}/100</p>
      <p>Status: ${analysis.statusCode}</p>
      ${buildExportHeadlineHtml(diff)}
    </div>
    <div class="card">
      <h2>Executive Readout</h2>
      <p>${escapeHtml(analysis.executiveSummary.overview)}</p>
      <p><strong>Main risk:</strong> ${escapeHtml(analysis.executiveSummary.mainRisk)}</p>
      <ul>${analysis.executiveSummary.takeaways.map((takeaway) => `<li>${escapeHtml(takeaway)}</li>`).join("")}</ul>
    </div>
    ${buildNarrativeHtml(analysis, diff, priorityActions)}
    <div class="card">
      <h2>Summary</h2>
      <p>Critical findings: ${summary.critical}</p>
      <p>Priority warning findings: ${summary.priorityWarnings}</p>
      <p>Supporting watch items: ${summary.supportingWatchItems}</p>
      <p>Observed signals: ${summary.observedSignals}</p>
    </div>
    <div class="card">
      <h2>Risk Themes</h2>
      <p>${escapeHtml(taxonomy.summary)}</p>
      <p><strong>OWASP themes</strong></p>
      <ul>${owaspThemeItems}</ul>
      <p><strong>MITRE relevance</strong></p>
      <ul>${mitreThemeItems}</ul>
    </div>
    <div class="card">
      <h2>Category Scores</h2>
      <p>These category scores are directional breakdowns by posture area. They explain where risk is concentrated, but they are not intended to exactly match the single overall score.</p>
      <ul>${areaItems}</ul>
    </div>
    <div class="card">
      <h2>Key Findings</h2>
      <ul>${issueItems}</ul>
    </div>
    <div class="card">
      <h2>Priority Actions</h2>
      <ul>${priorityItems}</ul>
    </div>
    <div class="card">
      <h2>Changes Since Last Scan</h2>
      ${diff
        ? `
      <p>Score delta: ${diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta ?? 0}</p>
      <p>New issues: ${diff.newIssues.length}</p>
      <p>Resolved issues: ${diff.resolvedIssues.length}</p>
      <p>Header changes: ${diff.headerChanges.length}</p>
      <p>New third parties: ${diff.newThirdPartyProviders.length}</p>
      <p>New AI vendors: ${diff.newAiVendors.length}</p>
      <p>New WAF signals: ${diff.wafProviderChanges.newProviders.length}</p>
      <ul>${diff.summary.length ? diff.summary.map((item) => `<li>${escapeHtml(item)}</li>`).join("") : "<li>No material posture changes summarized.</li>"}</ul>
      `
        : "<p>No previous local snapshot available for comparison.</p>"}
    </div>
    <div class="card">
      <h2>Domain &amp; Email Security</h2>
      <p>SPF: ${escapeHtml(analysis.domainSecurity.spf ?? "Not found")}</p>
      <p>DMARC: ${escapeHtml(analysis.domainSecurity.dmarc ?? "Not found")}</p>
      <p>DNSSEC: ${escapeHtml(analysis.domainSecurity.dnssec.status)}</p>
      <p>MX count: ${analysis.domainSecurity.mxRecords.length}</p>
      <p>CAA count: ${analysis.domainSecurity.caaRecords.length}</p>
    </div>
    <div class="card">
      <h2>Identity Provider &amp; OAuth Surface</h2>
      <p>Detected: ${analysis.identityProvider.detected ? "Yes" : "No"}</p>
      <p>Provider: ${escapeHtml(analysis.identityProvider.provider ?? "Not identified")}</p>
      <p>Protocol: ${escapeHtml(analysis.identityProvider.protocol ?? "Not inferred")}</p>
      <p>OIDC config: ${escapeHtml(analysis.identityProvider.openIdConfigurationUrl ?? "Not observed")}</p>
      <p>Redirect origins: ${escapeHtml(analysis.identityProvider.redirectOrigins.length ? analysis.identityProvider.redirectOrigins.join(", ") : "None recorded")}</p>
      <p>Auth-like hosts: ${escapeHtml(analysis.identityProvider.authHostCandidates.length ? analysis.identityProvider.authHostCandidates.join(", ") : "None recorded")}</p>
      <p>Login paths: ${escapeHtml(analysis.identityProvider.loginPaths.length ? analysis.identityProvider.loginPaths.join(", ") : "None recorded")}</p>
      <p>Tenant clues: ${escapeHtml(analysis.identityProvider.tenantSignals.length ? analysis.identityProvider.tenantSignals.join(", ") : "None recorded")}</p>
      <ul>${analysis.identityProvider.redirectUriSignals.length
        ? analysis.identityProvider.redirectUriSignals.map((signal) => `<li>Review redirect URI signal: ${escapeHtml(signal)}</li>`).join("")
        : "<li>No public redirect_uri-style parameters were recorded.</li>"}</ul>
    </div>
    <div class="card">
      <h2>Certificate Transparency</h2>
      <p>Queried domain: ${escapeHtml(analysis.ctDiscovery.queriedDomain)}</p>
      <p>${escapeHtml(analysis.ctDiscovery.coverageSummary)}</p>
      <p>Subdomains discovered: ${analysis.ctDiscovery.subdomains.length}</p>
      <p>Wildcard entries: ${analysis.ctDiscovery.wildcardEntries.length}</p>
      <ul>${ctItems}</ul>
      <ul>${buildCtSampleLines(analysis).map((line) => `<li>${escapeHtml(line.slice(2))}</li>`).join("")}</ul>
      <ul>${analysis.ctDiscovery.sampledHosts.some((host) => host.suspectedTakeover)
        ? analysis.ctDiscovery.sampledHosts
            .filter((host) => host.suspectedTakeover)
            .map((host) => `<li>Possible takeover: ${escapeHtml(host.host)} via ${escapeHtml(host.suspectedTakeover?.provider)} (${escapeHtml(host.suspectedTakeover?.confidence)} confidence)</li>`)
            .join("")
        : "<li>No takeover-style signatures were observed in the sampled CT hosts.</li>"}</ul>
    </div>
    <div class="card">
      <h2>WAF &amp; Edge Fingerprint</h2>
      <p>${escapeHtml(analysis.wafFingerprint.summary)}</p>
      <ul>${buildWafLines(analysis).map((line) => `<li>${escapeHtml(line.slice(2))}</li>`).join("")}</ul>
      <ul>${analysis.wafFingerprint.edgeSignals.length
        ? analysis.wafFingerprint.edgeSignals.map((signal) => `<li>${escapeHtml(signal)}</li>`).join("")
        : "<li>No extra edge evidence recorded.</li>"}</ul>
    </div>
    <div class="card">
      <h2>Public Trust Signals</h2>
      <p>HSTS preload status: ${escapeHtml(analysis.publicSignals.hstsPreload.status)}</p>
      <p>${escapeHtml(analysis.publicSignals.hstsPreload.summary)}</p>
    </div>
    <div class="card">
      <h2>Disclosure & Trust</h2>
      <p>${escapeHtml(disclosure.summary)}</p>
      <ul>
        ${disclosure.discoveredPages.length ? disclosure.discoveredPages.map((item) => `<li>Discovered page: ${escapeHtml(item)}</li>`).join("") : "<li>No obvious trust or policy pages discovered.</li>"}
        ${disclosure.strengths.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        ${disclosure.issues.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
    </div>
    <div class="card">
      <h2>Passive Discovery</h2>
      <p>Page title: ${escapeHtml(analysis.htmlSecurity.pageTitle ?? "Unavailable")}</p>
      <p>Discovery sources: ${escapeHtml(analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded")}</p>
      <p>Same-origin paths discovered: ${analysis.htmlSecurity.firstPartyPaths.length}</p>
      <ul>${discoveryItems}</ul>
      <p>Same-site hosts referenced: ${analysis.htmlSecurity.sameSiteHosts.length}</p>
      <ul>${sameSiteHostItems}</ul>
      <p>Passive leak and fingerprinting signals:</p>
      <ul>${passiveLeakItems}</ul>
      <p>Library version risk:</p>
      <ul>${libraryRiskItems}</ul>
    </div>
    <div class="card">
      <h2>Auth Surface</h2>
      <p>${escapeHtml(authSurface.summary)}</p>
      <p>Auth paths: ${authSurface.authPaths.length}</p>
      <p>Password forms: ${authSurface.passwordFormCount}</p>
      <p>External password targets: ${authSurface.externalPasswordForms.length}</p>
      <ul>${authSurface.authPaths.length
        ? authSurface.authPaths.map((item) => `<li>${escapeHtml(item.path)} (${escapeHtml(item.category)})</li>`).join("")
        : "<li>No auth-adjacent paths discovered passively.</li>"}</ul>
    </div>
    <div class="card">
      <h2>Data Collection Surface</h2>
      <p>${escapeHtml(dataCollection.summary)}</p>
      <p>Public forms: ${dataCollection.totalForms}</p>
      <p>POST forms: ${dataCollection.postForms}</p>
      <p>External form targets: ${dataCollection.externalForms.length}</p>
      <p>Insecure form submits: ${dataCollection.insecureForms}</p>
      <ul>${buildFormLines(analysis).map((line) => `<li>${escapeHtml(line.slice(2))}</li>`).join("")}</ul>
      <ul>${dataCollection.externalForms.length
        ? dataCollection.externalForms.map((target) => `<li>${escapeHtml(target)}</li>`).join("")
        : "<li>No external form targets were detected.</li>"}</ul>
    </div>
    <div class="card">
      <h2>Detected Stack</h2>
      <ul>${technologyItems}</ul>
    </div>
    <div class="card">
      <h2>Third-Party Trust</h2>
      <p>${escapeHtml(analysis.thirdPartyTrust.summary)}</p>
      <p>Providers detected: ${analysis.thirdPartyTrust.totalProviders}</p>
      <p>Higher-risk providers: ${analysis.thirdPartyTrust.highRiskProviders}</p>
      <ul>${analysis.thirdPartyTrust.providers.length
        ? analysis.thirdPartyTrust.providers.map((provider) => `<li><strong>${escapeHtml(provider.name)}</strong> [${escapeHtml(provider.category)} | ${escapeHtml(provider.risk)} risk] ${escapeHtml(provider.domain)}<br>${escapeHtml(provider.evidence)}</li>`).join("")
        : "<li>No third-party providers recorded.</li>"}</ul>
    </div>
    <div class="card">
      <h2>AI Surface</h2>
      <p>Classification: ${escapeHtml(aiSummary)}</p>
      <p>AI detected: ${analysis.aiSurface.detected ? "Yes" : "No"}</p>
      <p>Assistant visible: ${analysis.aiSurface.assistantVisible ? "Yes" : "No"}</p>
      <p>Vendors: ${escapeHtml(analysis.aiSurface.vendors.length ? analysis.aiSurface.vendors.map((vendor) => vendor.name).join(", ") : "None detected")}</p>
      <p>AI paths: ${escapeHtml(analysis.aiSurface.discoveredPaths.length ? analysis.aiSurface.discoveredPaths.join(", ") : "None detected")}</p>
      <p>AI privacy signals: ${escapeHtml(analysis.aiSurface.privacySignals.length ? analysis.aiSurface.privacySignals.join(" ") : "None detected")}</p>
      <p>AI governance signals: ${escapeHtml(analysis.aiSurface.governanceSignals.length ? analysis.aiSurface.governanceSignals.join(" ") : "None detected")}</p>
    </div>
    <div class="card">
      <h2>Low-Noise Exposure Checks</h2>
      <ul>${exposureItems}</ul>
    </div>
  </body>
</html>`;
};
