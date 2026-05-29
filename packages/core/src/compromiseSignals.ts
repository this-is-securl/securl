import type {
  CompromiseIndicator,
  CompromiseSignalsInfo,
  CtDiscoveryInfo,
  ExposureSummary,
  HtmlSecurityInfo,
} from "./types.js";
import { unique } from "./utils.js";

interface CompromiseSignalInput {
  finalUrl: URL;
  htmlSecurity: HtmlSecurityInfo;
  ctDiscovery: CtDiscoveryInfo;
  exposure: ExposureSummary;
}

const COLLECTION_BOUNDARY =
  "Public indicators only: visible HTML, public script and form destinations, public CT/DNS-derived observations, exposed public paths, and advisory metadata from detected client libraries. Reputation lookups are opt-in and are not run unless a provider is configured.";

const envValue = (key: string): string | undefined => {
  if (typeof process === "undefined" || !process.env) {
    return undefined;
  }
  return process.env[key];
};

const configuredReputationChecks = (): CompromiseSignalsInfo["reputationChecks"] => [
  {
    provider: "google_safe_browsing",
    status: envValue("GOOGLE_SAFE_BROWSING_API_KEY") ? "not_checked" : "not_configured",
    summary: envValue("GOOGLE_SAFE_BROWSING_API_KEY")
      ? "Google Safe Browsing key is configured, but live reputation lookup is not enabled in this passive engine build."
      : "Google Safe Browsing/Web Risk lookup is not configured.",
  },
  {
    provider: "urlhaus",
    status: envValue("URLHAUS_API_KEY") ? "not_checked" : "not_configured",
    summary: envValue("URLHAUS_API_KEY")
      ? "URLhaus key is configured, but live reputation lookup is not enabled in this passive engine build."
      : "URLhaus lookup is not configured.",
  },
  {
    provider: "virustotal",
    status: envValue("VIRUSTOTAL_API_KEY") ? "not_checked" : "not_configured",
    summary: envValue("VIRUSTOTAL_API_KEY")
      ? "VirusTotal key is configured, but live reputation lookup is not enabled in this passive engine build."
      : "VirusTotal lookup is not configured.",
  },
];

const addIndicator = (indicators: CompromiseIndicator[], indicator: CompromiseIndicator) => {
  const key = `${indicator.category}:${indicator.title}:${indicator.evidence.join("|")}`;
  if (!indicators.some((existing) => `${existing.category}:${existing.title}:${existing.evidence.join("|")}` === key)) {
    indicators.push(indicator);
  }
};

const severityRank: Record<CompromiseIndicator["severity"], number> = {
  info: 0,
  watch: 1,
  warning: 2,
  critical: 3,
};

const indicatorSort = (a: CompromiseIndicator, b: CompromiseIndicator) =>
  severityRank[b.severity] - severityRank[a.severity] || a.title.localeCompare(b.title);

const toSummary = (indicators: CompromiseIndicator[]): string => {
  if (!indicators.length) {
    return "No public indicators of compromise or abuse were inferred from the passive evidence collected.";
  }
  const critical = indicators.filter((item) => item.severity === "critical").length;
  const warning = indicators.filter((item) => item.severity === "warning").length;
  if (critical) {
    return `${critical} critical public abuse indicator${critical === 1 ? "" : "s"} should be reviewed immediately.`;
  }
  if (warning) {
    return `${warning} suspicious public indicator${warning === 1 ? "" : "s"} should be reviewed before treating the target as clean.`;
  }
  return `${indicators.length} low-confidence public signal${indicators.length === 1 ? "" : "s"} may be useful for triage.`;
};

export const emptyCompromiseSignals = (summary = "Compromise and abuse indicators were not assessed."): CompromiseSignalsInfo => ({
  posture: "not_assessed",
  summary,
  indicators: [],
  reputationChecks: configuredReputationChecks(),
  issues: [],
  strengths: [],
  collectionBoundary: COLLECTION_BOUNDARY,
});

export function buildCompromiseSignals({
  finalUrl,
  htmlSecurity,
  ctDiscovery,
  exposure,
}: CompromiseSignalInput): CompromiseSignalsInfo {
  const indicators: CompromiseIndicator[] = [];

  for (const form of htmlSecurity.forms) {
    if (form.hasPasswordField && form.offOriginSubmission) {
      addIndicator(indicators, {
        category: "credential_collection",
        severity: "critical",
        title: "Password form posts off-origin",
        detail: "A visible password form appears to submit to a different origin. This can be legitimate for hosted identity flows, but it is also a high-value compromise/phishing signal.",
        confidence: "medium",
        source: "html",
        evidence: [form.resolvedAction],
        action: "Confirm the destination is an expected identity provider or owned service before trusting the page.",
      });
    } else if (form.offOriginSubmission && form.method !== "GET") {
      addIndicator(indicators, {
        category: "credential_collection",
        severity: "watch",
        title: "Form posts off-origin",
        detail: "A visible form submits data to a different origin. Review whether this is expected for payment, CRM, newsletter, or identity workflows.",
        confidence: "medium",
        source: "html",
        evidence: [form.resolvedAction],
        action: "Validate the form destination and data handling path.",
      });
    }
  }

  for (const signal of htmlSecurity.suspiciousScriptSignals) {
    addIndicator(indicators, {
      category: "script_anomaly",
      severity: signal.severity === "warning" ? "warning" : "info",
      title: signal.title,
      detail: signal.detail,
      confidence: signal.severity === "warning" ? "medium" : "low",
      source: "html",
      evidence: signal.evidence,
      action: "Review whether the script pattern is expected, especially if CSP is weak or the host is unfamiliar.",
    });
  }

  for (const signal of htmlSecurity.passiveLeakSignals) {
    if (signal.category === "source_map" || signal.category === "public_token") {
      addIndicator(indicators, {
        category: "exposure",
        severity: signal.severity === "warning" ? "warning" : "watch",
        title: signal.title,
        detail: signal.detail,
        confidence: "medium",
        source: "html",
        evidence: signal.evidence,
        action: "Review whether the exposed artifact contains internal paths, secrets, or debugging details.",
      });
    }
  }

  for (const library of htmlSecurity.libraryRiskSignals) {
    const aliases = unique(library.vulnerabilities.flatMap((item) => item.aliases)).slice(0, 4);
    const hasHigh = library.vulnerabilities.some((item) => item.severity === "critical" || item.severity === "high");
    addIndicator(indicators, {
      category: "supply_chain",
      severity: hasHigh ? "warning" : "watch",
      title: "Known vulnerable client library visible",
      detail: `${library.packageName} ${library.version} matched ${library.vulnerabilities.length} OSV advisory match${library.vulnerabilities.length === 1 ? "" : "es"}.`,
      confidence: library.confidence,
      source: "asset",
      evidence: [library.sourceUrl, ...aliases].slice(0, 6),
      action: "Confirm whether the visible library is actually executed and update or remove it where possible.",
    });
  }

  for (const host of ctDiscovery.sampledHosts.filter((entry) => entry.suspectedTakeover)) {
    addIndicator(indicators, {
      category: "infrastructure",
      severity: "critical",
      title: "Possible subdomain takeover signal",
      detail: host.suspectedTakeover?.evidence || "A sampled CT host matched an unclaimed service pattern.",
      confidence: host.suspectedTakeover?.confidence || "medium",
      source: "ct",
      evidence: [host.host, ...(host.cnameTargets || [])].slice(0, 6),
      action: "Verify DNS ownership and remove or claim dangling service targets.",
    });
  }

  for (const probe of exposure.probes.filter((item) => item.finding === "exposed")) {
    addIndicator(indicators, {
      category: "exposure",
      severity: "warning",
      title: "Sensitive public path appears exposed",
      detail: probe.detail,
      confidence: "medium",
      source: "public_record",
      evidence: [new URL(probe.path, finalUrl.origin).toString(), String(probe.statusCode)],
      action: "Confirm whether this path should be public and restrict access if it exposes operational detail.",
    });
  }

  const sortedIndicators = indicators.sort(indicatorSort);
  const reputationChecks = configuredReputationChecks();
  const reputationFlagged = reputationChecks.some((check) => check.status === "flagged");
  const posture: CompromiseSignalsInfo["posture"] = reputationFlagged
    ? "reputation_flagged"
    : sortedIndicators.some((item) => item.severity === "critical")
      ? "suspicious"
      : sortedIndicators.length
        ? "review_recommended"
        : "no_public_ioc";

  return {
    posture,
    summary: toSummary(sortedIndicators),
    indicators: sortedIndicators,
    reputationChecks,
    issues: sortedIndicators
      .filter((item) => item.severity === "critical" || item.severity === "warning")
      .map((item) => item.title),
    strengths: sortedIndicators.length
      ? []
      : ["No passive public IOC-style indicators were inferred from the collected evidence."],
    collectionBoundary: COLLECTION_BOUNDARY,
  };
}
