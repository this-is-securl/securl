import type {
  AiSurfaceInfo,
  ApiSurfaceInfo,
  DomainSecurityInfo,
  HtmlSecurityInfo,
  IdentityProviderInfo,
  InfrastructureInfo,
  IssueConfidence,
  PassiveIntelligenceInfo,
  PassiveIntelligenceSignal,
  PublicSignalsInfo,
  SecurityTxtInfo,
  TechnologyResult,
  ThirdPartyProvider,
  ThirdPartyTrustInfo,
  WafFingerprintInfo,
} from "./types.js";
import { unique } from "./utils.js";

interface PassiveIntelligenceInput {
  technologies: TechnologyResult[];
  infrastructure: InfrastructureInfo;
  thirdPartyTrust: ThirdPartyTrustInfo;
  htmlSecurity: HtmlSecurityInfo;
  aiSurface: AiSurfaceInfo;
  domainSecurity: DomainSecurityInfo;
  securityTxt: SecurityTxtInfo;
  publicSignals: PublicSignalsInfo;
  identityProvider: IdentityProviderInfo;
  wafFingerprint: WafFingerprintInfo;
  apiSurface: ApiSurfaceInfo;
  assessmentLimitation?: { limited: boolean; title: string | null } | null;
}

const SOURCE_BOUNDARY =
  "Passive read only: normal HTTP/TLS responses, public DNS records, public trust records, and visible page assets. No port scanning, brute forcing, login probing, exploit payloads, or bypass attempts are used.";

const titleCase = (value: string): string =>
  value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const describeList = (items: string[], fallback: string, limit = 3): string => {
  const values = unique(items.filter(Boolean));
  if (!values.length) return fallback;
  if (values.length <= limit) return values.join(", ");
  return `${values.slice(0, limit).join(", ")} +${values.length - limit} more`;
};

const categoryRank: Record<PassiveIntelligenceSignal["risk"], number> = {
  attention: 0,
  watch: 1,
  neutral: 2,
  positive: 3,
};

const addSignal = (
  signals: PassiveIntelligenceSignal[],
  signal: PassiveIntelligenceSignal,
): void => {
  const key = `${signal.category}:${signal.title}:${signal.evidence.join("|")}`;
  if (signals.some((existing) => `${existing.category}:${existing.title}:${existing.evidence.join("|")}` === key)) {
    return;
  }
  signals.push(signal);
};

const confidenceFromTechnologies = (technologies: TechnologyResult[]): IssueConfidence => {
  if (technologies.some((technology) => technology.confidence === "high")) return "high";
  if (technologies.some((technology) => technology.confidence === "medium")) return "medium";
  return "low";
};

const visibleProviderNames = (providers: ThirdPartyProvider[], categories: ThirdPartyProvider["category"][]) =>
  unique(providers.filter((provider) => categories.includes(provider.category)).map((provider) => provider.name));

export function buildPassiveIntelligence(input: PassiveIntelligenceInput): PassiveIntelligenceInfo {
  const signals: PassiveIntelligenceSignal[] = [];
  const technologiesByCategory = (category: TechnologyResult["category"]) =>
    input.technologies.filter((technology) => technology.category === category);
  const networkStack = technologiesByCategory("network");
  const hostingStack = technologiesByCategory("hosting");
  const frontendStack = technologiesByCategory("frontend");
  const serverStack = technologiesByCategory("server");
  const securityStack = technologiesByCategory("security");

  if (input.assessmentLimitation?.limited) {
    addSignal(signals, {
      category: "exposure",
      title: "Limited external read",
      summary: input.assessmentLimitation.title || "The target did not return a normal page response.",
      confidence: "high",
      source: "derived",
      risk: "watch",
      evidence: [input.assessmentLimitation.title || "Limited assessment"],
      action: "Treat technology and missing-control observations as partial until a normal trusted response can be read.",
    });
  }

  if (networkStack.length || hostingStack.length || serverStack.length || frontendStack.length) {
    const stackNames = [
      ...networkStack,
      ...hostingStack,
      ...serverStack,
      ...frontendStack,
    ].map((technology) => technology.version ? `${technology.name} ${technology.version}` : technology.name);
    addSignal(signals, {
      category: "technology",
      title: "Visible technology stack",
      summary: `Public response and asset evidence suggests ${describeList(stackNames, "no obvious stack markers")}.`,
      confidence: confidenceFromTechnologies([...networkStack, ...hostingStack, ...serverStack, ...frontendStack]),
      source: "html",
      risk: "neutral",
      evidence: stackNames.slice(0, 6),
      action: "Use this as attribution context only; review exposed framework or server versions where exact versions are visible.",
    });
  }

  if (securityStack.length || input.wafFingerprint.detected || input.infrastructure.providers.length) {
    const providers = unique([
      ...input.infrastructure.providers.map((provider) => provider.provider),
      ...input.wafFingerprint.providers.map((provider) => provider.name),
      ...securityStack.map((technology) => technology.name),
    ]);
    addSignal(signals, {
      category: "infrastructure",
      title: "Edge and protection signals",
      summary: providers.length
        ? `Passive evidence points to ${describeList(providers, "no obvious edge provider")}.`
        : "No obvious edge provider was inferred.",
      confidence: input.wafFingerprint.providers.some((provider) => provider.confidence === "high") ? "high" : "medium",
      source: "headers",
      risk: providers.length ? "positive" : "neutral",
      evidence: providers.slice(0, 6),
      action: providers.length
        ? "Confirm security headers are applied consistently behind the edge layer, not only on the landing page."
        : null,
    });
  }

  const analyticsProviders = visibleProviderNames(input.thirdPartyTrust.providers, ["analytics", "ads"]);
  const replayProviders = visibleProviderNames(input.thirdPartyTrust.providers, ["session_replay"]);
  const consentProviders = visibleProviderNames(input.thirdPartyTrust.providers, ["consent"]);
  const supportProviders = visibleProviderNames(input.thirdPartyTrust.providers, ["support"]);
  const telemetryProviders = unique([...analyticsProviders, ...replayProviders, ...consentProviders, ...supportProviders]);
  if (telemetryProviders.length) {
    addSignal(signals, {
      category: "telemetry",
      title: "Visible telemetry and customer-experience tooling",
      summary: `The page publicly loads ${describeList(telemetryProviders, "visible telemetry tooling")}.`,
      confidence: "high",
      source: "asset",
      risk: replayProviders.length || analyticsProviders.length > 2 ? "watch" : "neutral",
      evidence: telemetryProviders.slice(0, 8),
      action: replayProviders.length
        ? "Check consent, masking, and retention settings for any session replay or behavioural analytics tooling."
        : "Confirm analytics and consent tooling are intentionally exposed and covered by privacy notices.",
    });
  }

  if (input.thirdPartyTrust.providers.length) {
    const providerDomains = input.thirdPartyTrust.providers.map((provider) => provider.domain);
    addSignal(signals, {
      category: "third_party",
      title: "Third-party dependency surface",
      summary: `${input.thirdPartyTrust.totalProviders} third-party provider${input.thirdPartyTrust.totalProviders === 1 ? "" : "s"} were visible from the fetched page.`,
      confidence: "high",
      source: "asset",
      risk: input.thirdPartyTrust.highRiskProviders > 0 ? "watch" : "neutral",
      evidence: providerDomains.slice(0, 8),
      action: "Review whether critical security, analytics, payments, and support dependencies are documented and monitored.",
    });
  }

  if (input.aiSurface.detected || input.aiSurface.vendors.length) {
    addSignal(signals, {
      category: "ai",
      title: "AI or support automation surface",
      summary: input.aiSurface.vendors.length
        ? `Visible page signals suggest ${describeList(input.aiSurface.vendors.map((vendor) => vendor.name), "AI or automation tooling")}.`
        : "AI or automation language was visible on the page.",
      confidence: input.aiSurface.vendors.some((vendor) => vendor.confidence === "high") ? "high" : "medium",
      source: "html",
      risk: input.aiSurface.issues.length ? "watch" : "neutral",
      evidence: [
        ...input.aiSurface.vendors.map((vendor) => `${vendor.name}: ${vendor.evidence}`),
        ...input.aiSurface.disclosures,
      ].slice(0, 6),
      action: input.aiSurface.issues.length
        ? "Check disclosure, privacy, and data-handling language for public AI or automation features."
        : "Keep AI and support automation disclosures aligned with privacy and customer-support practices.",
    });
  }

  const emailEvidence = unique([
    input.domainSecurity.emailPolicy.spf.status !== "missing"
      ? `SPF ${input.domainSecurity.emailPolicy.spf.status}`
      : "SPF missing",
    input.domainSecurity.emailPolicy.dmarc.status !== "missing"
      ? `DMARC ${input.domainSecurity.emailPolicy.dmarc.status}`
      : "DMARC missing",
    input.domainSecurity.mtaSts.dns ? "MTA-STS present" : "MTA-STS missing",
    input.domainSecurity.caaRecords.length ? "CAA present" : "CAA missing",
    input.domainSecurity.dnssec.enabled ? "DNSSEC signed" : "DNSSEC not signed",
  ]);
  addSignal(signals, {
    category: "email",
    title: "Domain and email trust posture",
    summary: input.domainSecurity.issues.length
      ? `${input.domainSecurity.issues.length} domain or email trust signal${input.domainSecurity.issues.length === 1 ? "" : "s"} need attention.`
      : "Core domain and email trust signals look broadly healthy from public records.",
    confidence: "high",
    source: "public_record",
    risk: input.domainSecurity.issues.length ? "watch" : "positive",
    evidence: emailEvidence,
    action: input.domainSecurity.issues.length
      ? "Prioritise DMARC/SPF/MTA-STS/DNSSEC gaps that align with how important email is for this domain."
      : null,
  });

  const trustEvidence = unique([
    input.securityTxt.status === "present_valid" ? "security.txt valid" : "security.txt missing or incomplete",
    `HSTS preload: ${titleCase(input.publicSignals.hstsPreload.status)}`,
    ...input.htmlSecurity.firstPartyPaths.filter((path) => /privacy|contact|security|support|legal/i.test(path)).slice(0, 5),
  ]);
  addSignal(signals, {
    category: "trust",
    title: "Public trust and disclosure signals",
    summary: input.securityTxt.status === "present_valid"
      ? "A vulnerability disclosure route was visible through security.txt."
      : "No valid security.txt disclosure route was visible from the standard location.",
    confidence: "high",
    source: "public_record",
    risk: input.securityTxt.status === "present_valid" ? "positive" : "watch",
    evidence: trustEvidence,
    action: input.securityTxt.status === "present_valid"
      ? "Keep disclosure contacts, expiry, and policy links current."
      : "Publish /.well-known/security.txt with a monitored contact and policy URL.",
  });

  if (input.htmlSecurity.passiveLeakSignals.length || input.htmlSecurity.clientExposureSignals.length || input.apiSurface.issues.length) {
    const exposureSignals = [
      ...input.htmlSecurity.passiveLeakSignals.map((signal) => signal.title),
      ...input.htmlSecurity.clientExposureSignals.map((signal) => signal.title),
      ...input.apiSurface.issues,
    ];
    addSignal(signals, {
      category: "exposure",
      title: "Client-visible exposure clues",
      summary: `${exposureSignals.length} client-visible exposure signal${exposureSignals.length === 1 ? "" : "s"} were observed in the fetched page or public API hints.`,
      confidence: "medium",
      source: "html",
      risk: input.htmlSecurity.passiveLeakSignals.some((signal) => signal.severity === "warning") ? "attention" : "watch",
      evidence: exposureSignals.slice(0, 8),
      action: "Review exposed client configuration, public endpoint references, source maps, and token-like values for intended visibility.",
    });
  }

  const orderedSignals = signals.sort((a, b) => categoryRank[a.risk] - categoryRank[b.risk]);
  const stackSummary = describeList(
    unique([
      ...networkStack.map((technology) => technology.name),
      ...hostingStack.map((technology) => technology.name),
      ...serverStack.map((technology) => technology.name),
      ...frontendStack.map((technology) => technology.name),
    ]),
    "No confident technology stack was inferred from passive evidence.",
  );
  const telemetrySummary = telemetryProviders.length
    ? `Visible telemetry/customer tooling: ${describeList(telemetryProviders, "none")}.`
    : "No prominent analytics, consent, support, or session-replay tooling was identified from visible assets.";
  const trustSummary = orderedSignals.some((signal) => signal.risk === "attention" || signal.risk === "watch")
    ? "Several public trust, exposure, or dependency signals deserve review."
    : "Passive intelligence did not surface major public trust or exposure concerns.";

  return {
    postureRead: orderedSignals.some((signal) => signal.risk === "attention")
      ? "Passive intelligence found public signals that should be reviewed."
      : orderedSignals.some((signal) => signal.risk === "watch")
        ? "Passive intelligence found useful context and a few watch items."
        : "Passive intelligence found useful context without obvious concerns.",
    stackSummary,
    telemetrySummary,
    trustSummary,
    collectionBoundary: SOURCE_BOUNDARY,
    signals: orderedSignals,
    issues: orderedSignals.filter((signal) => signal.risk === "attention" || signal.risk === "watch").map((signal) => signal.summary),
    strengths: orderedSignals.filter((signal) => signal.risk === "positive").map((signal) => signal.summary),
  };
}

export function emptyPassiveIntelligence(reason = "Passive intelligence was not available for this scan."): PassiveIntelligenceInfo {
  return {
    postureRead: reason,
    stackSummary: "No passive stack summary is available.",
    telemetrySummary: "No passive telemetry summary is available.",
    trustSummary: "No passive trust summary is available.",
    collectionBoundary: SOURCE_BOUNDARY,
    signals: [],
    issues: [],
    strengths: [],
  };
}
