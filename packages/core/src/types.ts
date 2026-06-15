export type Severity = "good" | "info" | "warning" | "critical";
export type IssueConfidence = "high" | "medium" | "low";
export type IssueSource = "observed" | "heuristic" | "inferred";
export type OwaspCategory =
  | "A01 Broken Access Control"
  | "A02 Cryptographic Failures"
  | "A03 Injection"
  | "A05 Security Misconfiguration"
  | "A06 Vulnerable and Outdated Components"
  | "A07 Identification and Authentication Failures";
export type MitreRelevance =
  | "Reconnaissance"
  | "Initial Access"
  | "Credential Access"
  | "Collection"
  | "Defense Evasion";

export interface SecurityHeaderResult {
  key: string;
  label: string;
  description: string;
  recommendation: string;
  value: string | null;
  status: "present" | "missing" | "warning";
  severity: Severity;
  summary: string;
}

export interface CookieResult {
  name: string;
  valuePreview: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain: string | null;
  path: string | null;
  expires: string | null;
  maxAge: string | null;
  issues: string[];
  risk: "low" | "medium" | "high";
}

export interface CookieRecord {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None" | "missing";
  hasHostPrefix: boolean;
  hasSecurePrefix: boolean;
  isSessionCookie: boolean;
}

export interface CookieAnalysisInfo {
  cookies: CookieRecord[];
  cookiesWithoutSecure: number;
  cookiesWithoutHttpOnly: number;
  cookiesWithSameSiteNone: number;
  cookiesWithoutSameSite: number;
  issues: string[];
  strengths: string[];
}

export interface TechnologyResult {
  name: string;
  category: "server" | "frontend" | "security" | "hosting" | "network";
  evidence: string;
  version: string | null;
  confidence: IssueConfidence;
  detection: "observed" | "inferred";
}

export interface CertificateResult {
  available: boolean;
  valid: boolean;
  authorized: boolean;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  protocol: string | null;
  cipher: string | null;
  fingerprint: string | null;
  subjectAltName: string[];
  issues: string[];
}

export interface LiveCertificateChainEntry {
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  fingerprint: string | null;
}

export interface LiveCertificateResult extends CertificateResult {
  host: string;
  port: number;
  checkedAt: string;
  serialNumber: string | null;
  keyBits: number | null;
  keyType: string | null;
  chain: LiveCertificateChainEntry[];
}

export interface RedirectHop {
  url: string;
  status: number;
  statusCode: number;
  location: string | null;
  isHttps: boolean;
  secure: boolean;
}

export interface RedirectChainInfo {
  hops: RedirectHop[];
  finalUrl: string;
  totalHops: number;
  hasMixedRedirect: boolean;
  isLongChain: boolean;
  crossesDomain: boolean;
  issues: string[];
  strengths: string[];
}

export interface ScanIssue {
  severity: Exclude<Severity, "good">;
  area: "transport" | "headers" | "certificate" | "cookies";
  title: string;
  detail: string;
  confidence: IssueConfidence;
  source: IssueSource;
  owasp: OwaspCategory[];
  mitre: MitreRelevance[];
  evidence?: ScanEvidenceReference[];
}

export interface RemediationSnippet {
  platform: "nginx" | "apache" | "cloudflare" | "vercel" | "netlify";
  title: string;
  description: string;
  filename: string;
  snippet: string;
}

export type ScanEvidenceKind =
  | "header"
  | "tls"
  | "cookie"
  | "redirect"
  | "dns"
  | "html"
  | "probe"
  | "public_record"
  | "score_driver";

export interface ScanEvidenceReference {
  kind: ScanEvidenceKind;
  label: string;
  observed: string | null;
  expected?: string;
  url?: string;
  source?: ScoreDriver["source"] | IssueSource | "derived";
}

export type RemediationOwner = "app" | "edge" | "dns" | "identity" | "third_party";
export type RemediationEffort = "low" | "medium" | "high";
export type RemediationImpact = "low" | "medium" | "high";

export interface RemediationPlanItem {
  id: string;
  priority: number;
  title: string;
  detail: string;
  owner: RemediationOwner;
  effort: RemediationEffort;
  impact: RemediationImpact;
  action: string;
  verify: string;
  scoreImpact: number | null;
  relatedFindings: string[];
  evidence: ScanEvidenceReference[];
}

export interface RemediationPlan {
  generatedAt: string;
  summary: string;
  totalActions: number;
  highImpactActions: number;
  quickWins: number;
  items: RemediationPlanItem[];
}

export interface PostureEvidenceSummaryReference extends ScanEvidenceReference {
  areaLabel?: string;
  relatedFinding?: string;
  severity?: Exclude<Severity, "good">;
  scoreImpact?: number | null;
}

export interface PostureEvidenceSummary {
  generatedAt: string;
  summary: string;
  totalEvidenceReferences: number;
  byKind: Partial<Record<ScanEvidenceKind, number>>;
  bySource: Record<string, number>;
  observedCount: number;
  derivedCount: number;
  topEvidence: PostureEvidenceSummaryReference[];
  scoreDriverEvidence: PostureEvidenceSummaryReference[];
  findingEvidence: PostureEvidenceSummaryReference[];
  limitation: AssessmentLimitation | null;
}

export type ExposureBriefLevel = "low" | "medium" | "high" | "critical" | "unknown";

export type ExposureBriefCategory =
  | "entry_point"
  | "trust_gap"
  | "abuse_signal"
  | "sensitive_exposure"
  | "third_party"
  | "identity"
  | "ai"
  | "infrastructure";

export type ExposureBriefSource =
  | "headers"
  | "tls"
  | "cookies"
  | "dns"
  | "html"
  | "public_record"
  | "third_party"
  | "ai"
  | "ct"
  | "api"
  | "exposure"
  | "derived";

export interface ExposureBriefItem {
  title: string;
  detail: string;
  severity: "info" | "watch" | "warning" | "critical";
  category: ExposureBriefCategory;
  confidence: IssueConfidence;
  source: ExposureBriefSource;
  evidence: string[];
  action: string | null;
}

export interface ExposureBrief {
  generatedAt: string;
  exposureLevel: ExposureBriefLevel;
  summary: string;
  counts: {
    publicEntryPoints: number;
    sensitiveExposures: number;
    trustGaps: number;
    abuseIndicators: number;
    thirdPartyProviders: number;
    highRiskThirdParties: number;
    aiVendors: number;
    ctPriorityHosts: number;
  };
  topRisks: ExposureBriefItem[];
  publicEntryPoints: ExposureBriefItem[];
  trustGaps: ExposureBriefItem[];
  nextActions: string[];
  collectionBoundary: string;
  limitation: AssessmentLimitation | null;
}

export type VendorExposureRisk = "low" | "medium" | "high";

export interface VendorExposureProvider {
  name: string;
  domain: string;
  category: ThirdPartyProvider["category"];
  risk: ThirdPartyProvider["risk"];
  evidence: string;
  reviewPriority: "routine" | "review" | "urgent";
  dataFlow: "content_delivery" | "telemetry" | "user_interaction" | "payment" | "security" | "ai" | "unknown";
  action: string;
}

export interface VendorExposureBrief {
  generatedAt: string;
  risk: VendorExposureRisk;
  summary: string;
  counts: {
    totalProviders: number;
    highRiskProviders: number;
    mediumRiskProviders: number;
    sessionReplayProviders: number;
    analyticsProviders: number;
    aiProviders: number;
    paymentProviders: number;
    supportProviders: number;
    missingSriScripts: number;
  };
  providers: VendorExposureProvider[];
  highPriorityProviders: VendorExposureProvider[];
  issues: string[];
  strengths: string[];
  nextActions: string[];
  collectionBoundary: string;
  limitation: AssessmentLimitation | null;
}

export type ActionPlanTheme =
  | "browser_hardening"
  | "transport"
  | "domain_trust"
  | "public_exposure"
  | "vendor_risk"
  | "identity"
  | "availability"
  | "monitoring";

export interface ActionPlanItem {
  id: string;
  priority: number;
  title: string;
  whyNow: string;
  action: string;
  verify: string;
  owner: RemediationOwner;
  effort: RemediationEffort;
  impact: RemediationImpact;
  scoreImpact: number | null;
  confidence: IssueConfidence;
  theme: ActionPlanTheme;
  evidence: ScanEvidenceReference[];
  relatedFindings: string[];
  source: "remediation" | "score_driver" | "exposure_brief" | "vendor_exposure";
}

export interface ActionPlan {
  generatedAt: string;
  summary: string;
  posture: {
    score: number;
    grade: string;
    limited: boolean;
    mainRisk: string | null;
  };
  totalActions: number;
  highImpactActions: number;
  quickWins: number;
  items: ActionPlanItem[];
  nextReview: string;
  limitation: AssessmentLimitation | null;
}

export interface CrawlPageResult {
  label: string;
  path: string;
  finalUrl: string;
  sameOrigin: boolean;
  statusCode: number;
  responseTimeMs: number;
  score: number;
  grade: string;
  missingHeaders: string[];
  warningHeaders: string[];
  issueCount: number;
}

export interface CrawlSummary {
  pages: CrawlPageResult[];
  weakestPage: string | null;
  strongestPage: string | null;
  inconsistentHeaders: string[];
  discoverySources: string[];
}

export interface HistorySnapshot {
  finalUrl: string;
  host: string;
  scannedAt: string;
  score: number;
  grade: string;
  statusCode: number;
  responseTimeMs: number;
  certificateDaysRemaining: number | null;
  thirdPartyProviders: string[];
  aiVendors: string[];
  identityProvider: string | null;
  wafProviders: string[];
  ctPriorityHosts: string[];
  headers: Pick<SecurityHeaderResult, "label" | "status" | "value">[];
  issues: Pick<ScanIssue, "severity" | "title" | "detail" | "confidence" | "source">[];
}

export interface HistoryDiff {
  previousScore: number | null;
  scoreDelta: number | null;
  previousGrade: string | null;
  currentGrade: string | null;
  statusCodeDelta: {
    from: number | null;
    to: number | null;
  } | null;
  certificateDaysRemainingDelta: {
    from: number | null;
    to: number | null;
    delta: number | null;
  } | null;
  newIssues: string[];
  resolvedIssues: string[];
  headerChanges: Array<{
    label: string;
    from: string;
    to: string;
  }>;
  newThirdPartyProviders: string[];
  removedThirdPartyProviders: string[];
  newAiVendors: string[];
  removedAiVendors: string[];
  identityProviderChange: {
    from: string | null;
    to: string | null;
  } | null;
  wafProviderChanges: {
    newProviders: string[];
    removedProviders: string[];
  };
  ctPriorityHostChanges: {
    newHosts: string[];
    removedHosts: string[];
  };
  summary: string[];
}

export type PostureRiskEventSeverity = "info" | "warning" | "critical";

export interface PostureRiskEvent {
  eventType: string;
  severity: PostureRiskEventSeverity;
  title: string;
  detail: string;
  metadata: Record<string, unknown>;
}

export type PostureDriftDirection = "improved" | "regressed" | "changed" | "unchanged";
export type PostureDriftSeverity = "none" | PostureRiskEventSeverity;
export type PostureDriftArea =
  | "score"
  | "grade"
  | "status"
  | "certificate"
  | "headers"
  | "findings"
  | "third_party"
  | "ai"
  | "identity"
  | "waf"
  | "ct";

export interface PostureDriftSnapshotSummary {
  finalUrl: string;
  host: string;
  scannedAt: string;
  score: number;
  grade: string;
  statusCode: number;
}

export interface PostureDriftSummary {
  direction: PostureDriftDirection;
  severity: PostureDriftSeverity;
  scoreDelta: number | null;
  gradeChanged: boolean;
  hasRegression: boolean;
  hasImprovement: boolean;
  eventCounts: Record<PostureRiskEventSeverity, number>;
  changedAreas: PostureDriftArea[];
  topEvents: PostureRiskEvent[];
  summary: string[];
}

export interface PostureDriftReport {
  current: PostureDriftSnapshotSummary;
  previous: PostureDriftSnapshotSummary;
  diff: HistoryDiff;
  riskEvents: PostureRiskEvent[];
  summary: PostureDriftSummary;
}

export type SecurityTxtStatus = "present_valid" | "present_expired" | "present_incomplete" | "missing";

export interface SecurityTxtInfo {
  status: SecurityTxtStatus;
  url: string | null;
  contact: string[];
  expires: string | null;
  isExpired: boolean;
  policy: string | null;
  acknowledgments: string | null;
  encryption: string[];
  hiring: string[];
  preferredLanguages: string | null;
  canonical: string[];
  raw: string | null;
  issues: string[];
  strengths: string[];
}

export interface DomainSecurityInfo {
  host: string;
  mxRecords: string[];
  nsRecords: string[];
  caaRecords: string[];
  dnssec: {
    enabled: boolean;
    dsRecords: string[];
    status: "signed" | "not_signed" | "unknown";
  };
  spf: string | null;
  dmarc: string | null;
  emailPolicy: {
    spf: {
      status: "strong" | "watch" | "weak" | "missing";
      allMechanism: "-all" | "~all" | "?all" | "+all" | null;
      dnsLookupMechanisms: number;
      summary: string;
    };
    dmarc: {
      status: "strong" | "watch" | "weak" | "missing";
      policy: "reject" | "quarantine" | "none" | null;
      subdomainPolicy: "reject" | "quarantine" | "none" | null;
      pct: number | null;
      reporting: boolean;
      summary: string;
    };
  };
  mtaSts: {
    dns: string | null;
    policyUrl: string | null;
    policy: string | null;
  };
  spfDetail?: {
    hasPlusAll: boolean;
    hasTildeAll: boolean;
    hasMinusAll: boolean;
    hasQuestionAll: boolean;
    includeCount: number;
    exceedsLookupLimit: boolean;
    isOverlyPermissive: boolean;
  };
  dkim?: {
    discovered: Array<{ selector: string; record: string }>;
    selectors: string[];
    count: number;
    summary: string;
  };
  tlsRpt?: {
    dns: string | null;
    reporting: boolean;
    summary: string;
  };
  bimi?: {
    dns: string | null;
    selector: string;
    status: "present" | "missing";
    summary: string;
  };
  emailDeliverabilityScore?: {
    score: number;
    grade: "A" | "B" | "C" | "D" | "F";
    breakdown: Record<string, number>;
  };
  issues: string[];
  strengths: string[];
}

export interface IdentityProviderInfo {
  detected: boolean;
  provider: string | null;
  protocol: "oidc" | "oauth" | "saml" | "mixed" | "unknown" | null;
  redirectOrigins: string[];
  authHostCandidates: string[];
  loginPaths: string[];
  openIdConfigurationUrl: string | null;
  wellKnownEndpoints: string[];
  issuer: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  endSessionEndpoint: string | null;
  redirectUriSignals: string[];
  tenantBrand: string | null;
  tenantRegion: string | null;
  tenantSignals: string[];
  issues: string[];
  strengths: string[];
}

export interface CtDiscoveredHost {
  host: string;
  category: "auth" | "app" | "api" | "admin" | "cdn" | "static" | "other";
  priority: "high" | "medium" | "low";
  evidence: string;
}

export interface CtHostObservation {
  host: string;
  category: CtDiscoveredHost["category"];
  priority: CtDiscoveredHost["priority"];
  reachable: boolean;
  finalUrl: string | null;
  statusCode: number;
  responseKind: "html" | "json" | "redirect" | "other" | "unknown";
  identityProvider: string | null;
  edgeProvider: string | null;
  cnameTargets: string[];
  suspectedTakeover: {
    provider: string;
    confidence: IssueConfidence;
    evidence: string;
  } | null;
  note: string;
}

export interface CtDiscoveryInfo {
  queriedDomain: string;
  sourceUrl: string;
  subdomains: string[];
  wildcardEntries: string[];
  prioritizedHosts: CtDiscoveredHost[];
  sampledHosts: CtHostObservation[];
  coverageSummary: string;
  issues: string[];
  strengths: string[];
}

export interface WafFingerprint {
  name: string;
  confidence: IssueConfidence;
  detection: "observed" | "inferred";
  evidence: string;
}

export interface WafFingerprintInfo {
  detected: boolean;
  providers: WafFingerprint[];
  edgeSignals: string[];
  issues: string[];
  strengths: string[];
  summary: string;
}

export interface HtmlFormInfo {
  action: string | null;
  resolvedAction: string;
  actionHost: string | null;
  method: string;
  insecureSubmission: boolean;
  hasPasswordField: boolean;
  offOriginSubmission: boolean;
}

export interface PassiveLeakSignal {
  category: "source_map" | "client_config" | "public_token" | "version_leak";
  severity: "info" | "warning";
  title: string;
  detail: string;
  evidence: string[];
}

export interface ClientExposureSignal {
  category: "api_endpoint" | "config" | "service" | "environment";
  severity: "info" | "warning";
  title: string;
  detail: string;
  evidence: string[];
}

export interface LibraryFingerprint {
  packageName: string;
  version: string;
  sourceUrl: string;
  confidence: IssueConfidence;
  evidence: string;
}

export interface LibraryVulnerability {
  id: string;
  summary: string;
  severity: "low" | "moderate" | "high" | "critical" | "unknown";
  aliases: string[];
  referenceUrl: string | null;
}

export interface LibraryRiskSignal {
  packageName: string;
  version: string;
  confidence: IssueConfidence;
  sourceUrl: string;
  evidence: string;
  vulnerabilities: LibraryVulnerability[];
}

export interface SriCoverageInfo {
  externalScripts: number;
  externalStylesheets: number;
  scriptsWithSri: number;
  stylesheetsWithSri: number;
  coveragePercent: number;
  issues: string[];
  strengths: string[];
}

export interface FrameworkVersionLeak {
  framework: string;
  versionHint: string | null;
  evidence: string;
  risk: "low" | "medium" | "high";
}

export interface SuspiciousScriptSignal {
  category: "obfuscation" | "dynamic_loader" | "suspicious_host";
  severity: "info" | "warning";
  title: string;
  detail: string;
  evidence: string[];
}

export interface HtmlSecurityInfo {
  fetched: boolean;
  pageUrl: string | null;
  pageTitle: string | null;
  metaGenerator: string | null;
  forms: HtmlFormInfo[];
  sameSiteHosts: string[];
  externalScriptDomains: string[];
  externalStylesheetDomains: string[];
  insecureResourceUrls: string[];
  inlineScriptCount: number;
  inlineStyleCount: number;
  missingSriScriptUrls: string[];
  sriCoverage: SriCoverageInfo;
  firstPartyPaths: string[];
  passiveLeakSignals: PassiveLeakSignal[];
  clientExposureSignals: ClientExposureSignal[];
  libraryFingerprints: LibraryFingerprint[];
  libraryRiskSignals: LibraryRiskSignal[];
  frameworkVersionLeaks: FrameworkVersionLeak[];
  suspiciousScriptSignals: SuspiciousScriptSignal[];
  detectedTechnologies: TechnologyResult[];
  aiSurface: AiSurfaceInfo;
  issues: string[];
  strengths: string[];
}

export interface AiSurfaceInfo {
  detected: boolean;
  assistantVisible: boolean;
  aiPageSignals: string[];
  vendors: Array<{
    name: string;
    evidence: string;
    category: "ai_vendor" | "support_automation" | "assistant_ui";
    confidence: IssueConfidence;
  }>;
  discoveredPaths: string[];
  disclosures: string[];
  privacySignals: string[];
  governanceSignals: string[];
  issues: string[];
  strengths: string[];
}

export interface ThirdPartyProvider {
  domain: string;
  name: string;
  category:
    | "analytics"
    | "consent"
    | "support"
    | "ai"
    | "session_replay"
    | "payments"
    | "social"
    | "ads"
    | "cdn"
    | "security"
    | "other";
  risk: "low" | "medium" | "high";
  evidence: string;
}

export interface ThirdPartyTrustInfo {
  totalProviders: number;
  highRiskProviders: number;
  providers: ThirdPartyProvider[];
  issues: string[];
  strengths: string[];
  summary: string;
}

export interface InfrastructureSignal {
  provider: string;
  category: "cloud" | "cdn" | "edge" | "paas" | "hosting";
  confidence: IssueConfidence;
  source: "dns" | "reverse_dns" | "headers" | "technology";
  evidence: string;
}

export interface InfrastructureInfo {
  host: string;
  addresses: string[];
  cnameTargets: string[];
  reverseDns: string[];
  providers: InfrastructureSignal[];
  protocol?: {
    http: "HTTP/1.1" | "HTTP/2" | "HTTP/3" | "unknown";
    http3Advertised: boolean;
    altSvc: string | null;
  };
  waf?: {
    detected: boolean;
    provider: string | null;
    confidence: IssueConfidence;
    evidence: string;
  };
  issues: string[];
  strengths: string[];
  summary: string;
}

export interface PassiveIntelligenceSignal {
  category:
    | "technology"
    | "infrastructure"
    | "telemetry"
    | "third_party"
    | "trust"
    | "email"
    | "exposure"
    | "ai";
  title: string;
  summary: string;
  confidence: IssueConfidence;
  source: "headers" | "dns" | "html" | "asset" | "public_record" | "derived";
  risk: "positive" | "neutral" | "watch" | "attention";
  evidence: string[];
  action: string | null;
}

export interface PassiveIntelligenceInfo {
  postureRead: string;
  stackSummary: string;
  telemetrySummary: string;
  trustSummary: string;
  collectionBoundary: string;
  signals: PassiveIntelligenceSignal[];
  issues: string[];
  strengths: string[];
}

export interface CompromiseIndicator {
  category:
    | "credential_collection"
    | "script_anomaly"
    | "supply_chain"
    | "infrastructure"
    | "exposure"
    | "reputation";
  severity: "info" | "watch" | "warning" | "critical";
  title: string;
  detail: string;
  confidence: IssueConfidence;
  source: "html" | "asset" | "dns" | "ct" | "public_record" | "reputation" | "derived";
  evidence: string[];
  action: string | null;
}

export interface ReputationCheckSummary {
  provider: "google_safe_browsing" | "google_web_risk" | "urlhaus" | "virustotal";
  status: "not_configured" | "not_checked" | "clean" | "flagged" | "error";
  summary: string;
}

export interface CompromiseSignalsInfo {
  posture: "no_public_ioc" | "review_recommended" | "suspicious" | "reputation_flagged" | "not_assessed";
  summary: string;
  indicators: CompromiseIndicator[];
  reputationChecks: ReputationCheckSummary[];
  issues: string[];
  strengths: string[];
  collectionBoundary: string;
}

export interface ExecutiveSummaryInfo {
  overview: string;
  mainRisk: string;
  posture: "strong" | "mixed" | "weak";
  takeaways: string[];
}

export interface ScoreDriver {
  areaKey: "edge" | "content" | "domain" | "exposure" | "api" | "trust" | "ai" | "overall";
  areaLabel: string;
  impact: number;
  label: string;
  detail: string;
  source: "headers" | "tls" | "cookies" | "dns" | "html" | "public_record" | "third_party" | "ai" | "availability" | "breadth" | "assessment_limit";
}

export interface AssessmentLimitation {
  limited: boolean;
  kind: "blocked_edge_response" | "auth_required" | "rate_limited" | "service_unavailable" | "other" | null;
  title: string | null;
  detail: string | null;
}

export interface ScanTimingInfo {
  totalMs: number;
  coreMs: number;
  enrichmentMs: number;
  timedOut: boolean;
  timeoutMs: number | null;
}

export interface ExposureProbe {
  label: string;
  path: string;
  statusCode: number;
  finalUrl: string;
  finding: "safe" | "interesting" | "blocked" | "exposed" | "error";
  detail: string;
}

export interface ExposureSummary {
  probes: ExposureProbe[];
  issues: string[];
  strengths: string[];
}

export interface CorsSecurityInfo {
  allowedOrigin: string | null;
  allowCredentials: string | null;
  allowMethods: string[];
  allowHeaders: string[];
  allowPrivateNetwork: string | null;
  vary: string | null;
  optionsStatus: number;
  issues: string[];
  strengths: string[];
}

export interface ApiSurfaceProbe {
  label: string;
  path: string;
  statusCode: number;
  finalUrl: string;
  classification: "absent" | "public" | "restricted" | "interesting" | "fallback" | "error";
  contentType: string | null;
  detail: string;
}

export interface ApiSurfaceInfo {
  probes: ApiSurfaceProbe[];
  issues: string[];
  strengths: string[];
}

export interface PublicSignalsInfo {
  hstsPreload: {
    status: "preloaded" | "pending" | "eligible" | "not_preloaded" | "unknown";
    summary: string;
    sourceUrl: string;
  };
  issues: string[];
  strengths: string[];
}

export interface AnalysisResult {
  inputUrl: string;
  normalizedUrl: string;
  finalUrl: string;
  host: string;
  scannedAt: string;
  responseTimeMs: number;
  statusCode: number;
  score: number;
  grade: string;
  summary: string;
  headers: SecurityHeaderResult[];
  rawHeaders: Record<string, string>;
  cookies: CookieResult[];
  cookieAnalysis: CookieAnalysisInfo | null;
  technologies: TechnologyResult[];
  certificate: CertificateResult;
  redirects: RedirectHop[];
  redirectChain: RedirectChainInfo;
  issues: ScanIssue[];
  strengths: string[];
  remediation: RemediationSnippet[];
  remediationPlan?: RemediationPlan;
  evidenceSummary?: PostureEvidenceSummary;
  exposureBrief?: ExposureBrief;
  vendorExposure?: VendorExposureBrief;
  actionPlan?: ActionPlan;
  crawl: CrawlSummary;
  securityTxt: SecurityTxtInfo;
  domainSecurity: DomainSecurityInfo;
  identityProvider: IdentityProviderInfo;
  ctDiscovery: CtDiscoveryInfo;
  htmlSecurity: HtmlSecurityInfo;
  aiSurface: AiSurfaceInfo;
  thirdPartyTrust: ThirdPartyTrustInfo;
  infrastructure: InfrastructureInfo;
  passiveIntelligence: PassiveIntelligenceInfo;
  compromiseSignals: CompromiseSignalsInfo;
  executiveSummary: ExecutiveSummaryInfo;
  scoreDrivers?: ScoreDriver[];
  assessmentLimitation: AssessmentLimitation;
  exposure: ExposureSummary;
  corsSecurity: CorsSecurityInfo;
  apiSurface: ApiSurfaceInfo;
  publicSignals: PublicSignalsInfo;
  wafFingerprint: WafFingerprintInfo;
  scanTiming?: ScanTimingInfo;
}

export interface AnalyzeTargetOptions {
  includeCertificate?: boolean;
  maxScanDurationMs?: number;
  requestTimeoutMs?: number;
  scanMode?: "standard" | "quiet" | "deep-passive";
}
