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

export interface RedirectHop {
  url: string;
  statusCode: number;
  location: string | null;
  secure: boolean;
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
}

export interface RemediationSnippet {
  platform: "nginx" | "apache" | "cloudflare" | "vercel" | "netlify";
  title: string;
  description: string;
  filename: string;
  snippet: string;
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

export interface SecurityTxtInfo {
  status: "present" | "missing" | "invalid";
  url: string | null;
  contact: string[];
  expires: string | null;
  policy: string[];
  acknowledgments: string[];
  encryption: string[];
  hiring: string[];
  preferredLanguages: string[];
  canonical: string[];
  raw: string | null;
  issues: string[];
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
  method: string;
  insecureSubmission: boolean;
  hasPasswordField: boolean;
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
  firstPartyPaths: string[];
  passiveLeakSignals: PassiveLeakSignal[];
  clientExposureSignals: ClientExposureSignal[];
  libraryFingerprints: LibraryFingerprint[];
  libraryRiskSignals: LibraryRiskSignal[];
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
  issues: string[];
  strengths: string[];
  summary: string;
}

export interface ExecutiveSummaryInfo {
  overview: string;
  mainRisk: string;
  posture: "strong" | "mixed" | "weak";
  takeaways: string[];
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
  technologies: TechnologyResult[];
  certificate: CertificateResult;
  redirects: RedirectHop[];
  issues: ScanIssue[];
  strengths: string[];
  remediation: RemediationSnippet[];
  crawl: CrawlSummary;
  securityTxt: SecurityTxtInfo;
  domainSecurity: DomainSecurityInfo;
  identityProvider: IdentityProviderInfo;
  ctDiscovery: CtDiscoveryInfo;
  htmlSecurity: HtmlSecurityInfo;
  aiSurface: AiSurfaceInfo;
  thirdPartyTrust: ThirdPartyTrustInfo;
  infrastructure: InfrastructureInfo;
  executiveSummary: ExecutiveSummaryInfo;
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
  scanMode?: "standard" | "quiet";
}
