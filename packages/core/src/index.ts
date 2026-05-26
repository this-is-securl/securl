import { URL } from "node:url";
import { scanTls } from "./certificate.js";
import { parseSetCookie } from "./cookie-analysis.js";
import { analyzeCookieHeaders } from "./cookieAnalysis.js";
import { fetchCtDiscovery } from "./ctDiscovery.js";
import { analyzeDomainSecurity } from "./domain-security.js";
import {
  API_SURFACE_PROBES,
  CRAWL_CONCURRENCY_LIMIT,
  CRAWL_CANDIDATES,
  EXPOSURE_PROBES,
  MAX_SCAN_DURATION_MS,
  REQUEST_TIMEOUT_MS,
  SECONDARY_REQUEST_TIMEOUT_MS,
} from "./scannerConfig.js";
import {
  analyzeHeaders,
  buildLibraryRiskIssues,
  buildRawHeaders,
  buildRemediation,
  classifyIssueTaxonomy,
  SECURITY_HEADERS,
} from "./header-analysis.js";
import { analyzeThirdPartyTrust, buildExecutiveSummary, mergeTechnologies } from "./htmlInsights.js";
import { analyzeHtmlDocument as analyzeHtmlDocumentFromModule, analyzeHtmlSecurity, detectAssessmentLimitation, fetchHtmlDocument } from "./html-page-analysis.js";
import {
  classifyHtmlApiFallback,
  isAccessDeniedHtml,
} from "./html-extraction.js";
import { analyzeIdentityProvider } from "./identityProvider.js";
import { analyzeInfrastructure } from "./infrastructure.js";
import {
  analyzeApiSurface,
  analyzeCorsSecurity,
  analyzeExposure,
  fetchPublicSignals,
} from "./surfaceEnrichment.js";
import { fetchLibraryRiskSignals } from "./libraryRisk.js";
import {
  fetchWithRedirects,
  requestJson,
  requestOnce,
  requestText,
  requestWithHeaders,
} from "./network.js";
import { normalizeDiscoveredPath, rankDiscoveredPaths } from "./path-discovery.js";
import { buildPassiveIntelligence, emptyPassiveIntelligence } from "./passive-intelligence.js";
import { analyzeRedirectChain } from "./redirectChain.js";
import { scoreAnalysis, scorePostureAnalysis, summarizePostureGrade } from "./scoring.js";
import { fetchSecurityTxt } from "./security-txt.js";
import { detectTechnologies } from "./technology-detection.js";
import { headerValue, mapWithConcurrency, unique, withTimeout } from "./utils.js";
import { analyzeWafFingerprint } from "./wafFingerprint.js";
import type { AnalysisResult, AnalyzeTargetOptions, HtmlSecurityInfo } from "./types.js";

type ScanMode = NonNullable<AnalyzeTargetOptions["scanMode"]>;
type CoreScanResult = Awaited<ReturnType<typeof analyzeUrlCore>>;
type DiscoveryResult = Awaited<ReturnType<typeof collectDiscoveryPaths>>;
type EnrichedAnalysisResult = Omit<AnalysisResult, "executiveSummary">;

const emptyCertificate = () => ({
  available: false,
  valid: false,
  authorized: false,
  issuer: null,
  subject: null,
  validFrom: null,
  validTo: null,
  daysRemaining: null,
  protocol: null,
  cipher: null,
  fingerprint: null,
  subjectAltName: [],
  issues: [],
});

function normalizeUrl(input) {
  let candidate = input.trim();
  if (!candidate) {
    throw new Error("Enter a URL to scan.");
  }

  if (!/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  const normalized = new URL(candidate);
  if (!["http:", "https:"].includes(normalized.protocol)) {
    throw new Error("Only http and https URLs are supported.");
  }

  return normalized;
}

function shouldRetryOverHttp(error) {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes("socket hang up") ||
    message.includes("econnreset") ||
    message.includes("tls") ||
    message.includes("ssl") ||
    message.includes("wrong version number") ||
    message.includes("alert handshake failure")
  );
}

function formatErrorMessage(error) {
  if (error instanceof AggregateError && Array.isArray(error.errors) && error.errors.length) {
    const messages = error.errors
      .map((item) => (item instanceof Error ? item.message : String(item)))
      .filter(Boolean);
    if (messages.length) {
      return messages.join("; ");
    }
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Unable to analyze URL.";
}

function sanitiseErrorDetail(msg: string): string {
  // Remove raw IP addresses to avoid leaking internal network topology
  return msg.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, "<host>");
}

function classifyAssessmentFailure(error: unknown) {
  const detail = formatErrorMessage(error);
  const message = detail.toLowerCase();

  if (message.includes("timed out")) {
    return {
      kind: "service_unavailable" as const,
      title: "The target did not respond in time.",
      detail: "The scanner could not complete a trusted response fetch before timing out, so this is only a limited assessment.",
    };
  }

  if (
    message.includes("certificate") ||
    message.includes("self-signed") ||
    message.includes("unable to verify") ||
    message.includes("hostname/ip does not match") ||
    message.includes("expired")
  ) {
    return {
      kind: "other" as const,
      title: "TLS certificate validation failed.",
      detail: sanitiseErrorDetail(`The scanner could not establish a trusted HTTPS connection: ${detail}`),
    };
  }

  if (
    message.includes("econnrefused") ||
    message.includes("enotfound") ||
    message.includes("socket hang up") ||
    message.includes("ehostunreach")
  ) {
    return {
      kind: "service_unavailable" as const,
      title: "The target could not be reached cleanly.",
      detail: `The scanner could not obtain a stable response from the target: ${detail}`,
    };
  }

  return {
    kind: "other" as const,
    title: "The target could not be assessed cleanly.",
    detail: `The scan did not complete normally: ${detail}`,
  };
}
export function analyzeHtmlDocument(input: string | URL, html: string): HtmlSecurityInfo {
  return analyzeHtmlDocumentFromModule(input, html);
}

function parseRobotsSitemaps(body: string): string[] {
  return unique(
    body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^sitemap:/i.test(line))
      .map((line) => line.replace(/^sitemap:\s*/i, "").trim()),
  );
}

function parseSitemapPaths(xml: string, finalUrl: URL): string[] {
  return rankDiscoveredPaths(
    [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map((match) =>
      normalizeDiscoveredPath(match[1].trim(), finalUrl),
    ),
  );
}

async function collectDiscoveryPaths(finalUrl, htmlSecurity, requestTextFn = requestText) {
  const discoverySources = [];
  const discoveredPaths = [...(htmlSecurity.firstPartyPaths || [])];

  if (htmlSecurity.firstPartyPaths?.length) {
    discoverySources.push("page links");
  }

  const sitemapCandidates = [new URL("/sitemap.xml", finalUrl.origin).toString()];

  try {
    const robotsResponse = await requestTextFn(new URL("/robots.txt", finalUrl.origin));
    if (robotsResponse.statusCode >= 200 && robotsResponse.statusCode < 300 && robotsResponse.body.trim()) {
      discoverySources.push("robots.txt");
      sitemapCandidates.push(...parseRobotsSitemaps(robotsResponse.body));
    }
  } catch {
    // Ignore robots fetch failures.
  }

  for (const sitemapCandidate of unique(sitemapCandidates).slice(0, 2)) {
    try {
      const sitemapUrl = new URL(sitemapCandidate, finalUrl);
      const response = await requestTextFn(sitemapUrl);
      if (response.statusCode >= 200 && response.statusCode < 300 && response.body.includes("<loc>")) {
        discoveredPaths.push(...parseSitemapPaths(response.body, finalUrl));
        discoverySources.push(sitemapUrl.pathname === "/sitemap.xml" ? "sitemap.xml" : "robots.txt sitemap");
        break;
      }
    } catch {
      // Ignore sitemap fetch failures.
    }
  }

  return {
    paths: rankDiscoveredPaths(discoveredPaths),
    sources: unique(discoverySources),
  };
}

async function analyzeUrlCore(input: string | URL, options: AnalyzeTargetOptions = {}) {
  const { includeCertificate = true } = options;
  const requestOptions = options.requestTimeoutMs ? { timeoutMs: options.requestTimeoutMs } : {};
  let normalizedUrl = input instanceof URL ? input : normalizeUrl(input);
  let requestData: Awaited<ReturnType<typeof fetchWithRedirects>>;

  try {
    requestData = await fetchWithRedirects(normalizedUrl, undefined, requestOptions);
  } catch (error) {
    if (normalizedUrl.protocol === "https:" && shouldRetryOverHttp(error)) {
      const fallbackUrl = new URL(normalizedUrl);
      fallbackUrl.protocol = "http:";
      normalizedUrl = fallbackUrl;
      try {
        requestData = await fetchWithRedirects(normalizedUrl, undefined, requestOptions);
      } catch (fallbackError) {
        throw new Error(
          `HTTPS failed and the site did not respond cleanly over HTTP either: ${formatErrorMessage(fallbackError)}`,
          { cause: fallbackError },
        );
      }
    } else {
      throw error;
    }
  }
  const certificate = includeCertificate ? await scanTls(requestData.finalUrl) : emptyCertificate();
  const rawHeaders = buildRawHeaders(requestData.response.headers);
  const { headers: headerResults, issues: headerIssues, strengths } = analyzeHeaders(
    requestData.response.headers,
    requestData.finalUrl.protocol === "https:",
  );
  const cookies = parseSetCookie(requestData.response.headers["set-cookie"]);
  const cookieAnalysis = analyzeCookieHeaders(requestData.response.headers["set-cookie"]);
  const redirectChain = analyzeRedirectChain(normalizedUrl, requestData.finalUrl, requestData.redirects);
  const technologies = detectTechnologies(requestData.response.headers, requestData.finalUrl);
  const { score, grade } = scoreAnalysis({
    isHttps: requestData.finalUrl.protocol === "https:",
    headerResults,
    certificate,
    cookies,
    redirects: requestData.redirects,
  });

  const cookieIssues = cookies.flatMap((cookie) =>
    cookie.issues.map((detail) => ({
      severity: cookie.risk === "high" ? "warning" : "info",
      area: "cookies",
      title: `Cookie ${cookie.name} needs attention`,
      detail,
      confidence: "high",
      source: "observed",
      owasp: [],
      mitre: [],
    })),
  );

  const redirectIssues =
    requestData.redirects.length > 1
      ? [
          {
            severity: "info",
            area: "transport",
            title: "Redirect chain detected",
            detail: `This scan followed ${requestData.redirects.length - 1} redirect${requestData.redirects.length > 2 ? "s" : ""} before reaching the final URL.`,
            confidence: "high",
            source: "observed",
            owasp: [],
            mitre: [],
          },
        ]
      : [];

  const issues = [...headerIssues, ...cookieIssues, ...redirectIssues];
  if (certificate.issues.length) {
    issues.push(
      ...certificate.issues.map((detail) => ({
        severity: /outdated|not trusted|expires/i.test(detail) ? "warning" : "info",
        area: "certificate",
        title: "TLS certificate needs attention",
        detail,
        confidence: /expires/i.test(detail) ? "high" : "medium",
        source: "observed",
        owasp: [],
        mitre: [],
      })),
    );
  }

  const normalizedIssues = issues.map(classifyIssueTaxonomy);

  const summary =
    grade === "A+"
      ? "Excellent baseline hardening."
      : grade === "A"
        ? "Strong setup with a few remaining improvements."
        : grade === "B"
        ? "Reasonably protected, but several headers or cookie controls can be improved."
        : "Security posture needs work before this would count as well hardened.";

  return {
    inputUrl: input instanceof URL ? input.toString() : input,
    normalizedUrl: normalizedUrl.toString(),
    finalUrl: requestData.finalUrl.toString(),
    host: requestData.finalUrl.hostname,
    scannedAt: new Date().toISOString(),
    responseTimeMs: requestData.response.elapsedMs,
    statusCode: requestData.response.statusCode,
    score,
    grade,
    summary,
    headers: headerResults,
    rawHeaders,
    cookies,
    cookieAnalysis,
    technologies,
    certificate,
    redirects: requestData.redirects,
    redirectChain,
    issues: normalizedIssues,
    strengths,
    remediation: buildRemediation(headerResults),
    assessmentLimitation: {
      limited: false,
      kind: null,
      title: null,
      detail: null,
    },
  };
}

async function analyzeHtmlSecuritySignals(finalUrl: URL, pageAnalysisEnabled: boolean) {
  let htmlDocument = null;
  if (pageAnalysisEnabled) {
    try {
      htmlDocument = await fetchHtmlDocument(finalUrl);
    } catch {
      htmlDocument = null;
    }
  }

  const emptyHtmlSecurity = analyzeHtmlSecurity(finalUrl, null);
  const baseHtmlSecurity = pageAnalysisEnabled
    ? analyzeHtmlSecurity(finalUrl, htmlDocument)
    : {
        ...emptyHtmlSecurity,
        issues: [],
        aiSurface: {
          ...emptyHtmlSecurity.aiSurface,
          issues: [],
        },
      };

  const libraryRiskSignals = pageAnalysisEnabled
    ? await fetchLibraryRiskSignals(baseHtmlSecurity.libraryFingerprints)
    : [];

  const htmlSecurity = {
    ...baseHtmlSecurity,
    libraryRiskSignals,
    issues: [
      ...baseHtmlSecurity.issues,
      ...libraryRiskSignals.map(
        (signal) =>
          `${signal.packageName} ${signal.version} matched ${signal.vulnerabilities.length} OSV advisor${signal.vulnerabilities.length === 1 ? "y" : "ies"} from public script references.`,
      ),
    ],
    strengths:
      baseHtmlSecurity.libraryFingerprints.length > 0 && libraryRiskSignals.length === 0
        ? [...baseHtmlSecurity.strengths, "No OSV advisory matches were found for the explicitly versioned client libraries detected on the fetched page."]
        : baseHtmlSecurity.strengths,
  };

  return { htmlDocument, htmlSecurity };
}

async function buildLimitedResult(
  input: string,
  normalizedInput: URL,
  failure: ReturnType<typeof classifyAssessmentFailure>,
  scanTiming?: AnalysisResult["scanTiming"],
): Promise<AnalysisResult> {
  const publicSignals = await fetchPublicSignals(normalizedInput.host, { requestText }).catch(() => ({
    hstsPreload: {
      status: "unknown" as const,
      summary: "Public HSTS preload status could not be determined.",
      sourceUrl: `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(normalizedInput.host)}`,
    },
    issues: [],
    strengths: [],
  }));
  const fallbackHtmlSecurity = analyzeHtmlSecurity(normalizedInput, null);
  const fallbackIssue = classifyIssueTaxonomy({
    severity: "warning",
    area: "transport",
    title: failure.title,
    detail: failure.detail,
    confidence: "high",
    source: "observed",
    owasp: ["A02 Cryptographic Failures"],
    mitre: ["Reconnaissance"],
  });
  const domainSecurity = await analyzeDomainSecurity(normalizedInput.host, requestText).catch(() => ({
    host: normalizedInput.host,
    mxRecords: [],
    nsRecords: [],
    caaRecords: [],
    dnssec: { enabled: false, dsRecords: [], status: "unknown" as const },
    spf: null,
    dmarc: null,
    emailPolicy: {
      spf: {
        status: "missing" as const,
        allMechanism: null,
        dnsLookupMechanisms: 0,
        summary: "SPF could not be evaluated during the limited fallback checks.",
      },
      dmarc: {
        status: "missing" as const,
        policy: null,
        subdomainPolicy: null,
        pct: null,
        reporting: false,
        summary: "DMARC could not be evaluated during the limited fallback checks.",
      },
    },
    mtaSts: { dns: null, policyUrl: null, policy: null },
    issues: [],
    strengths: [],
  }));

  return {
    inputUrl: input,
    normalizedUrl: normalizedInput.toString(),
    finalUrl: normalizedInput.toString(),
    host: normalizedInput.host,
    scannedAt: new Date().toISOString(),
    responseTimeMs: 0,
    statusCode: 0,
    score: 0,
    grade: "U",
    summary: "Assessment is limited because the target could not be reached or trusted cleanly.",
    headers: [],
    rawHeaders: {},
    cookies: [],
    cookieAnalysis: null,
    technologies: [],
    certificate: {
      ...emptyCertificate(),
      available: normalizedInput.protocol === "https:",
      subject: normalizedInput.hostname,
      issues: [failure.detail],
    },
    redirects: [],
    redirectChain: analyzeRedirectChain(normalizedInput, normalizedInput, []),
    issues: [fallbackIssue],
    strengths: [],
    remediation: [],
    crawl: emptyCrawlSummary(["limited assessment"]),
    securityTxt: emptySecurityTxt(),
    domainSecurity,
    identityProvider: emptyIdentityProvider(),
    ctDiscovery: {
      queriedDomain: normalizedInput.hostname,
      sourceUrl: `https://crt.sh/?q=%25.${normalizedInput.hostname}&output=json`,
      subdomains: [],
      wildcardEntries: [],
      prioritizedHosts: [],
      sampledHosts: [],
      coverageSummary: "Certificate transparency discovery was skipped because the primary assessment could not complete cleanly.",
      issues: [],
      strengths: [],
    },
    htmlSecurity: fallbackHtmlSecurity,
    aiSurface: fallbackHtmlSecurity.aiSurface,
    thirdPartyTrust: {
      totalProviders: 0,
      highRiskProviders: 0,
      providers: [],
      issues: [],
      strengths: [],
      summary: "Third-party trust could not be assessed from a limited scan.",
    },
    infrastructure: {
      host: normalizedInput.hostname,
      addresses: [],
      cnameTargets: [],
      reverseDns: [],
      providers: [],
      issues: [],
      strengths: [],
      summary: "Infrastructure attribution was not completed because the primary response could not be fetched cleanly.",
    },
    passiveIntelligence: emptyPassiveIntelligence("Passive intelligence was limited because the primary response could not be fetched cleanly."),
    executiveSummary: {
      overview:
        failure.kind === "service_unavailable"
          ? "The scanner could not obtain a stable response from the target, so this is only a limited availability read."
          : "The scanner could not establish a trusted connection to the target, so this is only a limited transport read.",
      mainRisk:
        failure.kind === "service_unavailable"
          ? "Availability or reachability issues prevented a normal posture assessment."
          : "TLS trust or certificate issues prevented a normal posture assessment.",
      posture: "weak",
      takeaways: [
        failure.detail,
        domainSecurity.issues.length > 0
          ? `${domainSecurity.issues.length} domain or mail-hygiene issue${domainSecurity.issues.length === 1 ? "" : "s"} were still detectable without a full page read.`
          : "No additional DNS or mail-hygiene issues were inferred from the limited fallback checks.",
        publicSignals.issues.length > 0
          ? `${publicSignals.issues.length} public trust signal${publicSignals.issues.length === 1 ? " was" : "s were"} still observable.`
          : "Public preload and trust signals could not materially improve this limited read.",
      ],
    },
    scoreDrivers: [
      {
        areaKey: "overall",
        areaLabel: "Overall posture",
        impact: 100,
        label: "Limited assessment",
        detail: failure.detail,
        source: "assessment_limit",
      },
    ] as AnalysisResult["scoreDrivers"],
    assessmentLimitation: {
      limited: true,
      kind: failure.kind,
      title: failure.title,
      detail: failure.detail,
    },
    scanTiming,
    exposure: emptyExposure(),
    corsSecurity: emptyCorsSecurity(),
    apiSurface: emptyApiSurface(),
    publicSignals,
    wafFingerprint: {
      detected: false,
      providers: [],
      edgeSignals: [],
      issues: [],
      strengths: [],
      summary: "Edge-protection fingerprinting was not completed because the primary response could not be fetched cleanly.",
    },
  };
}

async function enrichCoreResult(
  result: CoreScanResult,
  pageAnalysisEnabled: boolean,
): Promise<EnrichedAnalysisResult> {
  const finalUrl = new URL(result.finalUrl);
  const ctDiscoveryPromise = fetchCtDiscovery(result.host, requestJson, requestText, {
    sampleHosts: pageAnalysisEnabled,
  });
  const { htmlDocument, htmlSecurity } = await analyzeHtmlSecuritySignals(finalUrl, pageAnalysisEnabled);
  const thirdPartyTrust = analyzeThirdPartyTrust(finalUrl, htmlSecurity, htmlSecurity.aiSurface);
  const technologies = mergeTechnologies(result.technologies, htmlSecurity.detectedTechnologies);
  const secondaryRequestText = (targetUrl: URL, extraHeaders: Record<string, string> = {}) =>
    requestText(targetUrl, extraHeaders, { timeoutMs: SECONDARY_REQUEST_TIMEOUT_MS });
  const secondaryRequestOnce = (targetUrl: URL, method = "HEAD") =>
    requestOnce(targetUrl, method, { timeoutMs: SECONDARY_REQUEST_TIMEOUT_MS });
  const secondaryRequestWithHeaders = (targetUrl: URL, method = "HEAD", extraHeaders: Record<string, string> = {}) =>
    requestWithHeaders(targetUrl, method, extraHeaders, { timeoutMs: SECONDARY_REQUEST_TIMEOUT_MS });
  const secondaryFetchWithRedirects = (targetUrl: URL, redirectLimit?: number) =>
    fetchWithRedirects(targetUrl, redirectLimit, { timeoutMs: SECONDARY_REQUEST_TIMEOUT_MS });

  // Batch 1: fast/non-network tasks plus the two heaviest long-running ones
  const [
    discovery,
    publicSignals,
    infrastructure,
    ctDiscovery,
    domainSecurity,
    securityTxt,
  ] = await Promise.all([
    pageAnalysisEnabled
      ? collectDiscoveryPaths(finalUrl, htmlSecurity, secondaryRequestText)
      : Promise.resolve({ paths: [], sources: ["quiet mode"] } satisfies DiscoveryResult),
    fetchPublicSignals(result.host, { requestText }),
    analyzeInfrastructure(finalUrl, result.rawHeaders, technologies),
    ctDiscoveryPromise,
    analyzeDomainSecurity(result.host, secondaryRequestText),
    pageAnalysisEnabled ? fetchSecurityTxt(finalUrl, secondaryRequestText) : Promise.resolve(emptySecurityTxt()),
  ]);

  // Batch 2: tasks that depend on batch-1 results or do additional network probing
  const [
    identityProvider,
    crawl,
    exposure,
    corsSecurity,
    apiSurface,
  ] = await Promise.all([
    pageAnalysisEnabled
      ? analyzeIdentityProvider(
          finalUrl,
          result.redirects,
          htmlSecurity,
          htmlDocument?.html || null,
          requestJson,
          ctDiscovery,
        )
      : Promise.resolve(emptyIdentityProvider()),
    pageAnalysisEnabled ? crawlRelatedPages(result, discovery) : Promise.resolve(emptyCrawlSummary(discovery.sources)),
    pageAnalysisEnabled
      ? analyzeExposure(finalUrl, htmlDocument, {
          exposureProbes: EXPOSURE_PROBES,
          requestOnce: secondaryRequestOnce,
          requestText: secondaryRequestText,
          fetchWithRedirects: secondaryFetchWithRedirects,
          headerValue,
          formatErrorMessage,
          isAccessDeniedHtml,
          classifyHtmlApiFallback,
        })
      : Promise.resolve(emptyExposure()),
    pageAnalysisEnabled
      ? analyzeCorsSecurity(finalUrl, result.rawHeaders, {
          requestWithHeaders: secondaryRequestWithHeaders,
          headerValue,
        })
      : Promise.resolve(emptyCorsSecurity()),
    pageAnalysisEnabled
      ? analyzeApiSurface(finalUrl, htmlDocument, {
          apiSurfaceProbes: API_SURFACE_PROBES,
          requestText: secondaryRequestText,
          fetchWithRedirects: secondaryFetchWithRedirects,
          headerValue,
          isAccessDeniedHtml,
          classifyHtmlApiFallback,
        })
      : Promise.resolve(emptyApiSurface()),
  ]);

  const wafFingerprint = analyzeWafFingerprint(
    finalUrl,
    result.rawHeaders,
    htmlDocument?.html || null,
    result.redirects,
  );
  const assessmentLimitation = detectAssessmentLimitation(
    result.statusCode,
    result.rawHeaders,
    htmlDocument?.html || null,
  );
  const passiveIntelligence = buildPassiveIntelligence({
    technologies,
    infrastructure,
    thirdPartyTrust,
    htmlSecurity,
    aiSurface: htmlSecurity.aiSurface,
    domainSecurity,
    securityTxt,
    publicSignals,
    identityProvider,
    wafFingerprint,
    apiSurface,
    assessmentLimitation,
  });
  return {
    ...result,
    issues: [...result.issues, ...buildLibraryRiskIssues(htmlSecurity.libraryRiskSignals).map(classifyIssueTaxonomy)],
    technologies,
    crawl,
    securityTxt,
    domainSecurity,
    identityProvider,
    ctDiscovery,
    htmlSecurity,
    aiSurface: htmlSecurity.aiSurface,
    thirdPartyTrust,
    infrastructure,
    passiveIntelligence,
    wafFingerprint,
    exposure,
    corsSecurity,
    apiSurface,
    publicSignals,
    assessmentLimitation,
  };
}

function toCandidateLabel(pathname) {
  if (pathname === "/") {
    return "Homepage";
  }

  const segments = pathname
    .split("?")[0]
    .split("/")
    .filter(Boolean)
    .map((segment) => decodeURIComponent(segment).replace(/[-_]+/g, " ").trim())
    .filter(Boolean);

  const uniqueSegments = segments.filter((segment, index) => {
    return index === 0 || segment.toLowerCase() !== segments[index - 1].toLowerCase();
  });

  const preferredSegments =
    uniqueSegments.length <= 2
      ? uniqueSegments
      : [uniqueSegments[0], uniqueSegments[uniqueSegments.length - 1]];

  const label = preferredSegments
    .map((segment) =>
      segment
        .split(/\s+/)
        .slice(0, 3)
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(" "),
    )
    .join(" / ");

  return label.length > 42 ? `${label.slice(0, 39).trimEnd()}...` : label;
}

function buildCrawlCandidates(result, discoveryPaths = []) {
  const finalUrl = new URL(result.finalUrl);
  const userPath = new URL(result.normalizedUrl).pathname || "/";
  const seen = new Set<string>();

  return [
    { label: userPath === "/" ? "Homepage" : "Requested page", path: userPath },
    ...discoveryPaths.map((path) => ({ label: toCandidateLabel(path), path })),
    ...CRAWL_CANDIDATES,
  ]
    .map((candidate) => {
      const url = new URL(candidate.path, finalUrl.origin);
      return {
        label: candidate.label,
        path: url.pathname,
        url,
      };
    })
    .filter((candidate) => {
      const key = candidate.path;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .slice(0, 6);
}

function summarizePageAnalysis(label, path, pageResult, rootHost) {
  const sameOrigin = new URL(pageResult.finalUrl).hostname === rootHost;
  return {
    label,
    path,
    finalUrl: pageResult.finalUrl,
    sameOrigin,
    statusCode: pageResult.statusCode,
    responseTimeMs: pageResult.responseTimeMs,
    score: sameOrigin ? pageResult.score : 0,
    grade: sameOrigin ? pageResult.grade : "Redirected",
    missingHeaders: sameOrigin ? pageResult.headers
      .filter((header) => header.status === "missing")
      .map((header) => header.label) : [],
    warningHeaders: sameOrigin ? pageResult.headers
      .filter((header) => header.status === "warning")
      .map((header) => header.label) : [],
    issueCount: sameOrigin ? pageResult.issues.length : 1,
  };
}

async function crawlRelatedPages(rootResult, discovery) {
  const candidates = buildCrawlCandidates(rootResult, discovery.paths);
  const rootHost = new URL(rootResult.finalUrl).hostname;
  const pages = await mapWithConcurrency(candidates, CRAWL_CONCURRENCY_LIMIT, async (candidate) => {
    try {
      const pageResult = await analyzeUrlCore(candidate.url, {
        includeCertificate: false,
        requestTimeoutMs: SECONDARY_REQUEST_TIMEOUT_MS,
      });
      return summarizePageAnalysis(candidate.label, candidate.path, pageResult, rootHost);
    } catch {
      return {
        label: candidate.label,
        path: candidate.path,
        finalUrl: candidate.url.toString(),
        sameOrigin: true,
        statusCode: 0,
        responseTimeMs: 0,
        score: 0,
        grade: "F",
        missingHeaders: SECURITY_HEADERS.map((header) => header.label),
        warningHeaders: [],
        issueCount: 1,
      };
    }
  });

  const comparablePages = pages.filter((page) => page.sameOrigin);

  const strongestPage = comparablePages.length
    ? comparablePages.reduce((best, page) => (page.score > best.score ? page : best), comparablePages[0]).label
    : null;
  const weakestPage = comparablePages.length
    ? comparablePages.reduce((worst, page) => (page.score < worst.score ? page : worst), comparablePages[0]).label
    : null;

  const headerMap = new Map();
  for (const page of comparablePages) {
    for (const header of SECURITY_HEADERS) {
      const status = page.missingHeaders.includes(header.label)
        ? "missing"
        : page.warningHeaders.includes(header.label)
          ? "warning"
          : "present";
      const existing = headerMap.get(header.label) || new Set();
      existing.add(status);
      headerMap.set(header.label, existing);
    }
  }

  const inconsistentHeaders = [...headerMap.entries()]
    .filter(([, states]) => states.size > 1)
    .map(([label]) => label);

  return {
    pages,
    strongestPage,
    weakestPage,
    inconsistentHeaders,
    discoverySources: discovery.sources,
  };
}

const emptyCrawlSummary = (sources: string[] = []) => ({
  pages: [],
  weakestPage: null,
  strongestPage: null,
  inconsistentHeaders: [],
  discoverySources: sources,
});

const emptySecurityTxt = () => ({
  status: "missing" as const,
  url: null,
  contact: [],
  expires: null,
  isExpired: false,
  policy: null,
  acknowledgments: null,
  encryption: [],
  hiring: [],
  preferredLanguages: null,
  canonical: [],
  raw: null,
  issues: [],
  strengths: [],
});

const emptyIdentityProvider = () => ({
  detected: false,
  provider: null,
  protocol: null,
  redirectOrigins: [],
  authHostCandidates: [],
  loginPaths: [],
  openIdConfigurationUrl: null,
  wellKnownEndpoints: [],
  issuer: null,
  authorizationEndpoint: null,
  tokenEndpoint: null,
  endSessionEndpoint: null,
  redirectUriSignals: [],
  tenantBrand: null,
  tenantRegion: null,
  tenantSignals: [],
  issues: [],
  strengths: [],
});

const emptyExposure = () => ({
  probes: [],
  issues: [],
  strengths: [],
});

const emptyCorsSecurity = () => ({
  allowedOrigin: null,
  allowCredentials: null,
  allowMethods: [],
  allowHeaders: [],
  allowPrivateNetwork: null,
  vary: null,
  optionsStatus: 0,
  issues: [],
  strengths: [],
});

const emptyApiSurface = () => ({
  probes: [],
  issues: [],
  strengths: [],
});

const emptyPublicSignals = (host: string) => ({
  hstsPreload: {
    status: "unknown" as const,
    summary: "Public HSTS preload status could not be determined before the scan timeout.",
    sourceUrl: `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(host)}`,
  },
  issues: [],
  strengths: [],
});

function buildTimedOutEnrichmentResult(
  result: CoreScanResult,
  pageAnalysisEnabled: boolean,
  timeoutMs: number,
  coreMs: number,
): AnalysisResult {
  const finalUrl = new URL(result.finalUrl);
  const fallbackHtmlSecurity = analyzeHtmlSecurity(finalUrl, null);
  const timeoutIssue = classifyIssueTaxonomy({
    severity: "info",
    area: "transport",
    title: "Secondary evidence collection timed out",
    detail: `The primary response was assessed, but secondary enrichment exceeded the ${Math.round(timeoutMs / 1000)} second scan budget. Treat crawl, discovery, and passive enrichment sections as partial for this run.`,
    confidence: "high",
    source: "observed",
    owasp: [],
    mitre: [],
  });
  const timedOutResult = {
    ...result,
    issues: [...result.issues, timeoutIssue],
    crawl: emptyCrawlSummary(pageAnalysisEnabled ? ["scan timeout"] : ["quiet mode"]),
    securityTxt: emptySecurityTxt(),
    domainSecurity: {
      host: result.host,
      mxRecords: [],
      nsRecords: [],
      caaRecords: [],
      dnssec: { enabled: false, dsRecords: [], status: "unknown" as const },
      spf: null,
      dmarc: null,
      emailPolicy: {
        spf: {
          status: "missing" as const,
          allMechanism: null,
          dnsLookupMechanisms: 0,
          summary: "SPF was not evaluated before the scan timeout.",
        },
        dmarc: {
          status: "missing" as const,
          policy: null,
          subdomainPolicy: null,
          pct: null,
          reporting: false,
          summary: "DMARC was not evaluated before the scan timeout.",
        },
      },
      mtaSts: { dns: null, policyUrl: null, policy: null },
      issues: [],
      strengths: [],
    },
    identityProvider: emptyIdentityProvider(),
    ctDiscovery: {
      queriedDomain: result.host,
      sourceUrl: `https://crt.sh/?q=%25.${result.host}&output=json`,
      subdomains: [],
      wildcardEntries: [],
      prioritizedHosts: [],
      sampledHosts: [],
      coverageSummary: "Certificate transparency discovery did not complete before the scan timeout.",
      issues: [],
      strengths: [],
    },
    htmlSecurity: fallbackHtmlSecurity,
    aiSurface: fallbackHtmlSecurity.aiSurface,
    thirdPartyTrust: {
      totalProviders: 0,
      highRiskProviders: 0,
      providers: [],
      issues: [],
      strengths: [],
      summary: "Third-party trust could not be fully assessed before the scan timeout.",
    },
    infrastructure: {
      host: result.host,
      addresses: [],
      cnameTargets: [],
      reverseDns: [],
      providers: [],
      issues: [],
      strengths: [],
      summary: "Infrastructure attribution did not complete before the scan timeout.",
    },
    passiveIntelligence: emptyPassiveIntelligence("Passive intelligence did not complete before the scan timeout."),
    exposure: emptyExposure(),
    corsSecurity: emptyCorsSecurity(),
    apiSurface: emptyApiSurface(),
    publicSignals: emptyPublicSignals(result.host),
    wafFingerprint: analyzeWafFingerprint(finalUrl, result.rawHeaders, null, result.redirects),
    scoreDrivers: [
      {
        areaKey: "overall",
        areaLabel: "Overall posture",
        impact: 20,
        label: "Secondary enrichment timeout",
        detail: "The primary response was scored, but secondary enrichment did not complete within the scan budget.",
        source: "assessment_limit",
      },
    ] as AnalysisResult["scoreDrivers"],
    assessmentLimitation: {
      limited: true,
      kind: "other" as const,
      title: "Assessment limited by scan timeout",
      detail: "The primary page response was assessed, but secondary enrichment did not complete within the scan budget.",
    },
    scanTiming: {
      totalMs: timeoutMs,
      coreMs,
      enrichmentMs: Math.max(0, timeoutMs - coreMs),
      timedOut: true,
      timeoutMs,
    },
  };

  return {
    ...timedOutResult,
    executiveSummary: buildExecutiveSummary(timedOutResult),
  };
}

export async function analyzeUrl(input: string, options: AnalyzeTargetOptions = {}): Promise<AnalysisResult> {
  const scanStartedAt = Date.now();
  const scanMode: ScanMode = options.scanMode || "standard";
  const pageAnalysisEnabled = scanMode === "standard";
  const normalizedInput = normalizeUrl(input);
  const maxScanDurationMs = options.maxScanDurationMs ?? MAX_SCAN_DURATION_MS;
  const requestTimeoutMs = Math.min(options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS, maxScanDurationMs);
  let result: CoreScanResult;

  try {
    result = await withTimeout(
      analyzeUrlCore(normalizedInput, {
        ...options,
        includeCertificate: true,
        requestTimeoutMs,
      }),
      maxScanDurationMs,
      "Primary scan timed out.",
    );
  } catch (error) {
    const failure = classifyAssessmentFailure(error);
    const elapsedMs = Date.now() - scanStartedAt;
    return buildLimitedResult(input, normalizedInput, failure, {
      totalMs: elapsedMs,
      coreMs: elapsedMs,
      enrichmentMs: 0,
      timedOut: error instanceof Error && error.message === "Primary scan timed out.",
      timeoutMs: maxScanDurationMs,
    });
  }

  const coreMs = Date.now() - scanStartedAt;
  const remainingMs = Math.max(1, maxScanDurationMs - coreMs);
  let enrichedResult: EnrichedAnalysisResult;
  try {
    enrichedResult = await withTimeout(
      enrichCoreResult(result, pageAnalysisEnabled),
      remainingMs,
      "Secondary scan enrichment timed out.",
    );
  } catch (error) {
    if (error instanceof Error && error.message === "Secondary scan enrichment timed out.") {
      return buildTimedOutEnrichmentResult(result, pageAnalysisEnabled, maxScanDurationMs, coreMs);
    }
    throw error;
  }
  const assessmentLimitation = enrichedResult.assessmentLimitation;
  const postureScore = scorePostureAnalysis(enrichedResult);
  const totalMs = Date.now() - scanStartedAt;
  const scoredResult = {
    ...enrichedResult,
    score: postureScore.score,
    grade: postureScore.grade,
    scoreDrivers: postureScore.scoreDrivers,
    summary: assessmentLimitation.limited
      ? "Assessment is limited because the target returned a blocked or restricted response."
      : summarizePostureGrade(postureScore.grade),
    scanTiming: {
      totalMs,
      coreMs,
      enrichmentMs: Math.max(0, totalMs - coreMs),
      timedOut: false,
      timeoutMs: maxScanDurationMs,
    },
  };

  return {
    ...scoredResult,
    executiveSummary: buildExecutiveSummary(scoredResult),
  };
}

export const analyzeTarget = analyzeUrl;
export { formatErrorMessage };
export { analyzeInfrastructure } from "./infrastructure.js";
export { buildHistoryDiff, buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "./historyDiff.js";
export {
  assertPublicRequestTarget,
  isLocalHostname,
  isPrivateAddress,
} from "./network-validation.js";
export type * from "./types.js";
