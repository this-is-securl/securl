import dns from "node:dns/promises";
import {
  CT_CACHE_TTL_MS,
  DNS_LOOKUP_TIMEOUT_MS,
  CT_LOOKUP_TIMEOUT_MS,
  CT_SAMPLE_CONCURRENCY_LIMIT,
  CT_SAMPLE_LIMIT,
} from "./scannerConfig.js";
import type { CtDiscoveryInfo, CtDiscoveredHost, CtHostObservation } from "./types.js";
import { detectIdentityProviderName } from "./identityProvider.js";
import { headerValue, mapWithConcurrency, safeResolveWithTimeout, unique, withTimeout } from "./utils.js";

const CT_SUBDOMAIN_LIMIT = 20;
const CT_WILDCARD_LIMIT = 5;

interface CtCacheEntry {
  expiresAt: number;
  value: CtDiscoveryInfo;
}

interface JsonResponse<T = unknown> {
  statusCode: number;
  json: T | null;
}

interface TextResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

type RequestJsonFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<JsonResponse>;
type RequestTextFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<TextResponse>;

const ctCache = new Map<string, CtCacheEntry>();

const formatCtLookupFailure = (error: unknown) => {
  if (!(error instanceof Error)) {
    return {
      coverageSummary: "Public certificate-transparency coverage is temporarily unavailable for this domain.",
      issue: "Public certificate-transparency coverage could not be retrieved cleanly.",
    };
  }

  const message = error.message.toLowerCase();
  if (message.includes("timed out")) {
    return {
      coverageSummary: "Public certificate-transparency coverage did not return in time for this domain.",
      issue: "The public certificate-transparency source timed out before returning coverage data.",
    };
  }

  if (
    message.includes("not valid json") ||
    message.includes("unexpected token") ||
    message.includes("<html")
  ) {
    return {
      coverageSummary: "Public certificate-transparency coverage is temporarily unavailable for this domain.",
      issue: "The public certificate-transparency source returned an unreadable response.",
    };
  }

  return {
    coverageSummary: "Public certificate-transparency coverage is temporarily unavailable for this domain.",
    issue: "The public certificate-transparency source could not be queried cleanly.",
  };
};

const toDiscoveryDomain = (host: string) => {
  const normalized = host.replace(/\.$/, "").toLowerCase();
  const labels = normalized.split(".").filter(Boolean);
  if (labels.length <= 2) {
    return normalized;
  }

  const secondLevelLabels = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
  const last = labels[labels.length - 1];
  const secondLast = labels[labels.length - 2];
  if (last.length === 2 && secondLevelLabels.has(secondLast)) {
    return labels.slice(-3).join(".");
  }

  return labels.slice(-2).join(".");
};

const WAF_PATTERNS = [
  { name: "Cloudflare", test: (headers: Record<string, string | string[] | undefined>, body: string) => Boolean(headerValue(headers, "cf-ray") || /cloudflare/i.test(headerValue(headers, "server") || "") || /attention required|cloudflare/i.test(body)) },
  { name: "Akamai", test: (headers: Record<string, string | string[] | undefined>, body: string) => Boolean(headerValue(headers, "x-akamai-transformed") || headerValue(headers, "akamai-cache-status") || /akamai/i.test(headerValue(headers, "server") || "") || /reference #\d+\.[a-z0-9.]+\.akamai/i.test(body)) },
  { name: "Imperva", test: (headers: Record<string, string | string[] | undefined>, body: string) => Boolean(/imperva|incapsula/i.test(headerValue(headers, "server") || "") || headerValue(headers, "x-iinfo") || /incapsula incident id|imperva/i.test(body)) },
  { name: "Sucuri", test: (headers: Record<string, string | string[] | undefined>, body: string) => Boolean(headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache") || /sucuri/i.test(headerValue(headers, "server") || "") || /sucuri website firewall/i.test(body)) },
  { name: "Fastly", test: (headers: Record<string, string | string[] | undefined>) => Boolean((headerValue(headers, "x-served-by") || "").toLowerCase().includes("cache-") || (headerValue(headers, "x-cache") || "").toLowerCase().includes("fastly")) },
  { name: "AWS WAF / CloudFront", test: (headers: Record<string, string | string[] | undefined>) => Boolean(headerValue(headers, "x-amz-cf-id") || /cloudfront/i.test(headerValue(headers, "server") || "")) },
];

const TAKEOVER_SIGNATURES = [
  {
    provider: "GitHub Pages",
    targetPattern: /\.github\.io\.?$/i,
    bodyPattern: /there isn't a github pages site here/i,
    evidence: "CNAME points at GitHub Pages and the response matches the unclaimed-site pattern.",
  },
  {
    provider: "Amazon S3",
    targetPattern: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$/i,
    bodyPattern: /<code>nosuchbucket<\/code>|the specified bucket does not exist/i,
    evidence: "CNAME points at Amazon S3 and the response matches a missing-bucket pattern.",
  },
  {
    provider: "Azure App Service",
    targetPattern: /\.azurewebsites\.net\.?$/i,
    bodyPattern: /404 web site not found|app service unavailable/i,
    evidence: "CNAME points at Azure App Service and the response matches an unassigned-site pattern.",
  },
  {
    provider: "Heroku",
    targetPattern: /\.herokudns\.com\.?$/i,
    bodyPattern: /no such app/i,
    evidence: "CNAME points at Heroku and the response matches a missing-app pattern.",
  },
  {
    provider: "Netlify",
    targetPattern: /\.netlify\.app\.?$/i,
    bodyPattern: /page not found|not found - request id/i,
    evidence: "CNAME points at Netlify and the response looks like an unclaimed site.",
  },
];

const categorizeHost = (host: string): CtDiscoveredHost["category"] => {
  if (/^(?:auth|login|sso|signin|id|identity|oauth|accounts?)\./i.test(host) || /(?:^|\.)(?:auth|login|sso|signin|id|identity|oauth|accounts?)(?:[.-]|$)/i.test(host)) {
    return "auth";
  }
  if (/(^|\.)(?:api|graphql|rpc|gateway)(?:[.-]|$)/i.test(host)) {
    return "api";
  }
  if (/(^|\.)(?:admin|manage|console|portal)(?:[.-]|$)/i.test(host)) {
    return "admin";
  }
  if (/(^|\.)(?:app|www2?|dashboard|client|members?)(?:[.-]|$)/i.test(host)) {
    return "app";
  }
  if (/(^|\.)(?:cdn|assets?|static|media|img|images?)(?:[.-]|$)/i.test(host)) {
    return "static";
  }
  if (/(^|\.)(?:edge|cache|waf|shield)(?:[.-]|$)/i.test(host)) {
    return "cdn";
  }
  return "other";
};

const priorityForCategory = (category: CtDiscoveredHost["category"]): CtDiscoveredHost["priority"] => {
  if (category === "auth" || category === "admin" || category === "api") {
    return "high";
  }
  if (category === "app" || category === "cdn") {
    return "medium";
  }
  return "low";
};

const evidenceForCategory = (category: CtDiscoveredHost["category"]) => {
  switch (category) {
    case "auth":
      return "Hostname suggests identity or SSO surface.";
    case "api":
      return "Hostname suggests a public API or gateway surface.";
    case "admin":
      return "Hostname suggests administration or management surface.";
    case "app":
      return "Hostname suggests an application or customer-facing surface.";
    case "cdn":
      return "Hostname suggests edge delivery or protection infrastructure.";
    case "static":
      return "Hostname suggests static asset delivery.";
    default:
      return "Hostname was surfaced by CT logs without a stronger passive category match.";
  }
};

const rankHosts = (hosts: string[]): CtDiscoveredHost[] =>
  hosts
    .map((host) => {
      const category = categorizeHost(host);
      return {
        host,
        category,
        priority: priorityForCategory(category),
        evidence: evidenceForCategory(category),
      };
    })
    .sort((left, right) => {
      const priorityWeight = { high: 0, medium: 1, low: 2 };
      const categoryWeight = { auth: 0, admin: 1, api: 2, app: 3, cdn: 4, static: 5, other: 6 };
      return (
        priorityWeight[left.priority] - priorityWeight[right.priority] ||
        categoryWeight[left.category] - categoryWeight[right.category] ||
        left.host.localeCompare(right.host)
      );
    });

const detectEdgeProvider = (headers: Record<string, string | string[] | undefined>, body: string) => {
  for (const entry of WAF_PATTERNS) {
    if (entry.test(headers, body)) {
      return entry.name;
    }
  }
  const server = headerValue(headers, "server");
  if (server && /(proxy|gateway|edge|gtm|belfrage|varnish)/i.test(server)) {
    return server;
  }
  return null;
};

const classifyResponseKind = (statusCode: number, headers: Record<string, string | string[] | undefined>, body: string): CtHostObservation["responseKind"] => {
  if ([301, 302, 303, 307, 308].includes(statusCode)) {
    return "redirect";
  }
  const contentType = (headerValue(headers, "content-type") || "").toLowerCase();
  if (contentType.includes("text/html") || /<html[\s>]|<!doctype html/i.test(body)) {
    return "html";
  }
  if (contentType.includes("application/json") || /^\s*[{[]/.test(body)) {
    return "json";
  }
  if (contentType) {
    return "other";
  }
  return "unknown";
};

const summarizeObservationNote = (
  statusCode: number,
  responseKind: CtHostObservation["responseKind"],
  location: string | null,
  identityProvider: string | null,
  edgeProvider: string | null,
  suspectedTakeover: CtHostObservation["suspectedTakeover"],
) => {
  if (suspectedTakeover) {
    return `Possible takeover signal via ${suspectedTakeover.provider}. ${suspectedTakeover.evidence}`;
  }
  if (location && identityProvider) {
    return `Redirects toward ${identityProvider} identity infrastructure.`;
  }
  if (location) {
    return `Responded with a redirect to ${location}.`;
  }
  if (identityProvider) {
    return `Returned content with ${identityProvider} identity signals.`;
  }
  if (edgeProvider) {
    return `Returned through ${edgeProvider}.`;
  }
  if (statusCode >= 200 && statusCode < 300) {
    return `Responded normally with ${responseKind} content.`;
  }
  if (statusCode === 401 || statusCode === 403) {
    return "Host exists but is access controlled.";
  }
  if (statusCode === 404) {
    return "Host resolved but did not expose a default page.";
  }
  return `Observed HTTP ${statusCode}.`;
};

const detectTakeoverSignal = (cnameTargets: string[], body: string): CtHostObservation["suspectedTakeover"] => {
  const normalizedTargets = cnameTargets.map((value) => value.toLowerCase());
  const bodyLower = body.toLowerCase();

  for (const signature of TAKEOVER_SIGNATURES) {
    if (normalizedTargets.some((target) => signature.targetPattern.test(target)) && signature.bodyPattern.test(bodyLower)) {
      return {
        provider: signature.provider,
        confidence: "medium",
        evidence: signature.evidence,
      };
    }
  }

  return null;
};

const observeSampledHosts = async (
  prioritizedHosts: CtDiscoveredHost[],
  requestText: RequestTextFn,
): Promise<CtHostObservation[]> => {
  const samples = prioritizedHosts.slice(0, CT_SAMPLE_LIMIT);
  const observations = await mapWithConcurrency(
    samples,
    CT_SAMPLE_CONCURRENCY_LIMIT,
    async (hostInfo) => {
      const target = new URL(`https://${hostInfo.host}/`);
      const cnameTargets = (await safeResolveWithTimeout(
        () => dns.resolveCname(hostInfo.host),
        DNS_LOOKUP_TIMEOUT_MS,
      )) || [];

      try {
        const response = await withTimeout(
          requestText(target),
          CT_LOOKUP_TIMEOUT_MS,
          "CT sample request timed out.",
        );
        const location = headerValue(response.headers, "location");
        const redirectTarget = location ? new URL(location, target).hostname : null;
        const identityProvider = detectIdentityProviderName([
          hostInfo.host,
          redirectTarget,
          response.body,
          location,
        ].filter((value): value is string => Boolean(value)));
        const edgeProvider = detectEdgeProvider(response.headers, response.body);
        const responseKind = classifyResponseKind(response.statusCode, response.headers, response.body);
        const suspectedTakeover = detectTakeoverSignal(cnameTargets, response.body);

        return {
          host: hostInfo.host,
          category: hostInfo.category,
          priority: hostInfo.priority,
          reachable: true,
          finalUrl: target.toString(),
          statusCode: response.statusCode,
          responseKind,
          identityProvider,
          edgeProvider,
          cnameTargets,
          suspectedTakeover,
          note: summarizeObservationNote(response.statusCode, responseKind, location, identityProvider, edgeProvider, suspectedTakeover),
        } satisfies CtHostObservation;
      } catch (error) {
        return {
          host: hostInfo.host,
          category: hostInfo.category,
          priority: hostInfo.priority,
          reachable: false,
          finalUrl: target.toString(),
          statusCode: 0,
          responseKind: "unknown",
          identityProvider: null,
          edgeProvider: null,
          cnameTargets,
          suspectedTakeover: null,
          note: error instanceof Error ? error.message : "CT sample request failed.",
        } satisfies CtHostObservation;
      }
    },
  );

  return observations;
};

export const fetchCtDiscovery = async (
  host: string,
  requestJson: RequestJsonFn,
  requestText: RequestTextFn,
  options: { sampleHosts?: boolean } = {},
): Promise<CtDiscoveryInfo> => {
  const { sampleHosts = true } = options;
  const queriedDomain = toDiscoveryDomain(host);
  const cached = ctCache.get(queriedDomain);
  if (cached) {
    if (cached.expiresAt > Date.now()) return cached.value; // still valid
    ctCache.delete(queriedDomain); // expired — evict before re-fetch
  }
  if (ctCache.size > 2000) ctCache.clear();

  const sourceUrl = `https://crt.sh/?q=%25.${queriedDomain}&output=json`;

  try {
    const response = await withTimeout(
      requestJson(new URL(sourceUrl)),
      CT_LOOKUP_TIMEOUT_MS,
      "Certificate transparency lookup timed out.",
    );
    const rows = Array.isArray(response.json) ? response.json : [];
    const rawNames = rows.flatMap((entry) =>
      String((entry as { name_value?: string })?.name_value || "")
        .split(/\r?\n/)
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean),
    );

    const wildcardEntries = unique(
      rawNames
        .filter((value) => value.startsWith("*."))
        .map((value) => value.slice(2))
        .filter((value) => value === queriedDomain || value.endsWith(`.${queriedDomain}`)),
    ).slice(0, CT_WILDCARD_LIMIT);
    const subdomains = unique(
      rawNames.filter((value) => !value.startsWith("*.") && value !== queriedDomain && value.endsWith(`.${queriedDomain}`)),
    ).slice(0, CT_SUBDOMAIN_LIMIT);

    const prioritizedHosts = rankHosts(subdomains);
    const sampledHosts = sampleHosts ? await observeSampledHosts(prioritizedHosts, requestText) : [];
    const authCount = prioritizedHosts.filter((entry) => entry.category === "auth").length;
    const edgeHits = sampledHosts.filter((entry) => entry.edgeProvider).length;
    const takeoverHits = sampledHosts.filter((entry) => entry.suspectedTakeover);
    const coverageSummary = subdomains.length
      ? `CT logs surfaced ${subdomains.length} subdomain${subdomains.length === 1 ? "" : "s"} for ${queriedDomain}; ${prioritizedHosts.filter((entry) => entry.priority === "high").length} look high-priority${sampleHosts ? ` and ${sampledHosts.length} were lightly sampled` : ""}.`
      : `CT logs did not surface distinct subdomains for ${queriedDomain}.`;

    const value: CtDiscoveryInfo = {
      queriedDomain,
      sourceUrl,
      subdomains,
      wildcardEntries,
      prioritizedHosts,
      sampledHosts,
      coverageSummary,
      issues: [
        ...(subdomains.length
          ? []
          : ["Certificate transparency search did not return any distinct subdomains for this domain."]),
        ...(authCount
          ? [`CT logs surfaced ${authCount} auth- or login-like host${authCount === 1 ? "" : "s"} worth reviewing.`]
          : []),
        ...takeoverHits.map(
          (entry) =>
            `Possible subdomain takeover signal on ${entry.host} via ${entry.suspectedTakeover?.provider}. Review the DNS target and service ownership.`,
        ),
      ],
      strengths: [
        ...(subdomains.length
          ? [`Certificate transparency surfaced ${subdomains.length} subdomain${subdomains.length === 1 ? "" : "s"} without touching the target.`]
          : []),
        ...(sampledHosts.length
          ? [`Best-effort coverage sampled ${sampledHosts.length} discovered host${sampledHosts.length === 1 ? "" : "s"} to estimate exposed footprint.`]
          : []),
        ...(edgeHits
          ? [`${edgeHits} sampled host${edgeHits === 1 ? "" : "s"} showed edge or protection-provider signals.`]
          : []),
        ...(!takeoverHits.length && sampledHosts.some((entry) => entry.cnameTargets.length)
          ? ["No obvious takeover-style signatures were observed among the sampled CT hosts."]
          : []),
      ],
    };

    ctCache.set(queriedDomain, {
      expiresAt: Date.now() + CT_CACHE_TTL_MS,
      value,
    });

    return value;
  } catch (error) {
    const fallback = formatCtLookupFailure(error);
    return {
      queriedDomain,
      sourceUrl,
      subdomains: [],
      wildcardEntries: [],
      prioritizedHosts: [],
      sampledHosts: [],
      coverageSummary: fallback.coverageSummary,
      issues: [fallback.issue],
      strengths: [],
    };
  }
};
