import {
  LIBRARY_RISK_LOOKUP_LIMIT,
  OSV_DETAIL_CONCURRENCY_LIMIT,
  OSV_DETAIL_LOOKUP_LIMIT,
  OSV_QUERY_TIMEOUT_MS,
} from "./scannerConfig.js";
import { requestJson } from "./network.js";
import type { RequestJsonFn } from "./network.js";
import type { LibraryFingerprint, LibraryRiskSignal, LibraryVulnerability } from "./types.js";
import { mapWithConcurrency, unique } from "./utils.js";

const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";

const LIBRARY_PATTERNS: Array<{ packageName: string; pattern: RegExp; evidence: string }> = [
  { packageName: "jquery", pattern: /(?:^|[/_-])jquery(?:[-_.](?:slim|ui))?[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned jQuery script URL" },
  { packageName: "bootstrap", pattern: /(?:^|[/_-])bootstrap(?:\.bundle)?[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned Bootstrap script URL" },
  { packageName: "react", pattern: /(?:^|[/_-])react[-@/_]?v?(\d+\.\d+\.\d+)(?:\.production\.min|\.development|\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned React script URL" },
  { packageName: "react-dom", pattern: /(?:^|[/_-])react-dom[-@/_]?v?(\d+\.\d+\.\d+)(?:\.production\.min|\.development|\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned React DOM script URL" },
  { packageName: "vue", pattern: /(?:^|[/_-])vue(?:\.runtime|\.global|\.esm-browser|\.esm-bundler|\.cjs)?(?:\.prod)?[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned Vue script URL" },
  { packageName: "angular", pattern: /(?:^|[/_-])angular(?:\.min)?[-@/_]?v?(\d+\.\d+\.\d+)\.js(?:[?#]|$)/i, evidence: "Detected from a versioned AngularJS script URL" },
  { packageName: "lodash", pattern: /(?:^|[/_-])lodash[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned Lodash script URL" },
  { packageName: "moment", pattern: /(?:^|[/_-])moment[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned Moment.js script URL" },
  { packageName: "axios", pattern: /(?:^|[/_-])axios[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned Axios script URL" },
  { packageName: "chart.js", pattern: /(?:^|[/_-])chart(?:\.umd)?[-@/_]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js(?:[?#]|$)/i, evidence: "Detected from a versioned Chart.js script URL" },
];

const riskCache = new Map<string, LibraryRiskSignal[]>();

const requestOsvJson = async (
  url: string,
  requestJsonFn: RequestJsonFn,
  options: { method?: "GET" | "POST"; body?: string } = {},
) => {
  const response = await requestJsonFn(
    new URL(url),
    { "content-type": "application/json" },
    {
      timeoutMs: OSV_QUERY_TIMEOUT_MS,
      ...options,
    },
  );
  if (response.statusCode < 200 || response.statusCode >= 300 || !response.json || typeof response.json !== "object") {
    throw new Error(`OSV request failed with status ${response.statusCode}`);
  }
  return response.json as Record<string, unknown>;
};

const toSeverity = (value: unknown): LibraryVulnerability["severity"] => {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (normalized === "low" || normalized === "moderate" || normalized === "high" || normalized === "critical") {
    return normalized;
  }
  return "unknown";
};

const pickReferenceUrl = (references: unknown): string | null => {
  if (!Array.isArray(references)) {
    return null;
  }
  const preferred = references.find((item) => typeof item === "object" && item && "url" in item && typeof item.url === "string");
  return preferred && typeof preferred === "object" && preferred && "url" in preferred && typeof preferred.url === "string" ? preferred.url : null;
};

const toVulnerability = (payload: Record<string, unknown>): LibraryVulnerability => ({
  id: typeof payload.id === "string" ? payload.id : "unknown",
  summary: typeof payload.summary === "string" && payload.summary.trim() ? payload.summary.trim() : "Known advisory recorded in OSV.",
  severity:
    payload.database_specific && typeof payload.database_specific === "object"
      ? toSeverity((payload.database_specific as Record<string, unknown>).severity)
      : "unknown",
  aliases: Array.isArray(payload.aliases) ? payload.aliases.filter((item): item is string => typeof item === "string").slice(0, 4) : [],
  referenceUrl: pickReferenceUrl(payload.references),
});

export const collectLibraryFingerprints = (externalScriptUrls: string[]): LibraryFingerprint[] => {
  const fingerprints: LibraryFingerprint[] = [];
  const seen = new Set<string>();

  for (const sourceUrl of externalScriptUrls) {
    // Skip pathologically long URLs to guard against ReDoS
    if (sourceUrl.length > 1024) continue;
    for (const matcher of LIBRARY_PATTERNS) {
      const match = sourceUrl.match(matcher.pattern);
      if (!match?.[1]) {
        continue;
      }
      const version = match[1];
      const key = `${matcher.packageName}@${version}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      fingerprints.push({
        packageName: matcher.packageName,
        version,
        sourceUrl,
        confidence: "high",
        evidence: matcher.evidence,
      });
      break;
    }
  }

  return fingerprints.slice(0, LIBRARY_RISK_LOOKUP_LIMIT);
};

export const fetchLibraryRiskSignals = async (
  fingerprints: LibraryFingerprint[],
  requestJsonFn: RequestJsonFn = requestJson,
): Promise<LibraryRiskSignal[]> => {
  const queryableFingerprints = fingerprints.filter((item) => item.confidence === "high").slice(0, LIBRARY_RISK_LOOKUP_LIMIT);
  if (!queryableFingerprints.length) {
    return [];
  }

  const cacheKey = unique(queryableFingerprints.map((item) => `${item.packageName}@${item.version}`)).sort().join("|");
  const cached = riskCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  try {
    const queryResponse = await requestOsvJson(OSV_QUERYBATCH_URL, requestJsonFn, {
      method: "POST",
      body: JSON.stringify({
        queries: queryableFingerprints.map((item) => ({
          package: {
            ecosystem: "npm",
            name: item.packageName,
          },
          version: item.version,
        })),
      }),
    });

    const results = Array.isArray(queryResponse.results) ? queryResponse.results : [];
    const vulnerabilityIds = unique(
      results.flatMap((result) =>
        result && typeof result === "object" && Array.isArray((result as Record<string, unknown>).vulns)
          ? ((result as Record<string, unknown>).vulns as Array<Record<string, unknown>>)
              .map((item) => (typeof item.id === "string" ? item.id : null))
              .filter((item): item is string => Boolean(item))
          : [],
      ),
    ).slice(0, OSV_DETAIL_LOOKUP_LIMIT);

    const vulnerabilityDetails = await mapWithConcurrency(
      vulnerabilityIds,
      OSV_DETAIL_CONCURRENCY_LIMIT,
      async (id) => {
        try {
          const payload = await requestOsvJson(`${OSV_VULN_URL}${encodeURIComponent(id)}`, requestJsonFn);
          return [id, toVulnerability(payload)] as const;
        } catch {
          return [id, null] as const;
        }
      },
    );

    const vulnerabilityMap = new Map(vulnerabilityDetails.filter((entry): entry is readonly [string, LibraryVulnerability] => Boolean(entry[1])));

    const signals = queryableFingerprints.flatMap((fingerprint, index) => {
      const result = results[index];
      const ids =
        result && typeof result === "object" && Array.isArray((result as Record<string, unknown>).vulns)
          ? ((result as Record<string, unknown>).vulns as Array<Record<string, unknown>>)
              .map((item) => (typeof item.id === "string" ? item.id : null))
              .filter((item): item is string => Boolean(item))
          : [];

      const vulnerabilities = ids
        .map((id) => vulnerabilityMap.get(id))
        .filter((item): item is LibraryVulnerability => Boolean(item))
        .slice(0, 4);

      if (!vulnerabilities.length) {
        return [];
      }

      return [
        {
          packageName: fingerprint.packageName,
          version: fingerprint.version,
          confidence: fingerprint.confidence,
          sourceUrl: fingerprint.sourceUrl,
          evidence: fingerprint.evidence,
          vulnerabilities,
        } satisfies LibraryRiskSignal,
      ];
    });

    if (riskCache.size > 500) riskCache.clear();
    riskCache.set(cacheKey, signals);
    return signals;
  } catch {
    return [];
  }
};
