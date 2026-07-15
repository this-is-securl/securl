import { URL } from "node:url";
import { evaluateDetectionPacks, evidenceForWafOutput } from "./detectionPacks/evaluator.js";
import { FIRST_PARTY_DETECTION_PACKS } from "./detectionPacks/edgeProviders.js";
import type { RedirectHop, WafFingerprintInfo } from "./types.js";
import { unique } from "./utils.js";

type ResponseHeaders = Record<string, string | string[] | undefined>;

const headerValue = (headers: ResponseHeaders, name: string) => {
  const value = headers[name];
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return value ?? null;
};

const WAF_DETECTORS = [
  {
    name: "Imperva",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-iinfo") || /imperva|incapsula/i.test(headerValue(headers, "server") || "") || /incapsula incident id|imperva/i.test(body)),
    evidence: () => "Observed Imperva/Incapsula response markers.",
  },
  {
    name: "Sucuri",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache") || /sucuri/i.test(headerValue(headers, "server") || "") || /sucuri website firewall/i.test(body)),
    evidence: () => "Observed Sucuri edge headers or branded error-page markers.",
  },
  {
    name: "Azure Front Door",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Boolean(headerValue(headers, "x-azure-ref")),
    evidence: () => "Observed x-azure-ref edge headers.",
  },
  {
    name: "F5 BIG-IP ASM",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-wa-info") || headerValue(headers, "x-cnection") || /the requested url was rejected/i.test(body)),
    evidence: () => "Observed F5-style response headers or rejection-body markers.",
  },
  {
    name: "Barracuda",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Object.keys(headers).some((key) => key.toLowerCase().startsWith("x-barracuda-")),
    evidence: () => "Observed Barracuda-branded response headers.",
  },
  {
    name: "Nginx Plus / ModSecurity",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) =>
      Boolean((headerValue(headers, "server") || "").toLowerCase().includes("mod_security") || headerValue(headers, "x-response-code")),
    evidence: () => "Observed mod_security or gateway response markers.",
  },
  {
    name: "Palo Alto Prisma WAAS",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Boolean(headerValue(headers, "x-pan-request-id")),
    evidence: () => "Observed x-pan-request-id header.",
  },
  {
    name: "Google Cloud Armor",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) =>
      Object.keys(headers).some((key) => key.toLowerCase().startsWith("x-goog-")) &&
      (headerValue(headers, "via") || "").toLowerCase().includes("google"),
    evidence: () => "Observed x-goog-* headers with Google edge routing markers.",
  },
  {
    name: "Vercel Edge Network",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Boolean(headerValue(headers, "x-vercel-id")),
    evidence: () => "Observed x-vercel-id header.",
  },
];

export const analyzeWafFingerprint = (
  finalUrl: URL,
  headers: ResponseHeaders,
  html: string | null,
  redirects: RedirectHop[],
): WafFingerprintInfo => {
  const body = (html || "").toLowerCase();
  const packProviders = evaluateDetectionPacks({ headers, body }, FIRST_PARTY_DETECTION_PACKS)
    .filter((match) => Boolean(match.outputs.waf))
    .map((match) => {
      const waf = match.outputs.waf!;
      return {
        name: waf.name,
        confidence: waf.confidence,
        detection: waf.detection,
        evidence: evidenceForWafOutput({ headers, body }, waf),
      };
    });
  const staticProviders = WAF_DETECTORS
    .filter((detector) => detector.test(headers, body))
    .map((detector) => ({
      name: detector.name,
      confidence: detector.confidence,
      detection: detector.detection,
      evidence: detector.evidence(),
    }));
  const providers = unique([...packProviders, ...staticProviders].map((provider) => `${provider.name}|${provider.evidence}`))
    .map((key) => [...packProviders, ...staticProviders].find((provider) => `${provider.name}|${provider.evidence}` === key))
    .filter((provider): provider is (typeof packProviders)[number] => Boolean(provider));

  const via = headerValue(headers, "via");
  const server = headerValue(headers, "server");
  const xCdn = headerValue(headers, "x-cdn");
  const edgeSignals = unique([
    server && /(edge|proxy|gateway|cache|gtm|belfrage|varnish)/i.test(server) ? `Server: ${server}` : null,
    via ? `Via: ${via}` : null,
    xCdn ? `X-CDN: ${xCdn}` : null,
    redirects.some((hop) => {
      try {
        return hop.location ? new URL(hop.location, finalUrl).origin !== finalUrl.origin : false;
      } catch {
        return false;
      }
    })
      ? "Redirect chain includes a separate edge or identity origin."
      : null,
  ]);

  const strengths: string[] = [];
  const issues: string[] = [];

  if (providers.length) {
    strengths.push(`Edge protection or delivery signals point to ${providers.map((provider) => provider.name).join(", ")}.`);
  } else {
    strengths.push("No branded WAF or edge provider was conclusively identified from passive response evidence.");
  }

  if (edgeSignals.length) {
    strengths.push("Response headers exposed edge-network handling details that help classify the delivery path.");
  }

  if (providers.some((provider) => provider.name.includes("CloudFront"))) {
    issues.push("AWS edge delivery was observed, but passive evidence alone does not confirm whether AWS WAF policies are enforced.");
  }

  return {
    detected: Boolean(providers.length),
    providers,
    edgeSignals,
    issues,
    strengths,
    summary: providers.length
      ? `Passive response evidence suggests ${providers.map((provider) => provider.name).join(", ")} in front of the target.`
      : "No branded WAF or edge-protection provider was conclusively identified from passive response evidence.",
  };
};
