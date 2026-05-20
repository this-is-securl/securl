import dns from "node:dns/promises";
import { DNS_LOOKUP_TIMEOUT_MS } from "./scannerConfig.js";
import type { InfrastructureInfo, InfrastructureSignal, TechnologyResult } from "./types.js";
import { headerValue, mapWithConcurrency, safeResolveWithTimeout, unique } from "./utils.js";

interface InfrastructureResolver {
  resolveCname(host: string): Promise<string[]>;
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
  reverse(address: string): Promise<string[]>;
}

const defaultResolver: InfrastructureResolver = {
  resolveCname: (host) => dns.resolveCname(host),
  resolve4: (host) => dns.resolve4(host),
  resolve6: (host) => dns.resolve6(host),
  reverse: (address) => dns.reverse(address),
};

const PROVIDER_SIGNATURES: Array<{
  provider: string;
  category: InfrastructureSignal["category"];
  pattern: RegExp;
}> = [
  { provider: "Cloudflare", category: "edge", pattern: /cloudflare|cf-ray|cf-cache-status/i },
  { provider: "AWS / CloudFront", category: "cloud", pattern: /amazonaws|aws|cloudfront|awsglobalaccelerator|elb\.amazonaws/i },
  { provider: "Microsoft Azure", category: "cloud", pattern: /azure|trafficmanager\.net|cloudapp\.net|azurefd\.net|windows\.net/i },
  { provider: "Google Cloud", category: "cloud", pattern: /googleusercontent|googlehosted|googleapis|gcp|appspot\.com|goog/i },
  { provider: "Fastly", category: "cdn", pattern: /fastly|fastlylb/i },
  { provider: "Akamai", category: "cdn", pattern: /akamai|edgesuite|edgekey/i },
  { provider: "Bunny.net", category: "cdn", pattern: /bunnycdn|bunny\.net|b-cdn\.net/i },
  { provider: "Vercel", category: "paas", pattern: /vercel|now\.sh/i },
  { provider: "Netlify", category: "paas", pattern: /netlify/i },
  { provider: "Cloudflare Pages", category: "paas", pattern: /pages\.dev/i },
  { provider: "Railway", category: "paas", pattern: /railway\.app|up\.railway\.app/i },
  { provider: "Render", category: "paas", pattern: /render\.com|onrender\.com/i },
  { provider: "Fly.io", category: "paas", pattern: /fly\.dev|fly\.io/i },
  { provider: "DigitalOcean", category: "hosting", pattern: /digitalocean|do-static|ondigitalocean/i },
  { provider: "Hostinger", category: "hosting", pattern: /hostinger|hstgr\.io/i },
  { provider: "OVHcloud", category: "hosting", pattern: /ovh|ovhcloud/i },
  { provider: "Hetzner", category: "hosting", pattern: /hetzner|your-server\.de/i },
  { provider: "Heroku", category: "paas", pattern: /herokuapp|herokudns|heroku/i },
  { provider: "GitHub Pages", category: "paas", pattern: /github\.io|githubusercontent|github\.com/i },
];

const signalFromEvidence = (
  evidence: string,
  source: InfrastructureSignal["source"],
): InfrastructureSignal | null => {
  for (const signature of PROVIDER_SIGNATURES) {
    if (signature.pattern.test(evidence)) {
      return {
        provider: signature.provider,
        category: signature.category,
        confidence: source === "headers" || source === "technology" ? "high" : "medium",
        source,
        evidence,
      };
    }
  }

  return null;
};

const addSignals = (
  signals: InfrastructureSignal[],
  values: string[],
  source: InfrastructureSignal["source"],
) => {
  for (const value of values.filter(Boolean)) {
    const signal = signalFromEvidence(value, source);
    if (signal) {
      signals.push(signal);
    }
  }
};

const detectProtocol = (headers: Record<string, string | string[] | undefined>): InfrastructureInfo["protocol"] => {
  const altSvc = headerValue(headers, "alt-svc");
  const http3Advertised = Boolean(altSvc && /\bh3(?:-|=|")/i.test(altSvc));
  return {
    http: "HTTP/1.1",
    http3Advertised,
    altSvc,
  };
};

const detectWaf = (headers: Record<string, string | string[] | undefined>): NonNullable<InfrastructureInfo["waf"]> => {
  const server = headerValue(headers, "server") || "";
  const xCdn = headerValue(headers, "x-cdn") || "";
  const setCookie = headerValue(headers, "set-cookie") || "";
  const detectors: Array<{ provider: string; confidence: NonNullable<InfrastructureInfo["waf"]>["confidence"]; evidence: string; matched: boolean }> = [
    { provider: "Cloudflare", confidence: "high", evidence: "Observed Cloudflare edge headers.", matched: Boolean(headerValue(headers, "cf-ray") || headerValue(headers, "cf-cache-status") || /cloudflare/i.test(server)) },
    { provider: "Akamai", confidence: "high", evidence: "Observed Akamai cache/request headers.", matched: Boolean(headerValue(headers, "x-check-cacheable") || headerValue(headers, "x-akamai-request-id") || headerValue(headers, "akamai-cache-status")) },
    { provider: "AWS WAF / CloudFront", confidence: "medium", evidence: "Observed AWS CloudFront edge headers.", matched: Boolean(headerValue(headers, "x-amz-cf-id") || headerValue(headers, "x-amz-cf-pop")) },
    { provider: "Imperva", confidence: "high", evidence: "Observed Imperva / Incapsula headers.", matched: Boolean(headerValue(headers, "x-iinfo") || /imperva/i.test(xCdn)) },
    { provider: "Fastly", confidence: "medium", evidence: "Observed Fastly request/cache headers.", matched: Boolean(headerValue(headers, "x-fastly-request-id") || headerValue(headers, "fastly-restarts")) },
    { provider: "Vercel Edge", confidence: "high", evidence: "Observed Vercel edge headers.", matched: Boolean(headerValue(headers, "x-vercel-cache") || headerValue(headers, "x-vercel-id")) },
    { provider: "Sucuri", confidence: "high", evidence: "Observed Sucuri edge headers.", matched: Boolean(headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache")) },
    { provider: "Azure Front Door", confidence: "high", evidence: "Observed Azure Front Door headers.", matched: Boolean(headerValue(headers, "x-azure-ref") || headerValue(headers, "x-fd-healthprobe")) },
    { provider: "F5 / BIG-IP", confidence: "medium", evidence: "Observed F5 / BIG-IP headers or cookie markers.", matched: Boolean(headerValue(headers, "x-wa-info") || /bigipserver/i.test(setCookie)) },
  ];
  const match = detectors.find((detector) => detector.matched);
  return match
    ? { detected: true, provider: match.provider, confidence: match.confidence, evidence: match.evidence }
    : { detected: false, provider: null, confidence: "low", evidence: "No passive WAF signature headers were observed." };
};

export async function analyzeInfrastructure(
  finalUrl: URL,
  headers: Record<string, string | string[] | undefined>,
  technologies: TechnologyResult[],
  resolver: InfrastructureResolver = defaultResolver,
): Promise<InfrastructureInfo> {
  const host = finalUrl.hostname;
  const resolveDns = <T>(operation: () => Promise<T>) =>
    safeResolveWithTimeout(operation, DNS_LOOKUP_TIMEOUT_MS);
  const [cnameTargetsRaw, ipv4Raw, ipv6Raw] = await Promise.all([
    resolveDns(() => resolver.resolveCname(host)),
    resolveDns(() => resolver.resolve4(host)),
    resolveDns(() => resolver.resolve6(host)),
  ]);
  const cnameTargets = cnameTargetsRaw || [];
  const addresses = unique([...(ipv4Raw || []), ...(ipv6Raw || [])]);
  const reverseDns = unique(
    (
      await mapWithConcurrency(addresses.slice(0, 4), 2, async (address) =>
        (await resolveDns(() => resolver.reverse(address))) || [],
      )
    ).flat(),
  );

  const signals: InfrastructureSignal[] = [];
  addSignals(signals, [host, ...cnameTargets], "dns");
  addSignals(signals, reverseDns, "reverse_dns");
  addSignals(
    signals,
    [
      headerValue(headers, "server") || "",
      headerValue(headers, "via") || "",
      headerValue(headers, "x-served-by") || "",
      headerValue(headers, "x-cache") || "",
      headerValue(headers, "cf-ray") || "",
      headerValue(headers, "x-amz-cf-id") || "",
      headerValue(headers, "x-vercel-id") || "",
      headerValue(headers, "x-nf-request-id") || "",
      headerValue(headers, "x-render-origin-server") || "",
      headerValue(headers, "x-railway-edge") || "",
      headerValue(headers, "platform") || "",
      headerValue(headers, "panel") || "",
    ],
    "headers",
  );
  addSignals(
    signals,
    technologies.map((technology) => `${technology.name} ${technology.evidence}`),
    "technology",
  );

  const providers = unique(signals.map((signal) => `${signal.provider}|${signal.category}|${signal.source}`))
    .map((key) => signals.find((signal) => `${signal.provider}|${signal.category}|${signal.source}` === key))
    .filter((signal): signal is InfrastructureSignal => Boolean(signal));

  const providerNames = unique(providers.map((signal) => signal.provider));
  const protocol = detectProtocol(headers);
  const waf = detectWaf(headers);
  const issues: string[] = [];
  const strengths: string[] = [];

  if (protocol.http3Advertised) {
    strengths.push("HTTP/3 support is advertised via Alt-Svc.");
  } else {
    issues.push("No HTTP/3 Alt-Svc advertisement was visible on the main response.");
  }
  if (waf.detected && waf.provider) {
    strengths.push(`Passive WAF or edge-protection headers indicate ${waf.provider}.`);
  }

  return {
    host,
    addresses,
    cnameTargets,
    reverseDns,
    providers,
    protocol,
    waf,
    issues,
    strengths: [
      ...strengths,
      ...(providerNames.length
        ? [`Passive DNS, header, or stack evidence identified ${providerNames.join(", ")}.`]
        : []),
    ],
    summary: providerNames.length
      ? `Passive infrastructure evidence points to ${providerNames.join(", ")}.`
      : "No obvious cloud, CDN, or hosting provider was inferred from passive evidence.",
  };
}
