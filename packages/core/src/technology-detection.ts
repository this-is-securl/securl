import { evaluateDetectionPacks, evidenceForTechnologyOutput } from "./detectionPacks/evaluator.js";
import { FIRST_PARTY_DETECTION_PACKS } from "./detectionPacks/edgeProviders.js";
import type { TechnologyResult } from "./types.js";
import { headerValue } from "./utils.js";

type ResponseHeaders = Record<string, string | string[] | undefined>;

export const detectTechnologies = (headers: ResponseHeaders, finalUrl: URL): TechnologyResult[] => {
  const technologies: TechnologyResult[] = [];
  const seen = new Set<string>();

  const addTechnology = (
    name: string,
    category: TechnologyResult["category"],
    evidence: string,
    version: string | null,
    confidence: TechnologyResult["confidence"] = "high",
    detection: TechnologyResult["detection"] = "observed",
  ) => {
    const key = `${name}:${category}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    technologies.push({
      name,
      category,
      evidence,
      version: version || null,
      confidence,
      detection,
    });
  };

  const server = headerValue(headers, "server");
  const poweredBy = headerValue(headers, "x-powered-by");
  const via = headerValue(headers, "via");

  const classifyServerHeader = (value: string) => {
    const lower = value.toLowerCase();
    if (lower.includes("cloudflare")) return { name: "Cloudflare", category: "network" as const, version: value };
    if (lower.includes("sucuri")) return { name: "Sucuri", category: "network" as const, version: value };
    if (lower.includes("akamai")) return { name: "Akamai", category: "network" as const, version: value };
    if (lower.includes("fastly")) return { name: "Fastly", category: "network" as const, version: value };
    if (lower.includes("nginx")) return { name: "Nginx", category: "server" as const, version: value };
    if (lower.includes("apache")) return { name: "Apache", category: "server" as const, version: value };
    if (lower.includes("caddy")) return { name: "Caddy", category: "server" as const, version: value };
    if (/(gtm|gateway|proxy|edge|cache|router|traffic)/.test(lower)) {
      return { name: value, category: "network" as const, version: null };
    }
    return { name: value, category: "server" as const, version: null };
  };

  const addViaSignals = (viaHeader: string) => {
    const hops = viaHeader
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => part.replace(/^\d+(?:\.\d+)?\s+/i, "").trim());

    for (const hop of hops) {
      if (hop && /(bbc-gtm|gtm|gateway|proxy|edge|cache|belfrage|varnish)/.test(hop.toLowerCase())) {
        addTechnology(hop, "network", "Observed in Via response chain", null, "high", "observed");
      }
    }
  };

  if (server) {
    const classification = classifyServerHeader(server);
    addTechnology(classification.name, classification.category, "Observed in Server header", classification.version, "high", "observed");
  }
  if (via) addViaSignals(via);

  if (poweredBy) {
    addTechnology(poweredBy, "frontend", "Observed in X-Powered-By header", null, "high", "observed");
    const poweredByLower = poweredBy.toLowerCase();
    if (poweredByLower.includes("express")) addTechnology("Express", "frontend", "Observed in X-Powered-By header", null, "high", "observed");
    if (poweredByLower.includes("next")) addTechnology("Next.js", "frontend", "Observed in X-Powered-By header", null, "high", "observed");
  }

  if (headerValue(headers, "x-vercel-id")) addTechnology("Vercel", "hosting", "Observed in X-Vercel-Id header", null, "high", "observed");
  if (headerValue(headers, "x-cdn")) addTechnology(headerValue(headers, "x-cdn") as string, "network", "Observed in X-CDN header", null, "high", "observed");
  if (headerValue(headers, "x-envoy-upstream-service-time")) addTechnology("Envoy", "network", "Observed in Envoy upstream timing header", null, "high", "observed");
  if (headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache")) addTechnology("Sucuri", "network", "Observed in Sucuri edge headers", null, "high", "observed");
  for (const match of evaluateDetectionPacks({ headers, body: "" }, FIRST_PARTY_DETECTION_PACKS)) {
    const technology = match.outputs.technology;
    if (!technology) {
      continue;
    }
    addTechnology(
      technology.name,
      technology.category,
      evidenceForTechnologyOutput({ headers, body: "" }, technology),
      technology.version,
      technology.confidence,
      technology.detection,
    );
  }
  if (headerValue(headers, "server-timing")?.toLowerCase().includes("cdn-cache")) addTechnology("CDN", "network", "Observed in Server-Timing header", null, "medium", "observed");

  addTechnology(finalUrl.protocol === "https:" ? "HTTPS" : "HTTP", "security", "Derived from final URL", null, "high", "observed");
  return technologies;
};
