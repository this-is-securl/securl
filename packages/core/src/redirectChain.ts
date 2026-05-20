import type { RedirectChainInfo, RedirectHop } from "./types.js";
import { getSiteDomain } from "./utils.js";

const redirectStatuses = new Set([301, 302, 303, 307, 308]);

export function analyzeRedirectChain(
  submittedUrl: URL,
  finalUrl: URL,
  redirects: RedirectHop[],
): RedirectChainInfo {
  const hops = redirects.map((hop) => ({
    ...hop,
    status: hop.status ?? hop.statusCode,
    isHttps: hop.isHttps ?? hop.secure,
  }));
  const redirectHops = hops.filter((hop) => redirectStatuses.has(hop.status));
  const startedHttps = submittedUrl.protocol === "https:";
  const endedHttps = finalUrl.protocol === "https:";
  const hasMixedRedirect = startedHttps && endedHttps && hops.some((hop) => !hop.isHttps);
  const isLongChain = redirectHops.length > 3;
  const crossesDomain = getSiteDomain(submittedUrl.hostname) !== getSiteDomain(finalUrl.hostname);
  const issues: string[] = [];
  const strengths: string[] = [];

  if (hasMixedRedirect) {
    issues.push("Redirect chain includes an HTTP hop before reaching the final HTTPS URL.");
  }
  if (isLongChain) {
    issues.push("Redirect chain is longer than three hops, which adds latency and can make policy enforcement harder to reason about.");
  }
  if (crossesDomain) {
    issues.push("Final URL resolves to a different registrable domain than the submitted URL.");
  }
  if (!issues.length) {
    strengths.push("Redirect chain stayed short, HTTPS-only, and on the expected domain.");
  }

  return {
    hops,
    finalUrl: finalUrl.toString(),
    totalHops: redirectHops.length,
    hasMixedRedirect,
    isLongChain,
    crossesDomain,
    issues,
    strengths,
  };
}
