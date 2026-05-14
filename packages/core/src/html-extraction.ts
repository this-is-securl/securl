import { CLIENT_EXPOSURE_EVIDENCE_LIMIT, HTML_SIGNATURE_LIMIT, SUMMARY_EVIDENCE_LIMIT } from "./scannerConfig.js";
import { getSiteDomain, headerValue, unique } from "./utils.js";

type ResponseHeaders = Record<string, string | string[] | undefined>;

const stripTagBlocks = (input: string, tagName: string): string => {
  const openToken = `<${tagName}`;
  const closeToken = `</${tagName}>`;
  const lower = input.toLowerCase();
  let cursor = 0;
  let output = "";

  while (cursor < input.length) {
    const openIndex = lower.indexOf(openToken, cursor);
    if (openIndex === -1) {
      output += input.slice(cursor);
      break;
    }

    output += input.slice(cursor, openIndex);
    const closeIndex = lower.indexOf(closeToken, openIndex + openToken.length);
    if (closeIndex === -1) {
      break;
    }
    cursor = closeIndex + closeToken.length;
    output += " ";
  }

  return output;
};

export function normalizeHtmlSignature(body: string): string {
  const withoutScriptBlocks = stripTagBlocks(body, "script");
  const withoutStyleBlocks = stripTagBlocks(withoutScriptBlocks, "style");

  return withoutStyleBlocks
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .slice(0, HTML_SIGNATURE_LIMIT);
}

export function getHtmlTitle(body: string): string | null {
  const lower = body.toLowerCase();
  const openIndex = lower.indexOf("<title");
  if (openIndex === -1) {
    return null;
  }

  const openTagEnd = lower.indexOf(">", openIndex);
  if (openTagEnd === -1) {
    return null;
  }

  const closeIndex = lower.indexOf("</title>", openTagEnd + 1);
  if (closeIndex === -1 || closeIndex <= openTagEnd) {
    return null;
  }

  return body.slice(openTagEnd + 1, closeIndex).replace(/\s+/g, " ").trim();
}

export function extractHtmlTitle(body: string): string | null {
  const title = getHtmlTitle(body);
  return title ? title.toLowerCase() : null;
}

export function summarizeEvidence<T>(values: Array<T | null | undefined | false>, limit = SUMMARY_EVIDENCE_LIMIT): T[] {
  return unique(values).slice(0, limit);
}

export function redactToken(value: string, visible = 8): string {
  if (!value || value.length <= visible * 2) {
    return value;
  }
  return `${value.slice(0, visible)}...${value.slice(-visible)}`;
}

export function collectPassiveLeakSignals(
  html: string,
  finalUrl: URL,
  metaGenerator: string | null,
  externalScriptUrls: string[],
  externalStylesheetUrls: string[],
): Array<{ category: "source_map" | "client_config" | "public_token" | "version_leak"; severity: "info" | "warning"; title: string; detail: string; evidence: string[] }> {
  const signals: Array<{ category: "source_map" | "client_config" | "public_token" | "version_leak"; severity: "info" | "warning"; title: string; detail: string; evidence: string[] }> = [];
  const boundedHtml = html.slice(0, HTML_SIGNATURE_LIMIT * 100);
  const sourceMapReferences = summarizeEvidence([
    ...[...boundedHtml.matchAll(/sourceMappingURL\s*=\s*([^\s"'<>]+)/gi)].map((match) => match[1]),
    ...externalScriptUrls.filter((url) => /\.map(?:$|[?#])/i.test(url)),
    ...externalStylesheetUrls.filter((url) => /\.map(?:$|[?#])/i.test(url)),
  ]).map((value) => {
    try {
      return new URL(value, finalUrl).toString();
    } catch {
      return value;
    }
  });

  if (sourceMapReferences.length) {
    signals.push({
      category: "source_map",
      severity: "warning",
      title: "Source map references visible",
      detail: "Production page markup exposes source map references. Review whether any public source maps reveal internal code comments, paths, or debugging detail.",
      evidence: sourceMapReferences,
    });
  }

  const configMarkers = summarizeEvidence([
    /__NEXT_DATA__/.test(boundedHtml) ? "__NEXT_DATA__" : null,
    /__NUXT__/.test(boundedHtml) ? "__NUXT__" : null,
    /window\.__INITIAL_STATE__/.test(boundedHtml) ? "window.__INITIAL_STATE__" : null,
    /window\.__PRELOADED_STATE__/.test(boundedHtml) ? "window.__PRELOADED_STATE__" : null,
    /window\.__APOLLO_STATE__/.test(boundedHtml) ? "window.__APOLLO_STATE__" : null,
    /window\.__ENV\b/.test(boundedHtml) ? "window.__ENV" : null,
    /drupalSettings/.test(boundedHtml) ? "drupalSettings" : null,
    /window\.__remixContext/.test(boundedHtml) ? "window.__remixContext" : null,
  ]);

  if (configMarkers.length) {
    signals.push({
      category: "client_config",
      severity: "info",
      title: "Client bootstrap data is visible",
      detail: "The page exposes client-side bootstrap or state objects. That is often normal, but it is worth reviewing for internal URLs, feature flags, and environment metadata that should stay private.",
      evidence: configMarkers,
    });
  }

  const stripeKeyMatch = boundedHtml.match(/pk_(?:live|test)_[A-Za-z0-9]{16,}/);
  const gcpApiKeyMatch = boundedHtml.match(/AIza[0-9A-Za-z_-]{20,}/);
  const publicKeyMatch = boundedHtml.match(/pk\.[A-Za-z0-9_-]{20,}/);
  const sentryDsnMatch = boundedHtml.match(/https:\/\/[A-Za-z0-9_-]+@[A-Za-z0-9.-]+\.ingest\.sentry\.io\/\d+/);

  const publicTokenEvidence = summarizeEvidence([
    stripeKeyMatch ? redactToken(stripeKeyMatch[0]) : null,
    gcpApiKeyMatch ? redactToken(gcpApiKeyMatch[0]) : null,
    publicKeyMatch ? redactToken(publicKeyMatch[0]) : null,
    sentryDsnMatch ? redactToken(sentryDsnMatch[0]) : null,
    /apiKey["']?\s*:\s*["'][^"']{16,}["']/.test(boundedHtml) && /projectId["']?\s*:\s*["'][^"']+["']/.test(boundedHtml)
      ? "Firebase-style client config"
      : null,
  ]);

  if (publicTokenEvidence.length) {
    signals.push({
      category: "public_token",
      severity: "warning",
      title: "Public client-side tokens or DSNs were visible",
      detail: "The page markup includes token- or DSN-like values that may be intended for public use. Review scopes and restrictions so they cannot be misused or confused with secrets.",
      evidence: publicTokenEvidence,
    });
  }

  const wpVersionMatch = boundedHtml.match(/\/wp-(?:content|includes)\/[^"' ]+\?ver=\d[\w.-]*/i);
  const cmsMetaVersionMatch = boundedHtml.match(/content\s*=\s*["'][^"']*(wordpress|drupal|joomla|ghost)[^"']*\d[^"']*["']/i);
  const versionEvidence = summarizeEvidence([
    metaGenerator && /\d/.test(metaGenerator) ? metaGenerator : null,
    wpVersionMatch ? wpVersionMatch[0] : null,
    cmsMetaVersionMatch ? cmsMetaVersionMatch[0] : null,
  ]);

  if (versionEvidence.length) {
    signals.push({
      category: "version_leak",
      severity: "info",
      title: "Version metadata is publicly visible",
      detail: "The fetched page exposes framework or asset version markers. These can help maintenance, but they also make public fingerprinting easier.",
      evidence: versionEvidence,
    });
  }

  return signals;
}

export function collectClientExposureSignals(html: string, finalUrl: URL): Array<{ category: "api_endpoint" | "config" | "service" | "environment"; severity: "info" | "warning"; title: string; detail: string; evidence: string[] }> {
  const signals: Array<{ category: "api_endpoint" | "config" | "service" | "environment"; severity: "info" | "warning"; title: string; detail: string; evidence: string[] }> = [];
  const isLikelyApiAsset = (value: string) =>
    /\/assets?\//i.test(value) ||
    /\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|eot)(?:[?#]|$)/i.test(value);

  const endpointKeywords = ["/api", "/graphql", "/trpc", "/socket.io", "/rpc", "/_next/data"];
  const rawCandidates = html
    .slice(0, HTML_SIGNATURE_LIMIT * 100)
    .split(/[\s"'`<>]+/)
    .filter(Boolean)
    .filter((token) => token.startsWith("/") || token.startsWith("http://") || token.startsWith("https://"))
    .filter((token) => endpointKeywords.some((keyword) => token.toLowerCase().includes(keyword)));

  const rawEndpoints = summarizeEvidence(rawCandidates, CLIENT_EXPOSURE_EVIDENCE_LIMIT).map((value) => {
    try {
      return new URL(value, finalUrl).toString();
    } catch {
      return value;
    }
  }).filter((value) => !isLikelyApiAsset(value));

  if (rawEndpoints.length) {
    signals.push({
      category: "api_endpoint",
      severity: "info",
      title: "Client-visible API endpoints were referenced",
      detail: "The fetched page exposes endpoint-style paths or URLs in markup or bootstrap data. That is often normal, but it makes the public application surface easier to enumerate.",
      evidence: rawEndpoints,
    });
  }

  const serviceMarkers = summarizeEvidence([
    /supabase/i.test(html) ? "Supabase" : null,
    /algolia/i.test(html) ? "Algolia" : null,
    /sentry/i.test(html) ? "Sentry" : null,
    /firebase/i.test(html) ? "Firebase" : null,
    /segment/i.test(html) ? "Segment" : null,
    /launchdarkly/i.test(html) ? "LaunchDarkly" : null,
    /amplitude/i.test(html) ? "Amplitude" : null,
  ]);

  if (serviceMarkers.length) {
    signals.push({
      category: "service",
      severity: "info",
      title: "Client-integrated services were visible",
      detail: "Public page content reveals named third-party or backend-adjacent client integrations. Review what configuration or identifiers are intentionally exposed.",
      evidence: serviceMarkers,
    });
  }

  const configMarkers = summarizeEvidence([
    /apiBaseUrl/i.test(html) ? "apiBaseUrl" : null,
    /graphqlEndpoint/i.test(html) ? "graphqlEndpoint" : null,
    /sentryDsn/i.test(html) ? "sentryDsn" : null,
    /supabaseUrl/i.test(html) ? "supabaseUrl" : null,
    /projectId/i.test(html) && /apiKey/i.test(html) ? "projectId + apiKey" : null,
    /environment["']?\s*:\s*["'][^"']+/i.test(html) ? "environment" : null,
  ]);

  if (configMarkers.length) {
    signals.push({
      category: "config",
      severity: "info",
      title: "Client configuration markers were visible",
      detail: "The page includes configuration-style keys or bootstrap fields that may reveal how the client talks to backend services.",
      evidence: configMarkers,
    });
  }

  const environmentMarkers = summarizeEvidence([
    /\b(?:environment|env|release)[^"'`\n]{0,32}staging|staging[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "staging environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}dev(?:elopment)?|dev(?:elopment)?[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "development environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}internal|internal[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "internal environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}sandbox|sandbox[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "sandbox environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}preview|preview[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "preview environment" : null,
  ]);

  if (environmentMarkers.length) {
    signals.push({
      category: "environment",
      severity: "warning",
      title: "Environment naming was visible in client content",
      detail: "The fetched page references environment-like labels such as staging, development, preview, or internal. That can be harmless, but it is worth checking for unintended environment leakage.",
      evidence: environmentMarkers,
    });
  }

  return signals;
}

export function collectSameSiteHosts(
  finalUrl: URL,
  values: Array<string | null | undefined>,
): string[] {
  const siteDomain = getSiteDomain(finalUrl.hostname);

  const hosts = values
    .map((value) => {
      if (!value) {
        return null;
      }

      try {
        return new URL(value, finalUrl).hostname.toLowerCase();
      } catch {
        return null;
      }
    })
    .filter((hostname): hostname is string => Boolean(hostname))
    .filter((hostname) => hostname !== finalUrl.hostname.toLowerCase())
    .filter((hostname) => getSiteDomain(hostname) === siteDomain);

  return unique(hosts);
}

export function classifyHtmlApiFallback(
  probePath: string,
  finalUrl: URL,
  resolvedUrl: URL,
  body: string,
  homepageSignature: string | null,
  homepageTitle: string | null,
): boolean {
  const looksLikeHtml = /<html[\s>]|<!doctype html/i.test(body);
  if (!looksLikeHtml) {
    return false;
  }

  if (resolvedUrl.origin === finalUrl.origin && resolvedUrl.pathname === finalUrl.pathname) {
    return true;
  }

  const probeSegments = probePath.split("/").filter(Boolean);
  const resolvedSegments = resolvedUrl.pathname.split("/").filter(Boolean);
  if (!resolvedSegments.length && probeSegments.length) {
    return true;
  }

  const bodySignature = normalizeHtmlSignature(body);
  const bodyTitle = extractHtmlTitle(body);
  return Boolean(
    homepageSignature &&
      bodySignature &&
      (bodySignature === homepageSignature ||
        (homepageTitle && bodyTitle && homepageTitle === bodyTitle)),
  );
}

export function isAccessDeniedHtml(headers: ResponseHeaders, body: string): boolean {
  const server = (headerValue(headers, "server") || "").toLowerCase();
  const bodyText = body.toLowerCase();
  const title = extractHtmlTitle(body) || "";

  return (
    server.includes("sucuri") ||
    bodyText.includes("website security - access denied") ||
    bodyText.includes("access denied") ||
    bodyText.includes("403 forbidden") ||
    bodyText.includes("request forbidden by administrative rules") ||
    bodyText.includes("request blocked") ||
    title.includes("access denied") ||
    title.includes("403 forbidden")
  );
}
