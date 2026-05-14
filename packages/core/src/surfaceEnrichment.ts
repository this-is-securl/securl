import type http from "node:http";
import type {
  ApiSurfaceInfo,
  CorsSecurityInfo,
  ExposureSummary,
  PublicSignalsInfo,
} from "./types.js";

function sanitiseErrorDetail(msg: string): string {
  // Remove raw IP addresses to avoid leaking internal network topology
  return msg.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, "<host>");
}

type ResponseHeaders = http.IncomingHttpHeaders;

interface RequestHeadResult {
  statusCode: number;
  headers: ResponseHeaders;
  elapsedMs: number;
}

interface RequestTextResult {
  statusCode: number;
  headers: ResponseHeaders;
  body: string;
}

interface RedirectResult {
  response: RequestHeadResult | RequestTextResult;
  finalUrl: URL;
}

interface HomepageContext {
  signature?: string | null;
  pageTitle?: string | null;
}

interface SurfaceDeps {
  exposureProbes: Array<{ label: string; path: string }>;
  apiSurfaceProbes: Array<{ label: string; path: string }>;
  requestOnce: (targetUrl: URL, method?: string) => Promise<RequestHeadResult>;
  requestText: (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<RequestTextResult>;
  requestWithHeaders: (
    targetUrl: URL,
    method: string,
    extraHeaders?: Record<string, string>,
  ) => Promise<RequestHeadResult>;
  fetchWithRedirects: (initialUrl: URL, redirectLimit?: number) => Promise<RedirectResult>;
  headerValue: (headers: ResponseHeaders, name: string) => string | null;
  formatErrorMessage: (error: unknown) => string;
  isAccessDeniedHtml: (headers: ResponseHeaders, body: string) => boolean;
  classifyHtmlApiFallback: (
    probePath: string,
    finalUrl: URL,
    resolvedUrl: URL,
    body: string,
    homepageSignature: string,
    homepageTitle: string | null,
  ) => boolean;
}

const parseCsvHeader = (value: string | null): string[] =>
  value
    ? value
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean)
    : [];

export const fetchPublicSignals = async (
  host: string,
  deps: Pick<SurfaceDeps, "requestText">,
): Promise<PublicSignalsInfo> => {
  const apexHost = host.startsWith("www.") ? host.slice(4) : host;
  const sourceUrl = `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(apexHost)}`;
  const fallback: PublicSignalsInfo = {
    hstsPreload: {
      status: "unknown",
      summary: "Public HSTS preload status could not be determined.",
      sourceUrl,
    },
    issues: [],
    strengths: [],
  };

  try {
    const response = await deps.requestText(new URL(sourceUrl), { Accept: "application/json" });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return fallback;
    }

    const payload = JSON.parse(response.body);
    const statusText = String(payload.status || payload.result || "").toLowerCase();
    const message = String(payload.message || payload.status || "").trim();
    const errors = Array.isArray(payload.errors) ? payload.errors : [];
    const errorText = errors
      .map((entry: unknown) => (typeof entry === "string" ? entry : (entry as { message?: string })?.message || JSON.stringify(entry)))
      .join(" ");

    let status: PublicSignalsInfo["hstsPreload"]["status"] = "not_preloaded";
    if (payload.preloaded === true || statusText.includes("preloaded")) {
      status = "preloaded";
    } else if (statusText.includes("pending")) {
      status = "pending";
    } else if (payload.preloadable === true || payload.eligible === true || statusText.includes("eligible")) {
      status = "eligible";
    } else if (!statusText && !errorText) {
      status = "unknown";
    }

    const summary =
      message && message.toLowerCase() !== "unknown"
        ? message
        : errorText ||
          (status === "not_preloaded"
            ? "The domain is not currently shown as preloaded in the public HSTS preload dataset."
            : "HSTS preload status retrieved from the public preload dataset.");
    const issues: string[] = [];
    const strengths: string[] = [];

    if (status === "preloaded") {
      strengths.push("Domain appears in the public HSTS preload program.");
    } else if (status === "pending") {
      strengths.push("Domain appears to have an HSTS preload submission pending.");
    } else if (status === "eligible") {
      issues.push("Domain may be eligible for HSTS preload but is not currently shown as preloaded.");
    } else if (status === "not_preloaded") {
      issues.push("Domain is not shown as preloaded in the public HSTS preload dataset.");
    }

    return {
      hstsPreload: {
        status,
        summary,
        sourceUrl,
      },
      issues,
      strengths,
    };
  } catch {
    return fallback;
  }
};

export const analyzeExposure = async (
  finalUrl: URL,
  homepageContext: HomepageContext | null | undefined,
  deps: Pick<
    SurfaceDeps,
    | "exposureProbes"
    | "requestOnce"
    | "requestText"
    | "fetchWithRedirects"
    | "headerValue"
    | "formatErrorMessage"
    | "isAccessDeniedHtml"
    | "classifyHtmlApiFallback"
  >,
): Promise<ExposureSummary> => {
  const probes: ExposureSummary["probes"] = [];
  const issues: string[] = [];
  const strengths: string[] = [];
  let sawErrorProbe = false;
  let sawFrontendFallback = false;
  const homepageSignature = homepageContext?.signature || "";
  const homepageTitle = homepageContext?.pageTitle || null;

  for (const probe of deps.exposureProbes) {
    const probeUrl = new URL(probe.path, finalUrl.origin);
    try {
      let response: RequestHeadResult | RequestTextResult;
      let resolvedUrl = probeUrl;

      if (probe.path === "/robots.txt" || probe.path === "/sitemap.xml") {
        const redirectData = await deps.fetchWithRedirects(probeUrl, 3);
        response = redirectData.response;
        resolvedUrl = redirectData.finalUrl;
      } else {
        response = await deps.requestOnce(probeUrl, "HEAD");
        if (response.statusCode === 405) {
          response = await deps.requestText(probeUrl);
        } else if (response.statusCode === 401 || response.statusCode === 403) {
          response = await deps.requestText(probeUrl);
        } else if (response.statusCode >= 200 && response.statusCode < 300) {
          response = await deps.requestText(probeUrl);
        }
      }

      let finding: ExposureSummary["probes"][number]["finding"] = "safe";
      let detail = "Not exposed.";

      if (probe.path === "/robots.txt" || probe.path === "/sitemap.xml") {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          finding = "interesting";
          detail =
            resolvedUrl.toString() === probeUrl.toString()
              ? "Public discovery file is available."
              : `Public discovery file is available after redirect to ${resolvedUrl.toString()}.`;
          strengths.push(`${probe.label} is published.`);
        } else if (response.statusCode === 401 || response.statusCode === 403) {
          finding = "interesting";
          detail = "Discovery file exists but is access-controlled.";
        } else if (response.statusCode >= 500) {
          finding = "error";
          detail = "Discovery file path triggered a server-side error, so availability could not be determined cleanly.";
        } else {
          detail = "Discovery file not found.";
        }
      } else if (response.statusCode >= 200 && response.statusCode < 300) {
        const contentType = deps.headerValue(response.headers, "content-type") || "";
        const looksLikeFrontendFallback =
          "body" in response &&
          typeof response.body === "string" &&
          contentType.includes("text/html") &&
          deps.classifyHtmlApiFallback(
            probe.path,
            finalUrl,
            resolvedUrl,
            response.body,
            homepageSignature,
            homepageTitle,
          );

        if (looksLikeFrontendFallback) {
          finding = "interesting";
          detail = "Path appears to return the site's standard frontend shell rather than sensitive file contents.";
          sawFrontendFallback = true;
        } else {
          finding = "exposed";
          detail = "Sensitive path returned a successful response.";
          issues.push(`${probe.label} may be exposed at ${probe.path}.`);
        }
      } else if (response.statusCode === 401 || response.statusCode === 403) {
        const contentType = deps.headerValue(response.headers, "content-type") || "";
        const blockedByGenericRules =
          "body" in response &&
          typeof response.body === "string" &&
          contentType.includes("text/html") &&
          deps.isAccessDeniedHtml(response.headers, response.body);

        if (blockedByGenericRules) {
          finding = "blocked";
          detail = "Probe was blocked by generic server or edge protection rules. This does not confirm the sensitive file exists.";
          strengths.push(`${probe.label} probe was blocked by generic protection.`);
        } else {
          finding = "interesting";
          detail = "Sensitive path may exist but is access-controlled.";
          strengths.push(`${probe.label} appears access-controlled.`);
        }
        } else if (response.statusCode >= 500) {
          finding = "error";
          detail = "Sensitive path triggered a server-side error, so the path may exist or be handled unexpectedly.";
          sawErrorProbe = true;
        }

      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: response.statusCode,
        finalUrl: resolvedUrl.toString(),
        finding,
        detail,
      });
    } catch (error) {
      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: 0,
        finalUrl: probeUrl.toString(),
        finding: "error",
        detail: sanitiseErrorDetail(deps.formatErrorMessage(error) || "Probe failed unexpectedly."),
      });
      sawErrorProbe = true;
    }
  }

  if (sawErrorProbe) {
    issues.push("Some sensitive-path probes triggered server-side errors, so exposure could not be ruled out cleanly.");
  }

  if (!issues.length && !sawErrorProbe) {
    strengths.push("No obvious high-signal sensitive files were openly exposed in the limited probe set.");
  }
  if (sawFrontendFallback) {
    strengths.push("Some sensitive-looking paths appear to return the standard frontend shell rather than exposed file contents.");
  }

  return { probes, issues, strengths };
};

export const analyzeCorsSecurity = async (
  finalUrl: URL,
  responseHeaders: ResponseHeaders,
  deps: Pick<SurfaceDeps, "requestWithHeaders" | "headerValue">,
): Promise<CorsSecurityInfo> => {
  let optionsResponse: RequestHeadResult = { statusCode: 0, headers: {}, elapsedMs: 0 };
  try {
    optionsResponse = await deps.requestWithHeaders(finalUrl, "OPTIONS", {
      Origin: "https://security-posture-insight.local",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type,authorization",
    });
  } catch {
    // Keep the default empty response if OPTIONS is blocked or errors out.
  }

  const mergedHeaders = {
    ...responseHeaders,
    ...optionsResponse.headers,
  };
  const allowedOrigin = deps.headerValue(mergedHeaders, "access-control-allow-origin");
  const allowCredentials = deps.headerValue(mergedHeaders, "access-control-allow-credentials");
  const allowMethods = parseCsvHeader(deps.headerValue(mergedHeaders, "access-control-allow-methods"));
  const allowHeaders = parseCsvHeader(deps.headerValue(mergedHeaders, "access-control-allow-headers"));
  const allowPrivateNetwork = deps.headerValue(mergedHeaders, "access-control-allow-private-network");
  const vary = deps.headerValue(mergedHeaders, "vary");
  const issues: string[] = [];
  const strengths: string[] = [];

  if (allowedOrigin === "*") {
    if (allowCredentials?.toLowerCase() === "true") {
      issues.push("CORS allows any origin while also allowing credentials.");
    } else {
      issues.push("CORS allows any origin.");
    }
  } else if (allowedOrigin) {
    strengths.push(`CORS is scoped to ${allowedOrigin}.`);
  }
  if (allowMethods.includes("PUT") || allowMethods.includes("DELETE") || allowMethods.includes("PATCH")) {
    issues.push(`Preflight allows elevated methods: ${allowMethods.join(", ")}.`);
  }
  if (allowHeaders.includes("*")) {
    issues.push("CORS allows any request header.");
  }
  if (allowPrivateNetwork?.toLowerCase() === "true") {
    issues.push("CORS allows private network access.");
  }
  if (allowedOrigin && allowedOrigin !== "*" && !(vary || "").toLowerCase().includes("origin")) {
    issues.push("CORS varies by origin but the response does not advertise Vary: Origin.");
  }
  if (!allowedOrigin) {
    strengths.push("No permissive CORS policy detected on the scanned page.");
  }

  return {
    allowedOrigin,
    allowCredentials,
    allowMethods,
    allowHeaders,
    allowPrivateNetwork,
    vary,
    optionsStatus: optionsResponse.statusCode,
    issues,
    strengths,
  };
};

export const analyzeApiSurface = async (
  finalUrl: URL,
  homepageContext: HomepageContext | null | undefined,
  deps: Pick<
    SurfaceDeps,
    "apiSurfaceProbes" | "requestText" | "fetchWithRedirects" | "headerValue" | "isAccessDeniedHtml" | "classifyHtmlApiFallback"
  >,
): Promise<ApiSurfaceInfo> => {
  const probes: ApiSurfaceInfo["probes"] = [];
  const issues: string[] = [];
  const strengths: string[] = [];
  let sawErrorProbe = false;
  const homepageSignature = homepageContext?.signature || "";
  const homepageTitle = homepageContext?.pageTitle || null;

  for (const probe of deps.apiSurfaceProbes) {
    const targetUrl = new URL(probe.path, finalUrl.origin);
    try {
      let response = await deps.requestText(targetUrl, {
        Accept: "application/json,text/plain;q=0.9,*/*;q=0.8",
      });
      let resolvedUrl = targetUrl;

      if ([301, 302, 303, 307, 308].includes(response.statusCode) && deps.headerValue(response.headers, "location")) {
        const redirectData = await deps.fetchWithRedirects(targetUrl, 2);
        resolvedUrl = redirectData.finalUrl;
        response = await deps.requestText(resolvedUrl, {
          Accept: "application/json,text/plain;q=0.9,*/*;q=0.8",
        });
      }

      const contentType = deps.headerValue(response.headers, "content-type");
      let classification: ApiSurfaceInfo["probes"][number]["classification"] = "absent";
      let detail = "Endpoint not found.";

      if (response.statusCode === 401 || response.statusCode === 403) {
        classification = "restricted";
        detail = "Endpoint exists but requires authorization or is blocked.";
        strengths.push(`${probe.label} appears access-controlled.`);
      } else if (response.statusCode === 405) {
        classification = "interesting";
        detail = "Endpoint appears to exist, but it does not allow the request method used by this probe.";
      } else if (response.statusCode === 429) {
        classification = "restricted";
        detail = "Endpoint appears rate-limited, so availability could not be assessed cleanly.";
      } else if (response.statusCode === 404) {
        classification = "absent";
        detail = "Endpoint not found.";
      } else if (response.statusCode >= 500) {
        classification = "error";
        detail = "Endpoint triggered a server-side error, so the path exists or is handled but did not respond cleanly.";
        sawErrorProbe = true;
      } else if (response.statusCode >= 200 && response.statusCode < 300) {
        if ((contentType || "").includes("application/json")) {
          classification = "public";
          detail = "Public JSON-style endpoint responded successfully.";
          issues.push(`${probe.label} appears publicly reachable at ${probe.path}.`);
        } else if ((contentType || "").includes("text/html") && deps.isAccessDeniedHtml(response.headers, response.body)) {
          classification = "restricted";
          detail = "Endpoint response appears to be a web application firewall or access-denied page.";
          strengths.push(`${probe.label} appears blocked by edge protection.`);
        } else if ((contentType || "").includes("text/html")) {
          classification = "fallback";
          detail = deps.classifyHtmlApiFallback(
            probe.path,
            finalUrl,
            resolvedUrl,
            response.body,
            homepageSignature,
            homepageTitle,
          )
            ? "Endpoint appears to return the site's standard HTML page rather than an API response."
            : "Endpoint returns an HTML page rather than a machine-readable API response.";
        } else {
          classification = "interesting";
          detail = "Endpoint responded successfully but does not clearly look like JSON.";
        }
      } else if (response.statusCode >= 300 && response.statusCode < 400) {
        classification = "interesting";
        detail = "Endpoint redirected.";
      } else if (response.statusCode > 0) {
        classification = "interesting";
        detail = "Endpoint returned a non-success response that may still indicate application handling on this path.";
      }

      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: response.statusCode,
        finalUrl: resolvedUrl.toString(),
        classification,
        contentType,
        detail,
      });
    } catch (error) {
      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: 0,
        finalUrl: targetUrl.toString(),
        classification: "error",
        contentType: null,
        detail: error instanceof Error ? error.message : "Probe failed.",
      });
      sawErrorProbe = true;
    }
  }

  if (sawErrorProbe) {
    issues.push("Some API-style probes triggered server-side errors, so application handling on those paths deserves review.");
  }

  if (!issues.length && !sawErrorProbe) {
    strengths.push("No obviously public API endpoints were detected in the limited probe set.");
  }
  if (probes.some((probe) => probe.classification === "fallback")) {
    strengths.push("Some API-style paths appear to be frontend route fallbacks rather than exposed APIs.");
  }

  return { probes, issues, strengths };
};
