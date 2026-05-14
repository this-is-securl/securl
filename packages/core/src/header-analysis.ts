import type {
  LibraryRiskSignal,
  RemediationSnippet,
  ScanIssue,
  SecurityHeaderResult,
} from "./types.js";
import { headerValue, unique } from "./utils.js";

type ResponseHeaders = Record<string, string | string[] | undefined>;

export const SECURITY_HEADERS: Array<Pick<SecurityHeaderResult, "key" | "label" | "description" | "recommendation">> = [
  { key: "strict-transport-security", label: "Strict-Transport-Security", description: "Forces browsers to keep using HTTPS after the first secure visit.", recommendation: "Set HSTS with at least 6 months max-age and includeSubDomains." },
  { key: "content-security-policy", label: "Content-Security-Policy", description: "Reduces XSS and data injection risk by controlling allowed resource sources.", recommendation: "Add a CSP and avoid unsafe-inline / unsafe-eval where possible." },
  { key: "x-frame-options", label: "X-Frame-Options", description: "Helps prevent clickjacking in framed pages.", recommendation: "Use DENY or SAMEORIGIN unless framing is intentionally required." },
  { key: "x-content-type-options", label: "X-Content-Type-Options", description: "Stops MIME sniffing for mismatched content types.", recommendation: "Set X-Content-Type-Options to nosniff." },
  { key: "referrer-policy", label: "Referrer-Policy", description: "Limits how much referral data leaves the site.", recommendation: "Use strict-origin-when-cross-origin or stricter." },
  { key: "permissions-policy", label: "Permissions-Policy", description: "Restricts browser features such as camera and microphone access.", recommendation: "Disable unneeded browser capabilities with Permissions-Policy." },
  { key: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy", description: "Improves browsing context isolation against cross-window attacks.", recommendation: "Set COOP to same-origin for stronger isolation where compatible." },
  { key: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy", description: "Protects resources from being loaded by unintended origins.", recommendation: "Set CORP to same-origin or same-site when appropriate." },
];

export const REMEDIATION_TARGETS: Record<string, string> = {
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests",
  "x-frame-options": "SAMEORIGIN",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

export const analyzeHeaders = (headers: ResponseHeaders, isHttps: boolean) => {
  const results: SecurityHeaderResult[] = [];
  const issues: ScanIssue[] = [];
  const strengths: string[] = [];
  const createIssue = (
    severity: ScanIssue["severity"],
    area: ScanIssue["area"],
    title: string,
    detail: string,
    confidence: ScanIssue["confidence"] = "high",
    source: ScanIssue["source"] = "observed",
  ): ScanIssue => ({ severity, area, title, detail, confidence, source, owasp: [], mitre: [] });

  for (const definition of SECURITY_HEADERS) {
    const value = headerValue(headers, definition.key);
    let status: SecurityHeaderResult["status"] = value ? "present" : "missing";
    let severity: SecurityHeaderResult["severity"] = value ? "good" : "warning";
    let summary = value ? "Configured." : "Missing.";

    if (definition.key === "strict-transport-security" && value) {
      const lower = value.toLowerCase();
      const maxAgeMatch = lower.match(/max-age=(\d+)/);
      const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
      if (maxAge < 15552000 || !lower.includes("includesubdomains")) {
        status = "warning";
        severity = "warning";
        summary = "Present, but the policy is weaker than recommended.";
        issues.push(createIssue("warning", "transport", "HSTS could be stronger", "Increase max-age and include subdomains for better HTTPS protection.", "medium", "heuristic"));
      } else {
        strengths.push("Strong HSTS policy detected.");
      }
    }

    if (definition.key === "content-security-policy" && value) {
      const directives = Object.fromEntries(
        value.split(";").map((directive) => directive.trim()).filter(Boolean).map((directive) => {
          const [name, ...tokens] = directive.split(/\s+/);
          return [(name ?? "").toLowerCase(), tokens.map((token) => token.toLowerCase())];
        }),
      );
      const scriptSources = directives["script-src"] || directives["default-src"] || [];
      if (scriptSources.includes("'unsafe-inline'") || scriptSources.includes("'unsafe-eval'")) {
        status = "warning";
        severity = "warning";
        summary = "Present, but allows unsafe script execution in script policies.";
        issues.push(createIssue("warning", "headers", "CSP contains risky allowances", "unsafe-inline or unsafe-eval in script policies weakens CSP protections against XSS.", "high", "observed"));
      } else {
        strengths.push("CSP is present without obvious unsafe script allowances.");
      }
    }

    if (definition.key === "x-frame-options" && value) {
      const lower = value.toLowerCase();
      if (!["deny", "sameorigin"].includes(lower)) {
        status = "warning";
        severity = "warning";
        summary = "Present, but uses a less reliable policy.";
      }
    }

    if (definition.key === "referrer-policy" && value) {
      const lower = value.split(",").map((part) => part.trim().toLowerCase()).filter(Boolean).at(-1) || "";
      if (!["strict-origin", "strict-origin-when-cross-origin", "same-origin", "no-referrer"].includes(lower)) {
        status = "warning";
        severity = "warning";
        summary = "Present, but a stricter referrer policy is recommended.";
      }
    }

    if (!value) {
      issues.push(createIssue(definition.key === "permissions-policy" ? "info" : "warning", "headers", `${definition.label} is missing`, definition.recommendation, "high", "observed"));
    }

    results.push({ ...definition, value, status, severity, summary });
  }

  if (!isHttps) {
    issues.push(createIssue("critical", "transport", "Site is not using HTTPS", "Traffic can be intercepted or modified in transit over plain HTTP.", "high", "observed"));
  }

  return { headers: results, issues, strengths };
};

export const buildRawHeaders = (headers: ResponseHeaders): Record<string, string> =>
  Object.fromEntries(
    Object.entries(headers)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [key, Array.isArray(value) ? value.join(", ") : String(value)]),
  );

export const classifyIssueTaxonomy = (issue: ScanIssue): ScanIssue => {
  const text = `${issue.area} ${issue.title} ${issue.detail}`.toLowerCase();
  const owasp: ScanIssue["owasp"] = [];
  const mitre: ScanIssue["mitre"] = [];
  const isCookieIssue = issue.area === "cookies" || text.includes("cookie");
  const isHttpSurfaceDiscovery = text.includes("publicly reachable")
    || text.includes("exposed")
    || text.includes("fingerprint")
    || text.includes("banner")
    || text.includes("redirect chain")
    || text.includes("version")
    || text.includes("header");

  if (text.includes("outdated component") || text.includes("known advis") || text.includes("osv") || text.includes("vulnerab") || text.includes("library ")) owasp.push("A06 Vulnerable and Outdated Components");
  if (issue.area === "transport" || issue.area === "certificate" || text.includes("https") || text.includes("tls") || text.includes("certificate") || text.includes("hsts")) owasp.push("A02 Cryptographic Failures");
  if (issue.area === "headers" || text.includes("missing") || text.includes("csp") || text.includes("referrer-policy") || text.includes("permissions-policy") || text.includes("cors") || text.includes("samesite") || text.includes("httponly") || text.includes("secure flag")) owasp.push("A05 Security Misconfiguration");
  if (text.includes("unsafe-inline") || text.includes("unsafe-eval") || text.includes("xss") || text.includes("inline script")) owasp.push("A03 Injection");
  if (text.includes("publicly reachable") || text.includes("exposed") || text.includes("authorization") || text.includes("access-controlled")) owasp.push("A01 Broken Access Control");
  if (isCookieIssue) owasp.push("A07 Identification and Authentication Failures");
  if (text.includes("publicly reachable") || text.includes("exposed") || text.includes("site is not using https") || text.includes("redirect chain")) mitre.push("Initial Access");
  if (isHttpSurfaceDiscovery || text.includes("certificate") || text.includes("cors")) mitre.push("Reconnaissance");
  if (isCookieIssue || text.includes("password") || text.includes("token") || text.includes("session")) mitre.push("Credential Access");
  if (text.includes("referrer") || text.includes("inline script") || text.includes("sri")) mitre.push("Collection");
  if (text.includes("bypass") || text.includes("evasion") || text.includes("obfuscat")) mitre.push("Defense Evasion");
  return { ...issue, owasp: unique(owasp), mitre: unique(mitre) };
};

export const buildLibraryRiskIssues = (libraryRiskSignals: LibraryRiskSignal[]): ScanIssue[] =>
  libraryRiskSignals.map((signal) => {
    const highestSeverity: ScanIssue["severity"] = signal.vulnerabilities.some((item) => item.severity === "critical" || item.severity === "high")
      ? "critical"
      : signal.vulnerabilities.some((item) => item.severity === "moderate")
        ? "warning"
        : "info";
    const references = signal.vulnerabilities.flatMap((item) => item.aliases).filter(Boolean).slice(0, 3);
    return {
      severity: highestSeverity,
      area: "headers",
      title: `${signal.packageName} ${signal.version} has known advisories`,
      detail: `OSV returned ${signal.vulnerabilities.length} advisory match${signal.vulnerabilities.length === 1 ? "" : "es"} for this publicly referenced library version.${references.length ? ` References: ${references.join(", ")}.` : ""}`,
      confidence: signal.confidence,
      source: "observed",
      owasp: [],
      mitre: [],
    };
  });

export const buildRemediation = (headerResults: SecurityHeaderResult[]): RemediationSnippet[] => {
  const requiredHeaders = headerResults
    .filter((header) => header.status !== "present")
    .map((header) => ({ key: header.key, label: header.label, value: REMEDIATION_TARGETS[header.key] }))
    .filter((header) => header.value);
  if (!requiredHeaders.length) return [];

  const nginxLines = requiredHeaders.map((header) => `add_header ${header.label} "${header.value}" always;`);
  const apacheLines = requiredHeaders.map((header) => `Header always set ${header.label} "${header.value}"`);
  const cloudflareLines = requiredHeaders.map((header) => `secured.headers.set("${header.label}", "${(header.value ?? "").replaceAll('"', '\\"')}");`);
  const vercelLines = requiredHeaders.map((header) => `        { key: "${header.label}", value: "${header.value}" },`);
  const netlifyLines = requiredHeaders.map((header) => `  ${header.label}: ${header.value}`);
  const names = requiredHeaders.map((header) => header.label).join(", ");

  return [
    { platform: "nginx", title: "Nginx security headers", description: `Adds recommended headers for: ${names}.`, filename: "nginx.conf", snippet: ["server {", "  # ...existing config", ...nginxLines.map((line) => `  ${line}`), "}"].join("\n") },
    { platform: "apache", title: "Apache mod_headers rules", description: "Use inside your vhost or .htaccess where mod_headers is enabled.", filename: ".htaccess", snippet: ["<IfModule mod_headers.c>", ...apacheLines.map((line) => `  ${line}`), "</IfModule>"].join("\n") },
    { platform: "cloudflare", title: "Cloudflare Worker response hardening", description: "Apply these headers in a Worker or edge response transform.", filename: "worker.js", snippet: ["export default {", "  async fetch(request, env, ctx) {", "    const response = await fetch(request);", "    const secured = new Response(response.body, response);", ...cloudflareLines.map((line) => `    ${line}`), "    return secured;", "  },", "};"].join("\n") },
    { platform: "vercel", title: "Vercel headers() config", description: "Paste into next.config.js or next.config.mjs.", filename: "next.config.js", snippet: ["export default {", "  async headers() {", "    return [", "      {", '        source: "/(.*)",', "        headers: [", ...vercelLines, "        ],", "      },", "    ];", "  },", "};"].join("\n") },
    { platform: "netlify", title: "Netlify _headers file", description: "Add this block to your Netlify `_headers` file.", filename: "_headers", snippet: ["/*", ...netlifyLines, ""].join("\n") },
  ];
};
