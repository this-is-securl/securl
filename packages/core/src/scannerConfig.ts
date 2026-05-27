// Network and parsing limits are intentionally conservative because this package
// is designed for low-noise, best-effort external posture analysis rather than
// deep crawling or full content retrieval.
export const REQUEST_TIMEOUT_MS = 12_000;
export const SECONDARY_REQUEST_TIMEOUT_MS = 4_000;
export const MAX_SCAN_DURATION_MS = 45_000;
export const TLS_HANDSHAKE_TIMEOUT_MS = 10_000;
export const DNS_LOOKUP_TIMEOUT_MS = 2_500;

// Cap fetched text bodies so block pages or giant responses do not dominate
// memory use or slow downstream passive analysis.
export const TEXT_BODY_LIMIT = 256_000;

// Keep HTML signatures small because they are only used for lightweight
// fallback detection, not content comparison.
export const HTML_SIGNATURE_LIMIT = 280;

// Discovery and evidence limits are intentionally short to keep passive
// reporting readable and avoid over-claiming from noisy pages.
export const DISCOVERY_PATH_LIMIT = 10;
export const SUMMARY_EVIDENCE_LIMIT = 3;
export const CLIENT_EXPOSURE_EVIDENCE_LIMIT = 6;
export const LIBRARY_RISK_LOOKUP_LIMIT = 8;
export const OSV_QUERY_TIMEOUT_MS = 3_000;
export const OSV_DETAIL_LOOKUP_LIMIT = 12;
export const CT_LOOKUP_TIMEOUT_MS = 1_500;
export const CT_CACHE_TTL_MS = 15 * 60 * 1_000;
export const CT_SUBDOMAIN_LIMIT = 20;
export const CT_WILDCARD_LIMIT = 5;
export const CT_SAMPLE_LIMIT = 4;
export const CT_SAMPLE_CONCURRENCY_LIMIT = 2;
export const OIDC_DISCOVERY_TIMEOUT_MS = 4_000;
export const CRAWL_CONCURRENCY_LIMIT = 2;
export const CRAWL_PAGE_LIMIT = 6;
export const OSV_DETAIL_CONCURRENCY_LIMIT = 3;

export const DEEP_PASSIVE_SCAN_TIMEOUT_MS = 75_000;
export const DEEP_PASSIVE_CT_SUBDOMAIN_LIMIT = 50;
export const DEEP_PASSIVE_CT_WILDCARD_LIMIT = 10;
export const DEEP_PASSIVE_CT_SAMPLE_LIMIT = 10;
export const DEEP_PASSIVE_CRAWL_PAGE_LIMIT = 10;

// Redirect following stays shallow to reduce SSRF risk and keep scans close to
// normal browser behavior.
export const REDIRECT_LIMIT = 5;

export const CRAWL_CANDIDATES = [
  { label: "Homepage", path: "/" },
  { label: "Login", path: "/login" },
  { label: "App", path: "/app" },
  { label: "Dashboard", path: "/dashboard" },
  { label: "Admin", path: "/admin" },
  { label: "API root", path: "/api" },
];

export const EXPOSURE_PROBES = [
  { label: "Robots", path: "/robots.txt" },
  { label: "Sitemap", path: "/sitemap.xml" },
  { label: "Git metadata", path: "/.git/HEAD" },
  { label: "Environment file", path: "/.env" },
];

export const DEEP_PASSIVE_EXPOSURE_PROBES = [
  ...EXPOSURE_PROBES,
  { label: "Well-known security", path: "/.well-known/security.txt" },
  { label: "OpenID configuration", path: "/.well-known/openid-configuration" },
  { label: "OAuth metadata", path: "/.well-known/oauth-authorization-server" },
  { label: "Change password", path: "/.well-known/change-password" },
  { label: "Humans", path: "/humans.txt" },
  { label: "Ads", path: "/ads.txt" },
  { label: "Server status", path: "/server-status" },
  { label: "WordPress API", path: "/wp-json" },
];

export const API_SURFACE_PROBES = [
  { label: "API root", path: "/api" },
  { label: "GraphQL", path: "/graphql" },
  { label: "Versioned API", path: "/api/v1" },
];

export const DEEP_PASSIVE_API_SURFACE_PROBES = [
  ...API_SURFACE_PROBES,
  { label: "OpenAPI", path: "/openapi.json" },
  { label: "Swagger", path: "/swagger.json" },
  { label: "API docs", path: "/api-docs" },
  { label: "Docs", path: "/docs" },
  { label: "REST", path: "/rest" },
  { label: "RPC", path: "/rpc" },
];
