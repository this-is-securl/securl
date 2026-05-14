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
export const CT_SAMPLE_LIMIT = 4;
export const CT_SAMPLE_CONCURRENCY_LIMIT = 2;
export const OIDC_DISCOVERY_TIMEOUT_MS = 4_000;
export const CRAWL_CONCURRENCY_LIMIT = 2;
export const OSV_DETAIL_CONCURRENCY_LIMIT = 3;

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

export const API_SURFACE_PROBES = [
  { label: "API root", path: "/api" },
  { label: "GraphQL", path: "/graphql" },
  { label: "Versioned API", path: "/api/v1" },
];
