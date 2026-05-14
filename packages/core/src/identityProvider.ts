import { URL } from "node:url";
import type { CtDiscoveryInfo, HtmlSecurityInfo, IdentityProviderInfo, RedirectHop } from "./types.js";
import { DISCOVERY_PATH_LIMIT, OIDC_DISCOVERY_TIMEOUT_MS, SUMMARY_EVIDENCE_LIMIT } from "./scannerConfig.js";
import { unique, withTimeout } from "./utils.js";

interface JsonResponse<T = unknown> {
  statusCode: number;
  json: T | null;
}

type RequestJsonFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<JsonResponse>;

const AUTH_HOST_LIMIT = 5;

export const IDENTITY_PROVIDER_PATTERNS = [
  { provider: "Microsoft Entra ID", pattern: /(^|\.)login\.microsoftonline\.com$/i },
  { provider: "Okta", pattern: /(^|\.)okta(?:-emea)?\.com$/i },
  { provider: "Auth0", pattern: /(^|\.)auth0\.com$/i },
  { provider: "Ping Identity", pattern: /(^|\.)ping(?:one|identity)\.com$/i },
  { provider: "OneLogin", pattern: /(^|\.)onelogin\.com$/i },
  { provider: "Amazon Cognito", pattern: /amazoncognito\.com$/i },
  { provider: "Google Identity", pattern: /(^|\.)accounts\.google\.com$/i },
  { provider: "Keycloak", pattern: /keycloak/i },
];

export const detectIdentityProviderName = (candidates: string[]) => {
  for (const candidate of candidates) {
    for (const entry of IDENTITY_PROVIDER_PATTERNS) {
      if (entry.pattern.test(candidate)) {
        return entry.provider;
      }
    }
  }
  return null;
};

const inferProtocol = ({
  openIdConfigurationUrl,
  authorizationEndpoint,
  tokenEndpoint,
  redirectOrigins,
  redirectUriSignals,
  loginPaths,
}: {
  openIdConfigurationUrl: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  redirectOrigins: string[];
  redirectUriSignals: string[];
  loginPaths: string[];
}): IdentityProviderInfo["protocol"] => {
  if (openIdConfigurationUrl || authorizationEndpoint || tokenEndpoint) {
    return "oidc";
  }
  if (redirectOrigins.some((origin) => /saml|adfs/i.test(origin))) {
    return "saml";
  }
  if (
    redirectOrigins.length ||
    redirectUriSignals.length ||
    loginPaths.some((path) => /oauth|authorize|sso|auth/i.test(path))
  ) {
    return "oauth";
  }
  return null;
};

const collectRedirectUriSignals = (html: string, finalUrl: URL) => {
  const signals: string[] = [];
  const matches = [...html.matchAll(/(?:redirect_uri|post_logout_redirect_uri)=([^"'`\s<>()&]+)/gi)];

  for (const match of matches) {
    try {
      const decoded = decodeURIComponent(match[1] ?? "");
      const redirectUrl = new URL(decoded, finalUrl);
      if (
        redirectUrl.protocol === "http:" ||
        redirectUrl.hostname === "localhost" ||
        redirectUrl.hostname.endsWith(".localhost") ||
        redirectUrl.origin !== finalUrl.origin
      ) {
        signals.push(redirectUrl.toString());
      }
    } catch {
      continue;
    }
  }

  return unique(signals).slice(0, SUMMARY_EVIDENCE_LIMIT);
};

const deriveOpenIdCandidates = (
  finalUrl: URL,
  redirects: RedirectHop[],
  htmlSecurity: HtmlSecurityInfo,
  authHostCandidates: string[],
) => {
  const candidates = [new URL("/.well-known/openid-configuration", finalUrl.origin).toString()];
  if (/login\.microsoftonline\.com$/i.test(finalUrl.hostname)) {
    candidates.push(new URL("/common/v2.0/.well-known/openid-configuration", finalUrl.origin).toString());
  }
  for (const host of authHostCandidates) {
    if (host !== finalUrl.hostname) {
      candidates.push(new URL("/.well-known/openid-configuration", `https://${host}`).toString());
    }
  }

  const loginPaths = [
    ...redirects
      .map((hop) => hop.location)
      .filter((location): location is string => Boolean(location)),
    ...htmlSecurity.firstPartyPaths.filter((path) => /login|signin|oauth|authorize|sso|auth/i.test(path)),
  ];

  for (const value of loginPaths) {
    try {
      const resolved = new URL(value, finalUrl);
      const pathname = resolved.pathname;
      if (/\/oauth2\/[^/]+\/v1\/authorize/i.test(pathname)) {
        const issuerPath = pathname.replace(/\/v1\/authorize.*$/i, "");
        candidates.push(new URL(`${issuerPath}/.well-known/openid-configuration`, resolved.origin).toString());
      } else if (/\/authorize/i.test(pathname)) {
        const issuerPath = pathname.replace(/\/authorize.*$/i, "");
        candidates.push(new URL(`${issuerPath}/.well-known/openid-configuration`, resolved.origin).toString());
      }
    } catch {
      continue;
    }
  }

  return unique(candidates);
};

const deriveAuthHostCandidates = (
  finalUrl: URL,
  redirects: RedirectHop[],
  htmlSecurity: HtmlSecurityInfo,
  ctDiscovery?: CtDiscoveryInfo,
) =>
  unique([
    finalUrl.hostname,
    ...redirects
      .map((hop) => hop.location)
      .filter((location): location is string => Boolean(location))
      .map((location) => {
        try {
          return new URL(location, finalUrl).hostname;
        } catch {
          return null;
        }
      }),
    ...htmlSecurity.externalScriptDomains.filter(
      (hostname) =>
        /auth|login|okta|auth0|onelogin|microsoftonline|ping|cognito/i.test(hostname) ||
        /(^|\.)accounts\.google\.com$/i.test(hostname),
    ),
    ...htmlSecurity.firstPartyPaths
      .filter((path) => /login|signin|oauth|authorize|sso|auth/i.test(path))
      .map((path) => {
        try {
          return new URL(path, finalUrl).hostname;
        } catch {
          return null;
        }
      }),
    ...(ctDiscovery?.prioritizedHosts || [])
      .filter((entry) => entry.category === "auth" || entry.priority === "high")
      .map((entry) => entry.host),
  ]).slice(0, AUTH_HOST_LIMIT);

const extractTenantSignals = (provider: string | null, issuer: string | null, metadata: Record<string, string | undefined> | null) => {
  if (provider !== "Microsoft Entra ID") {
    return {
      tenantBrand: null,
      tenantRegion: null,
      tenantSignals: [] as string[],
    };
  }

  const signals = unique([
    issuer && /\/[0-9a-f-]{36}\//i.test(issuer) ? "Issuer exposes a tenant-specific GUID." : null,
    metadata?.tenant_region_scope ? `Tenant region scope: ${metadata.tenant_region_scope}` : null,
    metadata?.cloud_instance_name ? `Cloud instance: ${metadata.cloud_instance_name}` : null,
    metadata?.tenant_region_sub_scope ? `Tenant region sub-scope: ${metadata.tenant_region_sub_scope}` : null,
  ]);

  return {
    tenantBrand: metadata?.cloud_instance_name || "Microsoft Entra ID",
    tenantRegion: metadata?.tenant_region_scope || metadata?.tenant_region_sub_scope || null,
    tenantSignals: signals,
  };
};

export const analyzeIdentityProvider = async (
  finalUrl: URL,
  redirects: RedirectHop[],
  htmlSecurity: HtmlSecurityInfo,
  html: string | null,
  requestJson: RequestJsonFn,
  ctDiscovery?: CtDiscoveryInfo,
): Promise<IdentityProviderInfo> => {
  const redirectOrigins = unique(
    redirects
      .map((hop) => hop.location)
      .filter((location): location is string => Boolean(location))
      .map((location) => {
        try {
          const resolved = new URL(location, finalUrl);
          const looksAuthRelated =
            resolved.origin !== finalUrl.origin ||
            /login|signin|oauth|authorize|sso|auth|adfs|saml/i.test(resolved.pathname) ||
            detectIdentityProviderName([resolved.hostname]) !== null;
          return looksAuthRelated ? resolved.origin : null;
        } catch {
          return null;
        }
      }),
  );
  const redirectHosts = redirectOrigins.map((origin) => new URL(origin).hostname);
  const dedicatedRedirectOrigins = redirectOrigins.filter((origin) => origin !== finalUrl.origin);
  const loginPaths = unique(
    htmlSecurity.firstPartyPaths.filter((path) => /login|signin|oauth|authorize|sso|auth/i.test(path)),
  ).slice(0, DISCOVERY_PATH_LIMIT);
  const authHostCandidates = deriveAuthHostCandidates(finalUrl, redirects, htmlSecurity, ctDiscovery);
  const provider = detectIdentityProviderName([
    finalUrl.hostname,
    ...redirectHosts,
    ...authHostCandidates,
    ...htmlSecurity.externalScriptDomains,
    ...htmlSecurity.externalStylesheetDomains,
    ...htmlSecurity.aiSurface.discoveredPaths,
  ]);
  const redirectUriSignals = html ? collectRedirectUriSignals(html, finalUrl) : [];

  let openIdConfigurationUrl: string | null = null;
  let issuer: string | null = null;
  let authorizationEndpoint: string | null = null;
  let tokenEndpoint: string | null = null;
  let endSessionEndpoint: string | null = null;
  let metadataSnapshot: Record<string, string | undefined> | null = null;
  const strengths: string[] = [];
  const issues: string[] = [];
  const wellKnownEndpoints: string[] = [];

  for (const candidate of deriveOpenIdCandidates(finalUrl, redirects, htmlSecurity, authHostCandidates)) {
    try {
      const response = await withTimeout(
        requestJson(new URL(candidate)),
        OIDC_DISCOVERY_TIMEOUT_MS,
        "OIDC discovery timed out.",
      );
      if (response.statusCode >= 200 && response.statusCode < 300 && response.json) {
        const metadata = response.json as Record<string, string | undefined>;
        metadataSnapshot = metadata;
        openIdConfigurationUrl = candidate;
        wellKnownEndpoints.push(candidate);
        issuer = metadata.issuer || null;
        authorizationEndpoint = metadata.authorization_endpoint || null;
        tokenEndpoint = metadata.token_endpoint || null;
        endSessionEndpoint = metadata.end_session_endpoint || metadata.revocation_endpoint || null;
        break;
      }
    } catch {
      continue;
    }
  }

  const protocol = inferProtocol({
    openIdConfigurationUrl,
    authorizationEndpoint,
    tokenEndpoint,
    redirectOrigins: dedicatedRedirectOrigins,
    redirectUriSignals,
    loginPaths,
  });
  const { tenantBrand, tenantRegion, tenantSignals } = extractTenantSignals(provider, issuer, metadataSnapshot);

  if (provider) {
    strengths.push(`Identity provider signals point to ${provider}.`);
  }
  if (openIdConfigurationUrl) {
    strengths.push("An OpenID Connect configuration endpoint is publicly exposed.");
  }
  if (protocol) {
    strengths.push(`Passive evidence suggests a ${protocol.toUpperCase()}-style identity flow.`);
  }
  if (dedicatedRedirectOrigins.length) {
    strengths.push("Authentication redirects point to a dedicated identity origin.");
  }
  if (loginPaths.length) {
    strengths.push(`Passive discovery surfaced ${loginPaths.length} login-like path${loginPaths.length === 1 ? "" : "s"} on the scanned origin.`);
  }
  if (authHostCandidates.some((hostname) => hostname !== finalUrl.hostname)) {
    strengths.push("Separate auth-like hosts were passively observed alongside the main application origin.");
  }
  if (tenantSignals.length) {
    strengths.push("Passive tenant-level Entra metadata was visible.");
  }
  if (redirectUriSignals.length) {
    issues.push("Public markup exposed OAuth redirect_uri-style parameters worth review.");
  }
  if (protocol && !provider && !openIdConfigurationUrl) {
    issues.push("Identity-related flow signals were observed, but no provider or public metadata endpoint could be confirmed.");
  }
  if (!provider && !openIdConfigurationUrl && !loginPaths.length && !redirectOrigins.length) {
    strengths.push("No obvious public IdP or OAuth surface was detected from passive signals.");
  }

  return {
    detected: Boolean(provider || openIdConfigurationUrl || dedicatedRedirectOrigins.length || loginPaths.length || redirectUriSignals.length),
    provider,
    protocol,
    redirectOrigins,
    authHostCandidates,
    loginPaths,
    openIdConfigurationUrl,
    wellKnownEndpoints,
    issuer,
    authorizationEndpoint,
    tokenEndpoint,
    endSessionEndpoint,
    redirectUriSignals,
    tenantBrand,
    tenantRegion,
    tenantSignals,
    issues,
    strengths,
  };
};
