const DEFAULT_ALLOWED_ORIGINS = [
  "https://securl.online",
  "https://app.securl.online",
];

const DEFAULT_DEVELOPMENT_ORIGINS = [
  "http://localhost:8080",
  "http://127.0.0.1:8080",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
];

const DEFAULT_ALLOWED_HEADERS = [
  "Content-Type",
  "Authorization",
  "X-API-Key",
  "X-Scan-Owner",
  "X-SecURL-Client",
  "X-SecURL-Client-Version",
];

const DEFAULT_ALLOWED_METHODS = [
  "GET",
  "POST",
  "DELETE",
  "OPTIONS",
];

function normalizeOrigin(origin) {
  let normalized = origin.trim();
  while (normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

export function resolveAllowedOrigins(rawOrigins, isProduction) {
  const configuredOrigins = String(rawOrigins || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
    .map(normalizeOrigin);

  if (configuredOrigins.length > 0) {
    return new Set(configuredOrigins);
  }

  return new Set([
    ...DEFAULT_ALLOWED_ORIGINS,
    ...(isProduction ? [] : DEFAULT_DEVELOPMENT_ORIGINS),
  ]);
}

export function createCorsPolicy({
  allowedOrigins,
  allowedHeaders = DEFAULT_ALLOWED_HEADERS,
  allowedMethods = DEFAULT_ALLOWED_METHODS,
}) {
  const normalizedAllowedOrigins = new Set(
    [...allowedOrigins].map(normalizeOrigin),
  );
  const allowHeadersValue = allowedHeaders.join(", ");
  const allowMethodsValue = allowedMethods.join(", ");

  function getOriginHeaders(request) {
    const requestOrigin = request.headers.origin;
    if (!requestOrigin) {
      return {};
    }

    const normalizedRequestOrigin = normalizeOrigin(requestOrigin);
    if (!normalizedAllowedOrigins.has(normalizedRequestOrigin)) {
      return null;
    }

    return {
      "Access-Control-Allow-Origin": requestOrigin,
      "Access-Control-Allow-Headers": allowHeadersValue,
      "Access-Control-Allow-Methods": allowMethodsValue,
      "Access-Control-Max-Age": "600",
      Vary: "Origin",
    };
  }

  return {
    getOriginHeaders,
    isOriginAllowed(request) {
      return getOriginHeaders(request) !== null;
    },
  };
}
