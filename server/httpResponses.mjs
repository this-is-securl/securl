function withResponseHeaders(baseHeaders, extraHeaders = {}) {
  return {
    ...baseHeaders,
    ...extraHeaders,
  };
}

export function sendJson(response, statusCode, payload, extraHeaders = {}) {
  response.writeHead(statusCode, withResponseHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  }, extraHeaders));
  response.end(JSON.stringify(payload));
}

export function sendMethodNotAllowed(response, allowedMethods, extraHeaders = {}) {
  response.writeHead(405, withResponseHeaders({
    "Content-Type": "application/json; charset=utf-8",
    Allow: allowedMethods.join(", "),
  }, extraHeaders));
  response.end(JSON.stringify({
    error: `Method not allowed. Use ${allowedMethods.join(" or ")}.`,
  }));
}

export function sendRateLimited(
  response,
  retryAfterSeconds,
  message = "Too many analysis requests from this client. Please try again later.",
  extraHeaders = {},
) {
  response.writeHead(429, withResponseHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Retry-After": String(retryAfterSeconds),
  }, extraHeaders));
  response.end(JSON.stringify({
    error: message,
  }));
}
