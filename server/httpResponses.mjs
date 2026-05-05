export function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

export function sendMethodNotAllowed(response, allowedMethods) {
  response.writeHead(405, {
    "Content-Type": "application/json; charset=utf-8",
    Allow: allowedMethods.join(", "),
  });
  response.end(JSON.stringify({
    error: `Method not allowed. Use ${allowedMethods.join(" or ")}.`,
  }));
}

export function sendRateLimited(
  response,
  retryAfterSeconds,
  message = "Too many analysis requests from this client. Please try again later.",
) {
  response.writeHead(429, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Retry-After": String(retryAfterSeconds),
  });
  response.end(JSON.stringify({
    error: message,
  }));
}
