import fs from "node:fs";
import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, URL } from "node:url";
import { createRateLimiter } from "./rateLimiter.mjs";
import { buildScanEvidencePayload, buildScanFindingsPayload, buildScanSummaryPayload } from "./scanDtos.mjs";
import { createInMemoryScanRepository } from "./scanRepository.mjs";
import { classifyScanFailure, createTelemetryTracker } from "./telemetry.mjs";
import {
  analyzeUrl,
  formatErrorMessage,
  isPrivateAddress,
  isLocalHostname,
} from "../packages/core/dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const publicDir = path.join(projectRoot, "public");
const port = Number(process.env.PORT || 8787);
const isProduction = process.env.NODE_ENV === "production";
const apiKey = process.env.API_KEY || "";
const allowUnauthenticated = process.env.ALLOW_UNAUTHENTICATED === "true";
const trustProxy = process.env.TRUST_PROXY === "true";
const deploymentMode = process.env.DEPLOYMENT_MODE === "multi-instance" ? "multi-instance" : "single-instance";
const DEFAULT_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 30;
const DEFAULT_TARGET_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_TARGET_RATE_LIMIT_MAX_REQUESTS = 10;
const DEFAULT_ABUSE_ALERT_WINDOW_MS = 10 * 60 * 1000;
const DEFAULT_ABUSE_ALERT_THRESHOLD = 25;
const RATE_LIMIT_MAX_BUCKETS = 20000;
const configuredRateLimitBackend = (process.env.RATE_LIMIT_BACKEND || "").trim().toLowerCase();
const rateLimitBackend = configuredRateLimitBackend || (deploymentMode === "multi-instance" ? "upstash" : "in-memory");
const RATE_LIMIT_WINDOW_MS = (() => {
  const raw = Number(process.env.RATE_LIMIT_WINDOW_MS || DEFAULT_RATE_LIMIT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_RATE_LIMIT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const RATE_LIMIT_MAX_REQUESTS = (() => {
  const raw = Number(process.env.RATE_LIMIT_MAX_REQUESTS || DEFAULT_RATE_LIMIT_MAX_REQUESTS);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_RATE_LIMIT_MAX_REQUESTS;
  }
  return Math.floor(raw);
})();
const TARGET_RATE_LIMIT_WINDOW_MS = (() => {
  const raw = Number(process.env.TARGET_RATE_LIMIT_WINDOW_MS || DEFAULT_TARGET_RATE_LIMIT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_TARGET_RATE_LIMIT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const TARGET_RATE_LIMIT_MAX_REQUESTS = (() => {
  const raw = Number(process.env.TARGET_RATE_LIMIT_MAX_REQUESTS || DEFAULT_TARGET_RATE_LIMIT_MAX_REQUESTS);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_TARGET_RATE_LIMIT_MAX_REQUESTS;
  }
  return Math.floor(raw);
})();
const API_KEY_FINGERPRINT_SALT = process.env.API_KEY_FINGERPRINT_SALT || "epi-api-key-fingerprint-v1";
const SCAN_OWNER_HEADER = "x-scan-owner";
const ABUSE_ALERT_WINDOW_MS = (() => {
  const raw = Number(process.env.ABUSE_ALERT_WINDOW_MS || DEFAULT_ABUSE_ALERT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_ABUSE_ALERT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const ABUSE_ALERT_THRESHOLD = (() => {
  const raw = Number(process.env.ABUSE_ALERT_THRESHOLD || DEFAULT_ABUSE_ALERT_THRESHOLD);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_ABUSE_ALERT_THRESHOLD;
  }
  return Math.floor(raw);
})();
const upstashRestUrl = (process.env.UPSTASH_REDIS_REST_URL || "").trim();
const upstashRestToken = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const abuseSignalBuckets = new Map();
const exposeDetailedHealth = !isProduction;
const exposeTelemetry = process.env.EXPOSE_TELEMETRY === "true" || !isProduction;
const allowLegacyAnalyze = process.env.ALLOW_LEGACY_ANALYZE === "true" || !isProduction;
const telemetry = createTelemetryTracker();
const scanRepository = createInMemoryScanRepository();

const log = (level, event, details = {}) => {
  const payload = {
    level,
    event,
    time: new Date().toISOString(),
    ...details,
  };

  const line = JSON.stringify(payload);
  if (level === "error" || level === "warn") {
    console.error(line);
    return;
  }
  console.log(line);
};

function getClientIp(request) {
  if (trustProxy && shouldTrustForwardedHeaders(request)) {
    const forwarded = request.headers["x-forwarded-for"];
    const candidate = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.split(",")[0].trim();
    }
  }

  const remoteAddress = request.socket.remoteAddress || "";
  return remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
}

function shouldTrustForwardedHeaders(request) {
  const remoteAddress = request.socket.remoteAddress || "";
  const normalized = remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
  if (!normalized) {
    return false;
  }

  if (isLocalHostname(normalized)) {
    return true;
  }

  if (net.isIP(normalized)) {
    return !isPublicIp(normalized);
  }

  return false;
}

function isPublicIp(ip) {
  return net.isIP(ip) !== 0 && !isPrivateAddress(ip);
}

async function assertPublicHttpUrl(rawTarget) {
  if (!rawTarget.trim()) {
    throw new Error("Enter a URL to scan.");
  }

  const normalizedTarget = /^https?:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`;
  const targetUrl = new URL(normalizedTarget);

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    throw new Error("Only http and https URLs are supported.");
  }

  if (targetUrl.username || targetUrl.password) {
    throw new Error("URLs with embedded credentials are not supported.");
  }

  const hostname = targetUrl.hostname.toLowerCase();
  if (isLocalHostname(hostname)) {
    throw new Error("Localhost and private network targets are not allowed.");
  }

  if (net.isIP(hostname)) {
    if (!isPublicIp(hostname)) {
      throw new Error("Private or local network targets are not allowed.");
    }
    return targetUrl;
  }

  const records = await dns.lookup(hostname, { all: true });
  if (!records.length || records.some((record) => !isPublicIp(record.address))) {
    throw new Error("Target must resolve to a public IP address.");
  }

  return targetUrl;
}

function getPresentedApiKey(request) {
  const candidate = request.headers["x-api-key"];
  if (Array.isArray(candidate)) {
    return candidate[0] || "";
  }
  return typeof candidate === "string" ? candidate : "";
}

function getPresentedScanOwner(request) {
  const candidate = request.headers[SCAN_OWNER_HEADER];
  if (Array.isArray(candidate)) {
    return candidate[0] || "";
  }
  return typeof candidate === "string" ? candidate : "";
}

function tokenFingerprint(token) {
  // HMAC-SHA256 is fast, non-blocking, and constant-time — no event-loop stall.
  return crypto.createHmac("sha256", API_KEY_FINGERPRINT_SALT).update(token).digest("hex");
}

function getRequesterScope(clientIp, presentedApiKey) {
  if (apiKey && presentedApiKey) {
    return `api-key:${tokenFingerprint(presentedApiKey)}`;
  }
  return `ip:${clientIp || "unknown"}`;
}

function getScanOwnerId({ presentedApiKey, requesterScope, presentedScanOwner }) {
  if (apiKey && presentedApiKey) {
    return requesterScope;
  }

  const ownerToken = presentedScanOwner.trim();
  if (!ownerToken || ownerToken.length < 16 || ownerToken.length > 256) {
    return null;
  }

  return `scan-owner:${tokenFingerprint(ownerToken)}`;
}

function parseTargetHostForQuota(rawTarget) {
  if (!rawTarget.trim()) {
    return null;
  }

  try {
    const normalized = /^https?:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`;
    const parsed = new URL(normalized);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function recordAbuseSignal(signalType, details = {}) {
  const now = Date.now();
  const current = abuseSignalBuckets.get(signalType) || [];
  const recent = current.filter((timestamp) => now - timestamp < ABUSE_ALERT_WINDOW_MS);
  recent.push(now);
  abuseSignalBuckets.set(signalType, recent);

  log("warn", signalType, details);

  if (
    recent.length === ABUSE_ALERT_THRESHOLD
    || (recent.length > ABUSE_ALERT_THRESHOLD && recent.length % ABUSE_ALERT_THRESHOLD === 0)
  ) {
    log("error", "abuse_alert_threshold_reached", {
      signalType,
      count: recent.length,
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    });
  }
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function sendMethodNotAllowed(response, allowedMethods) {
  response.writeHead(405, {
    "Content-Type": "application/json; charset=utf-8",
    "Allow": allowedMethods.join(", "),
  });
  response.end(JSON.stringify({
    error: `Method not allowed. Use ${allowedMethods.join(" or ")}.`,
  }));
}

function sendRateLimited(response, retryAfterSeconds, message = "Too many analysis requests from this client. Please try again later.") {
  response.writeHead(429, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Retry-After": String(retryAfterSeconds),
  });
  response.end(JSON.stringify({
    error: message,
  }));
}

function getRequestedScanMode(input) {
  return input === "quiet" ? "quiet" : "standard";
}

function parseScanResourcePath(requestPath) {
  const match = requestPath.match(/^\/api\/scans\/([^/]+)(?:\/([^/]+))?$/);
  if (!match) {
    return null;
  }
  return {
    scanId: match[1],
    resource: match[2] || null,
  };
}

function normalizeScanErrorMessage(error) {
  return error instanceof Error && error.message
    ? error.message
    : "Unable to complete the scan for this target.";
}

function readJsonBody(request, { maxBytes = 32 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    let raw = "";
    let size = 0;

    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      size += Buffer.byteLength(chunk);
      if (size > maxBytes) {
        reject(new Error("Request body is too large."));
        request.destroy();
        return;
      }
      raw += chunk;
    });
    request.on("end", () => {
      if (!raw.trim()) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("Request body must be valid JSON."));
      }
    });
    request.on("error", reject);
  });
}

async function runScanAnalysis({ validatedTarget, mode, clientIp, requesterScope }) {
  telemetry.recordScanRequested({ mode });
  log("info", "analysis_requested", {
    clientIp,
    requesterScope,
    target: validatedTarget.toString(),
    mode,
  });
  const result = await analyzeUrl(validatedTarget.toString(), { scanMode: mode });
  telemetry.recordScanCompleted(result);
  return result;
}

async function checkTargetQuota({ requesterScope, target, clientIp, requestPath, response }) {
  const targetHost = parseTargetHostForQuota(target);
  if (!targetHost) {
    return { ok: true };
  }

  const targetScope = `${requesterScope}:${targetHost}`;
  const targetRateLimitState = await targetRateLimiter.check(targetScope);
  if (!targetRateLimitState.limited) {
    return { ok: true };
  }

  telemetry.recordTargetRateLimited();
  telemetry.recordFailure("target_rate_limited");
  recordAbuseSignal("target_quota_exceeded", {
    clientIp,
    requesterScope,
    targetHost,
    path: requestPath,
  });
  sendRateLimited(
    response,
    targetRateLimitState.retryAfterSeconds,
    "Too many analysis requests for this target from this client. Please try again later.",
  );
  return { ok: false };
}

async function authorizeAnalysisRequest({ request, response, requestPath, enforceRateLimit = true, requireScanOwner = false }) {
  const clientIp = getClientIp(request) || "unknown";
  const presentedApiKey = getPresentedApiKey(request);
  const presentedScanOwner = getPresentedScanOwner(request);
  const requesterScope = getRequesterScope(clientIp, presentedApiKey);

  if (apiKey && presentedApiKey !== apiKey) {
    telemetry.recordAuthRejected();
    telemetry.recordFailure("auth_rejected");
    recordAbuseSignal("api_key_rejected", {
      clientIp,
      path: requestPath,
    });
    sendJson(response, 401, {
      error: "A valid API key is required to analyze targets from this deployment.",
    });
    return null;
  }

  const ownerId = getScanOwnerId({
    presentedApiKey,
    requesterScope,
    presentedScanOwner,
  });

  if (requireScanOwner && !ownerId) {
    telemetry.recordAuthRejected();
    telemetry.recordFailure("auth_rejected");
    recordAbuseSignal("scan_owner_missing", {
      clientIp,
      requesterScope,
      path: requestPath,
    });
    sendJson(response, 401, {
      error: "A scan owner token is required to access scan resources from this deployment.",
    });
    return null;
  }

  if (!enforceRateLimit) {
    return { clientIp, requesterScope, ownerId };
  }

  const rateLimitState = await rateLimiter.check(requesterScope);
  if (rateLimitState.limited) {
    telemetry.recordRequesterRateLimited();
    telemetry.recordFailure("requester_rate_limited");
    recordAbuseSignal("rate_limit_exceeded", {
      clientIp,
      requesterScope,
      path: requestPath,
    });
    sendRateLimited(response, rateLimitState.retryAfterSeconds);
    return null;
  }

  return { clientIp, requesterScope, ownerId };
}

const rateLimiter = createRateLimiter({
  backend: rateLimitBackend,
  windowMs: RATE_LIMIT_WINDOW_MS,
  maxRequests: RATE_LIMIT_MAX_REQUESTS,
  maxBuckets: RATE_LIMIT_MAX_BUCKETS,
  upstashUrl: upstashRestUrl,
  upstashToken: upstashRestToken,
  prefix: "epi:rate-limit:requester",
  log,
});

const targetRateLimiter = createRateLimiter({
  backend: rateLimitBackend,
  windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
  maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
  maxBuckets: RATE_LIMIT_MAX_BUCKETS,
  upstashUrl: upstashRestUrl,
  upstashToken: upstashRestToken,
  prefix: "epi:rate-limit:target",
  log,
});

function getMimeType(filePath) {
  const ext = path.extname(filePath);
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}

function resolveStaticPath(baseDir, requestPath) {
  const trimmed = requestPath.replace(/^\/+/, "");
  const decoded = (() => {
    try {
      return decodeURIComponent(trimmed);
    } catch {
      return trimmed;
    }
  })();
  const normalizedRequest = path.normalize(decoded || "index.html");
  if (normalizedRequest.startsWith("..") || path.isAbsolute(normalizedRequest)) {
    return null;
  }

  const resolved = path.resolve(baseDir, normalizedRequest);
  const baseWithSep = baseDir.endsWith(path.sep) ? baseDir : `${baseDir}${path.sep}`;
  if (resolved !== baseDir && !resolved.startsWith(baseWithSep)) {
    return null;
  }

  return resolved;
}

function serveStatic(requestPath, method, response) {
  const cleanPath = requestPath === "/" ? "/index.html" : requestPath;
  const staticTarget = resolveStaticPath(distDir, cleanPath);
  const publicTarget = resolveStaticPath(publicDir, cleanPath);
  const fallbackTarget = path.join(distDir, "index.html");

  if (!staticTarget || !publicTarget) {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Invalid request path.");
    return;
  }

  const preferredPath = fs.existsSync(staticTarget)
    ? staticTarget
    : fs.existsSync(publicTarget)
      ? publicTarget
      : fs.existsSync(fallbackTarget)
        ? fallbackTarget
        : null;

  if (!preferredPath) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Frontend build not found. Run `npm run build` for a production preview.");
    return;
  }

  if (method === "GET" && path.basename(preferredPath) === "index.html") {
    telemetry.recordPageLoad();
  }

  const connectSources = ["'self'"];
  if (!isProduction) {
    connectSources.push("http://127.0.0.1:8787", "http://localhost:8787");
  }

  response.writeHead(200, {
    "Content-Type": getMimeType(preferredPath),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": `default-src 'self'; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; connect-src ${connectSources.join(" ")};`,
  });
  if (method === "HEAD") {
    response.end();
    return;
  }
  fs.createReadStream(preferredPath).pipe(response);
}

const server = http.createServer(async (request, response) => {
  const rawRequestPath = (request.url || "/").split("?")[0] || "/";
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);

  if (requestUrl.pathname === "/api/health") {
    const payload = {
      ok: true,
      now: new Date().toISOString(),
    };

    if (exposeDetailedHealth) {
      payload.deploymentMode = deploymentMode;
      payload.rateLimit = {
        backend: targetRateLimiter.backend,
        distributed: targetRateLimiter.distributed,
        requester: {
          maxRequests: RATE_LIMIT_MAX_REQUESTS,
          windowMs: RATE_LIMIT_WINDOW_MS,
        },
        target: {
          maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
          windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
        },
      };
      payload.abuseAlerting = {
        threshold: ABUSE_ALERT_THRESHOLD,
        windowMs: ABUSE_ALERT_WINDOW_MS,
      };
    }

    sendJson(response, 200, payload);
    return;
  }

  if (requestUrl.pathname === "/api/telemetry") {
    if (!exposeTelemetry) {
      sendJson(response, 404, {
        error: "Telemetry is not available.",
      });
      return;
    }

    sendJson(response, 200, telemetry.snapshot());
    return;
  }

  if (requestUrl.pathname === "/api/scans" && request.method === "GET") {
    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
      enforceRateLimit: false,
      requireScanOwner: true,
    });
    if (!authState) {
      return;
    }

    const rawLimit = Number(requestUrl.searchParams.get("limit"));
    const clampedLimit = Number.isFinite(rawLimit) ? Math.min(100, Math.max(1, rawLimit)) : 20;
    const scans = scanRepository.listScans({
      limit: clampedLimit,
      ownerId: authState.ownerId,
    });
    sendJson(response, 200, {
      scans,
    });
    return;
  }

  if (requestUrl.pathname === "/api/scans" && request.method === "POST") {
    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
      requireScanOwner: true,
    });
    if (!authState) {
      return;
    }

    try {
      const body = await readJsonBody(request);
      const target = typeof body.url === "string" ? body.url : "";
      const mode = getRequestedScanMode(body.mode);

      const targetQuota = await checkTargetQuota({
        requesterScope: authState.requesterScope,
        target,
        clientIp: authState.clientIp,
        requestPath: requestUrl.pathname,
        response,
      });
      if (!targetQuota.ok) {
        return;
      }

      const validatedTarget = await assertPublicHttpUrl(target);
      const scan = scanRepository.createScan({
        url: validatedTarget.toString(),
        mode,
        requesterScope: authState.requesterScope,
        ownerId: authState.ownerId,
        clientIp: authState.clientIp,
      });

      sendJson(response, 202, {
        scan: scanRepository.getScan(scan.id).summary,
      });

      queueMicrotask(async () => {
        scanRepository.markRunning(scan.id);
        try {
          const result = await runScanAnalysis({
            validatedTarget,
            mode,
            clientIp: authState.clientIp,
            requesterScope: authState.requesterScope,
          });
          scanRepository.markCompleted(scan.id, result);
        } catch (error) {
          const failureClass = classifyScanFailure(error);
          telemetry.recordFailure(failureClass);
          scanRepository.markFailed(scan.id, failureClass, normalizeScanErrorMessage(error));
          log("warn", "scan_resource_failed", {
            message: formatErrorMessage(error),
            clientIp: authState.clientIp,
            target: validatedTarget.toString(),
            scanId: scan.id,
          });
        }
      });
    } catch (error) {
      telemetry.recordFailure(classifyScanFailure(error));
      sendJson(response, 400, {
        error: normalizeScanErrorMessage(error),
      });
    }
    return;
  }

  if (requestUrl.pathname.startsWith("/api/scans/")) {
    if (request.method !== "GET") {
      sendMethodNotAllowed(response, ["GET"]);
      return;
    }

    const parsed = parseScanResourcePath(requestUrl.pathname);
    if (!parsed) {
      sendJson(response, 404, {
        error: "Scan not found.",
      });
      return;
    }

    const { scanId, resource } = parsed;
    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
      enforceRateLimit: false,
      requireScanOwner: true,
    });
    if (!authState) {
      return;
    }

    const scan = scanRepository.getScan(scanId, {
      ownerId: authState.ownerId,
    });
    if (!scan) {
      sendJson(response, 404, {
        error: "Scan not found.",
      });
      return;
    }

    if (!resource) {
      sendJson(response, 200, {
        scan,
      });
      return;
    }

    if (resource === "summary") {
      sendJson(response, 200, buildScanSummaryPayload(scan));
      return;
    }

    if (resource === "findings") {
      sendJson(response, 200, buildScanFindingsPayload(scan));
      return;
    }

    if (resource === "evidence") {
      sendJson(response, 200, buildScanEvidencePayload(scan));
      return;
    }

    sendJson(response, 404, {
      error: "Scan resource not found.",
    });
    return;
  }

  if (requestUrl.pathname === "/api/analyze") {
    if (!allowLegacyAnalyze) {
      sendJson(response, 410, {
        error: "Legacy GET analysis is disabled. Create scans with POST /api/scans.",
      });
      return;
    }

    if (request.method !== "GET") {
      sendMethodNotAllowed(response, ["GET"]);
      return;
    }

    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
    });
    if (!authState) {
      return;
    }

    try {
      const target = requestUrl.searchParams.get("url") || "";
      const mode = getRequestedScanMode(requestUrl.searchParams.get("mode"));
      const targetQuota = await checkTargetQuota({
        requesterScope: authState.requesterScope,
        target,
        clientIp: authState.clientIp,
        requestPath: requestUrl.pathname,
        response,
      });
      if (!targetQuota.ok) {
        return;
      }

      const validatedTarget = await assertPublicHttpUrl(target);
      const result = await runScanAnalysis({
        validatedTarget,
        mode,
        clientIp: authState.clientIp,
        requesterScope: authState.requesterScope,
      });
      sendJson(response, 200, result);
    } catch (error) {
      telemetry.recordFailure(classifyScanFailure(error));
      log("warn", "analysis_failed", {
        message: formatErrorMessage(error),
        clientIp: authState.clientIp,
        target: requestUrl.searchParams.get("url") || "",
      });
      sendJson(response, 400, {
        error: "Unable to analyze that target. Please check the URL and try again.",
      });
    }
    return;
  }

  if (request.method === "GET" || request.method === "HEAD") {
    serveStatic(rawRequestPath, request.method, response);
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not found");
});

if (!apiKey) {
  if (isProduction && !allowUnauthenticated) {
    log("error", "server_start_blocked", {
      reason: "API_KEY missing and ALLOW_UNAUTHENTICATED was not explicitly enabled.",
    });
    process.exit(1);
  }

  log("warn", "unauthenticated_mode", {
    production: isProduction,
    explicitOptIn: allowUnauthenticated,
  });
}

if (trustProxy) {
  log("warn", "trusted_proxy_mode", {
    message: "TRUST_PROXY is enabled; forwarded client IP attribution is only accepted when the direct peer is private/local.",
  });
}

if (isProduction && deploymentMode === "multi-instance" && rateLimiter.backend !== "upstash") {
  log("error", "server_start_blocked", {
    reason: "DEPLOYMENT_MODE=multi-instance requires RATE_LIMIT_BACKEND=upstash.",
  });
  process.exit(1);
}

if (rateLimiter.backend !== targetRateLimiter.backend) {
  log("error", "server_start_blocked", {
    reason: "Requester and target rate limiter backends must match.",
  });
  process.exit(1);
}

if (
  (rateLimiter.backend === "upstash" || targetRateLimiter.backend === "upstash")
  && (!upstashRestUrl || !upstashRestToken)
) {
  log("error", "server_start_blocked", {
    reason: "RATE_LIMIT_BACKEND=upstash requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.",
  });
  process.exit(1);
}

process.on("unhandledRejection", (reason) => {
  log("error", "unhandled_rejection", {
    message: reason instanceof Error ? reason.message : String(reason),
  });
});

process.on("uncaughtException", (error) => {
  log("error", "uncaught_exception", {
    message: error instanceof Error ? error.message : String(error),
  });
  process.exit(1);
});

server.listen(port, () => {
  log("info", "server_started", {
    port,
    url: `http://127.0.0.1:${port}`,
    production: isProduction,
    authenticated: Boolean(apiKey),
    allowUnauthenticated,
    trustProxy,
    deploymentMode,
    rateLimitBackend: targetRateLimiter.backend,
    distributedRateLimit: targetRateLimiter.distributed,
    requesterRateLimit: {
      maxRequests: RATE_LIMIT_MAX_REQUESTS,
      windowMs: RATE_LIMIT_WINDOW_MS,
    },
    targetRateLimit: {
      maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
      windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
    },
    abuseAlerting: {
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    },
  });
});
