import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
import { createCorsPolicy, resolveAllowedOrigins } from "./cors.mjs";
import { buildCapabilitiesPayload } from "./capabilities.mjs";
import { createRateLimiter } from "./rateLimiter.mjs";
import { sendJson, sendMethodNotAllowed, sendRateLimited } from "./httpResponses.mjs";
import {
  createRequestGuards,
  getClientIp,
  getRequestedScanMode,
  normalizeScanErrorMessage,
  readJsonBody,
} from "./requestGuards.mjs";
import {
  buildMonitoringTargetDetailPayload,
  buildMonitoringSummaryPayload,
  buildMonitoringTargetView,
  buildMonitoringTargetsPayload,
  buildScanEvidencePayload,
  buildScanFindingsPayload,
  buildScanHistoryPayload,
  buildScanSummaryPayload,
  buildTargetHistoryPayload,
} from "./scanDtos.mjs";
import {
  handleMonitoringSummaryRequest,
  handleMonitoringTargetCollectionRequest,
  handleMonitoringTargetItemRequest,
} from "./monitoringTargetHandlers.mjs";
import { createMonitoringScheduler } from "./monitoringScheduler.mjs";
import { handleAuthRequest, resolveAuthenticatedApiKey, resolveAuthenticatedSession } from "./authHandlers.mjs";
import { handleScanCollectionRequest, handleScanResourceRequest, runQueuedScan } from "./scanResourceHandlers.mjs";
import { createScanScheduler } from "./scanScheduler.mjs";
import { createStaticHandler } from "./staticServer.mjs";
import { enforceStartupConfiguration, initializeScanRepository } from "./startupValidation.mjs";
import { classifyTrafficSource, classifyScanFailure, createTelemetryTracker } from "./telemetry.mjs";
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
const serveFrontend = process.env.SERVE_FRONTEND === "true" || (!isProduction && process.env.SERVE_FRONTEND !== "false");
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
const DEFAULT_AUTH_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_AUTH_RATE_LIMIT_MAX_REQUESTS = 8;
const DEFAULT_SCAN_TIMEOUT_MS = 45 * 1000;
const DEFAULT_DEEP_PASSIVE_SCAN_TIMEOUT_MS = 75 * 1000;
const DEFAULT_SCAN_CONCURRENCY = 2;
const DEFAULT_STALE_RUNNING_SCAN_MS = 2 * 60 * 1000;
const DEFAULT_MONITORING_SWEEP_INTERVAL_MS = 15 * 60 * 1000;
const DEFAULT_MONITORING_SWEEP_LIMIT = 20;
const RATE_LIMIT_MAX_BUCKETS = 20000;
const configuredRateLimitBackend = (process.env.RATE_LIMIT_BACKEND || "").trim().toLowerCase();
const rateLimitBackend = configuredRateLimitBackend || (deploymentMode === "multi-instance" ? "upstash" : "in-memory");
const configuredScanRepositoryBackend = (process.env.SCAN_REPOSITORY_BACKEND || "").trim().toLowerCase();
const scanRepositoryBackend = configuredScanRepositoryBackend || "memory";
const databaseUrl = (process.env.DATABASE_URL || "").trim();
const allowedOrigins = resolveAllowedOrigins(process.env.ALLOWED_ORIGINS, isProduction);
const SCAN_OWNER_HEADER = "x-scan-owner";
const AUTH_TOKEN_FINGERPRINT_SALT = process.env.AUTH_TOKEN_FINGERPRINT_SALT || "epi-auth-token-fingerprint-v1";
const TELEMETRY_TOKEN = (process.env.TELEMETRY_TOKEN || process.env.ADMIN_TELEMETRY_TOKEN || "").trim();
const TELEMETRY_VISITOR_SALT = process.env.TELEMETRY_VISITOR_SALT || "epi-visitor-count-v1";
const TELEMETRY_STORAGE_PATH = (process.env.TELEMETRY_STORAGE_PATH || "").trim();
const MONITORING_SCHEDULER_ENABLED = process.env.MONITORING_SCHEDULER_ENABLED === "true";
const MONITORING_SCAN_MODE = ["quiet", "standard", "deep-passive"].includes(process.env.MONITORING_SCAN_MODE)
  ? process.env.MONITORING_SCAN_MODE
  : "quiet";
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
const AUTH_RATE_LIMIT_WINDOW_MS = (() => {
  const raw = Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || DEFAULT_AUTH_RATE_LIMIT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_AUTH_RATE_LIMIT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const AUTH_RATE_LIMIT_MAX_REQUESTS = (() => {
  const raw = Number(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || DEFAULT_AUTH_RATE_LIMIT_MAX_REQUESTS);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_AUTH_RATE_LIMIT_MAX_REQUESTS;
  }
  return Math.floor(raw);
})();
const SCAN_TIMEOUT_MS = (() => {
  const raw = Number(process.env.SCAN_TIMEOUT_MS || DEFAULT_SCAN_TIMEOUT_MS);
  if (!Number.isFinite(raw) || raw < 5_000) {
    return DEFAULT_SCAN_TIMEOUT_MS;
  }
  return Math.floor(raw);
})();
const DEEP_PASSIVE_SCAN_TIMEOUT_MS = (() => {
  const raw = Number(process.env.DEEP_PASSIVE_SCAN_TIMEOUT_MS || DEFAULT_DEEP_PASSIVE_SCAN_TIMEOUT_MS);
  if (!Number.isFinite(raw) || raw < SCAN_TIMEOUT_MS) {
    return Math.max(DEFAULT_DEEP_PASSIVE_SCAN_TIMEOUT_MS, SCAN_TIMEOUT_MS);
  }
  return Math.floor(raw);
})();
const SCAN_CONCURRENCY = (() => {
  const raw = Number(process.env.SCAN_CONCURRENCY || DEFAULT_SCAN_CONCURRENCY);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_SCAN_CONCURRENCY;
  }
  return Math.floor(raw);
})();
const STALE_RUNNING_SCAN_MS = (() => {
  const raw = Number(process.env.STALE_RUNNING_SCAN_MS || DEFAULT_STALE_RUNNING_SCAN_MS);
  if (!Number.isFinite(raw) || raw < 5_000) {
    return DEFAULT_STALE_RUNNING_SCAN_MS;
  }
  return Math.floor(raw);
})();
const MONITORING_SWEEP_INTERVAL_MS = (() => {
  const raw = Number(process.env.MONITORING_SWEEP_INTERVAL_MS || DEFAULT_MONITORING_SWEEP_INTERVAL_MS);
  if (!Number.isFinite(raw) || raw < 60_000) {
    return DEFAULT_MONITORING_SWEEP_INTERVAL_MS;
  }
  return Math.floor(raw);
})();
const MONITORING_SWEEP_LIMIT = (() => {
  const raw = Number(process.env.MONITORING_SWEEP_LIMIT || DEFAULT_MONITORING_SWEEP_LIMIT);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_MONITORING_SWEEP_LIMIT;
  }
  return Math.floor(raw);
})();
const upstashRestUrl = (process.env.UPSTASH_REDIS_REST_URL || "").trim();
const upstashRestToken = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const abuseSignalBuckets = new Map();
const exposeDetailedHealth = !isProduction;
const exposeTelemetry = process.env.EXPOSE_TELEMETRY === "true" || !isProduction;
const telemetry = createTelemetryTracker({ storagePath: TELEMETRY_STORAGE_PATH });
let scanRepository;
let scanScheduler;
let monitoringScheduler;

function buildVisitorKey(request) {
  const clientIp = getClientIp(request, { trustProxy, isLocalHostname, isPrivateAddress });
  const userAgent = String(request.headers["user-agent"] || "unknown").slice(0, 300);
  return crypto
    .createHash("sha256")
    .update(`${TELEMETRY_VISITOR_SALT}:${clientIp}:${userAgent}`)
    .digest("hex");
}

function isTelemetryRequestAuthorized(request) {
  if (!isProduction) {
    return true;
  }
  if (!TELEMETRY_TOKEN) {
    return false;
  }

  const authorization = String(request.headers.authorization || "");
  const bearerPrefix = "Bearer ";
  const providedToken = authorization.startsWith(bearerPrefix)
    ? authorization.slice(bearerPrefix.length)
    : String(request.headers["x-telemetry-token"] || "");

  return providedToken.length === TELEMETRY_TOKEN.length
    && crypto.timingSafeEqual(Buffer.from(providedToken), Buffer.from(TELEMETRY_TOKEN));
}

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

// Avoid persisting raw client IPs in scan logs; a salted hash still lets us
// correlate activity for abuse investigation without storing the address itself.
function hashClientIpForLog(clientIp) {
  if (!clientIp || clientIp === "unknown") {
    return "unknown";
  }
  return crypto
    .createHash("sha256")
    .update(`${TELEMETRY_VISITOR_SALT}:${clientIp}`)
    .digest("hex")
    .slice(0, 16);
}

// Log only the target origin (scheme + host); the full URL path/query can carry
// session tokens or other sensitive data we should not retain in logs.
function targetOriginForLog(validatedTarget) {
  try {
    return validatedTarget.origin;
  } catch {
    return "invalid-target";
  }
}

// Anonymous requester scopes embed the raw client IP ("ip:1.2.3.4"); hash that
// component so the scope stays stable as a correlation key without logging the IP.
function requesterScopeForLog(requesterScope) {
  if (typeof requesterScope === "string" && requesterScope.startsWith("ip:")) {
    return `ip:${hashClientIpForLog(requesterScope.slice(3))}`;
  }
  return requesterScope;
}

async function runScanAnalysis({ validatedTarget, mode, clientIp, requesterScope }) {
  const startedAt = Date.now();
  const maxScanDurationMs = mode === "deep-passive" ? DEEP_PASSIVE_SCAN_TIMEOUT_MS : SCAN_TIMEOUT_MS;
  const clientIpHash = hashClientIpForLog(clientIp);
  const targetOrigin = targetOriginForLog(validatedTarget);
  telemetry.recordScanRequested({ mode });
  log("info", "analysis_requested", {
    clientIpHash,
    requesterScope: requesterScopeForLog(requesterScope),
    targetOrigin,
    mode,
    maxScanDurationMs,
  });
  const result = await analyzeUrl(validatedTarget.toString(), {
    scanMode: mode,
    maxScanDurationMs,
  });
  telemetry.recordScanCompleted(result);
  log("info", "analysis_completed", {
    clientIpHash,
    requesterScope: requesterScopeForLog(requesterScope),
    targetOrigin,
    mode,
    durationMs: Date.now() - startedAt,
    score: result.score,
    grade: result.grade,
    limited: result.assessmentLimitation?.limited ?? false,
    timedOut: result.scanTiming?.timedOut ?? false,
  });
  return result;
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

const authRateLimiter = createRateLimiter({
  backend: rateLimitBackend,
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  maxRequests: AUTH_RATE_LIMIT_MAX_REQUESTS,
  maxBuckets: RATE_LIMIT_MAX_BUCKETS,
  upstashUrl: upstashRestUrl,
  upstashToken: upstashRestToken,
  prefix: "epi:rate-limit:auth",
  log,
});

const { assertPublicHttpUrl, checkTargetQuota, authorizeAnalysisRequest } = createRequestGuards({
  trustProxy,
  apiKey,
  apiKeyFingerprintSalt: process.env.API_KEY_FINGERPRINT_SALT || "epi-api-key-fingerprint-v1",
  scanOwnerHeader: SCAN_OWNER_HEADER,
  isLocalHostname,
  isPrivateAddress,
  telemetry,
  rateLimiter,
  targetRateLimiter,
  abuseSignalBuckets,
  abuseAlertWindowMs: ABUSE_ALERT_WINDOW_MS,
  abuseAlertThreshold: ABUSE_ALERT_THRESHOLD,
  sendJson,
  sendRateLimited,
  log,
});

const serveStatic = createStaticHandler({
  distDir,
  publicDir,
  isProduction,
  telemetry,
  getVisitorKey: buildVisitorKey,
});
const corsPolicy = createCorsPolicy({
  allowedOrigins,
});

const withAuthResolvers = (options) => authorizeAnalysisRequest({
  ...options,
  resolveSessionAuth: (token) => resolveAuthenticatedSession({
    token,
    scanRepository,
    authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
  }),
  resolveApiKeyAuth: (token) => resolveAuthenticatedApiKey({
    token,
    scanRepository,
    authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
  }),
  sendJsonResponse: options.sendJsonResponse ?? sendJson,
  sendRateLimitedResponse: options.sendRateLimitedResponse ?? sendRateLimited,
});

const server = http.createServer(async (request, response) => {
  const rawRequestPath = (request.url || "/").split("?")[0] || "/";
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);
  const apiCorsHeaders = corsPolicy.getOriginHeaders(request);
  const sendApiJson = (targetResponse, statusCode, payload) =>
    sendJson(targetResponse, statusCode, payload, apiCorsHeaders || {});
  const sendApiMethodNotAllowed = (targetResponse, allowedMethods) =>
    sendMethodNotAllowed(targetResponse, allowedMethods, apiCorsHeaders || {});
  const sendApiRateLimited = (targetResponse, retryAfterSeconds, message) =>
    sendRateLimited(targetResponse, retryAfterSeconds, message, apiCorsHeaders || {});
  const sendApiRepositoryUnavailable = (targetResponse, error, context) => {
    log("error", "scan_repository_unavailable", {
      context,
      message: formatErrorMessage(error),
      backend: scanRepository?.kind || scanRepositoryBackend,
    });
    sendApiJson(targetResponse, 503, {
      error: "Scan storage is temporarily unavailable. Please try again shortly.",
    });
  };

  if (requestUrl.pathname.startsWith("/api/") && request.headers.origin && apiCorsHeaders === null) {
    sendJson(response, 403, {
      error: "Origin is not allowed to access this API.",
    });
    return;
  }

  if (requestUrl.pathname.startsWith("/api/") && request.method === "OPTIONS") {
    if (apiCorsHeaders === null) {
      sendJson(response, 403, {
        error: "Origin is not allowed to access this API.",
      });
      return;
    }

    response.writeHead(204, {
      ...(apiCorsHeaders || {}),
      "Cache-Control": "no-store",
    });
    response.end();
    return;
  }

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
      payload.scanTimeoutMs = SCAN_TIMEOUT_MS;
      payload.deepPassiveScanTimeoutMs = DEEP_PASSIVE_SCAN_TIMEOUT_MS;
      payload.scanScheduler = scanScheduler?.snapshot?.() || {
        active: 0,
        queued: 0,
        concurrency: SCAN_CONCURRENCY,
        staleRunningScanMs: STALE_RUNNING_SCAN_MS,
      };
      payload.monitoringScheduler = monitoringScheduler?.snapshot?.() || {
        enabled: MONITORING_SCHEDULER_ENABLED,
        running: false,
        intervalMs: MONITORING_SWEEP_INTERVAL_MS,
        mode: MONITORING_SCAN_MODE,
        limit: MONITORING_SWEEP_LIMIT,
        lastSweep: null,
      };
      payload.serveFrontend = serveFrontend;
    }

    sendApiJson(response, 200, payload);
    return;
  }

  if (requestUrl.pathname === "/api/capabilities") {
    if (request.method !== "GET") {
      sendApiMethodNotAllowed(response, ["GET", "OPTIONS"]);
      return;
    }

    sendApiJson(response, 200, buildCapabilitiesPayload({
      authenticated: Boolean(apiKey),
      allowUnauthenticated,
      scanTimeoutMs: SCAN_TIMEOUT_MS,
      deepPassiveScanTimeoutMs: DEEP_PASSIVE_SCAN_TIMEOUT_MS,
      scanConcurrency: SCAN_CONCURRENCY,
      monitoringScheduler: monitoringScheduler?.snapshot?.(),
      serveFrontend,
    }));
    return;
  }

  if (requestUrl.pathname === "/api/telemetry/page-load") {
    if (request.method !== "POST") {
      sendApiMethodNotAllowed(response, ["POST", "OPTIONS"]);
      return;
    }

    const body = await readJsonBody(request, { maxBytes: 2 * 1024 }).catch(() => ({}));
    telemetry.recordPageLoad({
      visitorKey: buildVisitorKey(request),
      source: classifyTrafficSource({
        referrer: typeof body.referrer === "string" ? body.referrer : String(request.headers.referer || ""),
        currentUrl: typeof body.currentUrl === "string" ? body.currentUrl : "",
      }),
    });
    sendApiJson(response, 202, { ok: true });
    return;
  }

  if (requestUrl.pathname === "/api/telemetry/event") {
    if (request.method !== "POST") {
      sendApiMethodNotAllowed(response, ["POST", "OPTIONS"]);
      return;
    }

    const body = await readJsonBody(request, { maxBytes: 4 * 1024 }).catch(() => ({}));
    const source = classifyTrafficSource({
      referrer: typeof body.referrer === "string" ? body.referrer : String(request.headers.referer || ""),
      currentUrl: typeof body.currentUrl === "string" ? body.currentUrl : "",
    });
    const recorded = telemetry.recordFunnelEvent({
      event: typeof body.event === "string" ? body.event : "",
      source,
      target: typeof body.target === "string" ? body.target : null,
      scanId: typeof body.scanId === "string" ? body.scanId : null,
      format: typeof body.format === "string" ? body.format : null,
      mode: typeof body.mode === "string" ? body.mode : null,
    });
    sendApiJson(response, recorded ? 202 : 400, recorded ? { ok: true } : { error: "Unsupported telemetry event." });
    return;
  }

  if (requestUrl.pathname === "/api/telemetry") {
    if (!exposeTelemetry || !isTelemetryRequestAuthorized(request)) {
      sendApiJson(response, 404, {
        error: "Telemetry is not available.",
      });
      return;
    }

    sendApiJson(response, 200, telemetry.snapshot());
    return;
  }

  if (requestUrl.pathname.startsWith("/api/auth/")) {
    await handleAuthRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      readJsonBody,
      sendJson: sendApiJson,
      sendRateLimited: sendApiRateLimited,
      sendMethodNotAllowed: sendApiMethodNotAllowed,
      sendRepositoryUnavailable: sendApiRepositoryUnavailable,
      authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
      authRateLimiter,
      getClientIp,
      trustProxy,
      isLocalHostname,
      isPrivateAddress,
    });
    return;
  }

  if (requestUrl.pathname === "/api/scans") {
    await handleScanCollectionRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest: (options) => withAuthResolvers({
        ...options,
        sendJsonResponse: sendApiJson,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      readJsonBody,
      getRequestedScanMode,
      checkTargetQuota: (options) => checkTargetQuota({
        ...options,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      assertPublicHttpUrl,
      buildTargetHistoryPayload,
      sendJson: sendApiJson,
      sendMethodNotAllowed: sendApiMethodNotAllowed,
      sendRepositoryUnavailable: sendApiRepositoryUnavailable,
      telemetry,
      classifyScanFailure,
      normalizeScanErrorMessage,
      runScanAnalysis,
      enqueueScan: (job) => scanScheduler.enqueue(job),
      formatErrorMessage,
      log,
      requireScanOwner: true,
    });
    return;
  }

  if (requestUrl.pathname === "/api/monitoring-targets") {
    await handleMonitoringTargetCollectionRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest: (options) => withAuthResolvers({
        ...options,
        sendJsonResponse: sendApiJson,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      readJsonBody,
      assertPublicHttpUrl,
      buildMonitoringTargetView,
      buildMonitoringTargetsPayload,
      sendJson: sendApiJson,
      sendMethodNotAllowed: sendApiMethodNotAllowed,
      sendRepositoryUnavailable: sendApiRepositoryUnavailable,
      classifyScanFailure,
      normalizeScanErrorMessage,
      telemetry,
    });
    return;
  }

  if (requestUrl.pathname === "/api/monitoring-summary") {
    await handleMonitoringSummaryRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest: (options) => withAuthResolvers({
        ...options,
        sendJsonResponse: sendApiJson,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      buildMonitoringSummaryPayload,
      sendJson: sendApiJson,
      sendMethodNotAllowed: sendApiMethodNotAllowed,
      sendRepositoryUnavailable: sendApiRepositoryUnavailable,
    });
    return;
  }

  if (requestUrl.pathname.startsWith("/api/monitoring-targets/")) {
    await handleMonitoringTargetItemRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest: (options) => withAuthResolvers({
        ...options,
        sendJsonResponse: sendApiJson,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      readJsonBody,
      getRequestedScanMode,
      checkTargetQuota: (options) => checkTargetQuota({
        ...options,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      runScanAnalysis,
      enqueueScan: (job) => scanScheduler.enqueue(job),
      buildMonitoringTargetDetailPayload,
      telemetry,
      classifyScanFailure,
      normalizeScanErrorMessage,
      formatErrorMessage,
      log,
      sendJson: sendApiJson,
      sendMethodNotAllowed: sendApiMethodNotAllowed,
      sendRepositoryUnavailable: sendApiRepositoryUnavailable,
    });
    return;
  }

  if (requestUrl.pathname.startsWith("/api/scans/")) {
    await handleScanResourceRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest: (options) => withAuthResolvers({
        ...options,
        sendJsonResponse: sendApiJson,
        sendRateLimitedResponse: sendApiRateLimited,
      }),
      buildScanSummaryPayload,
      buildScanFindingsPayload,
      buildScanEvidencePayload,
      buildScanHistoryPayload,
      sendJson: sendApiJson,
      sendMethodNotAllowed: sendApiMethodNotAllowed,
      sendRepositoryUnavailable: sendApiRepositoryUnavailable,
      requireScanOwner: true,
    });
    return;
  }

  if (serveFrontend && (request.method === "GET" || request.method === "HEAD")) {
    serveStatic(rawRequestPath, request.method, request, response);
    return;
  }

  if (!requestUrl.pathname.startsWith("/api/") && (request.method === "GET" || request.method === "HEAD")) {
    response.writeHead(404, { "Content-Type": "application/json; charset=utf-8" });
    if (request.method === "HEAD") {
      response.end();
      return;
    }
    response.end(JSON.stringify({
      error: "SecURL API service. The frontend is served separately.",
    }));
    return;
  }

  response.writeHead(404, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify({ error: "Not found" }));
});

enforceStartupConfiguration({
  isProduction,
  apiKey,
  allowUnauthenticated,
  trustProxy,
  deploymentMode,
  rateLimiter,
  targetRateLimiter,
  upstashRestUrl,
  upstashRestToken,
  scanRepositoryBackend,
  databaseUrl,
  log,
});

try {
  scanRepository = await initializeScanRepository({
    scanRepositoryBackend,
    databaseUrl,
    log,
    formatErrorMessage,
  });
} catch (err) {
  log("error", "startup_failed", { message: formatErrorMessage(err) });
  process.exit(1);
}

scanScheduler = createScanScheduler({
  concurrency: SCAN_CONCURRENCY,
  staleRunningScanMs: STALE_RUNNING_SCAN_MS,
  scanRepository,
  runQueuedScan,
  log,
});
await scanScheduler.recoverStaleRunningScans();
monitoringScheduler = createMonitoringScheduler({
  enabled: MONITORING_SCHEDULER_ENABLED,
  intervalMs: MONITORING_SWEEP_INTERVAL_MS,
  scanRepository,
  enqueueScan: (job) => scanScheduler.enqueue({
    ...job,
    scanRepository,
    runScanAnalysis,
    telemetry,
    classifyScanFailure,
    normalizeScanErrorMessage,
    formatErrorMessage,
    log,
  }),
  mode: MONITORING_SCAN_MODE,
  limit: MONITORING_SWEEP_LIMIT,
  log,
});
if (monitoringScheduler.start()) {
  log("info", "monitoring_scheduler_started", {
    intervalMs: MONITORING_SWEEP_INTERVAL_MS,
    mode: MONITORING_SCAN_MODE,
    limit: MONITORING_SWEEP_LIMIT,
  });
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

let shutdownStarted = false;
const shutdownGracefully = (signal) => {
  if (shutdownStarted) {
    return;
  }
  shutdownStarted = true;
  log("info", "shutdown_started", { signal });
  monitoringScheduler?.stop?.();
  server.close((error) => {
    if (error) {
      log("error", "shutdown_failed", {
        signal,
        message: error instanceof Error ? error.message : String(error),
      });
      process.exit(1);
    }
    log("info", "shutdown_completed", { signal });
    process.exit(0);
  });
};

process.on("SIGTERM", () => shutdownGracefully("SIGTERM"));
process.on("SIGINT", () => shutdownGracefully("SIGINT"));

server.listen(port, () => {
  log("info", "server_started", {
    port,
    url: `http://127.0.0.1:${port}`,
    production: isProduction,
    serveFrontend,
    authenticated: Boolean(apiKey),
    allowUnauthenticated,
    trustProxy,
    deploymentMode,
    scanRepositoryBackend,
    rateLimitBackend: targetRateLimiter.backend,
    scanConcurrency: SCAN_CONCURRENCY,
    staleRunningScanMs: STALE_RUNNING_SCAN_MS,
    distributedRateLimit: targetRateLimiter.distributed,
    requesterRateLimit: {
      maxRequests: RATE_LIMIT_MAX_REQUESTS,
      windowMs: RATE_LIMIT_WINDOW_MS,
    },
    targetRateLimit: {
      maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
      windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
    },
    scanTimeoutMs: SCAN_TIMEOUT_MS,
    deepPassiveScanTimeoutMs: DEEP_PASSIVE_SCAN_TIMEOUT_MS,
    abuseAlerting: {
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    },
  });
});
