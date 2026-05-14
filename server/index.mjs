import http from "node:http";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
import { createCorsPolicy, resolveAllowedOrigins } from "./cors.mjs";
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
  buildMonitoringTargetView,
  buildMonitoringTargetsPayload,
  buildScanEvidencePayload,
  buildScanFindingsPayload,
  buildScanHistoryPayload,
  buildScanSummaryPayload,
  buildTargetHistoryPayload,
} from "./scanDtos.mjs";
import {
  handleMonitoringTargetCollectionRequest,
  handleMonitoringTargetItemRequest,
} from "./monitoringTargetHandlers.mjs";
import { handleAuthRequest, resolveAuthenticatedSession } from "./authHandlers.mjs";
import { handleScanCollectionRequest, handleScanResourceRequest, runQueuedScan } from "./scanResourceHandlers.mjs";
import { createStaticHandler } from "./staticServer.mjs";
import { enforceStartupConfiguration, initializeScanRepository } from "./startupValidation.mjs";
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
const DEFAULT_AUTH_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_AUTH_RATE_LIMIT_MAX_REQUESTS = 8;
const DEFAULT_SCAN_TIMEOUT_MS = 45 * 1000;
const RATE_LIMIT_MAX_BUCKETS = 20000;
const configuredRateLimitBackend = (process.env.RATE_LIMIT_BACKEND || "").trim().toLowerCase();
const rateLimitBackend = configuredRateLimitBackend || (deploymentMode === "multi-instance" ? "upstash" : "in-memory");
const configuredScanRepositoryBackend = (process.env.SCAN_REPOSITORY_BACKEND || "").trim().toLowerCase();
const scanRepositoryBackend = configuredScanRepositoryBackend || "memory";
const databaseUrl = (process.env.DATABASE_URL || "").trim();
const allowedOrigins = resolveAllowedOrigins(process.env.ALLOWED_ORIGINS, isProduction);
const SCAN_OWNER_HEADER = "x-scan-owner";
const AUTH_TOKEN_FINGERPRINT_SALT = process.env.AUTH_TOKEN_FINGERPRINT_SALT || "epi-auth-token-fingerprint-v1";
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
const upstashRestUrl = (process.env.UPSTASH_REDIS_REST_URL || "").trim();
const upstashRestToken = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const abuseSignalBuckets = new Map();
const exposeDetailedHealth = !isProduction;
const exposeTelemetry = process.env.EXPOSE_TELEMETRY === "true" || !isProduction;
const telemetry = createTelemetryTracker();
let scanRepository;

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

async function runScanAnalysis({ validatedTarget, mode, clientIp, requesterScope }) {
  const startedAt = Date.now();
  telemetry.recordScanRequested({ mode });
  log("info", "analysis_requested", {
    clientIp,
    requesterScope,
    target: validatedTarget.toString(),
    mode,
  });
  const result = await analyzeUrl(validatedTarget.toString(), {
    scanMode: mode,
    maxScanDurationMs: SCAN_TIMEOUT_MS,
  });
  telemetry.recordScanCompleted(result);
  log("info", "analysis_completed", {
    clientIp,
    requesterScope,
    target: validatedTarget.toString(),
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
});
const corsPolicy = createCorsPolicy({
  allowedOrigins,
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
    }

    sendApiJson(response, 200, payload);
    return;
  }

  if (requestUrl.pathname === "/api/telemetry") {
    if (!exposeTelemetry) {
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
      authorizeAnalysisRequest: (options) => authorizeAnalysisRequest({
        ...options,
        resolveSessionAuth: (token) => resolveAuthenticatedSession({
          token,
          scanRepository,
          authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
        }),
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
      authorizeAnalysisRequest: (options) => authorizeAnalysisRequest({
        ...options,
        resolveSessionAuth: (token) => resolveAuthenticatedSession({
          token,
          scanRepository,
          authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
        }),
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

  if (requestUrl.pathname.startsWith("/api/monitoring-targets/")) {
    await handleMonitoringTargetItemRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest: (options) => authorizeAnalysisRequest({
        ...options,
        resolveSessionAuth: (token) => resolveAuthenticatedSession({
          token,
          scanRepository,
          authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
        }),
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
      runQueuedScan,
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
      authorizeAnalysisRequest: (options) => authorizeAnalysisRequest({
        ...options,
        resolveSessionAuth: (token) => resolveAuthenticatedSession({
          token,
          scanRepository,
          authTokenFingerprintSalt: AUTH_TOKEN_FINGERPRINT_SALT,
        }),
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

  if (request.method === "GET" || request.method === "HEAD") {
    serveStatic(rawRequestPath, request.method, response);
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not found");
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
    scanRepositoryBackend,
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
    scanTimeoutMs: SCAN_TIMEOUT_MS,
    abuseAlerting: {
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    },
  });
});
