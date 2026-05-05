import http from "node:http";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
import { createRateLimiter } from "./rateLimiter.mjs";
import { sendJson, sendMethodNotAllowed, sendRateLimited } from "./httpResponses.mjs";
import { handleAnalyzeRequest } from "./analyzeHandler.mjs";
import { createRequestGuards, getRequestedScanMode, normalizeScanErrorMessage, readJsonBody } from "./requestGuards.mjs";
import { buildScanEvidencePayload, buildScanFindingsPayload, buildScanSummaryPayload } from "./scanDtos.mjs";
import { handleScanCollectionRequest, handleScanResourceRequest } from "./scanResourceHandlers.mjs";
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
const RATE_LIMIT_MAX_BUCKETS = 20000;
const configuredRateLimitBackend = (process.env.RATE_LIMIT_BACKEND || "").trim().toLowerCase();
const rateLimitBackend = configuredRateLimitBackend || (deploymentMode === "multi-instance" ? "upstash" : "in-memory");
const configuredScanRepositoryBackend = (process.env.SCAN_REPOSITORY_BACKEND || "").trim().toLowerCase();
const scanRepositoryBackend = configuredScanRepositoryBackend || "memory";
const databaseUrl = (process.env.DATABASE_URL || "").trim();
const SCAN_OWNER_HEADER = "x-scan-owner";
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
const upstashRestUrl = (process.env.UPSTASH_REDIS_REST_URL || "").trim();
const upstashRestToken = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const abuseSignalBuckets = new Map();
const exposeDetailedHealth = !isProduction;
const exposeTelemetry = process.env.EXPOSE_TELEMETRY === "true" || !isProduction;
const allowLegacyAnalyze = process.env.ALLOW_LEGACY_ANALYZE === "true" || !isProduction;
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

function sendRepositoryUnavailable(response, error, context) {
  log("error", "scan_repository_unavailable", {
    context,
    message: formatErrorMessage(error),
    backend: scanRepository?.kind || scanRepositoryBackend,
  });
  sendJson(response, 503, {
    error: "Scan storage is temporarily unavailable. Please try again shortly.",
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

  if (requestUrl.pathname === "/api/scans") {
    await handleScanCollectionRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest,
      readJsonBody,
      getRequestedScanMode,
      checkTargetQuota,
      assertPublicHttpUrl,
      sendJson,
      sendRepositoryUnavailable,
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

  if (requestUrl.pathname.startsWith("/api/scans/")) {
    await handleScanResourceRequest({
      request,
      response,
      requestUrl,
      scanRepository,
      authorizeAnalysisRequest,
      buildScanSummaryPayload,
      buildScanFindingsPayload,
      buildScanEvidencePayload,
      sendJson,
      sendMethodNotAllowed,
      sendRepositoryUnavailable,
      requireScanOwner: true,
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

    await handleAnalyzeRequest({
      request,
      response,
      requestUrl,
      authorizeAnalysisRequest,
      getRequestedScanMode,
      checkTargetQuota,
      assertPublicHttpUrl,
      runScanAnalysis,
      telemetry,
      classifyScanFailure,
      formatErrorMessage,
      sendJson,
      sendMethodNotAllowed,
      log,
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

scanRepository = await initializeScanRepository({
  scanRepositoryBackend,
  databaseUrl,
  log,
  formatErrorMessage,
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
    abuseAlerting: {
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    },
  });
});
