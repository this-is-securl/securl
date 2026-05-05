import { createScanRepository } from "./scanRepository.mjs";

function asNumber(value, fallback) {
  const parsed = Number(value ?? fallback);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

const env = process.env;
const nodeEnv = env.NODE_ENV || "development";
const allowUnauthenticated = env.ALLOW_UNAUTHENTICATED === "true";
const apiKey = env.API_KEY || "";
const deploymentMode = env.DEPLOYMENT_MODE === "multi-instance" ? "multi-instance" : "single-instance";
const configuredBackend = (env.RATE_LIMIT_BACKEND || "").trim().toLowerCase();
const rateLimitBackend = configuredBackend || (deploymentMode === "multi-instance" ? "upstash" : "in-memory");
const configuredScanRepositoryBackend = (env.SCAN_REPOSITORY_BACKEND || "").trim().toLowerCase();
const scanRepositoryBackend = configuredScanRepositoryBackend || "memory";
const databaseUrl = (env.DATABASE_URL || "").trim();
const upstashUrl = (env.UPSTASH_REDIS_REST_URL || "").trim();
const upstashToken = (env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const rateLimitWindowMs = asNumber(env.RATE_LIMIT_WINDOW_MS, 900000);
const rateLimitMaxRequests = asNumber(env.RATE_LIMIT_MAX_REQUESTS, 30);
const targetRateLimitWindowMs = asNumber(env.TARGET_RATE_LIMIT_WINDOW_MS, 900000);
const targetRateLimitMaxRequests = asNumber(env.TARGET_RATE_LIMIT_MAX_REQUESTS, 10);
const abuseAlertWindowMs = asNumber(env.ABUSE_ALERT_WINDOW_MS, 600000);
const abuseAlertThreshold = asNumber(env.ABUSE_ALERT_THRESHOLD, 25);

const errors = [];
const warnings = [];

if (nodeEnv !== "production") {
  errors.push("NODE_ENV must be set to production for public deployment.");
}

if (!apiKey && !allowUnauthenticated) {
  errors.push("Set API_KEY, or explicitly set ALLOW_UNAUTHENTICATED=true.");
}

if (!["in-memory", "upstash"].includes(rateLimitBackend)) {
  errors.push("RATE_LIMIT_BACKEND must be either 'in-memory' or 'upstash'.");
}

if (!["memory", "postgres"].includes(scanRepositoryBackend)) {
  errors.push("SCAN_REPOSITORY_BACKEND must be either 'memory' or 'postgres'.");
}

if (deploymentMode === "multi-instance" && rateLimitBackend !== "upstash") {
  errors.push("DEPLOYMENT_MODE=multi-instance requires RATE_LIMIT_BACKEND=upstash.");
}

if (scanRepositoryBackend === "postgres" && !databaseUrl) {
  errors.push("DATABASE_URL is required when SCAN_REPOSITORY_BACKEND=postgres.");
}

if (rateLimitBackend === "upstash") {
  if (!upstashUrl) {
    errors.push("UPSTASH_REDIS_REST_URL is required when RATE_LIMIT_BACKEND=upstash.");
  }
  if (!upstashToken) {
    errors.push("UPSTASH_REDIS_REST_TOKEN is required when RATE_LIMIT_BACKEND=upstash.");
  }
}

if (!Number.isFinite(rateLimitWindowMs) || rateLimitWindowMs < 1000) {
  errors.push("RATE_LIMIT_WINDOW_MS must be a number >= 1000.");
}

if (!Number.isFinite(rateLimitMaxRequests) || rateLimitMaxRequests < 1) {
  errors.push("RATE_LIMIT_MAX_REQUESTS must be a number >= 1.");
}

if (!Number.isFinite(targetRateLimitWindowMs) || targetRateLimitWindowMs < 1000) {
  errors.push("TARGET_RATE_LIMIT_WINDOW_MS must be a number >= 1000.");
}

if (!Number.isFinite(targetRateLimitMaxRequests) || targetRateLimitMaxRequests < 1) {
  errors.push("TARGET_RATE_LIMIT_MAX_REQUESTS must be a number >= 1.");
}

if (!Number.isFinite(abuseAlertWindowMs) || abuseAlertWindowMs < 1000) {
  errors.push("ABUSE_ALERT_WINDOW_MS must be a number >= 1000.");
}

if (!Number.isFinite(abuseAlertThreshold) || abuseAlertThreshold < 1) {
  errors.push("ABUSE_ALERT_THRESHOLD must be a number >= 1.");
}

if (!env.TRUST_PROXY || env.TRUST_PROXY !== "true") {
  warnings.push("TRUST_PROXY is disabled. This is fine for direct traffic, but verify proxy topology before public edge deployment.");
}

if (allowUnauthenticated) {
  warnings.push("ALLOW_UNAUTHENTICATED=true is enabled. Confirm this is intentional for a public deployment.");
}

const summary = {
  nodeEnv,
  deploymentMode,
  rateLimitBackend,
  scanRepositoryBackend,
  allowUnauthenticated,
  trustProxy: env.TRUST_PROXY === "true",
  rateLimitWindowMs,
  rateLimitMaxRequests,
  targetRateLimitWindowMs,
  targetRateLimitMaxRequests,
  abuseAlertWindowMs,
  abuseAlertThreshold,
};

if (errors.length === 0 && scanRepositoryBackend === "postgres") {
  const repository = createScanRepository({
    backend: scanRepositoryBackend,
    databaseUrl,
    log: () => {},
  });

  try {
    await repository.initialize?.();
    await repository.ping();
  } catch (error) {
    errors.push(`Configured Postgres scan repository is unavailable: ${error?.message || String(error)}`);
  } finally {
    await repository.close?.();
  }
}

console.log(JSON.stringify({ ok: errors.length === 0, summary, warnings, errors }, null, 2));

if (errors.length > 0) {
  process.exit(1);
}
