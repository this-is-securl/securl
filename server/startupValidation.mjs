import { createScanRepository } from "./scanRepository.mjs";

export async function initializeScanRepository({
  scanRepositoryBackend,
  databaseUrl,
  log,
  formatErrorMessage,
}) {
  const scanRepository = createScanRepository({
    backend: scanRepositoryBackend,
    databaseUrl,
    log: (...args) => log(...args),
  });

  try {
    await scanRepository.initialize?.();
    await scanRepository.ping();
  } catch (error) {
    log("error", "server_start_blocked", {
      reason: "Configured scan repository is unavailable.",
      backend: scanRepository.kind,
      message: formatErrorMessage(error),
    });
    await scanRepository.close?.();
    process.exit(1);
  }

  return scanRepository;
}

export function enforceStartupConfiguration({
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
}) {
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

  if (!["memory", "postgres"].includes(scanRepositoryBackend)) {
    log("error", "server_start_blocked", {
      reason: "SCAN_REPOSITORY_BACKEND must be 'memory' or 'postgres'.",
    });
    process.exit(1);
  }

  if (scanRepositoryBackend === "postgres" && !databaseUrl) {
    log("error", "server_start_blocked", {
      reason: "SCAN_REPOSITORY_BACKEND=postgres requires DATABASE_URL.",
    });
    process.exit(1);
  }

  if (isProduction && scanRepositoryBackend === "postgres" && process.env.PGSSL_REJECT_UNAUTHORIZED !== "true") {
    log("warn", "postgres_tls_verification_not_enforced", {
      message: "Postgres TLS is enabled without certificate verification. Set PGSSL_REJECT_UNAUTHORIZED=true when your provider chain is trusted.",
    });
  }

  if (isProduction && !process.env.AUTH_TOKEN_FINGERPRINT_SALT) {
    log("warn", "default_auth_fingerprint_salt", {
      message: "Set AUTH_TOKEN_FINGERPRINT_SALT to a deployment-specific secret before handling real user accounts.",
    });
  }

  if (isProduction && !process.env.API_KEY_FINGERPRINT_SALT) {
    log("warn", "default_api_key_fingerprint_salt", {
      message: "Set API_KEY_FINGERPRINT_SALT to a deployment-specific secret before handling production API keys.",
    });
  }
}
