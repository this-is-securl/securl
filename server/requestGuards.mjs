import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import { promisify } from "node:util";

const scryptAsync = promisify(crypto.scrypt);

function isPublicIp(ip, { isPrivateAddress }) {
  return net.isIP(ip) !== 0 && !isPrivateAddress(ip);
}

function shouldTrustForwardedHeaders(request, { isLocalHostname, isPrivateAddress }) {
  const remoteAddress = request.socket.remoteAddress || "";
  const normalized = remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
  if (!normalized) {
    return false;
  }

  if (isLocalHostname(normalized)) {
    return true;
  }

  if (net.isIP(normalized)) {
    return !isPublicIp(normalized, { isPrivateAddress });
  }

  return false;
}

function getClientIp(request, { trustProxy, isLocalHostname, isPrivateAddress }) {
  if (trustProxy && shouldTrustForwardedHeaders(request, { isLocalHostname, isPrivateAddress })) {
    const forwarded = request.headers["x-forwarded-for"];
    const candidate = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.split(",")[0].trim();
    }
  }

  const remoteAddress = request.socket.remoteAddress || "";
  return remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
}

function getPresentedApiKey(request) {
  const candidate = request.headers["x-api-key"];
  if (Array.isArray(candidate)) {
    return candidate[0] || "";
  }
  return typeof candidate === "string" ? candidate : "";
}

function getPresentedScanOwner(request, scanOwnerHeader) {
  const candidate = request.headers[scanOwnerHeader];
  if (Array.isArray(candidate)) {
    return candidate[0] || "";
  }
  return typeof candidate === "string" ? candidate : "";
}

async function tokenFingerprint(token, apiKeyFingerprintSalt) {
  const digest = await scryptAsync(token, apiKeyFingerprintSalt, 32);
  return `${apiKeyFingerprintSalt}:${digest.toString("hex")}`;
}

async function getRequesterScope({ clientIp, presentedApiKey, apiKey, apiKeyFingerprintSalt }) {
  if (apiKey && presentedApiKey) {
    return `api-key:${await tokenFingerprint(presentedApiKey, apiKeyFingerprintSalt)}`;
  }
  return `ip:${clientIp || "unknown"}`;
}

async function getScanOwnerId({
  presentedApiKey,
  requesterScope,
  presentedScanOwner,
  apiKey,
  apiKeyFingerprintSalt,
}) {
  if (apiKey && presentedApiKey) {
    return requesterScope;
  }

  const ownerToken = presentedScanOwner.trim();
  if (!ownerToken || ownerToken.length < 16 || ownerToken.length > 256) {
    return null;
  }

  return `scan-owner:${await tokenFingerprint(ownerToken, apiKeyFingerprintSalt)}`;
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

function recordAbuseSignal(signalType, details = {}, { abuseSignalBuckets, abuseAlertWindowMs, abuseAlertThreshold, log }) {
  const now = Date.now();
  const current = abuseSignalBuckets.get(signalType) || [];
  const recent = current.filter((timestamp) => now - timestamp < abuseAlertWindowMs);
  recent.push(now);
  abuseSignalBuckets.set(signalType, recent);

  log("warn", signalType, details);

  if (
    recent.length === abuseAlertThreshold
    || (recent.length > abuseAlertThreshold && recent.length % abuseAlertThreshold === 0)
  ) {
    log("error", "abuse_alert_threshold_reached", {
      signalType,
      count: recent.length,
      threshold: abuseAlertThreshold,
      windowMs: abuseAlertWindowMs,
    });
  }
}

export function getRequestedScanMode(input) {
  return input === "quiet" ? "quiet" : "standard";
}

export function normalizeScanErrorMessage(error) {
  return error instanceof Error && error.message
    ? error.message
    : "Unable to complete the scan for this target.";
}

export function readJsonBody(request, { maxBytes = 32 * 1024 } = {}) {
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

export function createRequestGuards({
  trustProxy,
  apiKey,
  apiKeyFingerprintSalt,
  scanOwnerHeader,
  isLocalHostname,
  isPrivateAddress,
  telemetry,
  rateLimiter,
  targetRateLimiter,
  abuseSignalBuckets,
  abuseAlertWindowMs,
  abuseAlertThreshold,
  sendJson,
  sendRateLimited,
  log,
}) {
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
      if (!isPublicIp(hostname, { isPrivateAddress })) {
        throw new Error("Private or local network targets are not allowed.");
      }
      return targetUrl;
    }

    const records = await dns.lookup(hostname, { all: true });
    if (!records.length || records.some((record) => !isPublicIp(record.address, { isPrivateAddress }))) {
      throw new Error("Target must resolve to a public IP address.");
    }

    return targetUrl;
  }

  async function checkTargetQuota({
    requesterScope,
    target,
    clientIp,
    requestPath,
    response,
    sendRateLimitedResponse = sendRateLimited,
  }) {
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
    }, {
      abuseSignalBuckets,
      abuseAlertWindowMs,
      abuseAlertThreshold,
      log,
    });
    sendRateLimitedResponse(
      response,
      targetRateLimitState.retryAfterSeconds,
      "Too many analysis requests for this target from this client. Please try again later.",
    );
    return { ok: false };
  }

  async function authorizeAnalysisRequest({
    request,
    response,
    requestPath,
    enforceRateLimit = true,
    requireScanOwner = false,
    sendJsonResponse = sendJson,
    sendRateLimitedResponse = sendRateLimited,
  }) {
    const clientIp = getClientIp(request, { trustProxy, isLocalHostname, isPrivateAddress }) || "unknown";
    const presentedApiKey = getPresentedApiKey(request);
    const presentedScanOwner = getPresentedScanOwner(request, scanOwnerHeader);
    const requesterScope = await getRequesterScope({
      clientIp,
      presentedApiKey,
      apiKey,
      apiKeyFingerprintSalt,
    });

    if (apiKey && presentedApiKey !== apiKey) {
      telemetry.recordAuthRejected();
      telemetry.recordFailure("auth_rejected");
      recordAbuseSignal("api_key_rejected", {
        clientIp,
        path: requestPath,
      }, {
        abuseSignalBuckets,
        abuseAlertWindowMs,
        abuseAlertThreshold,
        log,
      });
      sendJsonResponse(response, 401, {
        error: "A valid API key is required to analyze targets from this deployment.",
      });
      return null;
    }

    const ownerId = await getScanOwnerId({
      presentedApiKey,
      requesterScope,
      presentedScanOwner,
      apiKey,
      apiKeyFingerprintSalt,
    });

    if (requireScanOwner && !ownerId) {
      telemetry.recordAuthRejected();
      telemetry.recordFailure("auth_rejected");
      recordAbuseSignal("scan_owner_missing", {
        clientIp,
        requesterScope,
        path: requestPath,
      }, {
        abuseSignalBuckets,
        abuseAlertWindowMs,
        abuseAlertThreshold,
        log,
      });
      sendJsonResponse(response, 401, {
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
      }, {
        abuseSignalBuckets,
        abuseAlertWindowMs,
        abuseAlertThreshold,
        log,
      });
      sendRateLimitedResponse(response, rateLimitState.retryAfterSeconds);
      return null;
    }

    return { clientIp, requesterScope, ownerId };
  }

  return {
    assertPublicHttpUrl,
    checkTargetQuota,
    authorizeAnalysisRequest,
  };
}
