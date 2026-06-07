import crypto from "node:crypto";

const DEFAULT_PRIVACY_SALT = "epi-privacy-redaction-v1";

export function getPrivacySalt() {
  return process.env.PRIVACY_HASH_SALT
    || process.env.TELEMETRY_VISITOR_SALT
    || process.env.API_KEY_FINGERPRINT_SALT
    || DEFAULT_PRIVACY_SALT;
}

export function hashPrivacyValue(value, { salt = getPrivacySalt(), prefix = "", length = 16 } = {}) {
  const normalized = String(value || "").trim();
  if (!normalized || normalized === "unknown") {
    return "unknown";
  }

  const digest = crypto
    .createHash("sha256")
    .update(`${salt}:${normalized}`)
    .digest("hex")
    .slice(0, length);

  return prefix ? `${prefix}:${digest}` : digest;
}

export function hashClientIp(clientIp, options = {}) {
  return hashPrivacyValue(clientIp, options);
}

export function redactRequesterScope(requesterScope, options = {}) {
  if (typeof requesterScope === "string" && requesterScope.startsWith("ip:")) {
    return `ip:${hashClientIp(requesterScope.slice(3), options)}`;
  }
  return requesterScope;
}

export function targetOriginForPrivacy(value) {
  if (!value) {
    return null;
  }

  try {
    const url = value instanceof URL ? value : new URL(String(value));
    return url.origin;
  } catch {
    return null;
  }
}

export function targetForPrivacy(value) {
  return targetOriginForPrivacy(value) || (typeof value === "string" ? value.slice(0, 120) : null);
}
