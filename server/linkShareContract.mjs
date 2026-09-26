import crypto from "node:crypto";

export const LINK_SHARE_SCHEMA = "securl.link-share.v1";
export const LINK_SHARE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const VERDICTS = Object.freeze({
  no_obvious_concern: {
    level: "no_obvious_concern",
    title: "No obvious link-level concern found",
    summary: "The destination resolved and the passive URL and redirect checks found no obvious concern. This is not a malware verdict and does not mean the link is safe.",
  },
  review: {
    level: "review",
    title: "Review before opening",
    summary: "The link resolved, but one or more link-level characteristics deserve a closer look. Verify the destination before opening it.",
  },
  high_attention: {
    level: "high_attention",
    title: "Treat this link with caution",
    summary: "The URL or redirect path contains a high-attention characteristic. Verify it through another channel before opening it.",
  },
  blocked: {
    level: "blocked",
    title: "Link not opened",
    summary: "SecURL stopped before making a request because the URL was unsupported or unsafe to fetch.",
  },
});

const SIGNALS = Object.freeze({
  embedded_credentials: ["high", "The submitted URL contained embedded credentials"],
  internationalized_hostname: ["attention", "The hostname uses encoded international characters"],
  ip_literal: ["attention", "The link uses an IP address instead of a domain"],
  unusual_port: ["attention", "The link uses a non-standard port"],
  known_shortener: ["attention", "The destination is hidden by a link shortener"],
  deep_subdomain: ["attention", "The hostname has many subdomain levels"],
  nested_destination: ["attention", "The URL contained another destination"],
  redirect_limit: ["high", "The redirect chain did not reach a final response"],
  attachment: ["attention", "The destination returns a download"],
  non_html_response: ["info", "The destination is not a normal web page"],
  many_redirects: ["attention", "The link takes a long redirect path"],
  https_upgrade: ["info", "The destination upgrades to HTTPS"],
  unencrypted_http: ["attention", "The link starts without HTTPS"],
});

const LIMITATIONS = Object.freeze([
  "This passive check did not execute page scripts, submit forms, download attachments, or sign in.",
  "No malware, domain-age, blocklist, or reputation provider was queried, so this result is not a guarantee that a link is safe.",
]);

function publicUrl(value) {
  if (typeof value !== "string" || value.length > 8192) return null;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    const path = redactTokenLikePath(parsed.pathname || "/");
    return {
      scheme: parsed.protocol.slice(0, -1),
      hostname: parsed.hostname.toLowerCase(),
      path,
      displayUrl: `${parsed.protocol}//${parsed.hostname.toLowerCase()}${path}`,
    };
  } catch {
    return null;
  }
}

function redactTokenLikePath(pathname) {
  return pathname.split("/").map((segment) => {
    let decoded = segment;
    try { decoded = decodeURIComponent(segment); } catch { /* preserve malformed public path text */ }
    const looksLikeUuid = /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(decoded);
    const looksLikeJwt = decoded.split(".").length === 3 && decoded.length >= 24;
    const looksHighEntropy = decoded.length >= 24 && /^[A-Za-z0-9_~.-]+$/.test(decoded);
    return looksLikeUuid || looksLikeJwt || looksHighEntropy ? ":redacted" : segment;
  }).join("/");
}

function publicSignals(signals) {
  if (!Array.isArray(signals)) return [];
  const seen = new Set();
  return signals.flatMap((signal) => {
    const id = typeof signal?.id === "string" ? signal.id.replace(/_\d+$/, "") : "";
    const definition = SIGNALS[id];
    if (!definition || seen.has(id)) return [];
    seen.add(id);
    return [{ id, level: definition[0], title: definition[1] }];
  }).slice(0, 20);
}

export function buildLinkSharePreview(inspection) {
  if (!inspection || inspection.schema !== "securl.link-inspection.v1") {
    throw new Error("A completed SecURL link inspection is required.");
  }
  const source = publicUrl(inspection.normalizedUrl);
  if (!source) throw new Error("The inspection does not contain a valid public HTTP(S) source.");
  const verdict = VERDICTS[inspection.verdict?.level];
  if (!verdict) throw new Error("The inspection verdict is unsupported.");

  const redirects = Array.isArray(inspection.redirects)
    ? inspection.redirects.slice(0, 12).flatMap((hop, index) => {
      const hostname = publicUrl(hop?.url)?.hostname
        || (typeof hop?.hostname === "string" && /^[a-z0-9.-]{1,253}$/i.test(hop.hostname) ? hop.hostname.toLowerCase() : null);
      const statusCode = Number(hop?.statusCode);
      if (!hostname || !Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) return [];
      return [{
        position: index + 1,
        hostname,
        statusCode,
        originChanged: Boolean(hop?.originChanged),
        downgradedToHttp: Boolean(hop?.downgradedToHttp),
      }];
    })
    : [];

  const responseStatus = Number(inspection.response?.statusCode);
  const response = inspection.response && Number.isInteger(responseStatus) && responseStatus >= 100 && responseStatus <= 599
    ? {
      statusCode: responseStatus,
      contentType: typeof inspection.response.contentType === "string"
        ? inspection.response.contentType.slice(0, 120).replace(/[\r\n]/g, "")
        : null,
    }
    : null;

  return {
    schema: LINK_SHARE_SCHEMA,
    source,
    destination: publicUrl(inspection.destinationUrl),
    redirects,
    verdict: { ...verdict },
    signals: publicSignals(inspection.signals),
    response,
    limitations: [...LIMITATIONS],
  };
}

export function createLinkShareRecord({ inspection, now = new Date() }) {
  const createdAt = now.toISOString();
  return {
    publicId: crypto.randomBytes(24).toString("base64url"),
    revokeToken: crypto.randomBytes(32).toString("base64url"),
    createdAt,
    expiresAt: new Date(now.getTime() + LINK_SHARE_TTL_MS).toISOString(),
    preview: buildLinkSharePreview(inspection),
  };
}

export function hashRevokeToken(token, salt) {
  return crypto.createHmac("sha256", salt).update(String(token || "")).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]),
    );
  }
  return value;
}

function hmacInspection(inspection, salt, canonical) {
  const payload = JSON.stringify(canonical ? canonicalJson(inspection) : inspection);
  return crypto.createHmac("sha256", salt).update(payload).digest("base64url");
}

function proofsMatch(expectedProof, presentedProof) {
  const expected = Buffer.from(expectedProof);
  const presented = Buffer.from(presentedProof);
  return expected.length === presented.length && crypto.timingSafeEqual(expected, presented);
}

export function createInspectionProof(inspection, salt) {
  return hmacInspection(inspection, salt, true);
}

export function verifyInspectionProof(inspection, proof, salt) {
  if (typeof proof !== "string") return false;
  if (proofsMatch(createInspectionProof(inspection, salt), proof)) return true;

  // Proofs issued before canonical serialization used insertion-order JSON. Keep accepting
  // them for the short preview/create window so the hosted rollout is non-breaking.
  return proofsMatch(hmacInspection(inspection, salt, false), proof);
}

export function classifyLinkShare(record, now = new Date()) {
  if (!record) return "not_found";
  if (record.revokedAt) return "revoked";
  if (Date.parse(record.expiresAt) <= now.getTime()) return "expired";
  return "active";
}

export function publicLinkShare(record, publicBaseUrl) {
  return {
    ...structuredClone(record.preview),
    publicId: record.publicId,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    publicUrl: `${String(publicBaseUrl).replace(/\/$/, "")}/shared/link/${record.publicId}`,
  };
}
