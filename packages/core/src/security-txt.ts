import type { RequestTextFn } from "./network.js";
import type { SecurityTxtInfo } from "./types.js";
import { headerValue } from "./utils.js";

export function parseSecurityTxt(raw: string, url: URL): SecurityTxtInfo {
  const fields = {
    contact: [] as string[],
    policy: null as string | null,
    acknowledgments: null as string | null,
    encryption: [] as string[],
    hiring: [] as string[],
    preferredLanguages: null as string | null,
    canonical: [] as string[],
    expires: null as string | null,
  };
  const issues: string[] = [];
  const strengths: string[] = [];

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^([^:]+):\s*(.+)$/);
    if (!match) {
      continue;
    }
    const [, key, value] = match;
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "contact") fields.contact.push(value);
    if (normalizedKey === "expires") fields.expires = value;
    if (normalizedKey === "policy") fields.policy ??= value;
    if (normalizedKey === "acknowledgments") fields.acknowledgments ??= value;
    if (normalizedKey === "encryption") fields.encryption.push(value);
    if (normalizedKey === "hiring") fields.hiring.push(value);
    if (normalizedKey === "preferred-languages") fields.preferredLanguages ??= value;
    if (normalizedKey === "canonical") fields.canonical.push(value);
  }

  if (!fields.contact.length) {
    issues.push("security.txt is present but missing the required Contact field.");
  }
  if (!fields.expires) {
    issues.push("security.txt is present but missing the required Expires field.");
  }
  if (fields.canonical.length && !fields.canonical.includes(url.toString())) {
    issues.push("Canonical field does not include the discovered security.txt URL.");
  }

  const expiresDate = fields.expires ? new Date(fields.expires) : null;
  const expiresValid = Boolean(expiresDate && !Number.isNaN(expiresDate.getTime()));
  const isExpired = expiresValid ? expiresDate!.getTime() < Date.now() : false;

  if (fields.expires && !expiresValid) {
    issues.push("security.txt has an Expires field, but it is not a valid date.");
  }
  if (isExpired) {
    issues.push("security.txt is expired and should be refreshed.");
  }
  if (fields.contact.length && fields.expires && expiresValid && !isExpired) {
    strengths.push("security.txt is published with required contact and expiry fields.");
  }

  const status: SecurityTxtInfo["status"] = isExpired
    ? "present_expired"
    : issues.length
      ? "present_incomplete"
      : "present_valid";

  return {
    status,
    url: url.toString(),
    contact: fields.contact,
    expires: fields.expires,
    isExpired,
    policy: fields.policy,
    acknowledgments: fields.acknowledgments,
    encryption: fields.encryption,
    hiring: fields.hiring,
    preferredLanguages: fields.preferredLanguages,
    canonical: fields.canonical,
    raw: raw.trim() || null,
    issues,
    strengths,
  };
}

export async function fetchSecurityTxt(finalUrl: URL, requestText: RequestTextFn): Promise<SecurityTxtInfo> {
  const candidate = new URL("/.well-known/security.txt", finalUrl.origin);

  try {
    const response = await requestText(candidate);
    if (response.statusCode >= 200 && response.statusCode < 300 && response.body.trim()) {
      return parseSecurityTxt(response.body, candidate);
    }

    const location = headerValue(response.headers, "location");
    if ([301, 302, 303, 307, 308].includes(response.statusCode) && location) {
      const redirected = new URL(location, candidate);
      if (redirected.protocol === "https:") {
        const redirectedResponse = await requestText(redirected);
        if (redirectedResponse.statusCode >= 200 && redirectedResponse.statusCode < 300 && redirectedResponse.body.trim()) {
          return parseSecurityTxt(redirectedResponse.body, redirected);
        }
      }
    }
  } catch {
    // Missing/unreachable security.txt is represented as a normal passive finding below.
  }

  return {
    status: "missing",
    url: null,
    contact: [],
    expires: null,
    isExpired: false,
    policy: null,
    acknowledgments: null,
    encryption: [],
    hiring: [],
    preferredLanguages: null,
    canonical: [],
    raw: null,
    issues: ["No security.txt found. Publishing one signals responsible disclosure readiness."],
    strengths: [],
  };
}
