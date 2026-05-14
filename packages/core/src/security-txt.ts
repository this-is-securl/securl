import type { SecurityTxtInfo } from "./types.js";
import type { RequestTextFn } from "./network.js";

export function parseSecurityTxt(raw: string, url: URL): SecurityTxtInfo {
  const fields = {
    contact: [] as string[],
    policy: [] as string[],
    acknowledgments: [] as string[],
    encryption: [] as string[],
    hiring: [] as string[],
    preferredLanguages: [] as string[],
    canonical: [] as string[],
    expires: undefined as string | undefined,
  };
  const issues: string[] = [];

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^([^:]+):\s*(.+)$/);
    if (!match) {
      continue;
    }
    const key = match[1] ?? "";
    const value = match[2] ?? "";
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "contact") fields.contact.push(value);
    if (normalizedKey === "expires") fields.expires = value;
    if (normalizedKey === "policy") fields.policy.push(value);
    if (normalizedKey === "acknowledgments") fields.acknowledgments.push(value);
    if (normalizedKey === "encryption") fields.encryption.push(value);
    if (normalizedKey === "hiring") fields.hiring.push(value);
    if (normalizedKey === "preferred-languages") fields.preferredLanguages.push(value);
    if (normalizedKey === "canonical") fields.canonical.push(value);
  }

  if (!fields.contact.length) {
    issues.push("No Contact field found.");
  }
  if (!fields.expires) {
    issues.push("No Expires field found.");
  }
  if (fields.canonical.length && !fields.canonical.includes(url.toString())) {
    issues.push("Canonical field does not include the discovered security.txt URL.");
  }

  return {
    status: issues.length && !raw.includes("Contact:") ? "invalid" : "present",
    url: url.toString(),
    contact: fields.contact,
    expires: fields.expires || null,
    policy: fields.policy,
    acknowledgments: fields.acknowledgments,
    encryption: fields.encryption,
    hiring: fields.hiring,
    preferredLanguages: fields.preferredLanguages,
    canonical: fields.canonical,
    raw: raw.trim() || null,
    issues,
  };
}

export async function fetchSecurityTxt(finalUrl: URL, requestText: RequestTextFn): Promise<SecurityTxtInfo> {
  const candidates = [
    new URL("/.well-known/security.txt", finalUrl.origin),
    new URL("/security.txt", finalUrl.origin),
  ];

  for (const candidate of candidates) {
    try {
      const response = await requestText(candidate);
      if (response.statusCode >= 200 && response.statusCode < 300 && response.body.trim()) {
        return parseSecurityTxt(response.body, candidate);
      }
    } catch {
      // Continue to the fallback path.
    }
  }

  return {
    status: "missing",
    url: null,
    contact: [],
    expires: null,
    policy: [],
    acknowledgments: [],
    encryption: [],
    hiring: [],
    preferredLanguages: [],
    canonical: [],
    raw: null,
    issues: ["No security.txt file found at /.well-known/security.txt or /security.txt."],
  };
}
