export const CLIENT_ID_HEADER = "x-securl-client";
export const CLIENT_VERSION_HEADER = "x-securl-client-version";

const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CLIENT_VERSION_PATTERN = /^[a-z0-9][a-z0-9._+-]{0,39}$/i;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const LONG_HEX_PATTERN = /^[a-f0-9]{16,}$/i;

export function normalizeClientId(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return CLIENT_ID_PATTERN.test(normalized)
    && !UUID_PATTERN.test(normalized)
    && !LONG_HEX_PATTERN.test(normalized)
    ? normalized
    : null;
}

export function normalizeClientVersion(value) {
  const normalized = typeof value === "string" ? value.trim() : "";
  return CLIENT_VERSION_PATTERN.test(normalized)
    && !UUID_PATTERN.test(normalized)
    && !LONG_HEX_PATTERN.test(normalized)
    ? normalized
    : null;
}

export function readClientMetadata(request, { fallbackClient = null } = {}) {
  const client = normalizeClientId(request?.headers?.[CLIENT_ID_HEADER])
    || normalizeClientId(fallbackClient);
  const version = client
    ? normalizeClientVersion(request?.headers?.[CLIENT_VERSION_HEADER])
    : null;
  return { client, version };
}
