export const CLIENT_ID_HEADER = "x-securl-client";
export const CLIENT_VERSION_HEADER = "x-securl-client-version";
export const CLIENT_CHANNEL_HEADER = "x-securl-client-channel";

const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CLIENT_VERSION_PATTERN = /^[a-z0-9][a-z0-9._+-]{0,39}$/i;
const CLIENT_CHANNEL_ALIASES = new Map([
  ["appstore", "app-store"],
  ["app_store", "app-store"],
  ["app-store", "app-store"],
  ["store", "app-store"],
  ["testflight", "testflight"],
  ["test-flight", "testflight"],
  ["tf", "testflight"],
  ["debug", "development"],
  ["dev", "development"],
  ["development", "development"],
  ["local", "development"],
  ["automation", "automation"],
  ["automated", "automation"],
  ["ci", "automation"],
  ["smoke", "automation"],
]);

const CLIENT_APP_IDS = new Map([
  ["securl-ios", "com.ktbatterham.securl"],
  ["header-watch-ios", "com.ktbatterham.headerwatch"],
  ["cert-watch-ios", "com.ktbatterham.certwatch"],
]);
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

export function normalizeClientChannel(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return CLIENT_CHANNEL_ALIASES.get(normalized) || null;
}

export function inferAppIdFromClient(client) {
  const normalized = normalizeClientId(client);
  if (!normalized) {
    return null;
  }
  return CLIENT_APP_IDS.get(normalized) || (normalized.startsWith("com.") ? normalized : null);
}

export function inferClientChannel({ client = null, version = null } = {}) {
  const clientText = typeof client === "string" ? client.toLowerCase() : "";
  const versionText = typeof version === "string" ? version.toLowerCase() : "";
  if (
    clientText.includes("smoke")
    || clientText.includes("dast")
    || clientText.includes("ci")
    || versionText === "smoke"
    || versionText.includes("smoke")
  ) {
    return "automation";
  }
  return null;
}

export function readClientMetadata(request, { fallbackClient = null } = {}) {
  const client = normalizeClientId(request?.headers?.[CLIENT_ID_HEADER])
    || normalizeClientId(fallbackClient);
  const version = client
    ? normalizeClientVersion(request?.headers?.[CLIENT_VERSION_HEADER])
    : null;
  const channel = normalizeClientChannel(request?.headers?.[CLIENT_CHANNEL_HEADER])
    || inferClientChannel({ client, version });
  const appId = inferAppIdFromClient(client) || inferAppIdFromClient(fallbackClient);
  return { client, version, channel, appId };
}
