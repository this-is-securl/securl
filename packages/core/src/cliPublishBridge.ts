import { randomBytes } from "node:crypto";

const HOSTED_API_BASE_URL = "https://securl-app-production.up.railway.app";
const MOBILE_BRIDGE_BASE_URL = "https://securl.online";
const POLL_INTERVAL_MS = 2_000;
const PUBLISH_TIMEOUT_MS = 120_000;

type ScanMode = "standard" | "quiet" | "deep-passive";
type FetchLike = typeof fetch;

type HostedScanPayload = {
  scan?: {
    id?: string;
    status?: string;
    error?: string | null;
  };
};

export type PublishedScan = {
  scanId: string;
  reportUrl: string;
  mobileBridgeUrl: string;
};

export type PublishHostedScanOptions = {
  targetUrl: string;
  scanMode: ScanMode;
  clientVersion: string | null;
  fetchImpl?: FetchLike;
  sleep?: (milliseconds: number) => Promise<void>;
  ownerToken?: string;
  timeoutMs?: number;
};

const parseJson = async (response: Response): Promise<HostedScanPayload> => {
  try {
    return await response.json() as HostedScanPayload;
  } catch {
    throw new Error("Hosted publication returned an unreadable response.");
  }
};

const requestHeaders = (ownerToken: string, clientVersion: string | null) => ({
  "Content-Type": "application/json",
  Accept: "application/json",
  "X-Scan-Owner": ownerToken,
  "X-SecURL-Client": "securl-cli",
  ...(clientVersion ? { "X-SecURL-Client-Version": clientVersion } : {}),
  "X-SecURL-Client-Channel": "cli",
});

export async function publishHostedScan({
  targetUrl,
  scanMode,
  clientVersion,
  fetchImpl = fetch,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  ownerToken = randomBytes(32).toString("base64url"),
  timeoutMs = PUBLISH_TIMEOUT_MS,
}: PublishHostedScanOptions): Promise<PublishedScan> {
  const headers = requestHeaders(ownerToken, clientVersion);
  const currentUrl = new URL("https://app.securl.online/");
  currentUrl.searchParams.set("utm_source", "securl_cli");
  currentUrl.searchParams.set("utm_medium", "cli");
  currentUrl.searchParams.set("utm_campaign", "cli_publish_bridge");

  const createResponse = await fetchImpl(`${HOSTED_API_BASE_URL}/api/scans`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      url: targetUrl,
      mode: scanMode,
      currentUrl: currentUrl.toString(),
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const created = await parseJson(createResponse);
  if (!createResponse.ok || !created.scan?.id) {
    throw new Error(`Hosted publication failed (HTTP ${createResponse.status}).`);
  }

  const scanId = created.scan.id;
  const deadline = Date.now() + timeoutMs;
  let status = created.scan.status ?? "queued";
  while (!["completed", "failed"].includes(status)) {
    if (Date.now() >= deadline) {
      throw new Error("Hosted publication timed out before the report was ready.");
    }
    await sleep(POLL_INTERVAL_MS);
    const response = await fetchImpl(`${HOSTED_API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}`, {
      headers,
      signal: AbortSignal.timeout(15_000),
    });
    const payload = await parseJson(response);
    if (!response.ok || !payload.scan) {
      throw new Error(`Hosted publication status check failed (HTTP ${response.status}).`);
    }
    status = payload.scan.status ?? "unknown";
    if (status === "failed") {
      throw new Error(payload.scan.error || "Hosted publication scan failed.");
    }
  }

  return {
    scanId,
    reportUrl: `https://app.securl.online/report/${encodeURIComponent(scanId)}?utm_source=securl_cli&utm_medium=cli&utm_campaign=cli_published_report`,
    mobileBridgeUrl: `${MOBILE_BRIDGE_BASE_URL}/m/${encodeURIComponent(scanId)}`,
  };
}

export function formatPublishedScan(
  published: PublishedScan,
  qr: string | null = null,
): string {
  return [
    "Hosted report ready:",
    published.reportUrl,
    "",
    "Open or scan this link to continue on mobile:",
    published.mobileBridgeUrl,
    ...(qr ? ["", qr.trimEnd()] : []),
    "",
    "The mobile bridge only pre-fills the target. Scanning and monitoring still require your tap.",
    "",
  ].join("\n");
}
