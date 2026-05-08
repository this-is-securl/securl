import type { AnalysisResult } from "@/types/analysis";
import type {
  ApiScanRecord,
  CreateScanResponse,
  GetScanResponse,
  ScanEvidenceResponse,
  ScanFindingsResponse,
  ScanHistoryResponse,
  ScanSummaryResponse,
  TargetHistoryResponse,
} from "@/types/api";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import { SCAN_OWNER_KEY, STORAGE_SCHEMA_VERSION } from "@/lib/scanWorkspace";

const DEFAULT_SCAN_POLL_ATTEMPTS = 120;
const DEFAULT_SCAN_POLL_DELAY_MS = 1000;

const normalizeBaseUrl = (value: string) => value.trim().replace(/\/+$/, "");

export const resolveApiBaseUrl = (value?: string) => normalizeBaseUrl(value || "");

export const getApiBaseUrl = () => resolveApiBaseUrl(__API_BASE_URL__);

export const buildApiUrl = (path: string) => {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const baseUrl = getApiBaseUrl();
  return baseUrl ? `${baseUrl}${normalizedPath}` : normalizedPath;
};

export class ApiClientError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.payload = payload;
  }
}

const readJsonResponse = async <T,>(response: Response): Promise<T> => {
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : "Request failed.";
    throw new ApiClientError(message, response.status, payload);
  }
  return payload as T;
};

const sleep = (delayMs: number) =>
  new Promise<void>((resolve) => {
    window.setTimeout(resolve, delayMs);
  });

export const getScanOwnerToken = async () => {
  const existing = await readBrowserStorage<string | null>(SCAN_OWNER_KEY, null, STORAGE_SCHEMA_VERSION);
  if (existing) {
    return existing;
  }

  const generated = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  await writeBrowserStorage(SCAN_OWNER_KEY, generated, STORAGE_SCHEMA_VERSION);
  return generated;
};

const buildScanOwnerHeaders = (scanOwnerToken: string) => ({
  "X-Scan-Owner": scanOwnerToken,
});

export const createScan = async (url: string, mode: "standard" | "quiet" = "standard") => {
  const scanOwnerToken = await getScanOwnerToken();
  const response = await fetch(buildApiUrl("/api/scans"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...buildScanOwnerHeaders(scanOwnerToken),
    },
    body: JSON.stringify({ url, mode }),
  });

  const payload = await readJsonResponse<CreateScanResponse>(response);
  return {
    scanOwnerToken,
    scan: payload.scan,
  };
};

export const getScan = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}`), {
    headers: buildScanOwnerHeaders(scanOwnerToken),
  });
  return readJsonResponse<GetScanResponse>(response);
};

export const waitForScanCompletion = async (
  scanId: string,
  scanOwnerToken: string,
  {
    maxAttempts = DEFAULT_SCAN_POLL_ATTEMPTS,
    delayMs = DEFAULT_SCAN_POLL_DELAY_MS,
  }: {
    maxAttempts?: number;
    delayMs?: number;
  } = {},
): Promise<ApiScanRecord> => {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const payload = await getScan(scanId, scanOwnerToken);
    const scan = payload.scan;

    if (scan.status === "completed" && scan.result) {
      return scan;
    }

    if (scan.status === "failed") {
      throw new ApiClientError(scan.error || "Scan failed.", 400, payload);
    }

    await sleep(delayMs);
  }

  throw new ApiClientError("Scan is still running. Please try again shortly.", 408, null);
};

export const analyzeTarget = async (url: string, setMode: "standard" | "quiet" = "standard"): Promise<AnalysisResult> => {
  const { scan, scanOwnerToken } = await createScan(url, setMode);
  const completedScan = await waitForScanCompletion(scan.id, scanOwnerToken);
  if (!completedScan.result) {
    throw new ApiClientError("Completed scan did not include a result payload.", 500, completedScan);
  }
  return completedScan.result;
};

export const getTargetHistory = async (url: string) => {
  const scanOwnerToken = await getScanOwnerToken();
  const response = await fetch(buildApiUrl(`/api/scans?url=${encodeURIComponent(url)}`), {
    headers: buildScanOwnerHeaders(scanOwnerToken),
  });
  return readJsonResponse<TargetHistoryResponse>(response);
};

export const getScanSummary = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/summary`), {
    headers: buildScanOwnerHeaders(scanOwnerToken),
  });
  return readJsonResponse<ScanSummaryResponse>(response);
};

export const getScanFindings = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/findings`), {
    headers: buildScanOwnerHeaders(scanOwnerToken),
  });
  return readJsonResponse<ScanFindingsResponse>(response);
};

export const getScanEvidence = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/evidence`), {
    headers: buildScanOwnerHeaders(scanOwnerToken),
  });
  return readJsonResponse<ScanEvidenceResponse>(response);
};

export const getScanHistory = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/history`), {
    headers: buildScanOwnerHeaders(scanOwnerToken),
  });
  return readJsonResponse<ScanHistoryResponse>(response);
};
