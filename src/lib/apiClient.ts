import type { AnalysisResult } from "@/types/analysis";
import type {
  AuthSessionResponse,
  AuthStatusResponse,
  ApiMonitoringTarget,
  ApiScanRecord,
  ApiScanSummary,
  CreateScanResponse,
  DeleteMonitoringTargetResponse,
  GetScanResponse,
  MonitoringTargetResponse,
  MonitoringTargetsResponse,
  ScansResponse,
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
const AUTH_SESSION_KEY = "secure-header-insight:auth-session";
let inMemoryAuthSession: StoredAuthSession | null = null;

const normalizeBaseUrl = (value: string) => value.trim().replace(/\/+$/, "");

export const resolveApiBaseUrl = (value?: string) => normalizeBaseUrl(value || "");

export const getApiBaseUrl = () => resolveApiBaseUrl(__API_BASE_URL__);

export const buildApiUrl = (path: string) => {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const baseUrl = getApiBaseUrl();
  return baseUrl ? `${baseUrl}${normalizedPath}` : normalizedPath;
};

export const recordPageLoad = () => {
  const url = buildApiUrl("/api/telemetry/page-load");
  const payload = JSON.stringify({
    referrer: typeof document !== "undefined" ? document.referrer : "",
    currentUrl: typeof window !== "undefined" ? window.location.href : "",
  });
  if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
    navigator.sendBeacon(url, new Blob([payload], { type: "application/json" }));
    return;
  }

  void fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: payload,
    keepalive: true,
  }).catch(() => {
    // Telemetry must never interrupt the user journey.
  });
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

const buildSecureFallbackToken = () => {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new ApiClientError("Secure browser crypto is not available.", 500, null);
  }

  const bytes = new Uint8Array(16);
  cryptoApi.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
};

const isAnalysisResult = (value: unknown): value is AnalysisResult =>
  typeof value === "object"
  && value !== null
  && typeof (value as AnalysisResult).host === "string"
  && typeof (value as AnalysisResult).grade === "string"
  && typeof (value as AnalysisResult).finalUrl === "string";

export const getScanOwnerToken = async () => {
  const existing = await readBrowserStorage<string | null>(SCAN_OWNER_KEY, null, STORAGE_SCHEMA_VERSION);
  if (existing) {
    return existing;
  }

  const generated = globalThis.crypto?.randomUUID?.() ?? buildSecureFallbackToken();
  await writeBrowserStorage(SCAN_OWNER_KEY, generated, STORAGE_SCHEMA_VERSION);
  return generated;
};

const buildScanOwnerHeaders = (scanOwnerToken: string) => ({
  "X-Scan-Owner": scanOwnerToken,
});

export interface StoredAuthSession {
  token: string;
  user: AuthSessionResponse["user"];
  session: Omit<AuthSessionResponse["session"], "token">;
}

const readSessionStorageAuthSession = (): StoredAuthSession | null => {
  if (typeof window === "undefined") {
    return inMemoryAuthSession;
  }

  try {
    const raw = window.sessionStorage.getItem(AUTH_SESSION_KEY);
    if (!raw) {
      return inMemoryAuthSession;
    }

    const parsed = JSON.parse(raw) as StoredAuthSession | null;
    return parsed && parsed.token ? parsed : null;
  } catch {
    return inMemoryAuthSession;
  }
};

const writeSessionStorageAuthSession = (value: StoredAuthSession | null) => {
  inMemoryAuthSession = value;
  if (typeof window === "undefined") {
    return;
  }

  try {
    if (value) {
      window.sessionStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(value));
    } else {
      window.sessionStorage.removeItem(AUTH_SESSION_KEY);
    }
  } catch {
    // Ignore sessionStorage failures and keep the in-memory fallback.
  }
};

export const getStoredAuthSession = async () => readSessionStorageAuthSession();

export const setStoredAuthSession = async (value: AuthSessionResponse) =>
  writeSessionStorageAuthSession({
    token: value.session.token || "",
    user: value.user,
    session: {
      createdAt: value.session.createdAt,
      expiresAt: value.session.expiresAt,
      ...(value.session.lastSeenAt ? { lastSeenAt: value.session.lastSeenAt } : {}),
    },
  });

export const clearStoredAuthSession = async () => writeSessionStorageAuthSession(null);

const buildRequestAuthHeaders = async ({
  scanOwnerToken = null,
  requireScanOwner = false,
}: {
  scanOwnerToken?: string | null;
  requireScanOwner?: boolean;
}) => {
  const authSession = await getStoredAuthSession();
  if (authSession?.token) {
    return {
      Authorization: `Bearer ${authSession.token}`,
    };
  }

  if (scanOwnerToken) {
    return buildScanOwnerHeaders(scanOwnerToken);
  }

  if (!requireScanOwner) {
    return {};
  }

  const fallbackToken = await getScanOwnerToken();
  return buildScanOwnerHeaders(fallbackToken);
};

export const registerUser = async ({
  email,
  password,
  displayName,
}: {
  email: string;
  password: string;
  displayName?: string;
}) => {
  const response = await fetch(buildApiUrl("/api/auth/register"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
      ...(displayName ? { displayName } : {}),
    }),
  });
  const payload = await readJsonResponse<AuthSessionResponse>(response);
  await setStoredAuthSession(payload);
  return payload;
};

export const loginUser = async ({
  email,
  password,
}: {
  email: string;
  password: string;
}) => {
  const response = await fetch(buildApiUrl("/api/auth/login"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
    }),
  });
  const payload = await readJsonResponse<AuthSessionResponse>(response);
  await setStoredAuthSession(payload);
  return payload;
};

export const getAuthSession = async () => {
  const authSession = await getStoredAuthSession();
  const response = await fetch(buildApiUrl("/api/auth/session"), {
    headers: authSession?.token
      ? {
          Authorization: `Bearer ${authSession.token}`,
        }
      : {},
  });
  if (response.status === 401) {
    await clearStoredAuthSession();
  }
  const payload = await readJsonResponse<AuthStatusResponse>(response);
  if (!payload.authenticated) {
    await clearStoredAuthSession();
    return payload;
  }
  if (authSession?.token && payload.user && payload.session) {
    writeSessionStorageAuthSession({
      token: authSession.token,
      user: payload.user,
      session: {
        createdAt: payload.session.createdAt,
        expiresAt: payload.session.expiresAt,
        ...(payload.session.lastSeenAt ? { lastSeenAt: payload.session.lastSeenAt } : {}),
      },
    });
  }
  return payload;
};

export const logoutUser = async () => {
  const authSession = await getStoredAuthSession();
  await fetch(buildApiUrl("/api/auth/logout"), {
    method: "POST",
    headers: authSession?.token
      ? {
          Authorization: `Bearer ${authSession.token}`,
        }
      : {},
  });
  await clearStoredAuthSession();
};

export const createScan = async (url: string, mode: "standard" | "quiet" = "standard") => {
  const scanOwnerToken = await getScanOwnerToken();
  const response = await fetch(buildApiUrl("/api/scans"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true })),
    },
    body: JSON.stringify({ url, mode }),
  });

  const payload = await readJsonResponse<CreateScanResponse>(response);
  return {
    scanOwnerToken,
    scan: payload.scan,
    fromCache: Boolean(payload.fromCache),
  };
};

export const getScan = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}`), {
    headers: await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true }),
  });
  return readJsonResponse<GetScanResponse>(response);
};

export const getSavedScan = async (scanId: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}`), {
    headers: await buildRequestAuthHeaders({ requireScanOwner: true }),
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

export interface AnalyzeTargetResult {
  result: AnalysisResult;
  fromCache: boolean;
  scanId: string;
}

export const analyzeTargetWithMetadata = async (
  url: string,
  setMode: "standard" | "quiet" = "standard",
): Promise<AnalyzeTargetResult> => {
  const { scan, scanOwnerToken, fromCache } = await createScan(url, setMode);
  const scanId = scan.id;
  const completedScan = await waitForScanCompletion(scanId, scanOwnerToken);
  if (!completedScan.result) {
    throw new ApiClientError("Completed scan did not include a result payload.", 500, completedScan);
  }
  if (!isAnalysisResult(completedScan.result)) {
    throw new ApiClientError("Unexpected scan result shape received from server.", 500, completedScan);
  }
  return {
    result: completedScan.result,
    fromCache,
    scanId,
  };
};

export const getSharedScan = async (scanId: string): Promise<AnalysisResult | null> => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/share`));
  if (!response.ok) return null;
  const payload = await response.json().catch(() => null) as { scan?: { result?: unknown } } | null;
  const result = payload?.scan?.result;
  if (!isAnalysisResult(result)) return null;
  return result;
};

export const analyzeTarget = async (url: string, setMode: "standard" | "quiet" = "standard"): Promise<AnalysisResult> =>
  (await analyzeTargetWithMetadata(url, setMode)).result;

export const getRecentScanSummaries = async (limit = 10): Promise<ApiScanSummary[]> => {
  const response = await fetch(buildApiUrl(`/api/scans?limit=${encodeURIComponent(String(limit))}`), {
    headers: await buildRequestAuthHeaders({ requireScanOwner: true }),
  });
  const payload = await readJsonResponse<ScansResponse>(response);
  return payload.scans;
};

export const getTargetHistory = async (url: string) => {
  const scanOwnerToken = await getScanOwnerToken();
  const response = await fetch(buildApiUrl(`/api/scans?url=${encodeURIComponent(url)}`), {
    headers: await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true }),
  });
  return readJsonResponse<TargetHistoryResponse>(response);
};

export const getScanSummary = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/summary`), {
    headers: await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true }),
  });
  return readJsonResponse<ScanSummaryResponse>(response);
};

export const getScanFindings = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/findings`), {
    headers: await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true }),
  });
  return readJsonResponse<ScanFindingsResponse>(response);
};

export const getScanEvidence = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/evidence`), {
    headers: await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true }),
  });
  return readJsonResponse<ScanEvidenceResponse>(response);
};

export const getScanHistory = async (scanId: string, scanOwnerToken: string) => {
  const response = await fetch(buildApiUrl(`/api/scans/${encodeURIComponent(scanId)}/history`), {
    headers: await buildRequestAuthHeaders({ scanOwnerToken, requireScanOwner: true }),
  });
  return readJsonResponse<ScanHistoryResponse>(response);
};

export const getMonitoringTargets = async () => {
  const response = await fetch(buildApiUrl("/api/monitoring-targets"), {
    headers: await buildRequestAuthHeaders({ requireScanOwner: true }),
  });
  return readJsonResponse<MonitoringTargetsResponse>(response);
};

export const saveMonitoringTarget = async (
  url: string,
  cadence: "daily" | "weekly",
  label?: string,
): Promise<ApiMonitoringTarget> => {
  const response = await fetch(buildApiUrl("/api/monitoring-targets"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(await buildRequestAuthHeaders({ requireScanOwner: true })),
    },
    body: JSON.stringify({
      url,
      cadence,
      ...(label ? { label } : {}),
    }),
  });
  const payload = await readJsonResponse<MonitoringTargetResponse>(response);
  return payload.target;
};

export const deleteMonitoringTarget = async (targetId: string) => {
  const response = await fetch(buildApiUrl(`/api/monitoring-targets/${encodeURIComponent(targetId)}`), {
    method: "DELETE",
    headers: await buildRequestAuthHeaders({ requireScanOwner: true }),
  });
  return readJsonResponse<DeleteMonitoringTargetResponse>(response);
};
