import { beforeEach, describe, expect, it, vi } from "vitest";

vi.stubGlobal("__API_BASE_URL__", "");
vi.mock("@/lib/browserStorage", () => ({
  readBrowserStorage: vi.fn(),
  writeBrowserStorage: vi.fn(),
}));

describe("api client URL helpers", () => {
  beforeEach(() => {
    const sessionStore = new Map<string, string>();
    vi.stubGlobal("window", {
      sessionStorage: {
        getItem: (key: string) => sessionStore.get(key) ?? null,
        setItem: (key: string, value: string) => {
          sessionStore.set(key, value);
        },
        removeItem: (key: string) => {
          sessionStore.delete(key);
        },
        clear: () => {
          sessionStore.clear();
        },
      },
    });
    vi.resetModules();
    vi.clearAllMocks();
    window.sessionStorage.clear();
  });

  it("normalizes configured API base URLs", async () => {
    const { resolveApiBaseUrl } = await import("./apiClient");
    expect(resolveApiBaseUrl("https://api.securl.online/")).toBe("https://api.securl.online");
    expect(resolveApiBaseUrl("  https://api.securl.online///  ")).toBe("https://api.securl.online");
    expect(resolveApiBaseUrl("")).toBe("");
  });

  it("builds relative API paths when no explicit base URL is configured", async () => {
    const { buildApiUrl } = await import("./apiClient");
    expect(buildApiUrl("/api/scans")).toBe("/api/scans");
    expect(buildApiUrl("api/scans")).toBe("/api/scans");
  });

  it("falls back to crypto.getRandomValues when randomUUID is unavailable", async () => {
    const browserStorage = await import("@/lib/browserStorage");
    vi.mocked(browserStorage.readBrowserStorage).mockResolvedValue(null);
    vi.mocked(browserStorage.writeBrowserStorage).mockResolvedValue(undefined);

    const getRandomValues = vi.fn((bytes: Uint8Array) => {
      bytes.set(new Uint8Array(Array.from({ length: bytes.length }, (_, index) => index + 1)));
      return bytes;
    });

    vi.stubGlobal("crypto", {
      randomUUID: undefined,
      getRandomValues,
    });

    const { getScanOwnerToken } = await import("./apiClient");
    const token = await getScanOwnerToken();

    expect(token).toBe("0102030405060708090a0b0c0d0e0f10");
    expect(getRandomValues).toHaveBeenCalledOnce();
  });

  it("rejects completed scans with an unexpected result payload shape", async () => {
    const browserStorage = await import("@/lib/browserStorage");
    vi.mocked(browserStorage.readBrowserStorage).mockResolvedValue("existing-owner-token");

    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        scan: {
          id: "scan-1",
          status: "queued",
          url: "https://example.com/",
          mode: "standard",
          requestedAt: "2026-05-08T00:00:00.000Z",
          startedAt: null,
          completedAt: null,
          failureClass: null,
          error: null,
          score: null,
          grade: null,
          limited: false,
          limitedKind: null,
          title: null,
          mainRisk: null,
          findingsCount: 0,
        },
      }), { status: 202 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        scan: {
          id: "scan-1",
          ownerId: "scan-owner:test",
          status: "completed",
          url: "https://example.com/",
          mode: "standard",
          requesterScope: "ip:test",
          clientIp: "127.0.0.1",
          requestedAt: "2026-05-08T00:00:00.000Z",
          startedAt: "2026-05-08T00:00:01.000Z",
          completedAt: "2026-05-08T00:00:02.000Z",
          failureClass: null,
          error: null,
          summary: {
            id: "scan-1",
            status: "completed",
            url: "https://example.com/",
            mode: "standard",
            requestedAt: "2026-05-08T00:00:00.000Z",
            startedAt: "2026-05-08T00:00:01.000Z",
            completedAt: "2026-05-08T00:00:02.000Z",
            failureClass: null,
            error: null,
            score: 72,
            grade: "C",
            limited: false,
            limitedKind: null,
            title: "Example",
            mainRisk: "Risk",
            findingsCount: 1,
          },
          result: {},
        },
      }), { status: 200 })));

    const { analyzeTarget } = await import("./apiClient");

    await expect(analyzeTarget("https://example.com")).rejects.toThrow("Unexpected scan result shape received from server.");
  });

  it("prefers bearer auth over scan-owner headers when a stored session exists", async () => {
    window.sessionStorage.setItem("secure-header-insight:auth-session", JSON.stringify({
      token: "session-token-123",
      user: {
        id: "user-1",
        email: "keith@example.com",
        displayName: "Keith",
        createdAt: "2026-05-12T00:00:00.000Z",
      },
      session: {
        createdAt: "2026-05-12T00:00:00.000Z",
        expiresAt: "2026-06-12T00:00:00.000Z",
      },
    }));

    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ targets: [] }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const { getMonitoringTargets } = await import("./apiClient");
    await getMonitoringTargets();

    const [, options] = fetchMock.mock.calls[0];
    expect(options.headers).toEqual({
      Authorization: "Bearer session-token-123",
    });
    expect("X-Scan-Owner" in options.headers).toBe(false);
  });

  it("loads recent scan summaries through the authenticated account scope", async () => {
    window.sessionStorage.setItem("secure-header-insight:auth-session", JSON.stringify({
      token: "session-token-123",
      user: {
        id: "user-1",
        email: "keith@example.com",
        displayName: "Keith",
        createdAt: "2026-05-12T00:00:00.000Z",
      },
      session: {
        createdAt: "2026-05-12T00:00:00.000Z",
        expiresAt: "2026-06-12T00:00:00.000Z",
      },
    }));

    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      scans: [
        {
          id: "scan-1",
          status: "completed",
          url: "https://example.com/",
          mode: "standard",
          requestedAt: "2026-05-12T00:00:00.000Z",
          startedAt: "2026-05-12T00:00:01.000Z",
          completedAt: "2026-05-12T00:00:02.000Z",
          failureClass: null,
          error: null,
          score: 73,
          grade: "C",
          limited: false,
          limitedKind: null,
          title: "Example",
          mainRisk: "Risk",
          findingsCount: 3,
        },
      ],
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const { getRecentScanSummaries } = await import("./apiClient");
    const scans = await getRecentScanSummaries();

    expect(scans).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith("/api/scans?limit=10", {
      headers: {
        Authorization: "Bearer session-token-123",
      },
    });
  });

  it("reopens saved scans through the authenticated account scope", async () => {
    window.sessionStorage.setItem("secure-header-insight:auth-session", JSON.stringify({
      token: "session-token-123",
      user: {
        id: "user-1",
        email: "keith@example.com",
        displayName: "Keith",
        createdAt: "2026-05-12T00:00:00.000Z",
      },
      session: {
        createdAt: "2026-05-12T00:00:00.000Z",
        expiresAt: "2026-06-12T00:00:00.000Z",
      },
    }));

    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      scan: {
        id: "scan-1",
        ownerId: "user:user-1",
        status: "completed",
        url: "https://example.com/",
        mode: "standard",
        requesterScope: "user:user-1",
        clientIp: "127.0.0.1",
        requestedAt: "2026-05-12T00:00:00.000Z",
        startedAt: "2026-05-12T00:00:01.000Z",
        completedAt: "2026-05-12T00:00:02.000Z",
        failureClass: null,
        error: null,
        summary: null,
        result: null,
      },
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const { getSavedScan } = await import("./apiClient");
    await getSavedScan("scan-1");

    expect(fetchMock).toHaveBeenCalledWith("/api/scans/scan-1", {
      headers: {
        Authorization: "Bearer session-token-123",
      },
    });
  });
});
