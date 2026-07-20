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

  it("buildApiUrl returns absolute URL when base URL is set", async () => {
    vi.stubGlobal("__API_BASE_URL__", "https://securl-app-production.up.railway.app");
    const { buildApiUrl } = await import("./apiClient");
    expect(buildApiUrl("/api/scans")).toBe("https://securl-app-production.up.railway.app/api/scans");
    expect(buildApiUrl("api/scans")).toBe("https://securl-app-production.up.railway.app/api/scans");
    vi.stubGlobal("__API_BASE_URL__", "");
  });

  it("readJsonResponse throws ApiClientError on non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "Not found" }), { status: 404 }),
    ));

    const { getScanFindings, ApiClientError } = await import("./apiClient");
    await expect(getScanFindings("scan-1", "token")).rejects.toThrow(ApiClientError);
    await expect(getScanFindings("scan-1", "token")).rejects.toMatchObject({
      status: 404,
    });
  });

  it("readJsonResponse throws ApiClientError when payload is null on an ok response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response("not-json", { status: 200 }),
    ));

    const { getScanFindings, ApiClientError } = await import("./apiClient");
    await expect(getScanFindings("scan-1", "token")).rejects.toThrow(ApiClientError);
    await expect(getScanFindings("scan-1", "token")).rejects.toMatchObject({
      status: 200,
    });
  });

  it("fetches backend capabilities without auth headers", async () => {
    const capabilities = {
      apiVersion: "2026-05-14",
      service: {
        name: "SecURL API",
        appVersion: "1.0.1",
        corePackage: "securl",
        coreVersion: "1.0.1",
        serveFrontend: false,
      },
      auth: {
        methods: ["scan-owner"],
        anonymousScanOwner: true,
      },
      scans: {
        modes: ["standard", "quiet", "deep-passive"],
        statuses: ["queued", "running", "completed", "failed"],
        maxDurationMs: {
          standard: 45000,
          quiet: 45000,
          deepPassive: 75000,
        },
        concurrency: 2,
        resources: ["POST /api/scans"],
      },
      monitoring: {
        enabled: true,
        cadences: ["daily", "weekly"],
        scheduler: {
          enabled: true,
          mode: "quiet",
          intervalMs: 900000,
          limit: 20,
        },
        resources: ["POST /api/monitoring-targets"],
      },
      exports: {
        formats: ["json", "markdown", "sarif", "ci-json"],
        shareLinks: true,
      },
      safety: {
        passiveFirst: true,
        publicTargetsOnly: true,
        blocksPrivateNetworkTargets: true,
      },
    };

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(capabilities), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const { getCapabilities } = await import("./apiClient");
    await expect(getCapabilities()).resolves.toEqual(capabilities);
    expect(fetchMock).toHaveBeenCalledWith("/api/capabilities");
  });

  it("uses a CORS-safelisted MIME type for cross-origin telemetry beacons", async () => {
    const sendBeacon = vi.fn().mockReturnValue(true);
    vi.stubGlobal("navigator", { sendBeacon });
    vi.stubGlobal("document", { referrer: "https://www.npmjs.com/package/securl" });
    vi.stubGlobal("window", {
      ...window,
      location: { href: "https://app.securl.online/?utm_source=npm" },
    });

    const { recordPageLoad, recordTelemetryEvent } = await import("./apiClient");
    recordPageLoad();
    recordTelemetryEvent("scan_started", { mode: "standard" });

    expect(sendBeacon).toHaveBeenCalledTimes(2);
    for (const [, body] of sendBeacon.mock.calls) {
      expect(body).toBeInstanceOf(Blob);
      expect((body as Blob).type).toBe("text/plain;charset=utf-8");
    }
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

  it("fetches scan comparison through the authenticated account scope", async () => {
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
      apiVersion: "2026-05-14",
      scan: {
        id: "scan-2",
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
        scanTiming: null,
      },
      scans: [],
      comparison: null,
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const { getScanComparison } = await import("./apiClient");
    await getScanComparison("scan-2");

    expect(fetchMock).toHaveBeenCalledWith("/api/scans/scan-2/comparison", {
      headers: {
        Authorization: "Bearer session-token-123",
      },
    });
  });

  it("loads the web intelligence bundle from lightweight scan resources", async () => {
    const browserStorage = await import("@/lib/browserStorage");
    vi.mocked(browserStorage.readBrowserStorage).mockResolvedValue("owner-token-123");

    const payloads = [
      { digest: { signalClarity: { headline: "Clear signal" } } },
      { insights: { nextBestActions: [{ id: "a1", label: "Fix DNS" }] } },
      { vendors: { counts: { totalProviders: 1 } } },
      { actionPlan: { totalActions: 2 } },
      { drift: { monitoringEvents: [{ id: "event-1", title: "Grade dropped" }] } },
      { observationDrift: { changed: [] } },
    ];
    const fetchMock = vi.fn()
      .mockImplementation(() => Promise.resolve(new Response(JSON.stringify(payloads.shift()), { status: 200 })));
    vi.stubGlobal("fetch", fetchMock);

    const { getScanWebIntelligence } = await import("./apiClient");
    const intelligence = await getScanWebIntelligence("scan-3", "owner-token-123");

    expect(intelligence.digest?.signalClarity?.headline).toBe("Clear signal");
    expect(intelligence.insights?.nextBestActions[0].label).toBe("Fix DNS");
    expect(intelligence.vendors?.counts.totalProviders).toBe(1);
    expect(intelligence.actionPlan?.totalActions).toBe(2);
    expect(intelligence.monitoringEvents).toEqual([{ id: "event-1", title: "Grade dropped" }]);
    expect(intelligence.observationDriftAvailable).toBe(true);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/scans/scan-3/digest",
      "/api/scans/scan-3/insights",
      "/api/scans/scan-3/vendors",
      "/api/scans/scan-3/action-plan",
      "/api/scans/scan-3/drift",
      "/api/scans/scan-3/observation-drift",
    ]);
    for (const [, options] of fetchMock.mock.calls) {
      expect(options.headers).toEqual({ "X-Scan-Owner": "owner-token-123" });
    }
  });

  it("loads public shared scan cards without auth headers", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      apiVersion: "2026-05-14",
      ready: true,
      scan: {
        id: "scan-card",
        status: "completed",
        url: "https://example.com/",
        mode: "standard",
        completedAt: "2026-07-07T00:00:00.000Z",
        grade: "B",
        score: 82,
      },
      shareCard: {
        title: "SecURL report for example.com: B (82/100)",
        summary: "Looks mostly healthy.",
        target: { host: "example.com", finalUrl: "https://example.com/" },
        posture: { grade: "B", score: 82, mainRisk: null, signalClarity: null },
        topIssues: [],
        scoreDrivers: [],
        nextBestAction: "Add HSTS",
        share: {
          text: "SecURL report for example.com: B (82/100)",
          shortText: "SecURL report for example.com: B (82/100)",
          reportUrl: "https://app.securl.online/report/scan-card",
          scannerUrl: "https://app.securl.online/?url=https%3A%2F%2Fexample.com%2F",
        },
        links: {
          report: "/report/scan-card",
          webReport: "https://app.securl.online/report/scan-card",
          scannerHandoff: "https://app.securl.online/?url=https%3A%2F%2Fexample.com%2F",
          apiShare: "/api/scans/scan-card/share",
        },
        generatedAt: "2026-07-07T00:00:00.000Z",
      },
      resources: {},
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const { getSharedScanCard } = await import("./apiClient");
    await expect(getSharedScanCard("scan-card")).resolves.toMatchObject({
      ready: true,
      shareCard: {
        title: "SecURL report for example.com: B (82/100)",
      },
    });
    expect(fetchMock).toHaveBeenCalledWith("/api/scans/scan-card/share-card");
  });
});
