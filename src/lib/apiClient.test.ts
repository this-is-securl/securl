import { describe, expect, it, vi } from "vitest";

vi.stubGlobal("__API_BASE_URL__", "");

describe("api client URL helpers", () => {
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
});
