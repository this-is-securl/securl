import { describe, expect, it } from "vitest";
import { buildReportShareUrl, buildScannerHandoffUrl, getInitialScanHandoff } from "@/lib/deepLinks";

describe("deep link helpers", () => {
  it("reads mobile-friendly url handoff params before legacy target params", () => {
    expect(getInitialScanHandoff("?target=https://old.example&url=https://new.example&utm_source=securl_ios")).toEqual({
      target: "https://new.example",
      source: "securl_ios",
      medium: "web",
      campaign: "scan_handoff",
    });
  });

  it("keeps the existing target handoff param working", () => {
    expect(getInitialScanHandoff("?target=https%3A%2F%2Fexample.com&utm_medium=app&utm_campaign=mobile_share")).toEqual({
      target: "https://example.com",
      source: "direct",
      medium: "app",
      campaign: "mobile_share",
    });
  });

  it("returns null when no handoff target exists", () => {
    expect(getInitialScanHandoff("?utm_source=securl_ios")).toBeNull();
  });

  it("builds attributed public report share links", () => {
    expect(buildReportShareUrl("https://app.securl.online", "scan one")).toBe(
      "https://app.securl.online/report/scan%20one?utm_source=securl_web&utm_medium=share&utm_campaign=shared_report",
    );
  });

  it("builds attributed scanner handoff links for apps", () => {
    expect(buildScannerHandoffUrl("https://app.securl.online", "https://example.com", { source: "cert_watch_ios" })).toBe(
      "https://app.securl.online/?url=https%3A%2F%2Fexample.com&utm_source=cert_watch_ios&utm_medium=app&utm_campaign=mobile_handoff",
    );
  });
});
