import { describe, expect, it } from "vitest";
import { parseAppRoute } from "./appRoute";

describe("parseAppRoute", () => {
  it("routes the scanner home", () => {
    expect(parseAppRoute("/")).toEqual({ kind: "home" });
  });

  it("routes privacy with or without a trailing slash", () => {
    expect(parseAppRoute("/privacy")).toEqual({ kind: "privacy" });
    expect(parseAppRoute("/privacy/")).toEqual({ kind: "privacy" });
  });

  it("extracts and decodes a shared report scan id", () => {
    expect(parseAppRoute("/report/scan%2D123")).toEqual({
      kind: "report",
      scanId: "scan-123",
    });
  });

  it("routes only valid shareable link result identifiers", () => {
    const publicId = "aBcDeFgHiJkLmNoPqRsTuVwXyZ_12345";
    expect(parseAppRoute(`/shared/link/${publicId}`)).toEqual({
      kind: "shared-link",
      publicId,
    });
    expect(parseAppRoute("/shared/link/too-short")).toEqual({ kind: "not-found" });
  });

  it("keeps unknown and malformed paths out of known routes", () => {
    expect(parseAppRoute("/unknown")).toEqual({ kind: "not-found" });
    expect(parseAppRoute("/report/")).toEqual({ kind: "not-found" });
    expect(parseAppRoute("/report/one/more")).toEqual({ kind: "not-found" });
    expect(parseAppRoute("/report/%E0%A4%A")).toEqual({ kind: "not-found" });
  });
});
