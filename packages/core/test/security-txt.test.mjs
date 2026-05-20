import assert from "node:assert/strict";
import test from "node:test";
import { fetchSecurityTxt, parseSecurityTxt } from "../dist/security-txt.js";

test("parseSecurityTxt extracts expected RFC 9116 fields", () => {
  const parsed = parseSecurityTxt(
    [
      "Contact: mailto:security@example.com",
      "Expires: 2027-12-31T23:59:59Z",
      "Canonical: https://example.com/.well-known/security.txt",
      "Policy: https://example.com/security",
    ].join("\n"),
    new URL("https://example.com/.well-known/security.txt"),
  );

  assert.equal(parsed.status, "present_valid");
  assert.deepEqual(parsed.contact, ["mailto:security@example.com"]);
  assert.equal(parsed.expires, "2027-12-31T23:59:59Z");
  assert.equal(parsed.policy, "https://example.com/security");
  assert.equal(parsed.isExpired, false);
  assert.equal(parsed.issues.length, 0);
  assert.equal(parsed.strengths.length, 1);
});

test("parseSecurityTxt marks missing contact as incomplete", () => {
  const parsed = parseSecurityTxt(
    "Expires: 2027-12-31T23:59:59Z",
    new URL("https://example.com/.well-known/security.txt"),
  );

  assert.equal(parsed.status, "present_incomplete");
  assert.equal(parsed.issues.includes("security.txt is present but missing the required Contact field."), true);
});

test("parseSecurityTxt marks expired files clearly", () => {
  const parsed = parseSecurityTxt(
    [
      "Contact: mailto:security@example.com",
      "Expires: 2020-01-01T00:00:00Z",
    ].join("\n"),
    new URL("https://example.com/.well-known/security.txt"),
  );

  assert.equal(parsed.status, "present_expired");
  assert.equal(parsed.isExpired, true);
  assert.equal(parsed.issues.includes("security.txt is expired and should be refreshed."), true);
});

test("fetchSecurityTxt returns missing when the well-known file is absent", async () => {
  const parsed = await fetchSecurityTxt(new URL("https://example.com/"), async () => ({
    statusCode: 404,
    headers: {},
    body: "",
  }));

  assert.equal(parsed.status, "missing");
  assert.equal(parsed.issues.includes("No security.txt found. Publishing one signals responsible disclosure readiness."), true);
});
