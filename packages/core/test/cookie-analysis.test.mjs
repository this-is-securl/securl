import assert from "node:assert/strict";
import test from "node:test";
import { analyzeCookieHeaders } from "../dist/cookieAnalysis.js";

test("returns null when no cookies are set", () => {
  assert.equal(analyzeCookieHeaders(undefined), null);
  assert.equal(analyzeCookieHeaders([]), null);
});

test("flags cookies missing Secure", () => {
  const result = analyzeCookieHeaders(["sid=abc; HttpOnly; SameSite=Lax"]);

  assert.equal(result.cookiesWithoutSecure, 1);
  assert.equal(result.issues.some((issue) => issue.includes("missing Secure")), true);
});

test("flags cookies missing HttpOnly", () => {
  const result = analyzeCookieHeaders(["prefs=abc; Secure; SameSite=Lax"]);

  assert.equal(result.cookiesWithoutHttpOnly, 1);
  assert.equal(result.issues.some((issue) => issue.includes("missing HttpOnly")), true);
});

test("flags SameSite=None without Secure as the highest-risk combination", () => {
  const result = analyzeCookieHeaders(["cross=abc; HttpOnly; SameSite=None"]);

  assert.equal(result.cookiesWithSameSiteNone, 1);
  assert.equal(result.cookiesWithoutSecure, 1);
  assert.equal(result.issues.some((issue) => issue.includes("SameSite=None") && issue.includes("missing Secure")), true);
});

test("__Host- prefix cookies must use Secure, Path=/, and no Domain", () => {
  const good = analyzeCookieHeaders(["__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/"]);
  const bad = analyzeCookieHeaders(["__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com"]);

  assert.equal(good.cookies[0].hasHostPrefix, true);
  assert.equal(good.issues.some((issue) => issue.includes("__Host-")), false);
  assert.equal(bad.issues.some((issue) => issue.includes("__Host- cookie __Host-session")), true);
});

test("aggregates multiple cookie attribute gaps", () => {
  const result = analyzeCookieHeaders([
    "a=1; Secure; HttpOnly; SameSite=Lax",
    "b=2; HttpOnly",
    "c=3; Secure; SameSite=None",
  ]);

  assert.equal(result.cookies.length, 3);
  assert.equal(result.cookiesWithoutSecure, 1);
  assert.equal(result.cookiesWithoutHttpOnly, 1);
  assert.equal(result.cookiesWithSameSiteNone, 1);
  assert.equal(result.cookiesWithoutSameSite, 1);
});
