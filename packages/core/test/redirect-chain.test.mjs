import assert from "node:assert/strict";
import test from "node:test";
import { analyzeRedirectChain } from "../dist/redirectChain.js";

const hop = (url, status, location = null) => ({
  url,
  status,
  statusCode: status,
  location,
  isHttps: url.startsWith("https://"),
  secure: url.startsWith("https://"),
});

test("flags an HTTP hop in an otherwise HTTPS redirect flow", () => {
  const result = analyzeRedirectChain(
    new URL("https://example.com/"),
    new URL("https://example.com/app"),
    [
      hop("https://example.com/", 301, "http://example.com/app"),
      hop("http://example.com/app", 301, "https://example.com/app"),
      hop("https://example.com/app", 200),
    ],
  );

  assert.equal(result.hasMixedRedirect, true);
  assert.equal(result.issues.some((issue) => issue.includes("HTTP hop")), true);
});

test("flags redirect chains longer than three hops", () => {
  const result = analyzeRedirectChain(
    new URL("https://example.com/"),
    new URL("https://example.com/four"),
    [
      hop("https://example.com/", 301, "/one"),
      hop("https://example.com/one", 302, "/two"),
      hop("https://example.com/two", 307, "/three"),
      hop("https://example.com/three", 308, "/four"),
      hop("https://example.com/four", 200),
    ],
  );

  assert.equal(result.isLongChain, true);
  assert.equal(result.totalHops, 4);
  assert.equal(result.issues.some((issue) => issue.includes("longer than three hops")), true);
});

test("flags final URLs on a different apex domain", () => {
  const result = analyzeRedirectChain(
    new URL("https://example.com/"),
    new URL("https://example.net/"),
    [
      hop("https://example.com/", 302, "https://example.net/"),
      hop("https://example.net/", 200),
    ],
  );

  assert.equal(result.crossesDomain, true);
  assert.equal(result.issues.some((issue) => issue.includes("different registrable domain")), true);
});

test("keeps a clean single-hop HTTPS redirect quiet", () => {
  const result = analyzeRedirectChain(
    new URL("https://example.com/"),
    new URL("https://www.example.com/"),
    [
      hop("https://example.com/", 301, "https://www.example.com/"),
      hop("https://www.example.com/", 200),
    ],
  );

  assert.equal(result.hasMixedRedirect, false);
  assert.equal(result.isLongChain, false);
  assert.equal(result.crossesDomain, false);
  assert.deepEqual(result.issues, []);
  assert.equal(result.strengths.length, 1);
});
