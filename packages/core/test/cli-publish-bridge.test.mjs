import test from "node:test";
import assert from "node:assert/strict";
import { formatPublishedScan, publishHostedScan } from "../dist/cliPublishBridge.js";

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "Content-Type": "application/json" },
});

test("explicit CLI publication creates and waits for an authoritative hosted scan", async () => {
  const requests = [];
  const responses = [
    jsonResponse({ scan: { id: "11111111-1111-4111-8111-111111111111", status: "queued" } }, 202),
    jsonResponse({ scan: { id: "11111111-1111-4111-8111-111111111111", status: "running" } }),
    jsonResponse({ scan: { id: "11111111-1111-4111-8111-111111111111", status: "completed" } }),
  ];
  const published = await publishHostedScan({
    targetUrl: "https://example.com/",
    scanMode: "quiet",
    clientVersion: "1.27.0",
    ownerToken: "test-owner-token-that-is-long-and-random",
    sleep: async () => {},
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
  });

  assert.equal(requests.length, 3);
  assert.equal(requests[0].url, "https://securl-app-production.up.railway.app/api/scans");
  assert.equal(requests[0].options.method, "POST");
  assert.equal(requests[0].options.headers["X-Scan-Owner"], "test-owner-token-that-is-long-and-random");
  assert.equal(requests[0].options.headers["X-SecURL-Client"], "securl-cli");
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    url: "https://example.com/",
    mode: "quiet",
    currentUrl: "https://app.securl.online/?utm_source=securl_cli&utm_medium=cli&utm_campaign=cli_publish_bridge",
  });
  assert.equal(requests[0].options.body.includes("analysis"), false);
  assert.match(published.reportUrl, /app\.securl\.online\/report\/11111111/);
  assert.equal(
    published.mobileBridgeUrl,
    "https://securl.online/m/11111111-1111-4111-8111-111111111111",
  );
});

test("hosted publication fails clearly without exposing its owner token", async () => {
  await assert.rejects(
    publishHostedScan({
      targetUrl: "https://example.com/",
      scanMode: "standard",
      clientVersion: "1.27.0",
      ownerToken: "owner-token-must-not-appear",
      fetchImpl: async () => jsonResponse({ error: "rate_limited" }, 429),
    }),
    (error) => {
      assert.match(error.message, /HTTP 429/);
      assert.doesNotMatch(error.message, /owner-token/);
      return true;
    },
  );
});

test("published scan output keeps mobile continuation explicit", () => {
  const output = formatPublishedScan({
    scanId: "11111111-1111-4111-8111-111111111111",
    reportUrl: "https://app.securl.online/report/111",
    mobileBridgeUrl: "https://securl.online/m/111",
  }, "QR-CONTENT\n");

  assert.match(output, /Hosted report ready/);
  assert.match(output, /QR-CONTENT/);
  assert.match(output, /only pre-fills the target/);
  assert.match(output, /require your tap/);
});
