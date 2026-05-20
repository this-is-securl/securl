import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { analyzeInfrastructure } from "../dist/infrastructure.js";

test("analyzeInfrastructure infers providers from passive DNS, reverse DNS, headers, and stack evidence", async () => {
  const result = await analyzeInfrastructure(
    new URL("https://www.example.com/"),
    {
      server: "cloudflare",
      "x-amz-cf-id": "example-cloudfront-id",
    },
    [
      {
        name: "Vercel",
        category: "hosting",
        evidence: "Detected from x-vercel-id response header",
        version: null,
        confidence: "high",
        detection: "observed",
      },
    ],
    {
      resolveCname: async () => ["example.azurefd.net"],
      resolve4: async () => ["203.0.113.10"],
      resolve6: async () => [],
      reverse: async () => ["server.compute.amazonaws.com"],
    },
  );

  assert.deepEqual(result.addresses, ["203.0.113.10"]);
  assert.deepEqual(result.cnameTargets, ["example.azurefd.net"]);
  assert.deepEqual(result.reverseDns, ["server.compute.amazonaws.com"]);

  const providers = result.providers.map((signal) => signal.provider);
  assert.ok(providers.includes("Cloudflare"));
  assert.ok(providers.includes("AWS / CloudFront"));
  assert.ok(providers.includes("Microsoft Azure"));
  assert.ok(providers.includes("Vercel"));
  assert.equal(result.waf.detected, true);
  assert.equal(result.waf.provider, "Cloudflare");
  assert.match(result.summary, /Passive infrastructure evidence points to/);
});

test("analyzeInfrastructure bounds slow passive DNS lookups", async () => {
  const never = () => new Promise(() => {});
  const startedAt = performance.now();

  const result = await analyzeInfrastructure(
    new URL("https://www.example.com/"),
    {},
    [],
    {
      resolveCname: never,
      resolve4: never,
      resolve6: never,
      reverse: never,
    },
  );

  const elapsedMs = performance.now() - startedAt;

  assert.ok(elapsedMs < 3_500, `expected DNS enrichment to time out quickly, took ${elapsedMs}ms`);
  assert.deepEqual(result.addresses, []);
  assert.deepEqual(result.cnameTargets, []);
  assert.deepEqual(result.reverseDns, []);
  assert.equal(result.providers.length, 0);
});

test("analyzeInfrastructure recognises newer PaaS and hosting fingerprints", async () => {
  const result = await analyzeInfrastructure(
    new URL("https://app.example.com/"),
    {
      "x-railway-edge": "railway/eu-west4",
      "x-render-origin-server": "render",
      panel: "Hostinger",
    },
    [],
    {
      resolveCname: async () => ["app.up.railway.app", "example.onrender.com", "cdn.b-cdn.net"],
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => ["srv.hostinger.com"],
    },
  );

  const providers = result.providers.map((signal) => signal.provider);
  const bunnyProvider = ["Bunny", "net"].join(".");
  assert.ok(providers.includes("Railway"));
  assert.ok(providers.includes("Render"));
  assert.ok(providers.includes(bunnyProvider));
  assert.ok(providers.includes("Hostinger"));
});

test("analyzeInfrastructure detects HTTP/3 Alt-Svc advertisement", async () => {
  const result = await analyzeInfrastructure(
    new URL("https://www.example.com/"),
    {
      "alt-svc": 'h3=":443"; ma=86400',
    },
    [],
    {
      resolveCname: async () => [],
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => [],
    },
  );

  assert.equal(result.protocol.http3Advertised, true);
  assert.equal(result.protocol.altSvc, 'h3=":443"; ma=86400');
  assert.equal(result.strengths.includes("HTTP/3 support is advertised via Alt-Svc."), true);
});

test("analyzeInfrastructure detects passive WAF header signatures", async () => {
  const imperva = await analyzeInfrastructure(
    new URL("https://www.example.com/"),
    {
      "x-iinfo": "1-123-456 NNNN RT(1)",
    },
    [],
    {
      resolveCname: async () => [],
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => [],
    },
  );

  const absent = await analyzeInfrastructure(
    new URL("https://www.example.com/"),
    {},
    [],
    {
      resolveCname: async () => [],
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => [],
    },
  );

  assert.equal(imperva.waf.detected, true);
  assert.equal(imperva.waf.provider, "Imperva");
  assert.equal(absent.waf.detected, false);
});
