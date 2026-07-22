import assert from "node:assert/strict";
import test from "node:test";
import { buildCliGrowthBridge } from "../dist/cliGrowthBridge.js";

const interactiveScan = {
  targetUrl: "https://example.com/path?q=one two",
  targetCount: 1,
  format: "summary",
  outputPath: null,
  baselinePath: null,
  hasPolicy: false,
  stdoutIsTty: true,
  stderrIsTty: true,
};

test("CLI growth bridge attributes and pre-fills an interactive scan", () => {
  const bridge = buildCliGrowthBridge(interactiveScan);
  assert.ok(bridge);
  const url = new URL(bridge.trim().split("\n").at(-1));
  assert.equal(url.origin, "https://app.securl.online");
  assert.equal(url.searchParams.get("url"), interactiveScan.targetUrl);
  assert.equal(url.searchParams.get("utm_source"), "securl_cli");
  assert.equal(url.searchParams.get("utm_medium"), "cli");
  assert.equal(url.searchParams.get("utm_campaign"), "package_scan_bridge");
});

test("CLI growth bridge stays out of machine-oriented and policy runs", () => {
  const suppressedContexts = [
    { targetCount: 2 },
    { format: "json" },
    { format: "ci-json" },
    { format: "sarif" },
    { outputPath: "report.txt" },
    { baselinePath: "baseline.json" },
    { hasPolicy: true },
    { stdoutIsTty: false },
    { stderrIsTty: false },
  ];
  for (const override of suppressedContexts) {
    assert.equal(buildCliGrowthBridge({ ...interactiveScan, ...override }), null);
  }
});
