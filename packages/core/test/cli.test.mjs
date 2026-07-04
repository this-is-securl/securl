import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const cliPath = new URL("../dist/cli.js", import.meta.url).pathname;

test("CLI cert command renders a fast certificate summary", async () => {
  const { stdout } = await execFile(process.execPath, [cliPath, "cert", "http://example.com"]);

  assert.match(stdout, /Target: example\.com:443/);
  assert.match(stdout, /Available: no/);
  assert.match(stdout, /TLS certificate data is only available for HTTPS targets\./);
});

test("CLI cert command writes structured JSON output", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const outputPath = join(tempDir, "cert.json");

  await execFile(process.execPath, [cliPath, "cert", "http://example.com", "--format", "json", "--output", outputPath]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.host, "example.com");
  assert.equal(output.port, 443);
  assert.equal(output.available, false);
  assert.equal(output.issues[0], "TLS certificate data is only available for HTTPS targets.");
});

test("CLI cert command writes markdown output", async () => {
  const { stdout } = await execFile(process.execPath, [cliPath, "cert", "http://example.com", "--format", "markdown"]);

  assert.match(stdout, /# SecURL Certificate Check: example\.com/);
  assert.match(stdout, /## Issues/);
  assert.match(stdout, /TLS certificate data is only available for HTTPS targets\./);
});

test("CLI cert command rejects scan-only output and policy options", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--format", "sarif"]),
    (error) => {
      assert.match(error.stderr, /Certificate checks support summary, json, or markdown output\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--fail-on", "warning"]),
    (error) => {
      assert.match(error.stderr, /Certificate checks do not support scan comparison or CI policy options\./);
      return true;
    },
  );
});

test("CLI compare command renders a diff summary from saved reports", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 80,
    grade: "B",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = {
    ...baseline,
    scannedAt: "2026-04-16T09:00:00.000Z",
    score: 72,
    grade: "C",
    statusCode: 403,
    responseTimeMs: 90,
    issues: [{ severity: "warning", title: "Blocked edge response", detail: "Blocked", confidence: "high", source: "observed" }],
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  const { stdout } = await execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath]);

  assert.match(stdout, /Current: https:\/\/example.com/);
  assert.match(stdout, /Baseline: https:\/\/example.com/);
  assert.match(stdout, /Score change: 80\/100 \(B\) -> 72\/100 \(C\)/);
});

test("CLI compare command writes structured JSON output", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");
  const outputPath = join(tempDir, "compare.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 90,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = { ...baseline, score: 88, grade: "B", scannedAt: "2026-04-16T09:00:00.000Z" };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath, "--format", "json", "--output", outputPath]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.current.finalUrl, "https://example.com");
  assert.equal(output.baseline.grade, "A");
  assert.equal(output.diff.previousScore, 90);
});

test("CLI compare command writes ci-json output with policy summary", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");
  const outputPath = join(tempDir, "compare-ci.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 90,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = {
    ...baseline,
    score: 80,
    grade: "B",
    issues: [
      {
        severity: "warning",
        area: "headers",
        title: "Missing HSTS",
        detail: "Missing",
        confidence: "high",
        source: "observed",
        owasp: ["A05 Security Misconfiguration"],
        mitre: ["Defense Evasion"],
      },
    ],
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await execFile(process.execPath, [
    cliPath,
    "compare",
    currentPath,
    baselinePath,
    "--format",
    "ci-json",
    "--output",
    outputPath,
  ]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.mode, "compare");
  assert.equal(output.current.grade, "B");
  assert.equal(output.diff.scoreDelta, -10);
  assert.equal(output.policy.passed, true);
  assert.deepEqual(output.current.issueCounts, { info: 0, warning: 1, critical: 0 });
});

test("CLI compare command writes SARIF for newly introduced findings only", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");
  const outputPath = join(tempDir, "compare.sarif");

  const sharedIssue = {
    severity: "warning",
    area: "headers",
    title: "Missing HSTS",
    detail: "Strict-Transport-Security header is missing.",
    confidence: "high",
    source: "observed",
    owasp: ["A05 Security Misconfiguration"],
    mitre: ["Defense Evasion"],
  };
  const newIssue = {
    severity: "critical",
    area: "certificate",
    title: "Expired certificate",
    detail: "The observed TLS certificate is expired.",
    confidence: "high",
    source: "observed",
    owasp: ["A02 Cryptographic Failures"],
    mitre: ["Initial Access"],
  };

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 70,
    grade: "C",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [sharedIssue],
  };

  const current = {
    ...baseline,
    score: 52,
    grade: "D",
    scannedAt: "2026-04-16T09:00:00.000Z",
    issues: [sharedIssue, newIssue],
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath, "--format", "sarif", "--output", outputPath]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.version, "2.1.0");
  assert.equal(output.runs[0].results.length, 1);
  assert.equal(output.runs[0].results[0].ruleId, "expired-certificate");
  assert.match(output.runs[0].results[0].message.text, /New compared with baseline/);
});

test("CLI compare command fails policy when severity threshold is met", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 80,
    grade: "B",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = {
    ...baseline,
    issues: [
      {
        severity: "critical",
        area: "certificate",
        title: "Expired certificate",
        detail: "Expired",
        confidence: "high",
        source: "observed",
        owasp: ["A02 Cryptographic Failures"],
        mitre: ["Initial Access"],
      },
    ],
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await assert.rejects(
    execFile(process.execPath, [
      cliPath,
      "compare",
      currentPath,
      baselinePath,
      "--format",
      "ci-json",
      "--fail-on",
      "critical",
    ]),
    (error) => {
      assert.match(error.stderr, /Policy failed: findings at or above "critical" were detected\./);
      const output = JSON.parse(error.stdout);
      assert.equal(output.policy.passed, false);
      return true;
    },
  );
});

test("CLI compare command fails policy when score threshold is violated", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 90,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = {
    ...baseline,
    score: 68,
    grade: "D",
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await assert.rejects(
    execFile(process.execPath, [
      cliPath,
      "compare",
      currentPath,
      baselinePath,
      "--format",
      "ci-json",
      "--fail-if-score-below",
      "70",
    ]),
    (error) => {
      assert.match(error.stderr, /Policy failed: score fell below 70/);
      const output = JSON.parse(error.stdout);
      assert.equal(output.policy.passed, false);
      assert.equal(output.policy.failIfScoreBelow, 70);
      return true;
    },
  );
});

test("CLI compare command fails policy when regression mode detects regression", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 90,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = {
    ...baseline,
    score: 82,
    grade: "B",
    issues: [
      {
        severity: "warning",
        area: "headers",
        title: "Missing HSTS",
        detail: "Missing",
        confidence: "high",
        source: "observed",
        owasp: ["A05 Security Misconfiguration"],
        mitre: ["Defense Evasion"],
      },
    ],
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await assert.rejects(
    execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath, "--fail-on-regression"]),
    (error) => {
      assert.match(error.stderr, /Policy failed: baseline comparison detected a regression\./);
      return true;
    },
  );
});

test("CLI rejects malformed baseline JSON with a clean error", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");

  await writeFile(baselinePath, "{not valid json", "utf8");

  await assert.rejects(
    execFile(process.execPath, [cliPath, "compare", baselinePath, baselinePath]),
    (error) => {
      assert.match(error.stderr, /Baseline file is not valid JSON\./);
      assert.match(error.stderr, /Use --help for CLI usage\./);
      return true;
    },
  );
});

test("CLI rejects multi-target scans with a baseline file", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "scan", "example.com", "github.com", "--baseline", "previous-report.json"]),
    (error) => {
      assert.match(
        error.stderr,
        /Baseline comparison is only supported for a single target scan\./,
      );
      assert.match(error.stderr, /Use --help for CLI usage\./);
      return true;
    },
  );
});

test("CLI rejects regression policy in scan mode without baseline", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "scan", "example.com", "--fail-on-regression"]),
    (error) => {
      assert.match(error.stderr, /Regression policy mode requires --baseline for scan\./);
      assert.match(error.stderr, /Use --help for CLI usage\./);
      return true;
    },
  );
});

test("CLI rejects invalid score threshold values", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "scan", "example.com", "--fail-if-score-below", "101"]),
    (error) => {
      assert.match(error.stderr, /Invalid --fail-if-score-below value\. Use a number between 0 and 100\./);
      return true;
    },
  );
});
