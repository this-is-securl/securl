import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const cliPath = new URL("../dist/cli.js", import.meta.url).pathname;
const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

test("CLI schema command prints the posture manifest JSON Schema", async () => {
  const { stdout } = await execFile(process.execPath, [cliPath, "schema", "manifest"]);
  const output = JSON.parse(stdout);

  assert.equal(output.$id, "https://securl.online/schemas/posture-manifest-v1.json");
  assert.equal(output.title, "SecURL Posture Manifest v1");
  assert.equal(output.properties.version.const, "1.0");
  assert.deepEqual(output.required, [
    "version",
    "manifestId",
    "generatedAt",
    "engine",
    "target",
    "scan",
    "posture",
    "checks",
    "evidence",
    "policy",
  ]);
});

test("CLI schema command writes the posture manifest JSON Schema", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const outputPath = join(tempDir, "posture-manifest.schema.json");

  await execFile(process.execPath, [cliPath, "schema", "manifest", "--output", outputPath]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(output.properties.manifestId.pattern, "^pm_[a-f0-9]{24}$");
});

test("CLI schema command rejects scan-only options", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "schema", "manifest", "--quiet"]),
    (error) => {
      assert.match(error.stderr, /Schema command only supports --output\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "schema", "report"]),
    (error) => {
      assert.match(error.stderr, /Schema command supports exactly one target: securl schema manifest/);
      return true;
    },
  );
});

test("CLI scan command writes posture manifest output", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const outputPath = join(tempDir, "manifest.json");

  await execFile(process.execPath, [
    cliPath,
    "scan",
    "http://example.com",
    "--quiet",
    "--format",
    "manifest",
    "--output",
    outputPath,
  ]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.postureManifest.version, "1.0");
  assert.match(output.postureManifest.manifestId, /^pm_[a-f0-9]{24}$/);
  assert.equal(output.postureManifest.engine.name, "securl");
  assert.equal(output.postureManifest.engine.version, packageJson.version);
  assert.equal(output.postureManifest.target.host, "example.com");
  assert.equal(output.postureManifest.scan.mode, "quiet");
  assert.equal(typeof output.postureManifest.posture.score, "number");
  assert.ok(output.postureManifest.checks.observationLedger.observations.length > 0);
  assert.equal(output.postureManifest.policy.evaluation.version, "1.0");
});

test("CLI scan command writes batched posture manifest output", async () => {
  const { stdout } = await execFile(process.execPath, [
    cliPath,
    "scan",
    "http://example.com",
    "http://example.org",
    "--quiet",
    "--format",
    "manifest",
  ]);
  const output = JSON.parse(stdout);

  assert.equal(output.manifests.length, 2);
  assert.deepEqual(output.manifests.map((manifest) => manifest.target.host).sort(), ["example.com", "example.org"]);
  assert.ok(output.manifests.every((manifest) => manifest.scan.mode === "quiet"));
});

test("CLI scan command writes the external exposure inventory", async () => {
  const { stdout } = await execFile(process.execPath, [
    cliPath,
    "scan",
    "http://example.com",
    "--quiet",
    "--format",
    "exposure",
  ]);
  const output = JSON.parse(stdout);

  assert.equal(output.externalExposure.schemaVersion, "1.0");
  assert.ok(Array.isArray(output.externalExposure.inventory));
  assert.equal(typeof output.externalExposure.inventoryCounts.total, "number");
  assert.equal(typeof output.externalExposure.collectionBoundary, "string");
});

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

test("CLI cert command writes ci-json output with policy summary", async () => {
  const { stdout } = await execFile(process.execPath, [cliPath, "cert", "http://example.com", "--format", "ci-json"]);
  const output = JSON.parse(stdout);

  assert.equal(output.mode, "cert");
  assert.equal(output.certificate.host, "example.com");
  assert.equal(output.certificate.available, false);
  assert.equal(output.policy.passed, true);
  assert.deepEqual(output.policy.failures, []);
});

test("CLI cert command fails policy when invalid certificates are blocked", async () => {
  await assert.rejects(
    execFile(process.execPath, [
      cliPath,
      "cert",
      "http://example.com",
      "--format",
      "ci-json",
      "--fail-if-invalid",
    ]),
    (error) => {
      assert.match(error.stderr, /Policy failed: certificate is unavailable, invalid, or unauthorized\./);
      const output = JSON.parse(error.stdout);
      assert.equal(output.mode, "cert");
      assert.equal(output.policy.passed, false);
      assert.equal(output.policy.failIfInvalid, true);
      assert.equal(output.policy.failures.length, 1);
      return true;
    },
  );
});

test("CLI cert command applies named policy profiles", async () => {
  await assert.rejects(
    execFile(process.execPath, [
      cliPath,
      "cert",
      "http://example.com",
      "--format",
      "ci-json",
      "--policy",
      "production",
    ]),
    (error) => {
      assert.match(error.stderr, /Policy failed: certificate is unavailable, invalid, or unauthorized\./);
      const output = JSON.parse(error.stdout);
      assert.equal(output.policy.profile, "production");
      assert.equal(output.policy.failIfInvalid, true);
      assert.equal(output.policy.failIfExpiringWithinDays, 14);
      assert.equal(output.policy.failIfLegacyTls, true);
      assert.equal(output.policy.passed, false);
      return true;
    },
  );
});

test("CLI cert command lets explicit options tighten named policy profiles", async () => {
  await assert.rejects(
    execFile(process.execPath, [
      cliPath,
      "cert",
      "http://example.com",
      "--format",
      "ci-json",
      "--policy",
      "renewal-watch",
      "--fail-if-expiring-within",
      "45",
      "--fail-if-legacy-tls",
    ]),
    (error) => {
      const output = JSON.parse(error.stdout);
      assert.equal(output.policy.profile, "renewal-watch");
      assert.equal(output.policy.failIfExpiringWithinDays, 45);
      assert.equal(output.policy.failIfLegacyTls, true);
      return true;
    },
  );
});

test("CLI cert command fails policy when issuer expectation is not met", async () => {
  await assert.rejects(
    execFile(process.execPath, [
      cliPath,
      "cert",
      "http://example.com",
      "--expect-issuer",
      "Example CA",
    ]),
    (error) => {
      assert.match(error.stdout, /Policy: failed/);
      assert.match(error.stderr, /Policy failed: issuer did not match expected value "Example CA"\./);
      return true;
    },
  );
});

test("CLI cert command rejects scan-only output and scan policy options", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--format", "sarif"]),
    (error) => {
      assert.match(error.stderr, /Certificate checks support summary, json, markdown, or ci-json output\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--fail-on", "warning"]),
    (error) => {
      assert.match(error.stderr, /Certificate checks do not support scan comparison or scan score policy options\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--format", "manifest"]),
    (error) => {
      assert.match(error.stderr, /Certificate checks support summary, json, markdown, or ci-json output\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--format", "exposure"]),
    (error) => {
      assert.match(error.stderr, /Certificate checks support summary, json, markdown, or ci-json output\./);
      return true;
    },
  );
});

test("CLI rejects malformed certificate policy options", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--policy", "whatever"]),
    (error) => {
      assert.match(error.stderr, /Invalid --policy value\. Use production, strict, or renewal-watch\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "cert", "example.com", "--fail-if-expiring-within", "soon"]),
    (error) => {
      assert.match(error.stderr, /Invalid --fail-if-expiring-within value\. Use a non-negative whole number of days\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "scan", "example.com", "--fail-if-invalid"]),
    (error) => {
      assert.match(error.stderr, /Certificate policy options are only supported by the cert command\./);
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

test("CLI compare command rejects scan-only outputs", async () => {
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
  const current = { ...baseline, scannedAt: "2026-04-16T09:00:00.000Z" };
  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await assert.rejects(
    execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath, "--format", "manifest"]),
    (error) => {
      assert.match(error.stderr, /Manifest and exposure output are only supported by the scan command\./);
      return true;
    },
  );

  await assert.rejects(
    execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath, "--format", "exposure"]),
    (error) => {
      assert.match(error.stderr, /Manifest and exposure output are only supported by the scan command\./);
      return true;
    },
  );
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
