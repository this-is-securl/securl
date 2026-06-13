import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import test from "node:test";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

test("package surface exports expected public functions", async () => {
  const pkg = await import("../dist/index.js");
  const postureDigest = await import("../dist/postureDigest.js");
  const postureDrift = await import("../dist/postureDrift.js");
  const remediationPlan = await import("../dist/postureRemediation.js");

  assert.equal(typeof pkg.analyzeTarget, "function");
  assert.equal(typeof pkg.analyzeUrl, "function");
  assert.equal(typeof pkg.analyzeHtmlDocument, "function");
  assert.equal(typeof pkg.analyzeInfrastructure, "function");
  assert.equal(typeof pkg.snapshotFromAnalysis, "function");
  assert.equal(typeof pkg.buildHistoryDiffFromSnapshots, "function");
  assert.equal(typeof pkg.buildPostureRiskEventsFromSnapshots, "function");
  assert.equal(typeof pkg.buildPostureRiskEventsFromDiff, "function");
  assert.equal(typeof pkg.buildPostureDigest, "function");
  assert.equal(typeof postureDigest.buildPostureDigest, "function");
  assert.equal(typeof pkg.buildPostureDriftReportFromSnapshots, "function");
  assert.equal(typeof postureDrift.buildPostureDriftReportFromSnapshots, "function");
  assert.equal(typeof pkg.buildPostureRemediationPlan, "function");
  assert.equal(typeof remediationPlan.buildPostureRemediationPlan, "function");
  assert.equal(typeof pkg.formatErrorMessage, "function");
});

test("package surface includes a working CLI help entrypoint", async () => {
  await access(new URL("../dist/cli.js", import.meta.url));
  const { stdout } = await execFile(process.execPath, [new URL("../dist/cli.js", import.meta.url).pathname, "--help"]);

  assert.match(stdout, /External Posture Insight CLI/);
  assert.match(stdout, /epi scan <target\.\.\.>/);
  assert.match(stdout, /scan <target\.\.\.>/);
  assert.match(stdout, /--baseline/);
  assert.match(stdout, /json\|markdown\|summary\|sarif\|ci-json/);
  assert.match(stdout, /--fail-on info\|warning\|critical/);
  assert.match(stdout, /--fail-on-regression/);
  assert.match(stdout, /--fail-if-score-below <0-100>/);
  assert.match(stdout, /--quiet/);
  assert.match(stdout, /--deep-passive/);
  assert.match(stdout, /Scan modes:/);
  assert.match(stdout, /CI policy modes:/);
  assert.match(stdout, /compare <current-report\.json> <baseline-report\.json>/);
});

test("package surface exposes both long and short CLI binary names", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

  assert.equal(packageJson.bin.epi, "dist/cli.js");
  assert.equal(packageJson.bin["external-posture-insight"], "dist/cli.js");
});
