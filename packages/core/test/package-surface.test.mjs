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
  const evidenceQuality = await import("../dist/evidenceQuality.js");
  const exposureBrief = await import("../dist/exposureBrief.js");
  const vendorExposure = await import("../dist/vendorExposure.js");
  const actionPlan = await import("../dist/actionPlan.js");
  const postureInsights = await import("../dist/postureInsights.js");
  const certificate = await import("../dist/certificate.js");
  const observations = await import("../dist/observations.js");
  const observationDrift = await import("../dist/observationDrift.js");
  const observationPolicy = await import("../dist/observationPolicy.js");

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
  assert.equal(typeof pkg.buildPostureEvidenceSummary, "function");
  assert.equal(typeof remediationPlan.buildPostureEvidenceSummary, "function");
  assert.equal(typeof pkg.buildEvidenceQualitySummary, "function");
  assert.equal(typeof evidenceQuality.buildEvidenceQualitySummary, "function");
  assert.equal(typeof pkg.buildExposureBrief, "function");
  assert.equal(typeof exposureBrief.buildExposureBrief, "function");
  assert.equal(typeof pkg.buildVendorExposureBrief, "function");
  assert.equal(typeof vendorExposure.buildVendorExposureBrief, "function");
  assert.equal(typeof pkg.buildActionPlan, "function");
  assert.equal(typeof actionPlan.buildActionPlan, "function");
  assert.equal(typeof pkg.buildPostureInsights, "function");
  assert.equal(typeof postureInsights.buildPostureInsights, "function");
  assert.equal(typeof pkg.scanLiveCertificate, "function");
  assert.equal(typeof certificate.scanLiveCertificate, "function");
  assert.equal(typeof pkg.buildObservationLedger, "function");
  assert.equal(typeof observations.buildObservationLedger, "function");
  assert.equal(typeof pkg.diffObservationLedgers, "function");
  assert.equal(typeof observationDrift.diffObservationLedgers, "function");
  assert.equal(typeof pkg.evaluateObservationPolicy, "function");
  assert.equal(typeof observationPolicy.evaluateObservationPolicy, "function");
  assert.equal(typeof observationPolicy.validateObservationPolicy, "function");
  assert.equal(typeof pkg.formatErrorMessage, "function");
});

test("package surface includes a working CLI help entrypoint", async () => {
  await access(new URL("../dist/cli.js", import.meta.url));
  const { stdout } = await execFile(process.execPath, [new URL("../dist/cli.js", import.meta.url).pathname, "--help"]);

  assert.match(stdout, /SecURL CLI/);
  assert.match(stdout, /securl scan <target\.\.\.>/);
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

  assert.equal(packageJson.bin.securl, "dist/cli.js");
  assert.equal(packageJson.bin.epi, "dist/cli.js");
  assert.equal(packageJson.bin["external-posture-insight"], "dist/cli.js");
});
