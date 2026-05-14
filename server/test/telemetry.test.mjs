import assert from "node:assert/strict";
import test from "node:test";
import { classifyScanFailure, createTelemetryTracker } from "../telemetry.mjs";

test("telemetry tracker records aggregate counts", () => {
  const telemetry = createTelemetryTracker();

  telemetry.recordPageLoad();
  telemetry.recordScanRequested({ mode: "standard" });
  telemetry.recordScanRequested({ mode: "quiet" });
  telemetry.recordScanCompleted({
    assessmentLimitation: { limited: false },
    scanTiming: { totalMs: 1000, coreMs: 250, enrichmentMs: 750, timedOut: false },
  });
  telemetry.recordScanCompleted({
    assessmentLimitation: { limited: true, kind: "blocked_edge_response" },
    scanTiming: { totalMs: 45000, coreMs: 1000, enrichmentMs: 44000, timedOut: true },
  });
  telemetry.recordFailure("invalid_target_private");
  telemetry.recordAuthRejected();
  telemetry.recordRequesterRateLimited();
  telemetry.recordTargetRateLimited();

  const snapshot = telemetry.snapshot();
  assert.equal(snapshot.pageLoads, 1);
  assert.equal(snapshot.scans.requested, 2);
  assert.equal(snapshot.scans.completed, 2);
  assert.equal(snapshot.scans.fullReads, 1);
  assert.equal(snapshot.scans.limitedReads, 1);
  assert.equal(snapshot.scans.quietMode, 1);
  assert.equal(snapshot.scans.timedOut, 1);
  assert.equal(snapshot.scans.limitedReadKinds.blocked_edge_response, 1);
  assert.equal(snapshot.scans.timing.total.count, 2);
  assert.equal(snapshot.scans.timing.total.maxMs, 45000);
  assert.equal(snapshot.scans.timing.enrichment.p95Ms, 750);
  assert.equal(snapshot.failures.classes.invalid_target_private, 1);
  assert.equal(snapshot.failures.authRejected, 1);
  assert.equal(snapshot.failures.requesterRateLimited, 1);
  assert.equal(snapshot.failures.targetRateLimited, 1);
});

test("scan failure classification groups the common invalid-target cases", () => {
  assert.equal(classifyScanFailure(new Error("Enter a URL to scan.")), "invalid_target_empty");
  assert.equal(
    classifyScanFailure(new Error("URLs with embedded credentials are not supported.")),
    "invalid_target_credentials",
  );
  assert.equal(
    classifyScanFailure(new Error("Localhost and private network targets are not allowed.")),
    "invalid_target_private",
  );
  assert.equal(
    classifyScanFailure(new Error("Only http and https URLs are supported.")),
    "invalid_target_protocol",
  );
  assert.equal(
    classifyScanFailure(new Error("Target must resolve to a public IP address.")),
    "invalid_target_private",
  );
  assert.equal(classifyScanFailure(new Error("socket hang up")), "scan_runtime_failure");
});
