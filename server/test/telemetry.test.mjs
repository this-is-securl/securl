import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { classifyScanFailure, classifyTrafficSource, createTelemetryTracker } from "../telemetry.mjs";

test("telemetry tracker records aggregate counts", () => {
  const telemetry = createTelemetryTracker();

  telemetry.recordPageLoad({ visitorKey: "visitor-one", now: new Date("2026-05-15T08:00:00Z"), source: "hacker_news" });
  telemetry.recordPageLoad({ visitorKey: "visitor-one", now: new Date("2026-05-15T09:00:00Z"), source: "reddit" });
  telemetry.recordPageLoad({ visitorKey: "visitor-two", now: new Date("2026-05-15T10:00:00Z"), source: "hacker_news" });
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
  telemetry.recordFailure("invalid_target_private", {
    target: "https://example.com/",
    message: "Localhost and private network targets are not allowed.\n",
    source: "scan_analysis",
  });
  telemetry.recordAuthRejected();
  telemetry.recordRequesterRateLimited();
  telemetry.recordTargetRateLimited();

  const snapshot = telemetry.snapshot();
  assert.equal(snapshot.pageLoads, 3);
  assert.equal(snapshot.visitors.unique, 2);
  assert.equal(snapshot.visitors.totalPageLoads, 3);
  assert.equal(snapshot.visitors.recentDays.at(-1).date, "2026-05-15");
  assert.equal(snapshot.visitors.recentDays.at(-1).pageLoads, 3);
  assert.equal(snapshot.visitors.recentDays.at(-1).uniqueVisitors, 2);
  assert.equal(snapshot.trafficSources.pageLoads.hacker_news, 2);
  assert.equal(snapshot.trafficSources.pageLoads.reddit, 1);
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
  assert.equal(snapshot.failures.recent.length, 1);
  assert.equal(snapshot.failures.recent[0].class, "invalid_target_private");
  assert.equal(snapshot.failures.recent[0].target, "https://example.com/");
  assert.equal(snapshot.failures.recent[0].message, "Localhost and private network targets are not allowed.");
  assert.equal(snapshot.failures.recent[0].source, "scan_analysis");
  assert.equal(snapshot.failures.authRejected, 1);
  assert.equal(snapshot.failures.requesterRateLimited, 1);
  assert.equal(snapshot.failures.targetRateLimited, 1);
});

test("telemetry tracker can persist counters to disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "securl-telemetry-"));
  const storagePath = join(dir, "telemetry.json");

  try {
    const first = createTelemetryTracker({ storagePath });
    first.recordPageLoad({ visitorKey: "visitor-one", now: new Date("2026-05-15T08:00:00Z"), source: "reddit" });
    first.recordScanRequested({ mode: "quiet" });
    first.recordFailure("requester_rate_limited", {
      target: "https://example.com/path",
      message: "Too many requests\tfrom this client.",
      source: "request_guard",
    });

    const second = createTelemetryTracker({ storagePath });
    const snapshot = second.snapshot();

    assert.equal(snapshot.persistence, "file");
    assert.equal(snapshot.pageLoads, 1);
    assert.equal(snapshot.visitors.unique, 1);
    assert.equal(snapshot.visitors.recentDays.at(-1).date, "2026-05-15");
    assert.equal(snapshot.trafficSources.pageLoads.reddit, 1);
    assert.equal(snapshot.scans.requested, 1);
    assert.equal(snapshot.scans.quietMode, 1);
    assert.equal(snapshot.failures.classes.requester_rate_limited, 1);
    assert.equal(snapshot.failures.recent.length, 1);
    assert.equal(snapshot.failures.recent[0].class, "requester_rate_limited");
    assert.equal(snapshot.failures.recent[0].message, "Too many requests from this client.");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("traffic source classification groups common public launch channels", () => {
  assert.equal(classifyTrafficSource({ referrer: "" }), "direct");
  assert.equal(classifyTrafficSource({ referrer: "https://news.ycombinator.com/item?id=123" }), "hacker_news");
  assert.equal(classifyTrafficSource({ referrer: "https://www.reddit.com/r/netsec/comments/example" }), "reddit");
  assert.equal(classifyTrafficSource({ referrer: "https://github.com/ktbatterham/external-posture-insight" }), "github");
  assert.equal(classifyTrafficSource({ referrer: "https://app.securl.online/" }), "internal");
  assert.equal(
    classifyTrafficSource({ currentUrl: "https://app.securl.online/?utm_source=show_hn" }),
    "utm:show_hn",
  );
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
