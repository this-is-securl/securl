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
  telemetry.recordScanRequested({
    mode: "standard",
    source: "direct",
    channel: "browser_owner",
    requesterKey: "scan-owner-one",
    clientKey: "visitor-one",
    target: "https://example.com/path?secret=hidden",
    now: new Date("2026-05-15T11:00:00Z"),
  });
  telemetry.recordScanRequested({
    mode: "quiet",
    source: "utm:landing",
    channel: "api_key",
    requesterKey: "api-key-one",
    clientKey: "visitor-two",
    target: "https://example.com/other",
    now: new Date("2026-05-15T12:00:00Z"),
  });
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
  telemetry.recordFunnelEvent({
    event: "scan_started",
    source: "hacker_news",
    target: "https://example.com/",
    scanId: "scan-one",
    mode: "standard",
  });
  telemetry.recordFunnelEvent({
    event: "handoff_started",
    source: "utm:landing",
    target: "https://example.com/",
  });
  telemetry.recordFunnelEvent({
    event: "export_clicked",
    source: "hacker_news",
    target: "https://example.com/",
    scanId: "scan-one",
    format: "pdf",
  });
  telemetry.recordFunnelEvent({
    event: "monitoring_mobile_summary_read",
    source: "backend_api",
  });
  telemetry.recordFunnelEvent({
    event: "notification_device_registered",
    source: "backend_api",
    mode: "com.ktbatterham.securl",
  });
  telemetry.recordFunnelEvent({
    event: "notification_device_health_read",
    source: "backend_api",
  });
  telemetry.recordFunnelEvent({
    event: "live_certificate_read",
    source: "backend_api",
    target: "https://example.com/cert",
  });

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
  assert.equal(snapshot.scans.engagement.uniqueRequesters, 2);
  assert.equal(snapshot.scans.engagement.uniqueClients, 2);
  assert.equal(snapshot.scans.engagement.uniqueTargets, 1);
  assert.equal(snapshot.scans.engagement.sources.direct, 1);
  assert.equal(snapshot.scans.engagement.sources["utm:landing"], 1);
  assert.equal(snapshot.scans.engagement.channels.browser_owner, 1);
  assert.equal(snapshot.scans.engagement.channels.api_key, 1);
  assert.equal(snapshot.scans.engagement.recentDays.at(-1).date, "2026-05-15");
  assert.equal(snapshot.scans.engagement.recentDays.at(-1).uniqueTargets, 1);
  assert.equal(snapshot.scans.engagement.repeatTargets[0].target, "https://example.com");
  assert.equal(snapshot.scans.engagement.repeatTargets[0].count, 2);
  assert.equal(snapshot.scans.engagement.recent.length, 2);
  assert.equal(snapshot.scans.engagement.recent[0].target, "https://example.com");
  assert.equal(snapshot.scans.engagement.recent[0].channel, "api_key");
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
  assert.equal(snapshot.failures.recent[0].target, "https://example.com");
  assert.equal(snapshot.failures.recent[0].message, "Localhost and private network targets are not allowed.");
  assert.equal(snapshot.failures.recent[0].source, "scan_analysis");
  assert.equal(snapshot.failures.authRejected, 1);
  assert.equal(snapshot.failures.requesterRateLimited, 1);
  assert.equal(snapshot.failures.targetRateLimited, 1);
  assert.equal(snapshot.funnel.events.scan_started, 1);
  assert.equal(snapshot.funnel.events.handoff_started, 1);
  assert.equal(snapshot.funnel.events.export_clicked, 1);
  assert.equal(snapshot.funnel.events.monitoring_mobile_summary_read, 1);
  assert.equal(snapshot.funnel.events.notification_device_registered, 1);
  assert.equal(snapshot.funnel.events.notification_device_health_read, 1);
  assert.equal(snapshot.funnel.events.live_certificate_read, 1);
  assert.equal(snapshot.funnel.bySource.hacker_news.scan_started, 1);
  assert.equal(snapshot.funnel.bySource.backend_api.monitoring_mobile_summary_read, 1);
  assert.equal(snapshot.funnel.bySource["utm:landing"].handoff_started, 1);
  assert.equal(snapshot.funnel.byMode.standard.scan_started, 1);
  assert.equal(snapshot.funnel.byMode["com.ktbatterham.securl"].notification_device_registered, 1);
  assert.equal(snapshot.funnel.today.scan_started, 1);
  assert.equal(snapshot.funnel.today.handoff_started, 1);
  assert.equal(snapshot.funnel.recent.length, 7);
  assert.equal(snapshot.funnel.recent[0].event, "live_certificate_read");
  assert.equal(snapshot.clients.consumption.backendApiEvents, 4);
  assert.equal(snapshot.clients.consumption.todayBackendApiEvents, 4);
  assert.equal(snapshot.clients.consumption.monitoringMobileSummaryReads, 1);
  assert.equal(snapshot.clients.consumption.notificationDeviceRegistrations, 1);
  assert.equal(snapshot.clients.consumption.notificationDeviceHealthReads, 1);
  assert.equal(snapshot.clients.consumption.liveCertificateReads, 1);
  assert.equal(snapshot.clients.consumption.today.monitoringMobileSummaryReads, 1);
  assert.equal(snapshot.clients.consumption.byMode["com.ktbatterham.securl"].notificationDeviceRegistrations, 1);
  assert.deepEqual(snapshot.clients.consumption.adoptionSignals, {
    mobileMonitoring: true,
    pushRegistration: true,
    notificationHealth: true,
    certWatch: true,
  });
});

test("telemetry tracker can persist counters to disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "securl-telemetry-"));
  const storagePath = join(dir, "telemetry.json");

  try {
    const first = createTelemetryTracker({ storagePath });
    first.recordPageLoad({ visitorKey: "visitor-one", now: new Date("2026-05-15T08:00:00Z"), source: "reddit" });
    first.recordScanRequested({
      mode: "quiet",
      source: "reddit",
      channel: "browser_owner",
      requesterKey: "scan-owner-one",
      clientKey: "visitor-one",
      target: "https://example.com/path?token=secret",
      now: new Date("2026-05-15T09:00:00Z"),
    });
    first.recordFunnelEvent({
      event: "report_viewed",
      source: "reddit",
      target: "https://example.com/path?token=secret",
      mode: "ios",
    });
    first.recordFailure("requester_rate_limited", {
      target: "https://example.com/path?token=secret",
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
    assert.equal(snapshot.scans.engagement.sources.reddit, 1);
    assert.equal(snapshot.scans.engagement.channels.browser_owner, 1);
    assert.equal(snapshot.scans.engagement.uniqueRequesters, 1);
    assert.equal(snapshot.scans.engagement.uniqueClients, 1);
    assert.equal(snapshot.scans.engagement.uniqueTargets, 1);
    assert.equal(snapshot.scans.engagement.recent[0].target, "https://example.com");
    assert.equal(snapshot.funnel.events.report_viewed, 1);
    assert.equal(snapshot.funnel.bySource.reddit.report_viewed, 1);
    assert.equal(snapshot.funnel.byMode.ios.report_viewed, 1);
    assert.equal(snapshot.funnel.recent[0].target, "https://example.com");
    assert.equal(snapshot.clients.consumption.backendApiEvents, 0);
    assert.deepEqual(snapshot.clients.consumption.adoptionSignals, {
      mobileMonitoring: false,
      pushRegistration: false,
      notificationHealth: false,
      certWatch: false,
    });
    assert.equal(snapshot.failures.classes.requester_rate_limited, 1);
    assert.equal(snapshot.failures.recent.length, 1);
    assert.equal(snapshot.failures.recent[0].class, "requester_rate_limited");
    assert.equal(snapshot.failures.recent[0].target, "https://example.com");
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
  assert.equal(classifyTrafficSource({ referrer: "https://securl.online/" }), "internal");
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
