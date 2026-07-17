import assert from "node:assert/strict";
import test from "node:test";
import {
  buildMonitoringAttentionPayload,
  buildMonitoringCertSummaryPayload,
  buildMonitoringHealthPayload,
  buildMonitoringMobileSummaryPayload,
  buildMonitoringTargetDetailPayload,
  buildMonitoringTargetTimelinePayload,
  buildScanDriftPayload,
  buildScanObservationDriftPayload,
  buildScanVendorsPayload,
} from "../scanDtos.mjs";

function buildAnalysisResult(overrides = {}) {
  return {
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-19T08:00:00.000Z",
    score: 92,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    summary: "External posture is broadly sound.",
    executiveSummary: {
      overview: "Broadly sound with one content-security gap.",
      mainRisk: "CSP needs tightening.",
      posture: "mixed",
      takeaways: ["Tighten CSP."],
    },
    scoreDrivers: [
      {
        areaKey: "content",
        areaLabel: "Content",
        impact: 18,
        label: "Content-Security-Policy gap",
        detail: "CSP is weak.",
        source: "headers",
      },
    ],
    certificate: {
      available: true,
      valid: true,
      authorized: true,
      issuer: "Example CA",
      daysRemaining: 90,
      issues: [],
    },
    thirdPartyTrust: {
      providers: [],
      highRiskProviders: 0,
      issues: [],
    },
    aiSurface: {
      vendors: [],
    },
    identityProvider: {
      provider: null,
    },
    wafFingerprint: {
      providers: [{ name: "Cloudflare" }],
    },
    ctDiscovery: {
      prioritizedHosts: [],
    },
    headers: [
      {
        label: "Strict-Transport-Security",
        status: "pass",
        value: "max-age=31536000",
      },
    ],
    issues: [],
    cookies: [],
    cookieAnalysis: {
      issues: [],
    },
    redirects: [],
    redirectChain: {
      totalHops: 0,
      hasMixedRedirect: false,
      crossesDomain: false,
      issues: [],
    },
    exposure: {
      probes: [],
      issues: [],
    },
    apiSurface: {
      probes: [],
      issues: [],
    },
    corsSecurity: {
      issues: [],
      allowCredentials: null,
      allowedOrigin: null,
    },
    domainSecurity: {
      emailDeliverabilityScore: null,
      issues: [],
      strengths: [],
    },
    securityTxt: {
      status: "missing",
      contact: [],
    },
    infrastructure: {
      providers: [{ provider: "Cloudflare" }],
    },
    passiveIntelligence: {
      postureRead: "Passive public signals look stable.",
    },
    compromiseSignals: {
      posture: "stable",
      indicators: [],
    },
    assessmentLimitation: {
      limited: false,
      kind: null,
    },
    ...overrides,
  };
}

function buildCompletedRecord(id, resultOverrides = {}) {
  const result = buildAnalysisResult(resultOverrides);
  return {
    id,
    status: "completed",
    result,
    summary: {
      id,
      status: "completed",
      grade: result.grade,
      score: result.score,
      completedAt: result.scannedAt,
      findingsCount: result.issues.length,
      mainRisk: result.issues[0]?.title ?? null,
    },
  };
}

test("vendor payload upgrades persisted pre-inventory scan results", () => {
  const scan = buildCompletedRecord("legacy-vendors", {
    vendorExposure: {
      generatedAt: "2026-06-19T08:00:00.000Z",
      risk: "low",
      summary: "Legacy vendor brief.",
      counts: { total: 0, high: 0, medium: 0, low: 0 },
      providers: [],
      highPriorityProviders: [],
      issues: [],
      strengths: [],
      nextActions: [],
      collectionBoundary: "Legacy boundary.",
      limitation: null,
    },
  });

  const payload = buildScanVendorsPayload(scan);

  assert.equal(payload.vendors.schemaVersion, "1.0");
  assert.ok(Array.isArray(payload.vendors.inventory));
  assert.equal(typeof payload.vendors.inventoryCounts.total, "number");
});

test("vendor payload preserves current inventory scan results", () => {
  const currentInventory = {
    schemaVersion: "1.0",
    inventory: [{ id: "exposure:service:example:example.com" }],
    inventoryCounts: { total: 1 },
  };
  const scan = buildCompletedRecord("current-vendors", {
    vendorExposure: currentInventory,
  });

  const payload = buildScanVendorsPayload(scan);

  assert.equal(payload.vendors, currentInventory);
});

test("scan observation drift compares the selected scan with its predecessor", () => {
  const previous = buildCompletedRecord("previous", {
    observationLedger: {
      version: "1.0",
      target: "https://example.com/",
      generatedAt: "2026-06-19T08:00:00.000Z",
      observations: [{
        id: "obs_csp",
        category: "header",
        kind: "http.header.content-security-policy",
        subject: "https://example.com/",
        status: "observed",
        value: "default-src 'self'",
        confidence: "high",
        source: "header",
        observedAt: "2026-06-19T08:00:00.000Z",
        freshUntil: "2026-06-19T09:00:00.000Z",
        evidence: [],
      }],
      summary: { total: 1, byStatus: { observed: 1 }, byCategory: { header: 1 }, highConfidence: 1 },
    },
  });
  const current = buildCompletedRecord("current", {
    scannedAt: "2026-06-20T08:00:00.000Z",
    observationLedger: {
      ...previous.result.observationLedger,
      generatedAt: "2026-06-20T08:00:00.000Z",
      observations: [{
        ...previous.result.observationLedger.observations[0],
        status: "missing",
        value: null,
        observedAt: "2026-06-20T08:00:00.000Z",
      }],
    },
  });

  const payload = buildScanObservationDriftPayload(current, [current, previous]);
  assert.equal(payload.observationDrift.currentScanId, "current");
  assert.equal(payload.observationDrift.previousScanId, "previous");
  assert.equal(payload.observationDrift.summary.direction, "regressed");
  assert.equal(payload.observationDrift.summary.bySeverity.critical, 2);
});

test("mobile monitoring summary exposes certificate attention state", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-cert-1",
        url: "https://example.com/",
        label: "Example cert",
        cadence: "daily",
        kind: "cert",
        mode: null,
        appId: "com.ktbatterham.certwatch",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastCheckedAt: "2026-06-19T08:01:00.000Z",
        certState: {
          reachable: true,
          checkedAt: "2026-06-19T08:01:00.000Z",
          host: "example.com",
          issuer: "Example CA",
          validTo: "2026-06-25T00:00:00.000Z",
          daysRemaining: 6,
          serialNumber: "ABC123",
          lastEventType: null,
          lastWarnedBand: null,
          attention: {
            type: "cert_expiring",
            severity: "critical",
            warningBand: 7,
            title: "Certificate expiring: example.com",
            body: "6 days remaining.",
          },
          issues: [],
          history: [],
        },
      },
      records: [],
    },
  ]);

  assert.equal(payload.summary.certTargets, 1);
  assert.equal(payload.targets[0].cert.attention.type, "cert_expiring");
  assert.equal(payload.targets[0].cert.attention.severity, "critical");
  assert.equal(payload.targets[0].cert.attention.warningBand, 7);
  assert.equal(payload.targets[0].status.state, "needs_attention");
  assert.equal(payload.targets[0].status.reason, "cert_expiring");
  assert.equal(payload.targets[0].change.type, "cert_expiring");
  assert.equal(payload.targets[0].change.severity, "critical");
  assert.equal(payload.targets[0].events[0].eventType, "certificate_expiring");
  assert.equal(payload.targets[0].events[0].severity, "critical");
  assert.match(payload.targets[0].events[0].nextAction, /Renew the certificate/);
  assert.equal(payload.targets[0].cert.monitoringEvents.length, 0);
  assert.equal(payload.targets[0].nextCheck.cadence, "daily");
  assert.equal(payload.targets[0].nextCheck.scheduledAt, payload.targets[0].nextDueAt);
  assert.equal(payload.targets[0].actions[0].id, "review_certificate");
});

test("mobile monitoring summary filters certificate events by policy profile", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-cert-policy",
        url: "https://example.com/",
        label: "Example cert",
        cadence: "daily",
        kind: "cert",
        mode: null,
        appId: "com.ktbatterham.certwatch",
        certPolicy: "production",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastCheckedAt: "2026-06-19T08:01:00.000Z",
        certState: {
          reachable: true,
          checkedAt: "2026-06-19T08:01:00.000Z",
          host: "example.com",
          issuer: "Example CA",
          validTo: "2026-07-10T00:00:00.000Z",
          daysRemaining: 21,
          serialNumber: "ABC123",
          policyProfile: "production",
          monitoringEvents: [
            {
              source: "certificate",
              eventType: "certificate_expiring",
              severity: "warning",
              title: "Certificate expires soon",
            },
          ],
          issues: [],
          history: [],
        },
      },
      records: [],
    },
  ]);

  assert.equal(payload.targets[0].policy, "production");
  assert.equal(payload.targets[0].cert.policyProfile, "production");
  assert.equal(payload.targets[0].events.length, 0);
  assert.equal(payload.targets[0].cert.monitoringEvents.length, 0);
});

test("cert monitoring summary focuses the Cert Watch watch list and push health", () => {
  const payload = buildMonitoringCertSummaryPayload([
    {
      target: {
        id: "target-cert-expiring",
        url: "https://expiring.example/",
        label: "Expiring cert",
        cadence: "daily",
        kind: "cert",
        appId: "com.ktbatterham.certwatch",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastCheckedAt: "2026-06-19T08:01:00.000Z",
        nextDueAt: "2026-06-20T08:01:00.000Z",
        certState: {
          reachable: true,
          checkedAt: "2026-06-19T08:01:00.000Z",
          host: "expiring.example",
          issuer: "Example CA",
          validTo: "2026-06-25T00:00:00.000Z",
          daysRemaining: 6,
          attention: {
            type: "cert_expiring",
            severity: "critical",
            warningBand: 7,
            title: "Certificate expiring: expiring.example",
            body: "6 days remaining.",
          },
          history: [
            {
              eventType: "cert_expiring",
              severity: "critical",
              checkedAt: "2026-06-19T08:01:00.000Z",
              title: "Certificate expiring: expiring.example",
            },
          ],
        },
      },
      records: [],
    },
    {
      target: {
        id: "target-cert-healthy",
        url: "https://healthy.example/",
        label: "Healthy cert",
        cadence: "weekly",
        kind: "cert",
        appId: "com.ktbatterham.certwatch",
        addedAt: "2026-06-18T08:00:00.000Z",
        lastCheckedAt: "2026-06-18T08:01:00.000Z",
        nextDueAt: "2026-06-25T08:01:00.000Z",
        certState: {
          reachable: true,
          checkedAt: "2026-06-18T08:01:00.000Z",
          host: "healthy.example",
          issuer: "Example CA",
          validTo: "2026-09-25T00:00:00.000Z",
          daysRemaining: 98,
          attention: null,
          history: [],
        },
      },
      records: [],
    },
    {
      target: {
        id: "target-posture",
        url: "https://posture.example/",
        cadence: "daily",
        kind: "posture",
      },
      records: [],
    },
  ], [
    {
      id: "device-ready",
      appId: "com.ktbatterham.certwatch",
      lastSeenAt: "2026-06-19T08:02:00.000Z",
      lastPushSentAt: "2026-06-19T08:03:00.000Z",
      health: { status: "ready", needsRegistration: false },
    },
    {
      id: "device-stale",
      appId: "com.ktbatterham.certwatch",
      lastSeenAt: "2026-05-01T08:02:00.000Z",
      health: { status: "stale", needsRegistration: true },
    },
  ]);

  assert.equal(payload.summary.totalCerts, 2);
  assert.equal(payload.summary.expiringCerts, 1);
  assert.equal(payload.summary.healthyCerts, 1);
  assert.equal(payload.summary.needsAttention, 1);
  assert.equal(payload.summary.nextCheckTargetId, "target-cert-expiring");
  assert.equal(payload.push.configured, true);
  assert.equal(payload.push.registeredDevices, 2);
  assert.equal(payload.push.readyDevices, 1);
  assert.equal(payload.push.devicesNeedingRegistration, 1);
  assert.equal(payload.targets[0].id, "target-cert-expiring");
  assert.equal(payload.targets[0].health.state, "expiring");
  assert.equal(payload.targets[0].health.severity, "critical");
  assert.equal(payload.targets[1].health.state, "healthy");
  assert.equal(payload.recentChanges.length, 1);
  assert.equal(payload.recentChanges[0].type, "cert_expiring");
});

test("monitoring health payload summarizes owner targets, scheduler, and push state", () => {
  const payload = buildMonitoringHealthPayload({
    now: new Date("2026-06-20T08:30:00.000Z"),
    scheduler: {
      enabled: true,
      running: false,
      mode: "quiet",
      intervalMs: 900000,
      limit: 20,
      lastSweep: { checked: 2, due: 1, queued: 1, failed: 0 },
    },
    notifications: {
      enabled: true,
      provider: "apns",
      credentialsConfigured: true,
      topicConfigured: false,
      outbox: { enabled: true, running: false },
    },
    targetEntries: [
      {
        target: {
          id: "target-cert-expiring",
          url: "https://expiring.example/",
          label: "Expiring cert",
          cadence: "daily",
          kind: "cert",
          appId: "com.ktbatterham.certwatch",
          addedAt: "2026-06-18T08:00:00.000Z",
          lastCheckedAt: "2026-06-19T08:00:00.000Z",
          certState: {
            reachable: true,
            checkedAt: "2026-06-19T08:00:00.000Z",
            host: "expiring.example",
            validTo: "2026-06-25T00:00:00.000Z",
            daysRemaining: 5,
            attention: { type: "cert_expiring", severity: "critical" },
          },
        },
        records: [],
      },
      {
        target: {
          id: "target-posture-failed",
          url: "https://posture.example/",
          label: "Posture",
          cadence: "daily",
          kind: "posture",
          mode: "quiet",
          appId: "com.ktbatterham.headerwatch",
          addedAt: "2026-06-18T08:00:00.000Z",
          lastScannedAt: "2026-06-19T08:00:00.000Z",
        },
        records: [{
          id: "scan-failed",
          status: "failed",
          summary: {
            id: "scan-failed",
            status: "failed",
            failedAt: "2026-06-19T08:01:00.000Z",
            error: "scan failed",
          },
        }],
      },
    ],
    pushDevices: [
      {
        id: "device-ready",
        appId: "com.ktbatterham.certwatch",
        platform: "ios",
        environment: "sandbox",
        lastSeenAt: "2026-06-20T08:00:00.000Z",
        health: { status: "ready", needsRegistration: false },
      },
      {
        id: "device-stale",
        appId: "com.ktbatterham.headerwatch",
        platform: "ios",
        environment: "sandbox",
        lastSeenAt: "2026-05-01T08:00:00.000Z",
        health: { status: "stale", needsRegistration: true },
      },
    ],
  });

  assert.equal(payload.summary.totalTargets, 2);
  assert.equal(payload.summary.certTargets, 1);
  assert.equal(payload.summary.postureTargets, 1);
  assert.equal(payload.summary.dueTargets, 2);
  assert.equal(payload.summary.overdueTargets, 2);
  assert.equal(payload.summary.targetsNeedingAttention, 2);
  assert.equal(payload.summary.certAttentionTargets, 1);
  assert.equal(payload.summary.postureFailureTargets, 1);
  assert.equal(payload.summary.pushDevicesNeedingRegistration, 1);
  assert.equal(payload.scheduler.lastSweepHealthy, true);
  assert.equal(payload.notifications.devices.registeredDevices, 2);
  assert.equal(payload.apps["com.ktbatterham.certwatch"].certTargets, 1);
  assert.equal(payload.apps["com.ktbatterham.certwatch"].readyDevices, 1);
  assert.equal(payload.apps["com.ktbatterham.headerwatch"].postureTargets, 1);
  assert.equal(payload.apps["com.ktbatterham.headerwatch"].devicesNeedingRegistration, 1);
  assert.equal(payload.attention.certTargets[0].id, "target-cert-expiring");
  assert.equal(payload.attention.postureFailures[0].id, "target-posture-failed");
  assert.equal(payload.attention.pushDevices[0].id, "device-stale");
});

test("monitoring attention payload returns a compact owner action inbox", () => {
  const payload = buildMonitoringAttentionPayload({
    now: new Date("2026-06-20T08:30:00.000Z"),
    notifications: {
      enabled: true,
      credentialsConfigured: true,
      providers: {
        apns: { enabled: true },
        fcm: { enabled: true },
      },
    },
    targetEntries: [
      {
        target: {
          id: "target-cert-expiring",
          url: "https://expiring.example/",
          label: "Expiring cert",
          cadence: "daily",
          kind: "cert",
          appId: "com.ktbatterham.certwatch",
          addedAt: "2026-06-18T08:00:00.000Z",
          lastCheckedAt: "2026-06-19T08:00:00.000Z",
          certState: {
            reachable: true,
            checkedAt: "2026-06-19T08:00:00.000Z",
            host: "expiring.example",
            validTo: "2026-06-25T00:00:00.000Z",
            daysRemaining: 5,
            attention: {
              type: "cert_expiring",
              severity: "critical",
              title: "Certificate expiring: expiring.example",
              body: "5 days remaining.",
            },
          },
        },
        records: [],
      },
      {
        target: {
          id: "target-posture-failed",
          url: "https://posture.example/",
          label: "Posture",
          cadence: "daily",
          kind: "posture",
          mode: "quiet",
          appId: "com.ktbatterham.headerwatch",
          addedAt: "2026-06-18T08:00:00.000Z",
          lastScannedAt: "2026-06-19T08:00:00.000Z",
        },
        records: [{
          id: "scan-failed",
          status: "failed",
          summary: {
            id: "scan-failed",
            status: "failed",
            failedAt: "2026-06-19T08:01:00.000Z",
            error: "scan failed",
          },
        }],
      },
      {
        target: {
          id: "target-healthy",
          url: "https://healthy.example/",
          label: "Healthy cert",
          cadence: "weekly",
          kind: "cert",
          appId: "com.ktbatterham.certwatch",
          addedAt: "2026-06-18T08:00:00.000Z",
          lastCheckedAt: "2026-06-19T08:00:00.000Z",
          certState: {
            reachable: true,
            checkedAt: "2026-06-19T08:00:00.000Z",
            host: "healthy.example",
            validTo: "2026-09-25T00:00:00.000Z",
            daysRemaining: 98,
            attention: null,
          },
        },
        records: [],
      },
    ],
    pushDevices: [
      {
        id: "device-ready",
        appId: "com.ktbatterham.certwatch",
        lastSeenAt: "2026-06-20T08:00:00.000Z",
        lastPushSentAt: "2026-06-20T08:01:00.000Z",
        health: { status: "ready", needsRegistration: false },
      },
      {
        id: "device-stale",
        appId: "com.ktbatterham.headerwatch",
        lastSeenAt: "2026-05-01T08:00:00.000Z",
        health: { status: "stale", needsRegistration: true },
      },
    ],
  });

  assert.equal(payload.generatedAt, "2026-06-20T08:30:00.000Z");
  assert.equal(payload.summary.state, "needs_attention");
  assert.equal(payload.summary.highestSeverity, "critical");
  assert.equal(payload.summary.targetsTotal, 3);
  assert.equal(payload.summary.targetsNeedingAttention, 2);
  assert.equal(payload.summary.targetsUnhealthy, 2);
  assert.equal(payload.summary.push.state, "failing");
  assert.deepEqual(payload.summary.push.providers, ["apns", "fcm"]);
  assert.equal(payload.summary.push.devicesNeedingRegistration, 1);
  assert.equal(payload.attention.length, 2);
  assert.equal(payload.attention[0].targetId, "target-cert-expiring");
  assert.equal(payload.attention[0].severity, "critical");
  assert.equal(payload.attention[0].reason, "cert_expiring");
  assert.equal(payload.attention[0].host, "expiring.example");
  assert.equal(payload.attention[0].timeline.href, "/api/monitoring-targets/target-cert-expiring/timeline");
  assert.equal(payload.attention[0].links.target, "/api/monitoring-targets/target-cert-expiring");
  assert.equal(payload.attention[1].targetId, "target-posture-failed");
  assert.equal(payload.attention[1].severity, "warning");
  assert.equal(payload.attention[1].reason, "latest_scan_failed");
  assert.equal(payload.attention[1].links.latestScan, "/api/scans/scan-failed/mobile-summary");
});

test("mobile monitoring summary promotes latest certificate history metadata", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-cert-2",
        url: "https://example.com/",
        label: "Example cert",
        cadence: "daily",
        kind: "cert",
        mode: null,
        appId: "com.ktbatterham.certwatch",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastCheckedAt: "2026-06-19T08:01:00.000Z",
        certState: {
          reachable: true,
          checkedAt: "2026-06-19T08:01:00.000Z",
          host: "example.com",
          issuer: "Example CA",
          validTo: "2026-09-25T00:00:00.000Z",
          daysRemaining: 92,
          serialNumber: "DEF456",
          lastEventType: "cert_renewed",
          lastWarnedBand: null,
          attention: null,
          issues: [],
          history: [{
            checkedAt: "2026-06-19T08:01:00.000Z",
            eventType: "cert_renewed",
            eventSeverity: "info",
            eventTitle: "Certificate renewed: example.com",
            eventDetail: "New certificate from Example CA.",
            daysRemaining: 92,
            previousDaysRemaining: 6,
            daysRemainingDelta: 86,
          }],
        },
      },
      records: [],
    },
  ]);

  assert.equal(payload.targets[0].status.state, "changed");
  assert.equal(payload.targets[0].change.type, "cert_renewed");
  assert.equal(payload.targets[0].change.title, "Certificate renewed: example.com");
  assert.equal(payload.targets[0].change.detail, "New certificate from Example CA.");
  assert.equal(payload.targets[0].actions[0].id, "confirm_certificate_renewal");
});

test("mobile monitoring summary exposes compact posture drift for apps", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-posture-1",
        url: "https://example.com/",
        label: "Example posture",
        cadence: "daily",
        kind: "posture",
        mode: "quiet",
        appId: "com.ktbatterham.securl",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastScannedAt: "2026-06-19T09:00:00.000Z",
      },
      records: [
        buildCompletedRecord("scan-current", {
          scannedAt: "2026-06-19T09:00:00.000Z",
          score: 58,
          grade: "D",
          certificate: {
            daysRemaining: 5,
          },
          wafFingerprint: {
            providers: [],
          },
          headers: [
            {
              label: "Strict-Transport-Security",
              status: "missing",
              value: null,
            },
          ],
          issues: [
            {
              severity: "critical",
              title: "Exposed admin surface",
              detail: "An admin path was reachable.",
              confidence: "medium",
              source: "observed",
            },
          ],
        }),
        buildCompletedRecord("scan-previous"),
      ],
    },
  ]);

  const target = payload.targets[0];
  assert.equal(target.scoreDelta, -34);
  assert.equal(target.posture.currentScanId, "scan-current");
  assert.equal(target.posture.previousScanId, "scan-previous");
  assert.equal(target.posture.direction, "regressed");
  assert.equal(target.posture.severity, "critical");
  assert.equal(target.posture.gradeChanged, true);
  assert.equal(target.posture.hasRegression, true);
  assert.ok(target.posture.changedAreas.includes("score"));
  assert.ok(target.posture.changedAreas.includes("headers"));
  assert.ok(target.posture.changedAreas.includes("certificate"));
  assert.ok(target.posture.eventCounts.critical >= 4);
  assert.ok(target.posture.topEvents.length > 0);
  assert.ok(target.posture.monitoringEvents.length > 0);
  assert.equal(target.events[0].source, "posture");
  assert.equal(target.events[0].targetId, "target-posture-1");
  assert.equal(target.events[0].eventId, target.events[0].id);
  assert.deepEqual(target.events[0].deepLink, {
    route: "monitoring_target",
    targetId: "target-posture-1",
    eventId: target.events[0].id,
  });
  assert.equal(typeof target.events[0].push.title, "string");
  assert.equal(typeof target.events[0].nextAction, "string");
  assert.equal(target.status.state, "needs_attention");
  assert.equal(target.status.reason, "posture_regressed");
  assert.equal(target.change.type, "posture_regressed");
  assert.equal(target.change.severity, "critical");
  assert.equal(target.actions[0].id, "review_posture_regression");
  assert.equal(target.nextCheck.due, target.due);
  assert.equal(target.changes.postureRiskEvents, 6);
  assert.ok(target.changes.monitoringEvents > 0);
  assert.equal(payload.summary.changes, target.changes.postureRiskEvents);
});

test("monitoring target detail decorates comparison events with stable navigation identity", () => {
  const target = {
    id: "target-posture-detail",
    url: "https://example.com/",
    label: "Example posture",
    cadence: "daily",
    kind: "cert",
    mode: "quiet",
    addedAt: "2026-06-19T08:00:00.000Z",
    lastScannedAt: "2026-06-19T09:00:00.000Z",
  };
  const records = [
    buildCompletedRecord("scan-current", {
      scannedAt: "2026-06-19T09:00:00.000Z",
      score: 58,
      grade: "D",
    }),
    buildCompletedRecord("scan-previous"),
  ];

  const payload = buildMonitoringTargetDetailPayload(target, records);
  const event = payload.comparison.monitoringEvents[0];

  assert.equal(event.targetId, target.id);
  assert.equal(event.eventId, event.id);
  assert.deepEqual(event.deepLink, {
    route: "monitoring_target",
    targetId: target.id,
    eventId: event.id,
  });
});

test("monitoring target timeline exposes stable posture event identity and evidence", () => {
  const target = {
    id: "target-posture-timeline",
    url: "https://example.com/",
    label: "Example posture",
    cadence: "daily",
    kind: "posture",
    mode: "quiet",
    appId: "com.ktbatterham.headerwatch",
    addedAt: "2026-06-19T08:00:00.000Z",
    lastScannedAt: "2026-06-20T08:00:00.000Z",
  };
  const records = [
    buildCompletedRecord("scan-current", {
      scannedAt: "2026-06-20T08:00:00.000Z",
      score: 58,
      grade: "D",
      headers: [
        {
          label: "Strict-Transport-Security",
          status: "missing",
          value: null,
        },
      ],
    }),
    buildCompletedRecord("scan-previous", {
      scannedAt: "2026-06-19T08:00:00.000Z",
      score: 92,
      grade: "A",
    }),
  ];

  const payload = buildMonitoringTargetTimelinePayload(target, records);
  const event = payload.timeline[0];

  assert.equal(payload.targetId, target.id);
  assert.equal(payload.target.kind, "posture");
  assert.equal(payload.summary.latestEventId, event.eventId);
  assert.equal(event.targetId, target.id);
  assert.equal(event.eventId, event.eventId);
  assert.equal(event.sourceType, "posture_drift");
  assert.equal(event.occurredAt, "2026-06-20T08:00:00.000Z");
  assert.equal(event.links.scan, "/api/scans/scan-current");
  assert.equal(event.links.comparison, "/api/scans/scan-current/comparison");
  assert.ok(["critical", "warning", "info"].includes(event.severity));
  assert.ok(Array.isArray(event.evidence));
  assert.equal(typeof event.explanation.headline, "string");
});

test("monitoring target timeline reuses certificate monitoring event ids when available", () => {
  const target = {
    id: "target-cert-timeline",
    url: "https://example.com/",
    label: "Example cert",
    cadence: "daily",
    kind: "cert",
    appId: "com.ktbatterham.certwatch",
    certPolicy: "strict",
    addedAt: "2026-06-19T08:00:00.000Z",
    lastCheckedAt: "2026-06-20T08:00:00.000Z",
    certState: {
      reachable: true,
      checkedAt: "2026-06-20T08:00:00.000Z",
      host: "example.com",
      issuer: "Example CA",
      validTo: "2026-06-25T00:00:00.000Z",
      daysRemaining: 5,
      history: [{
        checkedAt: "2026-06-20T08:00:00.000Z",
        eventType: "cert_expiring",
        eventSeverity: "critical",
        eventTitle: "Certificate expiring: example.com",
        eventDetail: "5 days remaining.",
        issuer: "Example CA",
        serialNumber: "ABC123",
        validTo: "2026-06-25T00:00:00.000Z",
        daysRemaining: 5,
        previousDaysRemaining: 32,
        monitoringEvent: {
          id: "example.com:443:2026-06-20T08:00:00.000Z:certificate_expiring",
          source: "certificate",
          eventType: "certificate_expiring",
          severity: "critical",
          title: "Certificate expires soon",
          message: "The served certificate has 5 days remaining.",
          nextAction: "Renew the certificate before the expiry window closes.",
          changedEvidence: [{ label: "Days remaining", previous: 32, current: 5 }],
        },
      }],
    },
  };

  const payload = buildMonitoringTargetTimelinePayload(target, []);
  const event = payload.timeline[0];

  assert.equal(payload.target.policy, "strict");
  assert.equal(event.eventId, "example.com:443:2026-06-20T08:00:00.000Z:certificate_expiring");
  assert.equal(event.type, "cert_expiring");
  assert.equal(event.sourceType, "certificate");
  assert.equal(event.severity, "critical");
  assert.equal(event.mattersToPolicy, true);
  assert.equal(event.explanation.action, "Renew the certificate before the expiry window closes.");
  assert.equal(event.evidence[0].name, "Days remaining");
  assert.equal(event.links.history, "/api/monitoring-targets/target-cert-timeline/history");
});

test("scan drift payload includes monitoring events alongside legacy risk events", () => {
  const previous = buildCompletedRecord("previous");
  const current = buildCompletedRecord("current", {
    scannedAt: "2026-06-20T08:00:00.000Z",
    score: 60,
    grade: "D",
    certificate: {
      daysRemaining: 5,
    },
    headers: [
      {
        label: "Strict-Transport-Security",
        status: "missing",
        value: null,
      },
    ],
    issues: [
      {
        severity: "critical",
        title: "Expired certificate",
        detail: "The observed certificate is expired.",
        confidence: "high",
        source: "observed",
      },
    ],
  });

  const payload = buildScanDriftPayload(current, [current, previous]);

  assert.equal(payload.drift.currentScanId, "current");
  assert.ok(Array.isArray(payload.drift.riskEvents));
  assert.ok(Array.isArray(payload.drift.monitoringEvents));
  assert.ok(payload.drift.monitoringEvents.length > 0);
  assert.equal(payload.drift.monitoringEvents[0].target.host, "example.com");
  assert.equal(typeof payload.drift.monitoringEvents[0].push.body, "string");
});

test("mobile monitoring summary includes a compact latest digest preview", () => {
  const payload = buildMonitoringMobileSummaryPayload([
    {
      target: {
        id: "target-posture-2",
        url: "https://example.com/",
        label: "Example posture",
        cadence: "daily",
        kind: "posture",
        mode: "quiet",
        appId: "com.ktbatterham.securl",
        addedAt: "2026-06-19T08:00:00.000Z",
        lastScannedAt: "2026-06-19T09:00:00.000Z",
      },
      records: [
        buildCompletedRecord("scan-current", {
          issues: [
            {
              severity: "warning",
              title: "CSP allows unsafe inline script",
              detail: "The observed CSP permits inline script execution.",
              confidence: "high",
              source: "observed",
            },
            {
              severity: "info",
              title: "Security.txt missing",
              detail: "No security.txt file was found.",
              confidence: "medium",
              source: "heuristic",
            },
          ],
          thirdPartyTrust: {
            providers: [{ name: "Stripe" }, { name: "Plausible" }],
            highRiskProviders: 0,
            issues: [],
          },
          identityProvider: {
            provider: "Okta",
          },
          compromiseSignals: {
            posture: "review_recommended",
            indicators: [
              {
                severity: "warning",
                category: "script_anomaly",
                title: "Suspicious inline script marker",
                detail: "A script marker matched a review heuristic.",
                confidence: "medium",
              },
            ],
          },
          ctDiscovery: {
            prioritizedHosts: [{ host: "admin.example.com" }],
          },
          aiSurface: {
            vendors: [{ name: "OpenAI" }],
          },
        }),
      ],
    },
  ]);

  const digest = payload.targets[0].latestDigest;
  assert.equal(digest.scanId, "scan-current");
  assert.equal(digest.target.host, "example.com");
  assert.equal(digest.posture.grade, "A");
  assert.equal(digest.posture.score, 92);
  assert.equal(digest.posture.scoreDrivers.length, 1);
  assert.ok(digest.signalClarity);
  assert.equal(typeof digest.signalClarity.headline, "string");
  assert.ok(Array.isArray(digest.signalClarity.topNegativeDrivers));
  assert.equal(digest.findings.total, 2);
  assert.equal(digest.findings.top.length, 2);
  assert.equal(digest.controls.tls.daysRemaining, 90);
  assert.deepEqual(digest.trust.thirdPartyProviders, ["Stripe", "Plausible"]);
  assert.equal(digest.trust.identityProvider, "Okta");
  assert.deepEqual(digest.trust.wafProviders, ["Cloudflare"]);
  assert.equal(digest.intelligence.riskIndicators.length, 1);
  assert.deepEqual(digest.intelligence.ctPriorityHosts, ["admin.example.com"]);
  assert.deepEqual(digest.intelligence.aiVendors, ["OpenAI"]);
});
