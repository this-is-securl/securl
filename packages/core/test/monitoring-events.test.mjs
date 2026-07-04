import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCertificateMonitoringEvents,
  buildHistoryDiffFromSnapshots,
  buildMonitoringEventsFromSnapshots,
} from "../dist/index.js";

function buildSnapshot(overrides = {}) {
  return {
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-07-04T08:00:00.000Z",
    score: 92,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 100,
    certificateDaysRemaining: 90,
    thirdPartyProviders: [],
    aiVendors: [],
    identityProvider: null,
    wafProviders: ["Cloudflare"],
    ctPriorityHosts: [],
    headers: [
      {
        label: "Strict-Transport-Security",
        status: "pass",
        value: "max-age=31536000",
      },
    ],
    issues: [],
    ...overrides,
  };
}

function buildCertificate(overrides = {}) {
  return {
    host: "example.com",
    port: 443,
    checkedAt: "2026-07-04T08:00:00.000Z",
    available: true,
    valid: true,
    authorized: true,
    issuer: "Example CA",
    subject: "example.com",
    validFrom: "2026-06-01T00:00:00.000Z",
    validTo: "2026-07-10T00:00:00.000Z",
    daysRemaining: 6,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    fingerprint: "aa:bb",
    serialNumber: "123",
    keyBits: 2048,
    keyType: "RSA",
    subjectAltName: ["example.com"],
    issues: [],
    chain: [],
    ...overrides,
  };
}

test("monitoring events convert posture regressions into push-safe product events", () => {
  const previous = buildSnapshot();
  const current = buildSnapshot({
    scannedAt: "2026-07-04T09:00:00.000Z",
    score: 61,
    grade: "C",
    certificateDaysRemaining: 5,
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
        detail: "The observed TLS certificate is expired.",
        confidence: "high",
        source: "observed",
      },
    ],
  });
  const diff = buildHistoryDiffFromSnapshots(current, previous);

  const events = buildMonitoringEventsFromSnapshots(current, previous, diff);
  const eventTypes = events.map((event) => event.eventType);

  assert.equal(events[0].severity, "critical");
  assert.ok(eventTypes.includes("new_critical_findings"));
  assert.ok(eventTypes.includes("grade_dropped"));
  assert.ok(eventTypes.includes("certificate_expiring_soon"));

  const gradeEvent = events.find((event) => event.eventType === "grade_dropped");
  assert.equal(gradeEvent.source, "posture");
  assert.equal(gradeEvent.target.host, "example.com");
  assert.equal(gradeEvent.current.grade, "C");
  assert.equal(gradeEvent.previous.grade, "A");
  assert.match(gradeEvent.push.title, /SecURL: Grade dropped/);
  assert.match(gradeEvent.push.body, /example\.com/);
  assert.match(gradeEvent.nextAction, /score drivers/);
  assert.deepEqual(gradeEvent.changedEvidence, [{ label: "Grade", previous: "A", current: "C" }]);
});

test("certificate monitoring events fire on initial expiring certificate observation", () => {
  const [event] = buildCertificateMonitoringEvents(buildCertificate(), null);

  assert.equal(event.source, "certificate");
  assert.equal(event.eventType, "certificate_expiring");
  assert.equal(event.severity, "critical");
  assert.equal(event.previous.observedAt, null);
  assert.equal(event.current.certificateDaysRemaining, 6);
  assert.match(event.message, /6 days remaining/);
  assert.match(event.nextAction, /Renew the certificate/);
  assert.equal(event.dedupeKey, "certificate:example.com:443:certificate_expiring");
});

test("certificate monitoring events classify rotation and issuer changes", () => {
  const previous = buildCertificate({
    checkedAt: "2026-07-03T08:00:00.000Z",
    fingerprint: "old",
    issuer: "Old CA",
    daysRemaining: 120,
  });
  const current = buildCertificate({
    checkedAt: "2026-07-04T08:00:00.000Z",
    fingerprint: "new",
    issuer: "New CA",
    daysRemaining: 120,
  });

  const [event] = buildCertificateMonitoringEvents(current, previous);

  assert.equal(event.eventType, "certificate_rotated");
  assert.equal(event.severity, "info");
  assert.equal(event.metadata.fingerprintChanged, true);
  assert.equal(event.metadata.issuerChanged, true);
  assert.match(event.push.body, /fingerprint changed/);
});

test("certificate monitoring events stay quiet when the cert is healthy and unchanged", () => {
  const previous = buildCertificate({ daysRemaining: 120, fingerprint: "same" });
  const current = buildCertificate({ daysRemaining: 119, fingerprint: "same" });

  assert.deepEqual(buildCertificateMonitoringEvents(current, previous), []);
});
