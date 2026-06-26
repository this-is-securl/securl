import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCertAttention,
  buildCertMonitoringEventDetails,
  detectCertMonitoringEvent,
  normalizeMonitoringAppId,
  normalizeMonitoringCadence,
  normalizeMonitoringKind,
} from "../certMonitoring.mjs";

test("monitoring normalizers accept mobile aliases and cert cadences", () => {
  assert.equal(normalizeMonitoringKind("cert"), "cert");
  assert.equal(normalizeMonitoringKind("anything-else"), "posture");
  assert.equal(normalizeMonitoringCadence("hourly"), "hourly");
  assert.equal(normalizeMonitoringCadence("6h"), "6h");
  assert.equal(normalizeMonitoringCadence("nonsense"), "daily");
  assert.equal(normalizeMonitoringAppId("cert-watch"), "com.ktbatterham.certwatch");
});

test("cert monitoring detects renewal before issuer-only changes", () => {
  const event = detectCertMonitoringEvent(
    {
      reachable: true,
      serialNumber: "ABC",
      issuer: "Old CA",
      lastWarnedBand: 14,
    },
    {
      reachable: true,
      serialNumber: "DEF",
      issuer: "New CA",
      daysRemaining: 89,
    },
  );

  assert.deepEqual(event, {
    type: "cert_renewed",
    severity: "info",
    resetWarningBand: true,
  });
});

test("cert monitoring event details include previous, current, and delta context", () => {
  const previous = {
    reachable: true,
    issuer: "Old CA",
    serialNumber: "ABC",
    validTo: "2026-07-01T00:00:00.000Z",
    daysRemaining: 5,
    lastWarnedBand: 7,
  };
  const current = {
    reachable: true,
    host: "example.com",
    issuer: "New CA",
    serialNumber: "DEF",
    validTo: "2026-09-01T00:00:00.000Z",
    daysRemaining: 67,
  };
  const event = buildCertMonitoringEventDetails(
    { type: "cert_renewed", severity: "info", resetWarningBand: true },
    previous,
    current,
  );

  assert.equal(event.type, "cert_renewed");
  assert.equal(event.title, "Certificate renewed: example.com");
  assert.equal(event.resetWarningBand, true);
  assert.equal(event.previous.serialNumber, "ABC");
  assert.equal(event.current.serialNumber, "DEF");
  assert.equal(event.delta.daysRemaining, 62);
});

test("cert monitoring detects issuer changes when serial is unchanged", () => {
  const event = detectCertMonitoringEvent(
    {
      reachable: true,
      serialNumber: "ABC",
      issuer: "Old CA",
    },
    {
      reachable: true,
      serialNumber: "ABC",
      issuer: "New CA",
      daysRemaining: 89,
    },
  );

  assert.deepEqual(event, {
    type: "issuer_changed",
    severity: "warning",
  });
});

test("cert monitoring only emits tighter expiry bands", () => {
  assert.deepEqual(
    detectCertMonitoringEvent(
      { reachable: true, serialNumber: "ABC", issuer: "CA", lastWarnedBand: 30 },
      { reachable: true, serialNumber: "ABC", issuer: "CA", daysRemaining: 13 },
    ),
    { type: "cert_expiring", severity: "warning", warningBand: 14 },
  );

  assert.equal(
    detectCertMonitoringEvent(
      { reachable: true, serialNumber: "ABC", issuer: "CA", lastWarnedBand: 14 },
      { reachable: true, serialNumber: "ABC", issuer: "CA", daysRemaining: 13 },
    ),
    null,
  );
});

test("cert monitoring surfaces initial certificate attention without firing an event", () => {
  const expiringState = {
    reachable: true,
    host: "example.com",
    daysRemaining: 6,
    issues: [],
  };

  assert.equal(detectCertMonitoringEvent(null, expiringState), null);
  assert.deepEqual(buildCertAttention(expiringState), {
    type: "cert_expiring",
    severity: "critical",
    warningBand: 7,
    title: "Certificate expiring: example.com",
    body: "6 days remaining.",
  });
});

test("cert monitoring attention clears when the certificate is healthy", () => {
  assert.equal(
    buildCertAttention({
      reachable: true,
      host: "example.com",
      daysRemaining: 89,
      issues: [],
    }),
    null,
  );
});

test("cert monitoring marks first-seen expired and unreachable certificates as critical attention", () => {
  assert.deepEqual(
    buildCertAttention({
      reachable: true,
      host: "expired.example",
      daysRemaining: 0,
      issues: [],
    }),
    {
      type: "cert_expired",
      severity: "critical",
      title: "Certificate expired: expired.example",
      body: "The served certificate is no longer within its validity window.",
    },
  );

  assert.deepEqual(
    buildCertAttention({
      reachable: false,
      host: "down.example",
      issues: ["connect timeout"],
    }),
    {
      type: "unreachable",
      severity: "critical",
      title: "Certificate check failed: down.example",
      body: "connect timeout",
    },
  );
});

test("cert monitoring reports unreachable only after a previously reachable check", () => {
  assert.deepEqual(
    detectCertMonitoringEvent(
      { reachable: true, serialNumber: "ABC", issuer: "CA" },
      { reachable: false, issues: ["connect timeout"] },
    ),
    { type: "unreachable", severity: "critical" },
  );

  assert.equal(
    detectCertMonitoringEvent(null, { reachable: false, issues: ["connect timeout"] }),
    null,
  );
});
