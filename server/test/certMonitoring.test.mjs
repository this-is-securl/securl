import assert from "node:assert/strict";
import test from "node:test";
import {
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
