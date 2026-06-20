import assert from "node:assert/strict";
import test from "node:test";
import { diffObservationLedgers } from "../dist/observationDrift.js";

const observedAt = "2026-06-20T10:00:00.000Z";
const observation = (overrides = {}) => ({
  id: "obs_header",
  category: "header",
  kind: "http.header.content-security-policy",
  subject: "https://example.com/",
  status: "observed",
  value: "default-src 'self'",
  confidence: "high",
  source: "header",
  observedAt,
  freshUntil: "2026-06-20T11:00:00.000Z",
  evidence: [],
  ...overrides,
});
const ledger = (observations, generatedAt = observedAt) => ({
  version: "1.0",
  target: "https://example.com/",
  generatedAt,
  observations,
  summary: { total: observations.length, byStatus: {}, byCategory: {}, highConfidence: observations.length },
});

test("observation drift classifies missing critical controls as regressions", () => {
  const previous = ledger([observation()]);
  const current = ledger([observation({ status: "missing", value: null })], "2026-06-20T11:00:00.000Z");
  const drift = diffObservationLedgers(current, previous);

  assert.equal(drift.summary.direction, "regressed");
  assert.equal(drift.summary.regressions, 2);
  assert.ok(drift.changes.every((change) => change.severity === "critical"));
  assert.deepEqual(drift.changes.map((change) => change.type).sort(), ["status_changed", "value_changed"]);
});

test("observation drift treats certificate renewal as improvement and normal daily decay as neutral", () => {
  const cert = (days) => observation({
    id: "obs_cert_days",
    category: "certificate",
    kind: "tls.certificate.days_remaining",
    subject: "example.com",
    value: days,
    source: "tls",
  });

  const daily = diffObservationLedgers(ledger([cert(39)]), ledger([cert(40)]));
  assert.equal(daily.summary.direction, "changed");
  assert.equal(daily.changes[0].impact, "change");

  const renewed = diffObservationLedgers(ledger([cert(90)]), ledger([cert(10)]));
  assert.equal(renewed.summary.direction, "improved");
  assert.equal(renewed.changes[0].impact, "improvement");
});

test("observation drift reports added and removed provider signals", () => {
  const oldProvider = observation({ id: "obs_old", category: "infrastructure", kind: "infrastructure.provider.edge.old", value: "Old Edge" });
  const newProvider = observation({ id: "obs_new", category: "infrastructure", kind: "infrastructure.provider.edge.new", value: "New Edge" });
  const drift = diffObservationLedgers(ledger([newProvider]), ledger([oldProvider]));

  assert.equal(drift.changes.length, 2);
  assert.ok(drift.changes.some((change) => change.type === "added"));
  assert.ok(drift.changes.some((change) => change.type === "removed"));
});
