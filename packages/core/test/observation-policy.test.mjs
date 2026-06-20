import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_OBSERVATION_POLICY,
  evaluateObservationPolicy,
  validateObservationPolicy,
} from "../dist/observationPolicy.js";

const observedAt = "2026-06-20T12:00:00.000Z";
const observation = (id, kind, value, status = "observed") => ({
  id,
  category: kind.startsWith("tls.certificate") ? "certificate" : kind.startsWith("email") ? "email" : "header",
  kind,
  subject: "example.com",
  status,
  value,
  confidence: "high",
  source: kind.startsWith("tls") ? "tls" : kind.startsWith("email") ? "dns" : "header",
  observedAt,
  freshUntil: "2026-06-20T18:00:00.000Z",
  evidence: [],
});
const ledger = (observations) => ({
  version: "1.0",
  target: "https://example.com/",
  generatedAt: observedAt,
  observations,
  summary: { total: observations.length, byStatus: {}, byCategory: {}, highConfidence: observations.length },
});

test("default observation policy reports current posture violations", () => {
  const evaluation = evaluateObservationPolicy({
    ledger: ledger([
      observation("cert-valid", "tls.certificate.valid", true),
      observation("cert-days", "tls.certificate.days_remaining", 10),
      observation("hsts", "http.header.strict-transport-security", "max-age=1"),
      observation("csp", "http.header.content-security-policy", null, "missing"),
      observation("dmarc", "email.dmarc", "missing", "missing"),
    ]),
  });

  assert.equal(evaluation.passed, false);
  assert.equal(evaluation.summary.bySeverity.critical, 1);
  assert.equal(evaluation.summary.bySeverity.warning, 2);
  assert.deepEqual(evaluation.violations.map(({ ruleId }) => ruleId).sort(), ["certificate-window", "csp-present", "dmarc-enforced"]);
});

test("custom observation policy supports selectors and numeric assertions", () => {
  const policy = validateObservationPolicy({
    id: "strict-certs",
    name: "Strict certificates",
    version: "1",
    rules: [{
      id: "cert-30-days",
      title: "Certificate window",
      severity: "warning",
      scope: "observation",
      selector: { kind: "tls.certificate.days_remaining" },
      assertion: { field: "value", operator: "gte", value: 30 },
      requireMatch: true,
    }],
  });
  const evaluation = evaluateObservationPolicy({
    policy,
    ledger: ledger([observation("cert-days", "tls.certificate.days_remaining", 29)]),
  });
  assert.equal(evaluation.violations.length, 1);
  assert.equal(evaluation.violations[0].actual, 29);
});

test("change-scoped policy rules evaluate drift without requiring a change", () => {
  const evaluation = evaluateObservationPolicy({
    ledger: ledger([]),
    drift: {
      version: "1.0",
      target: "https://example.com/",
      comparedAt: observedAt,
      previousObservedAt: observedAt,
      currentObservedAt: observedAt,
      changes: [{
        id: "change-one",
        observationId: "csp",
        type: "status_changed",
        impact: "regression",
        severity: "critical",
        category: "header",
        kind: "http.header.content-security-policy",
        subject: "example.com",
        previous: null,
        current: null,
        summary: "CSP disappeared.",
      }],
      summary: { direction: "regressed", total: 1, regressions: 1, improvements: 0, neutralChanges: 0, bySeverity: { info: 0, warning: 0, critical: 1 }, byCategory: { header: 1 } },
    },
    policy: DEFAULT_OBSERVATION_POLICY,
  });
  assert.ok(evaluation.violations.some(({ ruleId }) => ruleId === "critical-regression"));
});

test("policy validation rejects oversized and malformed rule sets", () => {
  assert.throws(() => validateObservationPolicy({ id: "x", name: "x", version: "1", rules: [] }), /between 1 and 25/i);
  assert.throws(() => validateObservationPolicy({
    id: "x",
    name: "x",
    version: "1",
    rules: [{ id: "x", title: "x", severity: "warning", scope: "observation", selector: {}, assertion: { field: "value", operator: "gte", value: "30" } }],
  }), /numeric assertion/i);
});
