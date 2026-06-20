import assert from "node:assert/strict";
import test from "node:test";
import { buildObservationLedger } from "../dist/observations.js";

function result(overrides = {}) {
  return {
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt: "2026-06-20T10:00:00.000Z",
    statusCode: 200,
    headers: [
      { key: "strict-transport-security", label: "HSTS", status: "present", value: "max-age=31536000" },
      { key: "content-security-policy", label: "CSP", status: "missing", value: null },
    ],
    certificate: {
      available: true,
      valid: true,
      authorized: true,
      daysRemaining: 40,
      protocol: "TLSv1.3",
    },
    domainSecurity: {
      host: "example.com",
      dnssec: { enabled: false, status: "not_signed" },
      emailPolicy: {
        spf: { status: "strong" },
        dmarc: { status: "missing" },
      },
    },
    securityTxt: { status: "present_valid" },
    infrastructure: {
      providers: [{ provider: "Example Edge", category: "edge", confidence: "high", source: "headers", evidence: "server header" }],
    },
    technologies: [{ name: "Example Framework", category: "frontend", evidence: "asset path", version: "1.2.3", confidence: "medium", detection: "observed" }],
    wafFingerprint: { providers: [] },
    assessmentLimitation: { limited: false, kind: null, detail: null },
    ...overrides,
  };
}

test("observation ledger produces stable source-aware observations", () => {
  const first = buildObservationLedger(result());
  const second = buildObservationLedger(result({ scannedAt: "2026-06-20T11:00:00.000Z" }));

  assert.equal(first.version, "1.0");
  assert.equal(first.target, "https://example.com/");
  assert.equal(first.summary.total, first.observations.length);
  assert.deepEqual(first.observations.map(({ id }) => id), second.observations.map(({ id }) => id));
  assert.ok(first.observations.every(({ id }) => /^obs_[a-f0-9]{20}$/.test(id)));
  assert.equal(new Set(first.observations.map(({ id }) => id)).size, first.observations.length);
  assert.ok(first.observations.every(({ freshUntil, observedAt }) => freshUntil > observedAt));
});

test("observation ledger distinguishes missing, unavailable, inferred, and observed evidence", () => {
  const ledger = buildObservationLedger(result({
    statusCode: 0,
    infrastructure: {
      providers: [{ provider: "Example PaaS", category: "paas", confidence: "medium", source: "technology", evidence: "framework marker" }],
    },
    assessmentLimitation: { limited: true, kind: "service_unavailable", detail: "No stable response." },
  }));

  assert.ok(ledger.summary.byStatus.observed > 0);
  assert.ok(ledger.summary.byStatus.missing > 0);
  assert.ok(ledger.summary.byStatus.unavailable > 0);
  assert.ok(ledger.summary.byStatus.inferred > 0);
  assert.equal(ledger.observations.find(({ kind }) => kind === "http.header.content-security-policy").value, null);
});
