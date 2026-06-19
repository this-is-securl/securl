import assert from "node:assert/strict";
import test from "node:test";
import { buildMonitoringMobileSummaryPayload } from "../scanDtos.mjs";

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
});
