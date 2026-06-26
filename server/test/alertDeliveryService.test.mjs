import assert from "node:assert/strict";
import test from "node:test";
import { buildWebhookSignature, createAlertDeliveryService } from "../alertDeliveryService.mjs";
import { createInMemoryScanRepository } from "../scanRepository.mjs";

const policy = {
  id: "cert-policy",
  name: "Certificate policy",
  version: "1",
  rules: [{
    id: "cert-window",
    title: "Certificate must have 14 days remaining",
    severity: "critical",
    scope: "observation",
    selector: { kind: "tls.certificate.days_remaining" },
    assertion: { field: "value", operator: "gte", value: 14 },
    requireMatch: true,
  }],
};

function result(days, scannedAt) {
  const observation = {
    id: "obs_cert_days",
    category: "certificate",
    kind: "tls.certificate.days_remaining",
    subject: "example.com",
    status: "observed",
    value: days,
    confidence: "high",
    source: "tls",
    observedAt: scannedAt,
    freshUntil: new Date(new Date(scannedAt).getTime() + 3600_000).toISOString(),
    evidence: [],
  };
  return {
    finalUrl: "https://example.com/",
    normalizedUrl: "https://example.com/",
    host: "example.com",
    grade: days < 14 ? "D" : "B",
    score: days < 14 ? 50 : 80,
    observationLedger: {
      version: "1.0",
      target: "https://example.com/",
      generatedAt: scannedAt,
      observations: [observation],
      summary: { total: 1, byStatus: { observed: 1, inferred: 0, missing: 0, unavailable: 0 }, byCategory: { certificate: 1 }, highConfidence: 1 },
    },
  };
}

async function saveCompleted(repository, scanResult) {
  const scan = await repository.createScan({
    url: "https://example.com/",
    mode: "quiet",
    requesterScope: "owner:test",
    ownerId: "scan-owner:test",
    clientIp: "127.0.0.1",
  });
  await repository.markCompleted(scan.id, scanResult);
  return repository.getScanById(scan.id);
}

test("webhook signatures bind timestamp and body", () => {
  const signature = buildWebhookSignature("secret", "123", '{"ok":true}');
  assert.equal(signature, "12f14ade5e7e737164d9ae20ea4e070056a3045b2c8f42f5f216008eae4684dd");
});

test("policy alerts route new violations to APNs and durable destinations once", async () => {
  const repository = createInMemoryScanRepository();
  await repository.upsertMonitoringTarget({
    url: "https://example.com/",
    label: "Example",
    cadence: "daily",
    kind: "posture",
    mode: "quiet",
    requesterScope: "owner:test",
    ownerId: "scan-owner:test",
    observationPolicy: policy,
  });
  await repository.upsertAlertDestination({
    ownerId: "scan-owner:test",
    requesterScope: "owner:test",
    type: "webhook",
    label: "Webhook",
    endpoint: "https://hooks.example.com/securl",
    signingSecret: "secret",
  });
  await saveCompleted(repository, result(30, "2026-06-20T10:00:00.000Z"));
  const current = await saveCompleted(repository, result(10, "2026-06-20T11:00:00.000Z"));
  let pushCalls = 0;
  let webhookCalls = 0;
  const service = createAlertDeliveryService({
    scanRepository: repository,
    notificationService: {
      async sendPolicyAlert() {
        pushCalls += 1;
        return { attempted: 1, sent: 1 };
      },
    },
    webhookTransport: async (_destination, payload) => {
      webhookCalls += 1;
      assert.equal(payload.type, "observation_policy_violation");
      assert.equal(payload.brief.highestSeverity, "critical");
      assert.match(payload.brief.title, /example\.com: 1 critical policy violation/);
      assert.equal(payload.summary.newBySeverity.critical, 1);
      assert.equal(payload.violations[0].ruleId, "cert-window");
      assert.equal(payload.violations[0].category, "certificate");
      assert.equal(payload.violations[0].action.id, "review_certificate");
      assert.equal(payload.actions[0].id, "review_certificate");
      return { ok: true, statusCode: 204, retryable: false };
    },
  });

  const delivered = await service.processMonitoringScan({
    completedScan: current,
    result: current.result,
    telemetryContext: { channel: "monitoring_scheduler" },
  });
  assert.equal(delivered.violations, 1);
  assert.equal(pushCalls, 1);
  assert.equal(webhookCalls, 1);
  assert.deepEqual(await repository.getAlertOutboxStats(), { total: 1, byStatus: { sent: 1 } });

  const repeated = await saveCompleted(repository, result(9, "2026-06-20T12:00:00.000Z"));
  const skipped = await service.processMonitoringScan({
    completedScan: repeated,
    result: repeated.result,
    telemetryContext: { channel: "monitoring_scheduler" },
  });
  assert.equal(skipped.skipped, "no_new_violations");
  assert.equal(pushCalls, 1);
  assert.equal(webhookCalls, 1);
});

test("destination tests send the enriched policy alert contract", async () => {
  const repository = createInMemoryScanRepository();
  const destination = await repository.upsertAlertDestination({
    ownerId: "scan-owner:test",
    requesterScope: "owner:test",
    type: "webhook",
    label: "Webhook",
    endpoint: "https://hooks.example.com/securl",
    signingSecret: "secret",
  });
  const [secretDestination] = await repository.listAlertDestinations({ ownerId: "scan-owner:test", includeSecrets: true });
  let deliveredPayload = null;
  const service = createAlertDeliveryService({
    scanRepository: repository,
    webhookTransport: async (_destination, payload) => {
      deliveredPayload = payload;
      return { ok: true, statusCode: 204, retryable: false };
    },
  });

  const result = await service.sendTestDestination(secretDestination);

  assert.equal(destination.endpoint, undefined);
  assert.equal(result.queued, 1);
  assert.equal(deliveredPayload.type, "alert_destination_test");
  assert.equal(deliveredPayload.brief.title, "SecURL test: 1 info policy violation");
  assert.equal(deliveredPayload.summary.newBySeverity.info, 1);
  assert.equal(deliveredPayload.violations[0].category, "delivery");
  assert.equal(deliveredPayload.violations[0].action.id, "review_alert_delivery");
  assert.equal(deliveredPayload.actions[0].id, "review_alert_delivery");
});
