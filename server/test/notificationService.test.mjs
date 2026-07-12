import assert from "node:assert/strict";
import test from "node:test";
import { classifyApnsResponse, classifyFcmResponse, createNotificationService } from "../notificationService.mjs";
import { createInMemoryScanRepository } from "../scanRepository.mjs";

function buildDevice(overrides = {}) {
  return {
    id: "device-1",
    ownerId: "owner-1",
    requesterScope: "scope-1",
    token: "a".repeat(64),
    environment: "production",
    appId: "com.ktbatterham.securl",
    ...overrides,
  };
}

function buildAndroidDevice(overrides = {}) {
  return buildDevice({
    id: "device-android-1",
    platform: "android",
    token: "f".repeat(120),
    environment: "production",
    ...overrides,
  });
}

function buildRepository(device = buildDevice()) {
  const attempts = [];
  const disabled = [];
  return {
    attempts,
    disabled,
    async recordPushDeliveryAttempt(id, details) {
      attempts.push({ id, ...details });
      return { id, ...details };
    },
    async disablePushDevice(id) {
      disabled.push(id);
      return id === device.id;
    },
  };
}

function createService({ repository, transport, sleep = async () => {}, telemetry = null, maxAttempts = 3 } = {}) {
  return createNotificationService({
    scanRepository: repository,
    transport,
    sleep,
    telemetry,
    apns: {
      teamId: "TEAM",
      keyId: "KEY",
      privateKey: "PRIVATE KEY",
      maxAttempts,
      timeoutMs: 25,
    },
  });
}

function createFcmService({ repository, fcmTransport, sleep = async () => {}, telemetry = null, maxAttempts = 3 } = {}) {
  return createNotificationService({
    scanRepository: repository,
    fcmTransport,
    sleep,
    telemetry,
    fcm: {
      projectId: "securl-test",
      clientEmail: "firebase-adminsdk@example.iam.gserviceaccount.com",
      privateKey: "PRIVATE KEY",
      maxAttempts,
      timeoutMs: 25,
    },
  });
}

test("APNs response classification only disables genuinely invalid tokens", () => {
  assert.deepEqual(classifyApnsResponse({ statusCode: 400, body: { reason: "BadTopic" } }), {
    outcome: "failed",
    retryable: false,
    disableToken: false,
    status: "apns_400",
    reason: "BadTopic",
  });
  assert.equal(classifyApnsResponse({ statusCode: 400, body: { reason: "BadDeviceToken" } }).disableToken, true);
  assert.equal(classifyApnsResponse({ statusCode: 410, body: { reason: "Unregistered" } }).disableToken, true);
  assert.equal(classifyApnsResponse({ statusCode: 403, body: { reason: "InvalidProviderToken" } }).disableToken, false);
  assert.equal(classifyApnsResponse({ statusCode: 503, body: { reason: "Shutdown" } }).retryable, true);
  assert.equal(classifyApnsResponse({ statusCode: 400, body: { reason: "IdleTimeout" } }).retryable, true);
  assert.equal(classifyApnsResponse({ statusCode: 0, body: null }).retryable, true);
});

test("FCM response classification disables only token-level failures", () => {
  assert.deepEqual(classifyFcmResponse({ statusCode: 200, body: { name: "messages/1" } }), {
    outcome: "sent",
    retryable: false,
    disableToken: false,
    status: "sent",
    reason: null,
  });
  assert.equal(classifyFcmResponse({
    statusCode: 404,
    body: { error: { status: "NOT_FOUND", details: [{ errorCode: "UNREGISTERED" }] } },
  }).disableToken, true);
  assert.equal(classifyFcmResponse({
    statusCode: 403,
    body: { error: { status: "PERMISSION_DENIED" } },
  }).disableToken, false);
  assert.equal(classifyFcmResponse({
    statusCode: 400,
    body: { error: { status: "INVALID_ARGUMENT", message: "Payload contains an invalid field." } },
  }).disableToken, false);
  assert.equal(classifyFcmResponse({ statusCode: 503, body: { error: { status: "UNAVAILABLE" } } }).retryable, true);
});

test("bad APNs topics fail without disabling a valid device token", async () => {
  const repository = buildRepository();
  const service = createService({
    repository,
    transport: async () => ({ statusCode: 400, body: { reason: "BadTopic" } }),
  });

  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(result.failed, 1);
  assert.equal(result.disabled, 0);
  assert.equal(result.attempts, 1);
  assert.equal(repository.attempts[0].status, "apns_400");
  assert.deepEqual(repository.disabled, []);
});

test("invalid APNs tokens are audited and disabled without retry", async () => {
  const repository = buildRepository();
  const service = createService({
    repository,
    transport: async () => ({ statusCode: 400, body: { reason: "BadDeviceToken" } }),
  });

  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(result.disabled, 1);
  assert.equal(result.retried, 0);
  assert.equal(repository.attempts[0].status, "invalid_token");
  assert.deepEqual(repository.disabled, ["device-1"]);
});

test("transient APNs failures retry within bounds and preserve the final success", async () => {
  const repository = buildRepository();
  const delays = [];
  let calls = 0;
  const service = createService({
    repository,
    transport: async ({ timeoutMs }) => {
      assert.equal(timeoutMs, 25);
      calls += 1;
      return calls === 1
        ? { statusCode: 503, retryAfter: "0", body: { reason: "Shutdown" } }
        : { statusCode: 200, apnsId: "apns-1", body: null };
    },
    sleep: async (delayMs) => delays.push(delayMs),
  });

  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(result.sent, 1);
  assert.equal(result.attempts, 2);
  assert.equal(result.retried, 1);
  assert.deepEqual(delays, [100]);
  assert.equal(repository.attempts.length, 1);
  assert.equal(repository.attempts[0].status, "sent");
});

test("network failures stop after the configured attempt bound", async () => {
  const repository = buildRepository();
  let calls = 0;
  const service = createService({
    repository,
    transport: async () => {
      calls += 1;
      throw new Error("network unavailable");
    },
  });

  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(calls, 3);
  assert.equal(result.failed, 1);
  assert.equal(result.attempts, 3);
  assert.equal(result.retried, 2);
  assert.equal(result.disabled, 0);
  assert.equal(repository.attempts[0].status, "send_failed");
});

test("policy alerts use the monitoring target app id and policy channel", async () => {
  const device = buildDevice();
  const repository = {
    ...buildRepository(device),
    async listPushDeviceSecrets({ appId }) {
      assert.equal(appId, "com.ktbatterham.securl");
      return [device];
    },
  };
  let deliveredPayload = null;
  const service = createService({
    repository,
    transport: async ({ payload }) => {
      deliveredPayload = payload;
      return { statusCode: 200, apnsId: "policy-apns", body: null };
    },
  });
  const result = await service.sendPolicyAlert({
    completedScan: { id: "scan-one" },
    target: {
      id: "target-one",
      ownerId: "owner-1",
      requesterScope: "scope-1",
      appId: "com.ktbatterham.securl",
      label: "Example",
      url: "https://example.com/",
    },
    payload: {
      type: "observation_policy_violation",
      policy: { id: "policy-one" },
      summary: { highestSeverity: "critical" },
      brief: {
        title: "Example: 1 critical new policy violation",
        body: "Certificate expired",
      },
      actions: [{ id: "review_certificate", label: "Review certificate renewal", count: 1 }],
      violations: [{ title: "Certificate expired" }],
    },
  });
  assert.equal(result.sent, 1);
  assert.equal(deliveredPayload.type, "observation_policy_violation");
  assert.equal(deliveredPayload.aps.alert.title, "Example: 1 critical new policy violation");
  assert.equal(deliveredPayload.aps.alert.body, "Certificate expired");
  assert.equal(deliveredPayload.actions[0].id, "review_certificate");
  assert.equal(deliveredPayload.aps["thread-id"], "example.com");
});

test("timeouts are retried but remain a recoverable device health failure", async () => {
  const repository = buildRepository();
  const service = createService({
    repository,
    maxAttempts: 2,
    transport: async () => {
      const error = new Error("APNs request timed out.");
      error.code = "APNS_TIMEOUT";
      throw error;
    },
  });

  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(result.attempts, 2);
  assert.equal(result.results[0].status, "timed_out");
  assert.equal(result.disabled, 0);
  assert.equal(repository.attempts[0].status, "timed_out");
});

test("per-device app ids remove the need for one global APNs topic", async () => {
  const repository = buildRepository();
  let topic = null;
  const service = createService({
    repository,
    transport: async (request) => {
      topic = request.topic;
      return { statusCode: 200, body: null };
    },
  });

  assert.equal(service.snapshot().enabled, true);
  assert.equal(service.snapshot().topicConfigured, false);
  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(result.sent, 1);
  assert.equal(topic, "com.ktbatterham.securl");
});

test("Android devices route through FCM with the existing notification payload", async () => {
  const repository = buildRepository(buildAndroidDevice());
  let delivered = null;
  const service = createFcmService({
    repository,
    fcmTransport: async (request) => {
      delivered = request;
      return { statusCode: 200, body: { name: "projects/securl-test/messages/1" } };
    },
  });

  assert.equal(service.snapshot().enabled, true);
  assert.equal(service.snapshot().providers.fcm.enabled, true);
  const result = await service.sendTestNotification({ device: buildAndroidDevice() });
  assert.equal(result.sent, 1);
  assert.equal(result.results[0].provider, "fcm");
  assert.equal(delivered.token, "f".repeat(120));
  assert.equal(delivered.payload.type, "notification_test");
  assert.equal(repository.attempts[0].status, "sent");
});

test("missing FCM credentials are reported without attempting APNs", async () => {
  const repository = buildRepository(buildAndroidDevice());
  let called = false;
  const service = createNotificationService({
    scanRepository: repository,
    fcmTransport: async () => {
      called = true;
      return { statusCode: 200, body: null };
    },
  });

  const result = await service.sendTestNotification({ device: buildAndroidDevice() });
  assert.equal(result.failed, 1);
  assert.equal(result.skipped, "fcm_not_configured");
  assert.equal(result.results[0].status, "fcm_not_configured");
  assert.equal(called, false);
});

test("missing per-device and fallback topics fail without contacting APNs", async () => {
  const repository = buildRepository();
  let called = false;
  const service = createService({
    repository,
    transport: async () => {
      called = true;
      return { statusCode: 200, body: null };
    },
  });

  const result = await service.sendTestNotification({ device: buildDevice({ appId: null }) });
  assert.equal(result.failed, 1);
  assert.equal(result.results[0].status, "missing_topic");
  assert.equal(called, false);
});

test("test notifications expose delivery telemetry without exposing tokens", async () => {
  const repository = buildRepository();
  const telemetryCalls = [];
  let deliveredPayload = null;
  const service = createService({
    repository,
    telemetry: {
      recordNotificationDelivery(value) {
        telemetryCalls.push(value);
      },
    },
    transport: async ({ payload }) => {
      deliveredPayload = payload;
      return { statusCode: 200, body: null };
    },
  });

  const result = await service.sendTestNotification({ device: buildDevice() });
  assert.equal(result.sent, 1);
  assert.equal(deliveredPayload.type, "notification_test");
  assert.equal(JSON.stringify(result).includes("a".repeat(64)), false);
  assert.equal(telemetryCalls[0].channel, "device_test");
  assert.equal(telemetryCalls[0].sent, 1);
});

test("durable outbox delivers idempotently for repeated monitoring events", async () => {
  const repository = createInMemoryScanRepository();
  await repository.upsertPushDevice({
    token: "c".repeat(64),
    appId: "com.ktbatterham.certwatch",
    requesterScope: "scope-1",
    ownerId: "owner-1",
  });
  let calls = 0;
  let deliveredPayload = null;
  const service = createService({
    repository,
    transport: async ({ payload }) => {
      calls += 1;
      deliveredPayload = payload;
      return { statusCode: 200, body: null };
    },
  });
  const input = {
    target: {
      id: "target-1",
      ownerId: "owner-1",
      requesterScope: "scope-1",
      appId: "com.ktbatterham.certwatch",
      url: "https://example.com/",
      label: "example.com",
    },
    event: {
      type: "cert_expiring",
      severity: "warning",
      title: "Certificate expiring",
      body: "12 days remain.",
      warningBand: 14,
      previous: { daysRemaining: 29, serialNumber: "ABC" },
      current: { daysRemaining: 12, serialNumber: "ABC" },
      delta: { daysRemaining: -17 },
    },
    certState: { host: "example.com", daysRemaining: 12, reachable: true },
  };

  const first = await service.notifyCertMonitoringEvent(input);
  const duplicate = await service.notifyCertMonitoringEvent(input);
  assert.equal(first.sent, 1);
  assert.equal(duplicate.skipped, "already_queued_or_processed");
  assert.equal(calls, 1);
  assert.equal(deliveredPayload.event.warningBand, 14);
  assert.equal(deliveredPayload.event.previous.daysRemaining, 29);
  assert.equal(deliveredPayload.event.current.daysRemaining, 12);
  assert.equal(deliveredPayload.event.delta.daysRemaining, -17);
  assert.equal(deliveredPayload.monitoringEvent, null);
  assert.equal((await repository.getNotificationOutboxStats()).byStatus.sent, 1);
});

test("certificate monitoring pushes include enriched monitoring event copy when available", async () => {
  const repository = createInMemoryScanRepository();
  await repository.upsertPushDevice({
    token: "e".repeat(64),
    appId: "com.ktbatterham.certwatch",
    requesterScope: "scope-1",
    ownerId: "owner-1",
  });
  let deliveredPayload = null;
  const service = createService({
    repository,
    transport: async ({ payload }) => {
      deliveredPayload = payload;
      return { statusCode: 200, body: null };
    },
  });

  await service.notifyCertMonitoringEvent({
    target: {
      id: "target-1",
      ownerId: "owner-1",
      requesterScope: "scope-1",
      appId: "com.ktbatterham.certwatch",
      url: "https://example.com/",
      label: "example.com",
    },
    event: {
      type: "cert_expired",
      severity: "critical",
      title: "Certificate expired",
      body: "The certificate has expired.",
      monitoringEvent: {
        id: "certificate_expired:example.com:443",
        source: "certificate",
        eventType: "certificate_expired",
        severity: "critical",
        title: "Certificate expired",
        message: "example.com is serving an expired certificate.",
        nextAction: "Renew the certificate and verify the deployed chain.",
        changedEvidence: [{ label: "Days remaining", previous: 1, current: -1 }],
        dedupeKey: "certificate_expired:example.com:443",
        push: {
          title: "Certificate expired: example.com",
          body: "Renew the certificate and verify the deployed chain.",
        },
      },
    },
    certState: { host: "example.com", daysRemaining: -1, reachable: true },
  });

  assert.equal(deliveredPayload.aps.alert.title, "Certificate expired: example.com");
  assert.equal(deliveredPayload.targetId, "target-1");
  assert.equal(deliveredPayload.eventId, "certificate_expired:example.com:443");
  assert.deepEqual(deliveredPayload.deepLink, {
    route: "monitoring_target",
    targetId: "target-1",
    eventId: "certificate_expired:example.com:443",
  });
  assert.equal(deliveredPayload.monitoringEvent.eventType, "certificate_expired");
  assert.equal(deliveredPayload.monitoringEvent.changedEvidence[0].label, "Days remaining");
  assert.equal(deliveredPayload.event.type, "cert_expired");
});

test("posture monitoring pushes include target and event navigation identity", async () => {
  const repository = createInMemoryScanRepository();
  await repository.upsertPushDevice({
    token: "f".repeat(64),
    appId: "com.ktbatterham.headerwatch",
    requesterScope: "scope-1",
    ownerId: "owner-1",
  });
  const result = (scannedAt, score, grade) => ({
    finalUrl: "https://example.com/",
    host: "example.com",
    scannedAt,
    score,
    grade,
    statusCode: 200,
    responseTimeMs: 100,
    certificate: { available: true, valid: true, authorized: true, daysRemaining: 90, issues: [] },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  });
  const previous = await repository.createScan({
    url: "https://example.com/",
    mode: "quiet",
    requesterScope: "scope-1",
    clientIp: "monitoring-scheduler",
    ownerId: "owner-1",
  });
  await repository.markCompleted(previous.id, result("2026-07-11T08:00:00.000Z", 92, "A"));
  const current = await repository.createScan({
    url: "https://example.com/",
    mode: "quiet",
    requesterScope: "scope-1",
    clientIp: "monitoring-scheduler",
    ownerId: "owner-1",
  });
  const currentResult = result("2026-07-12T08:00:00.000Z", 60, "D");
  const completedScan = await repository.markCompleted(current.id, currentResult);
  let deliveredPayload = null;
  const service = createService({
    repository,
    transport: async ({ payload }) => {
      deliveredPayload = payload;
      return { statusCode: 200, body: null };
    },
  });

  const delivery = await service.notifyMonitoringScanCompleted({
    completedScan,
    result: currentResult,
    telemetryContext: { channel: "monitoring_scheduler", targetId: "target-posture-1" },
  });

  assert.equal(delivery.sent, 1);
  assert.equal(deliveredPayload.targetId, "target-posture-1");
  assert.equal(deliveredPayload.eventId, deliveredPayload.monitoringEvents[0].id);
  assert.deepEqual(deliveredPayload.deepLink, {
    route: "monitoring_target",
    targetId: "target-posture-1",
    eventId: deliveredPayload.eventId,
  });
});

test("durable outbox drains work left behind by an interrupted worker", async () => {
  const repository = createInMemoryScanRepository();
  await repository.upsertPushDevice({
    token: "d".repeat(64),
    appId: "com.ktbatterham.securl",
    requesterScope: "scope-1",
    ownerId: "owner-1",
  });
  const [device] = await repository.listPushDeviceSecrets({ ownerId: "owner-1" });
  await repository.enqueueNotificationOutbox({
    devices: [device],
    payload: { aps: { alert: { title: "Recovered", body: "Delivered after restart." } }, type: "monitoring_drift" },
    referenceId: "scan-recovery",
    channel: "monitoring_posture",
  });
  let calls = 0;
  const service = createService({
    repository,
    transport: async () => {
      calls += 1;
      return { statusCode: 200, body: null };
    },
  });

  const summary = await service.drainOutbox();
  assert.equal(summary.claimed, 1);
  assert.equal(summary.sent, 1);
  assert.equal(calls, 1);
  assert.equal((await repository.getNotificationOutboxStats()).byStatus.sent, 1);
});
