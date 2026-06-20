import assert from "node:assert/strict";
import test from "node:test";
import { classifyApnsResponse, createNotificationService } from "../notificationService.mjs";

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
