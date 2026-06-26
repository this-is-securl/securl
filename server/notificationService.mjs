import crypto from "node:crypto";
import http2 from "node:http2";
import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";
import { buildPostureRiskEventsFromDiff } from "../packages/core/dist/riskEvents.js";

function base64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function privateKeyFromEnv(value) {
  if (!value) {
    return "";
  }
  return String(value).includes("\\n") ? String(value).replace(/\\n/g, "\n") : String(value);
}

function buildApnsJwt({ teamId, keyId, privateKey }) {
  const header = base64Url(JSON.stringify({ alg: "ES256", kid: keyId }));
  const claims = base64Url(JSON.stringify({ iss: teamId, iat: Math.floor(Date.now() / 1000) }));
  const signingInput = `${header}.${claims}`;
  const signature = crypto.sign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${base64Url(signature)}`;
}

function apnsHost(environment) {
  return environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";
}

const INVALID_TOKEN_REASONS = new Set([
  "BadDeviceToken",
  "DeviceTokenNotForTopic",
  "Unregistered",
]);
const TRANSIENT_STATUS_CODES = new Set([429, 500, 503]);

function parseApnsBody(body) {
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch {
    return { reason: String(body).slice(0, 500) };
  }
}

export function classifyApnsResponse(response = {}) {
  const statusCode = Number(response.statusCode || 0);
  const reason = typeof response.body?.reason === "string" ? response.body.reason : null;
  if (statusCode >= 200 && statusCode < 300) {
    return { outcome: "sent", retryable: false, disableToken: false, status: "sent", reason: null };
  }
  if (statusCode === 410 || INVALID_TOKEN_REASONS.has(reason)) {
    return { outcome: "failed", retryable: false, disableToken: true, status: "invalid_token", reason };
  }
  const retryable = statusCode === 0
    || TRANSIENT_STATUS_CODES.has(statusCode)
    || statusCode >= 500
    || reason === "IdleTimeout";
  return {
    outcome: "failed",
    retryable,
    disableToken: false,
    status: `apns_${statusCode || "unknown"}`,
    reason,
  };
}

async function sendApns({ token, environment, topic, payload, config, timeoutMs = 10_000, collapseId = null, expiration = 0 }) {
  const jwt = buildApnsJwt(config);
  const client = http2.connect(apnsHost(environment));
  let timeout = null;

  try {
    return await Promise.race([
      (async () => {
        await new Promise((resolve, reject) => {
          client.once("error", reject);
          client.once("connect", resolve);
        });
        return await new Promise((resolve, reject) => {
          const headers = {
            ":method": "POST",
            ":path": `/3/device/${token}`,
            authorization: `bearer ${jwt}`,
            "apns-topic": topic,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "apns-expiration": String(expiration),
            "content-type": "application/json",
          };
          if (collapseId) headers["apns-collapse-id"] = collapseId;
          const apnsRequest = client.request(headers);
          let body = "";
          let statusCode = 0;
          let apnsId = null;
          let retryAfter = null;
          apnsRequest.setEncoding("utf8");
          apnsRequest.on("data", (chunk) => {
            body += chunk;
          });
          apnsRequest.on("response", (headers) => {
            statusCode = Number(headers[":status"] || 0);
            apnsId = headers["apns-id"] ?? null;
            retryAfter = headers["retry-after"] ?? null;
          });
          apnsRequest.on("error", reject);
          apnsRequest.on("end", () => {
            resolve({ statusCode, apnsId, retryAfter, body: parseApnsBody(body) });
          });
          apnsRequest.end(JSON.stringify(payload));
        });
      })(),
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          const error = new Error(`APNs request timed out after ${timeoutMs}ms.`);
          error.code = "APNS_TIMEOUT";
          client.destroy(error);
          reject(error);
        }, timeoutMs);
        timeout.unref?.();
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
    client.close();
  }
}

function buildNotificationChangeSummary(diff, riskEvents) {
  const changes = [];
  if (diff.previousGrade !== diff.currentGrade) {
    changes.push(`grade ${diff.previousGrade ?? "unknown"} to ${diff.currentGrade ?? "unknown"}`);
  }
  if (typeof diff.scoreDelta === "number" && diff.scoreDelta !== 0) {
    changes.push(`score ${diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta}`);
  }
  if (diff.headerChanges?.length) {
    changes.push(`${diff.headerChanges.length} header change${diff.headerChanges.length === 1 ? "" : "s"}`);
  }
  if (diff.certificateDaysRemainingDelta?.delta) {
    changes.push("certificate window changed");
  }
  if (riskEvents?.length && changes.length === 0) {
    changes.push(riskEvents[0].title);
  }
  return changes;
}

function retryDelayMs(attempt, response) {
  const retryAfterSeconds = Number(response?.retryAfter);
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds >= 0) {
    return Math.min(5_000, Math.max(100, Math.round(retryAfterSeconds * 1_000)));
  }
  return attempt <= 1 ? 250 : 750;
}

async function buildMonitoringPushPayload({ scanRepository, completedScan, result }) {
  const records = await scanRepository.listPersistedRecords({
    ownerId: completedScan.ownerId,
    requesterScope: completedScan.ownerId ? null : completedScan.requesterScope,
    url: completedScan.url,
    limit: 5,
  });
  const completed = records.filter((record) => record.status === "completed" && record.result);
  if (completed.length < 2) {
    return null;
  }

  const [current, previous] = completed;
  const diff = buildHistoryDiffFromSnapshots(snapshotFromAnalysis(current.result), snapshotFromAnalysis(previous.result));
  const riskEvents = buildPostureRiskEventsFromDiff(diff);
  const changes = buildNotificationChangeSummary(diff, riskEvents);
  if (changes.length === 0) {
    return null;
  }

  const host = result.host || new URL(completedScan.url).hostname;
  return {
    aps: {
      alert: {
        title: `SecURL changed: ${host}`,
        body: changes.slice(0, 2).join(", "),
      },
      sound: "default",
      "thread-id": host,
    },
    type: "monitoring_drift",
    scanId: completedScan.id,
    url: completedScan.url,
    host,
    grade: result.grade,
    score: result.score,
    changes,
    riskEvents: riskEvents.slice(0, 5).map((event) => ({
      eventType: event.eventType,
      severity: event.severity,
      title: event.title,
    })),
  };
}

export function createNotificationService({
  scanRepository,
  log = () => {},
  apns = {},
  telemetry = null,
  transport = sendApns,
  sleep = (delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs)),
} = {}) {
  const explicitTimeoutMs = Number(apns.timeoutMs);
  const environmentTimeoutMs = Number(process.env.APNS_TIMEOUT_MS);
  const configuredMaxAttempts = Number(apns.maxAttempts ?? process.env.APNS_MAX_ATTEMPTS);
  const config = {
    teamId: apns.teamId || process.env.APNS_TEAM_ID || "",
    keyId: apns.keyId || process.env.APNS_KEY_ID || "",
    privateKey: privateKeyFromEnv(apns.privateKey || process.env.APNS_PRIVATE_KEY || ""),
    defaultTopic: apns.topic || process.env.APNS_BUNDLE_ID || "",
    timeoutMs: Number.isFinite(explicitTimeoutMs)
      ? Math.max(1, Math.floor(explicitTimeoutMs))
      : Number.isFinite(environmentTimeoutMs)
      ? Math.max(1_000, Math.floor(environmentTimeoutMs))
      : 10_000,
    maxAttempts: Number.isFinite(configuredMaxAttempts) ? Math.min(5, Math.max(1, Math.floor(configuredMaxAttempts))) : 3,
  };
  const enabled = Boolean(config.teamId && config.keyId && config.privateKey);
  const outboxEnabled = Boolean(
    scanRepository?.enqueueNotificationOutbox
    && scanRepository?.claimNotificationOutbox
    && scanRepository?.completeNotificationOutbox,
  );
  const outboxWorkerId = `notification:${process.pid}:${crypto.randomUUID()}`;
  const outboxLeaseMs = 60_000;
  const outboxMaxAttempts = 5;
  let outboxTimer = null;
  let outboxRunning = false;
  let outboxLastDrain = null;

  function recordDeliveryTelemetry(result, channel) {
    telemetry?.recordNotificationDelivery?.({
      channel,
      attempted: result.attempted,
      attempts: result.attempts,
      sent: result.sent,
      failed: result.failed,
      disabled: result.disabled,
      retried: result.retried,
      skipped: result.skipped,
    });
  }

  async function deliverPushPayload({
    devices,
    payload,
    referenceId,
    logEventName = "push_delivery_result",
    channel = "monitoring",
    claimedEntries = null,
    persistToOutbox = true,
  }) {
    if (!devices.length) {
      const result = { attempted: 0, attempts: 0, sent: 0, failed: 0, disabled: 0, retried: 0, skipped: "no_devices", results: [] };
      recordDeliveryTelemetry(result, channel);
      return result;
    }
    let outboxEntries = Array.isArray(claimedEntries) ? claimedEntries : [];
    let deliveryDevices = devices;
    if (outboxEnabled && persistToOutbox) {
      const queuedEntries = await scanRepository.enqueueNotificationOutbox({
        devices,
        payload,
        referenceId,
        channel,
      });
      outboxEntries = await scanRepository.claimNotificationOutbox({
        workerId: outboxWorkerId,
        ids: queuedEntries.map((entry) => entry.id),
        limit: queuedEntries.length,
        leaseMs: outboxLeaseMs,
      });
      const claimedDeviceIds = new Set(outboxEntries.map((entry) => entry.deviceId));
      deliveryDevices = devices.filter((device) => claimedDeviceIds.has(device.id));
      if (!deliveryDevices.length) {
        const result = { attempted: 0, attempts: 0, sent: 0, failed: 0, disabled: 0, retried: 0, skipped: "already_queued_or_processed", results: [] };
        recordDeliveryTelemetry(result, channel);
        return result;
      }
    }
    const outboxByDeviceId = new Map(outboxEntries.map((entry) => [entry.deviceId, entry]));

    if (!enabled) {
      log("warn", "push_delivery_skipped", {
        reason: "apns_not_configured",
        referenceId,
        devices: deliveryDevices.length,
      });
      for (const entry of outboxEntries) {
        const retryLater = channel !== "device_test";
        await scanRepository.completeNotificationOutbox(entry.id, {
          status: retryLater ? "queued" : "skipped",
          error: "APNs credentials are not configured.",
          availableAt: retryLater ? new Date(Date.now() + 15 * 60_000).toISOString() : null,
          workerId: outboxWorkerId,
        });
      }
      const result = { attempted: deliveryDevices.length, attempts: 0, sent: 0, failed: 0, disabled: 0, retried: 0, skipped: "apns_not_configured", results: [] };
      recordDeliveryTelemetry(result, channel);
      return result;
    }

    let sent = 0;
    let failed = 0;
    let disabled = 0;
    let attempts = 0;
    let retried = 0;
    const results = [];
    for (const device of deliveryDevices) {
      const attemptedAt = new Date().toISOString();
      const topic = device.appId || config.defaultTopic;
      let finalClassification = null;
      let finalResponse = null;
      let deviceAttempts = 0;

      if (!topic) {
        finalClassification = {
          outcome: "failed",
          retryable: false,
          disableToken: false,
          status: "missing_topic",
          reason: "No APNs topic is configured for this device.",
        };
      } else {
        for (let attempt = 1; attempt <= config.maxAttempts; attempt += 1) {
          deviceAttempts += 1;
          attempts += 1;
          try {
            finalResponse = await transport({
              token: device.token,
              environment: device.environment,
              topic,
              payload,
              config,
              timeoutMs: config.timeoutMs,
              collapseId: crypto.createHash("sha256").update(String(referenceId)).digest("hex").slice(0, 64),
              expiration: payload?.type === "notification_test" ? 0 : Math.floor(Date.now() / 1000) + 60 * 60,
            });
            finalClassification = classifyApnsResponse(finalResponse);
          } catch (error) {
            finalResponse = null;
            finalClassification = {
              outcome: "failed",
              retryable: true,
              disableToken: false,
              status: error?.code === "APNS_TIMEOUT" ? "timed_out" : "send_failed",
              reason: error instanceof Error ? error.message : String(error),
            };
          }

          log(finalClassification.outcome === "sent" ? "info" : "warn", logEventName, {
            referenceId,
            deviceId: device.id,
            attempt,
            status: finalClassification.status,
            statusCode: finalResponse?.statusCode ?? null,
            apnsId: finalResponse?.apnsId ?? null,
            retryable: finalClassification.retryable,
          });

          if (finalClassification.outcome === "sent" || !finalClassification.retryable || attempt >= config.maxAttempts) {
            break;
          }
          retried += 1;
          await sleep(retryDelayMs(attempt, finalResponse));
        }
      }

      const deliveryError = finalClassification.reason ? String(finalClassification.reason).slice(0, 500) : null;
      const wasSent = finalClassification.outcome === "sent";
      if (wasSent) sent += 1;
      else failed += 1;

      await scanRepository.recordPushDeliveryAttempt?.(device.id, {
        ownerId: device.ownerId,
        requesterScope: device.ownerId ? null : device.requesterScope,
        attemptedAt,
        sentAt: wasSent ? attemptedAt : null,
        status: finalClassification.status,
        error: deliveryError,
      });
      if (finalClassification.disableToken) {
        const didDisable = await scanRepository.disablePushDevice(device.id, {
          ownerId: device.ownerId,
          requesterScope: device.ownerId ? null : device.requesterScope,
        });
        if (didDisable) disabled += 1;
      }
      results.push({
        deviceId: device.id,
        status: finalClassification.status,
        reason: deliveryError,
        attempts: deviceAttempts,
        disabled: finalClassification.disableToken,
      });
      const outboxEntry = outboxByDeviceId.get(device.id);
      if (outboxEntry) {
        const retryOutbox = finalClassification.retryable
          && outboxEntry.attempts < outboxMaxAttempts
          && channel !== "device_test";
        await scanRepository.completeNotificationOutbox(outboxEntry.id, {
          status: wasSent ? "sent" : retryOutbox ? "queued" : "failed",
          error: deliveryError,
          availableAt: retryOutbox
            ? new Date(Date.now() + Math.min(15 * 60_000, 30_000 * outboxEntry.attempts)).toISOString()
            : null,
          workerId: outboxWorkerId,
        });
      }
    }

    const result = { attempted: deliveryDevices.length, attempts, sent, failed, disabled, retried, skipped: null, results };
    recordDeliveryTelemetry(result, channel);
    return result;
  }

  async function notifyMonitoringScanCompleted({ completedScan, result, telemetryContext = {} }) {
    if (telemetryContext.channel !== "monitoring_scheduler") {
      return { attempted: 0, sent: 0, skipped: "not_monitoring_scheduler" };
    }

    const payload = await buildMonitoringPushPayload({ scanRepository, completedScan, result });
    if (!payload) {
      return { attempted: 0, sent: 0, skipped: "no_drift" };
    }

    const devices = await scanRepository.listPushDeviceSecrets({
      ownerId: completedScan.ownerId,
      requesterScope: completedScan.ownerId ? null : completedScan.requesterScope,
      limit: 50,
    });
    if (!devices.length) {
      return { attempted: 0, sent: 0, skipped: "no_devices" };
    }

    return deliverPushPayload({
      devices,
      payload,
      referenceId: completedScan.id,
      channel: "monitoring_posture",
    });
  }

  async function notifyCertMonitoringEvent({ target, event, certState }) {
    if (!event || !target) {
      return { attempted: 0, sent: 0, skipped: "no_event" };
    }

    const devices = await scanRepository.listPushDeviceSecrets({
      ownerId: target.ownerId,
      requesterScope: target.ownerId ? null : target.requesterScope,
      appId: target.appId ?? null,
      limit: 50,
    });
    const host = certState?.host || target.label || target.url;
    const payload = {
      aps: {
        alert: {
          title: event.title,
          body: event.body,
        },
        sound: "default",
        "thread-id": host,
      },
      type: event.type,
      targetId: target.id,
      url: target.url,
      host,
      appId: target.appId ?? null,
      severity: event.severity,
      event: {
        type: event.type,
        severity: event.severity,
        warningBand: event.warningBand ?? null,
        previous: event.previous ?? null,
        current: event.current ?? null,
        delta: event.delta ?? null,
      },
      certificate: {
        issuer: certState?.issuer ?? null,
        serialNumber: certState?.serialNumber ?? null,
        validTo: certState?.validTo ?? null,
        daysRemaining: certState?.daysRemaining ?? null,
        reachable: certState?.reachable ?? false,
      },
    };

    return deliverPushPayload({
      devices,
      payload,
      referenceId: target.id,
      logEventName: "cert_push_delivery_result",
      channel: "monitoring_certificate",
    });
  }

  async function sendTestNotification({ device }) {
    const appName = device.appId || "SecURL";
    return deliverPushPayload({
      devices: [device],
      payload: {
        aps: {
          alert: {
            title: "SecURL notifications are ready",
            body: `Test notification for ${appName}.`,
          },
          sound: "default",
        },
        type: "notification_test",
        appId: device.appId ?? null,
      },
      referenceId: `test:${device.id}:${crypto.randomUUID()}`,
      logEventName: "test_push_delivery_result",
      channel: "device_test",
    });
  }

  async function sendPolicyAlert({ completedScan, target, payload }) {
    const devices = await scanRepository.listPushDeviceSecrets({
      ownerId: target.ownerId,
      requesterScope: target.ownerId ? null : target.requesterScope,
      appId: target.appId ?? null,
      limit: 50,
    });
    const highest = payload.summary?.highestSeverity || "warning";
    const first = payload.violations?.[0]?.title || "Monitoring policy failed";
    const title = payload.brief?.title || `SecURL ${highest}: ${target.label}`;
    const body = payload.brief?.body || (payload.violations.length > 1 ? `${first} and ${payload.violations.length - 1} more.` : first);
    return deliverPushPayload({
      devices,
      payload: {
        aps: {
          alert: {
            title,
            body,
          },
          sound: highest === "critical" ? "default" : undefined,
          "thread-id": new URL(target.url).hostname,
        },
        ...payload,
      },
      referenceId: `${completedScan.id}:${payload.policy.id}`,
      logEventName: "policy_push_delivery_result",
      channel: "monitoring_policy",
    });
  }

  async function drainOutbox({ limit = 20 } = {}) {
    if (!outboxEnabled || outboxRunning) return outboxLastDrain;
    outboxRunning = true;
    const summary = { claimed: 0, sent: 0, failed: 0, skipped: 0 };
    try {
      const entries = await scanRepository.claimNotificationOutbox({
        workerId: outboxWorkerId,
        limit,
        leaseMs: outboxLeaseMs,
      });
      summary.claimed = entries.length;
      for (const entry of entries) {
        const device = await scanRepository.getPushDeviceSecret?.(entry.deviceId, {
          ownerId: entry.ownerId,
          requesterScope: entry.ownerId ? null : entry.requesterScope,
        });
        if (!device) {
          await scanRepository.completeNotificationOutbox(entry.id, {
            status: "skipped",
            error: "Notification device is unavailable or disabled.",
            workerId: outboxWorkerId,
          });
          summary.skipped += 1;
          continue;
        }
        const result = await deliverPushPayload({
          devices: [device],
          payload: entry.payload,
          referenceId: entry.referenceId,
          channel: entry.channel,
          claimedEntries: [entry],
          persistToOutbox: false,
        });
        summary.sent += result.sent;
        summary.failed += result.failed;
      }
      const pruned = await scanRepository.pruneNotificationOutbox?.();
      summary.pruned = Number(pruned || 0);
      summary.stats = await scanRepository.getNotificationOutboxStats?.();
      outboxLastDrain = { ...summary, completedAt: new Date().toISOString() };
      return outboxLastDrain;
    } finally {
      outboxRunning = false;
    }
  }

  function start() {
    if (!outboxEnabled || outboxTimer) return false;
    outboxTimer = setInterval(() => {
      void drainOutbox().catch((error) => {
        log("error", "notification_outbox_drain_failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      });
    }, 15_000);
    outboxTimer.unref?.();
    queueMicrotask(() => void drainOutbox().catch(() => {}));
    return true;
  }

  function stop() {
    if (!outboxTimer) return false;
    clearInterval(outboxTimer);
    outboxTimer = null;
    return true;
  }

  return {
    enabled,
    notifyMonitoringScanCompleted,
    notifyCertMonitoringEvent,
    sendTestNotification,
    sendPolicyAlert,
    drainOutbox,
    start,
    stop,
    snapshot() {
      return {
        enabled,
        provider: "apns",
        credentialsConfigured: enabled,
        topicConfigured: Boolean(config.defaultTopic),
        timeoutMs: config.timeoutMs,
        maxAttempts: config.maxAttempts,
        outbox: {
          enabled: outboxEnabled,
          running: outboxRunning,
          lastDrain: outboxLastDrain,
        },
      };
    },
  };
}
