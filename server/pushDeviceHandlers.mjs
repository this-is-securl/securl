import { API_VERSION } from "./scanDtos.mjs";

const TOKEN_PATTERN = /^[a-f0-9]{64,200}$/i;

function normalizeEnvironment(value) {
  return value === "sandbox" ? "sandbox" : "production";
}

function normalizePlatform(value) {
  return value === "ios" || value === "ipados" ? value : "ios";
}

function clampLimit(value, fallback = 50, max = 100) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(1, Math.floor(parsed)));
}

const STALE_DEVICE_AFTER_MS = 30 * 24 * 60 * 60 * 1000;
const APNS_REJECTION_STATUSES = new Set(["invalid_token", "apns_410"]);
const APNS_TRANSIENT_STATUSES = new Set(["send_failed", "timed_out", "apns_429", "apns_500", "apns_503"]);

export function classifyDeviceHealth(device, now = Date.now()) {
  if (device.disabledAt) {
    return {
      status: "disabled",
      stale: false,
      needsRegistration: true,
      reason: "device_disabled",
    };
  }

  if (APNS_REJECTION_STATUSES.has(device.lastPushStatus)) {
    return {
      status: "rejected",
      stale: false,
      needsRegistration: true,
      reason: device.lastPushStatus,
    };
  }

  const lastSeenTime = device.lastSeenAt ? new Date(device.lastSeenAt).getTime() : NaN;
  const stale = !Number.isFinite(lastSeenTime) || now - lastSeenTime > STALE_DEVICE_AFTER_MS;
  if (stale) {
    return {
      status: "stale",
      stale: true,
      needsRegistration: true,
      reason: "last_seen_stale",
    };
  }

  if (APNS_TRANSIENT_STATUSES.has(device.lastPushStatus) || /^apns_(?:[45]\d\d|unknown)$/.test(device.lastPushStatus || "")) {
    return {
      status: "push_failed",
      stale: false,
      needsRegistration: false,
      reason: "last_push_failed",
    };
  }

  return {
    status: "ready",
    stale: false,
    needsRegistration: false,
    reason: null,
  };
}

export async function handlePushDeviceCollectionRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  readJsonBody,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  telemetry = null,
  readClientMetadata = null,
}) {
  if (request.method === "GET") {
    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
      enforceRateLimit: false,
      requireScanOwner: true,
    });
    if (!authState) {
      return true;
    }

    try {
      const devices = await scanRepository.listPushDevices({
        ownerId: authState.ownerId,
        requesterScope: authState.ownerId ? null : authState.requesterScope,
        limit: clampLimit(requestUrl.searchParams.get("limit")),
      });
      sendJson(response, 200, {
        apiVersion: API_VERSION,
        devices,
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "list_push_devices");
    }
    return true;
  }

  if (request.method !== "POST") {
    sendMethodNotAllowed(response, ["GET", "POST"]);
    return true;
  }

  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
    requireScanOwner: true,
  });
  if (!authState) {
    return true;
  }

  try {
    const body = await readJsonBody(request);
    const token = typeof body.apnsToken === "string" ? body.apnsToken.trim() : "";
    if (!TOKEN_PATTERN.test(token)) {
      sendJson(response, 400, {
        error: "A valid APNs device token is required.",
      });
      return true;
    }

    const device = await scanRepository.upsertPushDevice({
      platform: normalizePlatform(body.platform),
      token,
      appId: typeof body.appId === "string" && body.appId.trim() ? body.appId.trim().slice(0, 200) : null,
      environment: normalizeEnvironment(body.environment),
      requesterScope: authState.requesterScope,
      ownerId: authState.ownerId,
    });
    const clientMetadata = readClientMetadata?.(request, { fallbackClient: device.appId }) || {};
    telemetry?.recordFunnelEvent?.({
      event: "notification_device_registered",
      source: "backend_api",
      mode: device.appId || "unknown",
      client: clientMetadata.client,
      clientVersion: clientMetadata.version,
    });

    sendJson(response, 201, {
      apiVersion: API_VERSION,
      device,
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, "upsert_push_device");
  }

  return true;
}

export async function handlePushDeviceHealthRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  telemetry = null,
  readClientMetadata = null,
}) {
  if (request.method !== "GET") {
    sendMethodNotAllowed(response, ["GET"]);
    return true;
  }

  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
    enforceRateLimit: false,
    requireScanOwner: true,
  });
  if (!authState) {
    return true;
  }

  try {
    const devices = await scanRepository.listPushDevices({
      ownerId: authState.ownerId,
      requesterScope: authState.ownerId ? null : authState.requesterScope,
      limit: clampLimit(requestUrl.searchParams.get("limit"), 100, 250),
    });
    const clientMetadata = readClientMetadata?.(request) || {};
    telemetry?.recordFunnelEvent?.({
      event: "notification_device_health_read",
      source: "backend_api",
      client: clientMetadata.client,
      clientVersion: clientMetadata.version,
    });
    const activeDevices = devices.filter((device) => !device.disabledAt);
    const now = Date.now();
    const deviceHealth = new Map(
      activeDevices.map((device) => [device.id, classifyDeviceHealth(device, now)]),
    );
    const byAppId = {};
    const byStatus = {
      ready: 0,
      stale: 0,
      push_failed: 0,
      rejected: 0,
      disabled: 0,
    };
    for (const device of activeDevices) {
      const key = device.appId || "unknown";
      byAppId[key] = (byAppId[key] ?? 0) + 1;
      const health = deviceHealth.get(device.id);
      if (health?.status in byStatus) {
        byStatus[health.status] += 1;
      }
    }

    sendJson(response, 200, {
      apiVersion: API_VERSION,
      health: {
        registeredDevices: devices.length,
        activeDevices: activeDevices.length,
        readyDevices: byStatus.ready,
        staleDevices: byStatus.stale,
        devicesNeedingRegistration: activeDevices.filter((device) =>
          deviceHealth.get(device.id)?.needsRegistration,
        ).length,
        byAppId,
        byStatus,
        staleAfterDays: Math.round(STALE_DEVICE_AFTER_MS / (24 * 60 * 60 * 1000)),
        lastSeenAt: activeDevices[0]?.lastSeenAt ?? null,
        lastPushAttemptedAt: activeDevices.find((device) => device.lastPushAttemptedAt)?.lastPushAttemptedAt ?? null,
        lastPushSentAt: activeDevices.find((device) => device.lastPushSentAt)?.lastPushSentAt ?? null,
      },
      devices: activeDevices.map((device) => ({
        ...deviceHealth.get(device.id),
        id: device.id,
        platform: device.platform,
        appId: device.appId,
        environment: device.environment,
        lastSeenAt: device.lastSeenAt,
        lastPushAttemptedAt: device.lastPushAttemptedAt,
        lastPushSentAt: device.lastPushSentAt,
        lastPushStatus: device.lastPushStatus,
        lastPushError: device.lastPushError,
      })),
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, "notification_device_health");
  }

  return true;
}

export async function handlePushDeviceItemRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  notificationService = null,
  telemetry = null,
  readClientMetadata = null,
}) {
  const match = requestUrl.pathname.match(/^\/api\/notification-devices\/([^/]+)(?:\/(test))?$/);
  if (!match) {
    sendJson(response, 404, {
      error: "Notification device not found.",
    });
    return true;
  }

  const action = match[2] || null;
  const expectedMethod = action === "test" ? "POST" : "DELETE";
  if (request.method !== expectedMethod) {
    sendMethodNotAllowed(response, [expectedMethod]);
    return true;
  }

  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
    requireScanOwner: true,
  });
  if (!authState) {
    return true;
  }

  try {
    if (action === "test") {
      const device = await scanRepository.getPushDeviceSecret(match[1], {
        ownerId: authState.ownerId,
        requesterScope: authState.ownerId ? null : authState.requesterScope,
      });
      if (!device) {
        sendJson(response, 404, { error: "Notification device not found." });
        return true;
      }
      if (!notificationService?.sendTestNotification) {
        sendJson(response, 503, { error: "Notification delivery is unavailable." });
        return true;
      }

      const delivery = await notificationService.sendTestNotification({ device });
      const clientMetadata = readClientMetadata?.(request, { fallbackClient: device.appId }) || {};
      telemetry?.recordFunnelEvent?.({
        event: "notification_test_requested",
        source: "backend_api",
        mode: device.appId || "unknown",
        client: clientMetadata.client,
        clientVersion: clientMetadata.version,
      });
      sendJson(response, delivery.sent === 1 ? 200 : 503, {
        apiVersion: API_VERSION,
        delivered: delivery.sent === 1,
        delivery,
      });
      return true;
    }

    const deleted = await scanRepository.disablePushDevice(match[1], {
      ownerId: authState.ownerId,
      requesterScope: authState.ownerId ? null : authState.requesterScope,
    });
    if (!deleted) {
      sendJson(response, 404, {
        error: "Notification device not found.",
      });
      return true;
    }
    sendJson(response, 200, {
      apiVersion: API_VERSION,
      deleted: true,
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, "delete_push_device");
  }

  return true;
}
