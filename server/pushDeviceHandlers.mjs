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

    sendJson(response, 201, {
      apiVersion: API_VERSION,
      device,
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, "upsert_push_device");
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
}) {
  const match = requestUrl.pathname.match(/^\/api\/notification-devices\/([^/]+)$/);
  if (!match) {
    sendJson(response, 404, {
      error: "Notification device not found.",
    });
    return true;
  }

  if (request.method !== "DELETE") {
    sendMethodNotAllowed(response, ["DELETE"]);
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
