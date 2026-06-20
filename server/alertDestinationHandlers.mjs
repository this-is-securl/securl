import crypto from "node:crypto";
import { assertPublicRequestTarget } from "../packages/core/dist/network-validation.js";
import { API_VERSION } from "./scanDtos.mjs";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_DESTINATIONS_PER_OWNER = 10;

function clampLimit(value, fallback = 50, max = 100) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(1, Math.floor(parsed))) : fallback;
}

async function normalizeDestination(body) {
  const type = body.type === "email" ? "email" : body.type === "webhook" ? "webhook" : null;
  if (!type) throw new Error("Alert destination type must be webhook or email.");
  const label = typeof body.label === "string" && body.label.trim() ? body.label.trim().slice(0, 120) : type;
  if (type === "email") {
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (!EMAIL_PATTERN.test(email) || email.length > 254) throw new Error("A valid alert email address is required.");
    return { type, label, email, endpoint: null, signingSecret: null };
  }
  const endpoint = new URL(typeof body.url === "string" ? body.url : "");
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash || endpoint.search) {
    throw new Error("Webhook destinations require an HTTPS URL without credentials, query parameters, or fragments.");
  }
  if (endpoint.toString().length > 2048) throw new Error("Webhook destination URL is too long.");
  await assertPublicRequestTarget(endpoint);
  return {
    type,
    label,
    endpoint: endpoint.toString(),
    email: null,
    signingSecret: crypto.randomBytes(32).toString("hex"),
  };
}

export async function handleAlertDestinationCollectionRequest({
  request, response, requestUrl, scanRepository, authorizeAnalysisRequest, readJsonBody,
  sendJson, sendMethodNotAllowed, sendRepositoryUnavailable,
}) {
  if (!["GET", "POST"].includes(request.method)) {
    sendMethodNotAllowed(response, ["GET", "POST"]);
    return true;
  }
  const authState = await authorizeAnalysisRequest({
    request, response, requestPath: requestUrl.pathname,
    enforceRateLimit: request.method === "GET" ? false : undefined,
    requireScanOwner: true,
  });
  if (!authState) return true;
  if (!["session", "api-key"].includes(authState.authMode)) {
    sendJson(response, 403, { error: "Alert destinations require an authenticated account or user API key." });
    return true;
  }
  try {
    if (request.method === "GET") {
      const destinations = await scanRepository.listAlertDestinations({
        ownerId: authState.ownerId,
        requesterScope: authState.ownerId ? null : authState.requesterScope,
        limit: clampLimit(requestUrl.searchParams.get("limit")),
      });
      sendJson(response, 200, { apiVersion: API_VERSION, destinations });
      return true;
    }
    const normalized = await normalizeDestination(await readJsonBody(request));
    const existing = await scanRepository.listAlertDestinations({ ownerId: authState.ownerId, limit: MAX_DESTINATIONS_PER_OWNER + 1 });
    if (existing.length >= MAX_DESTINATIONS_PER_OWNER) {
      sendJson(response, 409, { error: `Alert destinations are limited to ${MAX_DESTINATIONS_PER_OWNER} per account.` });
      return true;
    }
    const destination = await scanRepository.upsertAlertDestination({
      ...normalized,
      ownerId: authState.ownerId,
      requesterScope: authState.requesterScope,
    });
    sendJson(response, 201, {
      apiVersion: API_VERSION,
      destination,
      ...(normalized.type === "webhook" ? { webhookSigningSecret: normalized.signingSecret } : {}),
    });
  } catch (error) {
    sendJson(response, 400, { error: error instanceof Error ? error.message : "Alert destination is invalid." });
  }
  return true;
}

export async function handleAlertDestinationItemRequest({
  request, response, requestUrl, scanRepository, authorizeAnalysisRequest, alertDeliveryService,
  sendJson, sendMethodNotAllowed, sendRepositoryUnavailable,
}) {
  const match = requestUrl.pathname.match(/^\/api\/alert-destinations\/([^/]+)(?:\/(test))?$/);
  if (!match) {
    sendJson(response, 404, { error: "Alert destination not found." });
    return true;
  }
  const action = match[2] || null;
  const allowed = action === "test" ? ["POST"] : ["DELETE"];
  if (!allowed.includes(request.method)) {
    sendMethodNotAllowed(response, allowed);
    return true;
  }
  const authState = await authorizeAnalysisRequest({
    request, response, requestPath: requestUrl.pathname, requireScanOwner: true,
  });
  if (!authState) return true;
  if (!["session", "api-key"].includes(authState.authMode)) {
    sendJson(response, 403, { error: "Alert destinations require an authenticated account or user API key." });
    return true;
  }
  try {
    if (action === "test") {
      const destination = await scanRepository.getAlertDestination(match[1], {
        ownerId: authState.ownerId,
        requesterScope: authState.ownerId ? null : authState.requesterScope,
        includeSecrets: true,
      });
      if (!destination) {
        sendJson(response, 404, { error: "Alert destination not found." });
        return true;
      }
      const result = await alertDeliveryService.sendTestDestination(destination);
      sendJson(response, 202, { apiVersion: API_VERSION, result });
      return true;
    }
    const deleted = await scanRepository.disableAlertDestination(match[1], {
      ownerId: authState.ownerId,
      requesterScope: authState.ownerId ? null : authState.requesterScope,
    });
    sendJson(response, deleted ? 200 : 404, deleted
      ? { apiVersion: API_VERSION, deleted: true }
      : { error: "Alert destination not found." });
  } catch (error) {
    sendRepositoryUnavailable(response, error, action === "test" ? "test_alert_destination" : "delete_alert_destination");
  }
  return true;
}
