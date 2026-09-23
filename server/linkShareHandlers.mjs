import { timingSafeEqual } from "node:crypto";
import { buildLinkSharePreview, createLinkShareRecord, hashRevokeToken, classifyLinkShare, publicLinkShare, verifyInspectionProof } from "./linkShareContract.mjs";

const ERROR_STATUS = Object.freeze({ not_found: 404, revoked: 410, expired: 410 });

function sendState(response, sendJson, state) {
  sendJson(response, ERROR_STATUS[state], {
    error: state === "not_found" ? "Shared link result not found." : `Shared link result ${state}.`,
    code: `link_share_${state}`,
  });
}

export async function handleLinkShareCollection({
  request, response, requestUrl, authorizeAnalysisRequest, readJsonBody, repository,
  createRateLimiter, sendJson, sendMethodNotAllowed, telemetry, publicBaseUrl, revokeSalt,
}) {
  if (request.method !== "POST") {
    sendMethodNotAllowed(response, ["POST", "OPTIONS"]);
    return true;
  }
  const authState = await authorizeAnalysisRequest({ request, response, requestPath: requestUrl.pathname, requireScanOwner: true });
  if (!authState) return true;
  const limited = await createRateLimiter.check(authState.ownerId || authState.requesterScope);
  if (limited.limited) {
    sendJson(response, 429, { error: "Too many shared results created. Try again later.", code: "link_share_create_rate_limited", retryAfterSeconds: limited.retryAfterSeconds });
    return true;
  }
  try {
    const body = await readJsonBody(request, { maxBytes: 96 * 1024 });
    if (!verifyInspectionProof(body.inspection, body.shareProof, revokeSalt)) {
      sendJson(response, 400, { error: "A backend-issued proof for this completed inspection is required.", code: "link_share_proof_invalid" });
      return true;
    }
    const record = createLinkShareRecord({ inspection: body.inspection });
    await repository.createLinkShare({
      publicId: record.publicId,
      revokeTokenHash: hashRevokeToken(record.revokeToken, revokeSalt),
      preview: record.preview,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    });
    telemetry.recordFunnelEvent({ event: "link_share_created", source: "backend_api" });
    sendJson(response, 201, {
      share: publicLinkShare(record, publicBaseUrl),
      revokeToken: record.revokeToken,
    });
  } catch (error) {
    sendJson(response, 400, { error: error instanceof Error ? error.message : "Invalid shared result.", code: "link_share_invalid" });
  }
  return true;
}

export async function handleLinkSharePreview({
  request, response, requestUrl, authorizeAnalysisRequest, readJsonBody, sendJson,
  sendMethodNotAllowed, revokeSalt,
}) {
  if (requestUrl.pathname !== "/api/link-shares/preview") return false;
  if (request.method !== "POST") {
    sendMethodNotAllowed(response, ["POST", "OPTIONS"]);
    return true;
  }
  const authState = await authorizeAnalysisRequest({ request, response, requestPath: requestUrl.pathname, requireScanOwner: true });
  if (!authState) return true;
  try {
    const body = await readJsonBody(request, { maxBytes: 96 * 1024 });
    if (!verifyInspectionProof(body.inspection, body.shareProof, revokeSalt)) {
      sendJson(response, 400, { error: "A backend-issued proof for this completed inspection is required.", code: "link_share_proof_invalid" });
      return true;
    }
    sendJson(response, 200, { preview: buildLinkSharePreview(body.inspection) });
  } catch (error) {
    sendJson(response, 400, { error: error instanceof Error ? error.message : "Invalid shared result.", code: "link_share_invalid" });
  }
  return true;
}

export async function handleLinkShareItem({
  request, response, requestUrl, repository, readJsonBody, readRateLimiter, sendJson,
  sendMethodNotAllowed, telemetry, publicBaseUrl, revokeSalt,
}) {
  const match = requestUrl.pathname.match(/^\/api\/link-shares\/([A-Za-z0-9_-]{32})$/);
  if (!match) return false;
  const publicId = match[1];
  const limited = await readRateLimiter.check(hashRevokeToken(publicId, revokeSalt));
  if (limited.limited) {
    sendJson(response, 429, { error: "Too many shared-result requests. Try again later.", code: "link_share_read_rate_limited", retryAfterSeconds: limited.retryAfterSeconds });
    return true;
  }
  const record = await repository.getLinkShare(publicId);
  const state = classifyLinkShare(record);

  if (request.method === "GET") {
    if (state !== "active") return sendState(response, sendJson, state), true;
    telemetry.recordFunnelEvent({ event: "link_share_card_viewed", source: "shared_link" });
    response.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
    sendJson(response, 200, { share: publicLinkShare(record, publicBaseUrl) });
    return true;
  }
  if (request.method === "DELETE") {
    if (state !== "active") return sendState(response, sendJson, state), true;
    const body = await readJsonBody(request, { maxBytes: 2 * 1024 }).catch(() => ({}));
    const presented = hashRevokeToken(body.revokeToken, revokeSalt);
    if (!body.revokeToken || presented.length !== record.revokeTokenHash.length
      || !cryptoSafeEqual(presented, record.revokeTokenHash)) {
      sendJson(response, 403, { error: "A valid creator revocation token is required.", code: "link_share_revoke_forbidden" });
      return true;
    }
    await repository.revokeLinkShare(publicId, new Date().toISOString());
    sendJson(response, 200, { ok: true, state: "revoked" });
    return true;
  }
  sendMethodNotAllowed(response, ["GET", "DELETE", "OPTIONS"]);
  return true;
}

function cryptoSafeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export async function handleLinkShareRecheckEvent({ request, response, requestUrl, repository, readJsonBody, readRateLimiter, sendJson, sendMethodNotAllowed, telemetry, revokeSalt }) {
  const match = requestUrl.pathname.match(/^\/api\/link-shares\/([A-Za-z0-9_-]{32})\/recheck-events$/);
  if (!match) return false;
  if (request.method !== "POST") {
    sendMethodNotAllowed(response, ["POST", "OPTIONS"]);
    return true;
  }
  const limited = await readRateLimiter.check(hashRevokeToken(match[1], revokeSalt));
  if (limited.limited) {
    sendJson(response, 429, { error: "Too many shared-result requests. Try again later.", code: "link_share_read_rate_limited", retryAfterSeconds: limited.retryAfterSeconds });
    return true;
  }
  const state = classifyLinkShare(await repository.getLinkShare(match[1]));
  if (state !== "active") return sendState(response, sendJson, state), true;
  const body = await readJsonBody(request, { maxBytes: 1024 }).catch(() => ({}));
  if (!['started', 'completed'].includes(body.stage)) {
    sendJson(response, 400, { error: "stage must be started or completed.", code: "link_share_recheck_invalid" });
    return true;
  }
  telemetry.recordFunnelEvent({ event: `link_share_recipient_recheck_${body.stage}`, source: "shared_link" });
  sendJson(response, 202, { ok: true });
  return true;
}
