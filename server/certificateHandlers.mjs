import { scanLiveCertificate } from "../packages/core/dist/certificate.js";
import { API_VERSION } from "./scanDtos.mjs";

export async function handleLiveCertificateRequest({
  request,
  response,
  requestUrl,
  authorizeAnalysisRequest,
  assertPublicHttpUrl,
  checkTargetQuota,
  classifyScanFailure,
  normalizeScanErrorMessage,
  telemetry,
  readClientMetadata,
  sendJson,
  sendMethodNotAllowed,
}) {
  if (request.method !== "GET") {
    sendMethodNotAllowed(response, ["GET"]);
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

  const clientMetadata = readClientMetadata?.(request, {
    fallbackClient: requestUrl.searchParams.get("appId"),
  }) || {};
  const ownerOrScope = authState.ownerId || authState.requesterScope || null;
  const target = requestUrl.searchParams.get("url") || requestUrl.searchParams.get("target") || "";
  let validatedTarget = null;

  try {
    validatedTarget = await assertPublicHttpUrl(target);
    if (validatedTarget.protocol !== "https:") {
      telemetry.recordFunnelEvent({
        event: "live_certificate_failed",
        source: "backend_api",
        mode: clientMetadata.appId,
        target,
        client: clientMetadata.client,
        clientVersion: clientMetadata.version,
        clientChannel: clientMetadata.channel,
        clientKey: ownerOrScope,
      });
      sendJson(response, 400, {
        error: "Live certificate checks require an HTTPS URL.",
      });
      return true;
    }

    const targetQuota = await checkTargetQuota({
      requesterScope: authState.requesterScope,
      target: validatedTarget.toString(),
      clientIp: authState.clientIp,
      requestPath: requestUrl.pathname,
      response,
    });
    if (!targetQuota.ok) {
      return true;
    }

    const certificate = await scanLiveCertificate(validatedTarget);
    telemetry.recordFunnelEvent({
      event: "live_certificate_read",
      source: "backend_api",
      mode: clientMetadata.appId,
      target: validatedTarget.toString(),
      client: clientMetadata.client,
      clientVersion: clientMetadata.version,
      clientChannel: clientMetadata.channel,
      clientKey: ownerOrScope,
    });
    sendJson(response, 200, {
      apiVersion: API_VERSION,
      target: {
        url: validatedTarget.toString(),
        host: validatedTarget.hostname,
        port: Number(validatedTarget.port || 443),
      },
      certificate,
    });
  } catch (error) {
    telemetry.recordFunnelEvent({
      event: "live_certificate_failed",
      source: "backend_api",
      mode: clientMetadata.appId,
      target: validatedTarget?.toString?.() || target,
      client: clientMetadata.client,
      clientVersion: clientMetadata.version,
      clientChannel: clientMetadata.channel,
      clientKey: ownerOrScope,
    });
    telemetry.recordFailure(classifyScanFailure(error), {
      target: validatedTarget?.toString?.() || target,
      message: normalizeScanErrorMessage(error),
      source: "live_certificate",
    });
    sendJson(response, 400, {
      error: normalizeScanErrorMessage(error),
    });
  }

  return true;
}
