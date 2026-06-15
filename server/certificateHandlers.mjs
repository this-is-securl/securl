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

  try {
    const target = requestUrl.searchParams.get("url") || requestUrl.searchParams.get("target") || "";
    const validatedTarget = await assertPublicHttpUrl(target);
    if (validatedTarget.protocol !== "https:") {
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
    telemetry.recordFailure(classifyScanFailure(error));
    sendJson(response, 400, {
      error: normalizeScanErrorMessage(error),
    });
  }

  return true;
}
