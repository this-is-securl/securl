import { inspectLink } from "../packages/core/dist/link-inspection.js";
import { createInspectionProof } from "./linkShareContract.mjs";

function readEntryPoint(request, body) {
  if (typeof body.entryPoint === "string") {
    return body.entryPoint;
  }
  const surface = String(request.headers["x-securl-client-surface"] || "").trim().toLowerCase();
  return surface === "share-extension" ? "share_extension" : surface || "unknown";
}

export async function handleLinkInspectionRequest({
  request,
  response,
  requestUrl,
  authorizeAnalysisRequest,
  readJsonBody,
  checkTargetQuota,
  sendJson,
  sendMethodNotAllowed,
  classifyScanFailure,
  normalizeScanErrorMessage,
  telemetry,
  readClientMetadata,
  inspectionProofSalt,
}) {
  if (request.method !== "POST") {
    sendMethodNotAllowed(response, ["POST", "OPTIONS"]);
    return true;
  }
  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
    requireScanOwner: true,
  });
  if (!authState) return true;

  const ownerOrScope = authState.ownerId || authState.requesterScope || null;
  let clientMetadata = {};
  let entryPoint = "unknown";

  try {
    const body = await readJsonBody(request);
    const target = typeof body.url === "string" ? body.url : "";
    entryPoint = readEntryPoint(request, body);
    clientMetadata = readClientMetadata?.(request, {
      fallbackClient: body.appId,
      authState,
    }) || {};
    const targetQuota = await checkTargetQuota({
      requesterScope: authState.requesterScope,
      target,
      clientIp: authState.clientIp,
      requestPath: requestUrl.pathname,
      response,
    });
    if (!targetQuota.ok) return true;

    const telemetryContext = {
      source: "backend_api",
      mode: clientMetadata.appId,
      entryPoint,
      client: clientMetadata.client,
      clientVersion: clientMetadata.version,
      clientChannel: clientMetadata.channel,
      clientAttribution: clientMetadata.category,
      clientProvenance: clientMetadata.provenance,
      clientKey: ownerOrScope,
    };
    telemetry.recordFunnelEvent({ event: "link_inspection_started", ...telemetryContext });
    const inspection = await inspectLink(target);
    telemetry.recordFunnelEvent({
      event: inspection.verdict?.level === "blocked"
        ? "link_inspection_blocked"
        : "link_inspection_completed",
      ...telemetryContext,
    });
    sendJson(response, 200, {
      apiVersion: "2026-08-14",
      inspection,
      shareProof: createInspectionProof(inspection, inspectionProofSalt),
    });
  } catch (error) {
    telemetry.recordFunnelEvent({
      event: "link_inspection_failed",
      source: "backend_api",
      mode: clientMetadata.appId,
      entryPoint,
      client: clientMetadata.client,
      clientVersion: clientMetadata.version,
      clientChannel: clientMetadata.channel,
      clientAttribution: clientMetadata.category,
      clientProvenance: clientMetadata.provenance,
      clientKey: ownerOrScope,
    });
    telemetry.recordFailure(classifyScanFailure(error));
    sendJson(response, 400, { error: normalizeScanErrorMessage(error) });
  }
  return true;
}
