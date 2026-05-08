export async function handleMonitoringTargetCollectionRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  readJsonBody,
  assertPublicHttpUrl,
  buildMonitoringTargetView,
  buildMonitoringTargetsPayload,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  classifyScanFailure,
  normalizeScanErrorMessage,
  telemetry,
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
      const targets = await scanRepository.listMonitoringTargets({
        ownerId: authState.ownerId,
        limit: Number(requestUrl.searchParams.get("limit") || 50),
      });

      const enriched = await Promise.all(
        targets.map(async (target) => {
          const records = await scanRepository.listPersistedRecords({
            ownerId: authState.ownerId,
            url: target.url,
            limit: 5,
          });
          return buildMonitoringTargetView(target, records);
        }),
      );

      sendJson(response, 200, buildMonitoringTargetsPayload(enriched));
    } catch (error) {
      sendRepositoryUnavailable(response, error, "list_monitoring_targets");
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
    const target = typeof body.url === "string" ? body.url : "";
    const cadence = body.cadence === "weekly" ? "weekly" : "daily";
    const validatedTarget = await assertPublicHttpUrl(target);
    const label = typeof body.label === "string" && body.label.trim()
      ? body.label.trim().slice(0, 200)
      : validatedTarget.hostname;

    const savedTarget = await scanRepository.upsertMonitoringTarget({
      url: validatedTarget.toString(),
      label,
      cadence,
      requesterScope: authState.requesterScope,
      ownerId: authState.ownerId,
    });

    const records = await scanRepository.listPersistedRecords({
      ownerId: authState.ownerId,
      url: savedTarget.url,
      limit: 5,
    });

    sendJson(response, 201, {
      target: buildMonitoringTargetView(savedTarget, records),
    });
  } catch (error) {
    telemetry.recordFailure(classifyScanFailure(error));
    sendJson(response, 400, {
      error: normalizeScanErrorMessage(error),
    });
  }

  return true;
}

export async function handleMonitoringTargetItemRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
}) {
  const match = requestUrl.pathname.match(/^\/api\/monitoring-targets\/([^/]+)$/);
  if (!match) {
    sendJson(response, 404, {
      error: "Monitoring target not found.",
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
    const deleted = await scanRepository.deleteMonitoringTarget(match[1], {
      ownerId: authState.ownerId,
    });
    if (!deleted) {
      sendJson(response, 404, {
        error: "Monitoring target not found.",
      });
      return true;
    }

    sendJson(response, 200, {
      ok: true,
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, "delete_monitoring_target");
  }

  return true;
}
