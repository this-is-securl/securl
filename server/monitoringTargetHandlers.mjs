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
  readJsonBody,
  getRequestedScanMode,
  checkTargetQuota,
  runScanAnalysis,
  runQueuedScan,
  buildMonitoringTargetDetailPayload,
  telemetry,
  classifyScanFailure,
  normalizeScanErrorMessage,
  formatErrorMessage,
  log,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
}) {
  const match = requestUrl.pathname.match(/^\/api\/monitoring-targets\/([^/]+)(?:\/([^/]+))?$/);
  if (!match) {
    sendJson(response, 404, {
      error: "Monitoring target not found.",
    });
    return true;
  }

  const requestedAction = match[2] || null;
  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
    enforceRateLimit: request.method === "GET" && !requestedAction ? false : undefined,
    requireScanOwner: true,
  });
  if (!authState) {
    return true;
  }

  let action = null;
  try {
    const target = await scanRepository.getMonitoringTarget(match[1], {
      ownerId: authState.ownerId,
    });
    if (!target) {
      sendJson(response, 404, {
        error: "Monitoring target not found.",
      });
      return true;
    }

    action = requestedAction;

    if (!action && request.method === "GET") {
      const records = await scanRepository.listPersistedRecords({
        ownerId: authState.ownerId,
        url: target.url,
        limit: Number(requestUrl.searchParams.get("limit") || 10),
      });

      const events = [];
      const eventLimit = Number(requestUrl.searchParams.get("eventLimit") || 20);
      for (const record of records.slice(0, 5)) {
        const scanEvents = await scanRepository.listScanEvents(record.id, {
          ownerId: authState.ownerId,
        });
        events.push(...scanEvents);
      }
      events.sort((left, right) => new Date(right.occurredAt).getTime() - new Date(left.occurredAt).getTime());

      sendJson(response, 200, buildMonitoringTargetDetailPayload(target, records, events.slice(0, eventLimit)));
      return true;
    }

    if (action === "run") {
      if (request.method !== "POST") {
        sendMethodNotAllowed(response, ["POST"]);
        return true;
      }

      const body = await readJsonBody(request);
      const mode = getRequestedScanMode(body?.mode);
      const targetQuota = await checkTargetQuota({
        requesterScope: authState.requesterScope,
        target: target.url,
        clientIp: authState.clientIp,
        requestPath: requestUrl.pathname,
        response,
      });
      if (!targetQuota.ok) {
        return true;
      }

      let scan;
      try {
        scan = await scanRepository.createScan({
          url: target.url,
          mode,
          requesterScope: authState.requesterScope,
          ownerId: authState.ownerId,
          clientIp: authState.clientIp,
        });

        sendJson(response, 202, {
          scan: (await scanRepository.getScan(scan.id, { ownerId: authState.ownerId })).summary,
          target: {
            id: target.id,
            url: target.url,
            cadence: target.cadence,
          },
        });
      } catch (error) {
        sendRepositoryUnavailable(response, error, "run_monitoring_target");
        return true;
      }

      queueMicrotask(() => {
        void runQueuedScan({
          scan,
          validatedTarget: new URL(target.url),
          mode,
          authState,
          scanRepository,
          runScanAnalysis,
          telemetry,
          classifyScanFailure,
          normalizeScanErrorMessage,
          formatErrorMessage,
          log,
        });
      });
      return true;
    }

    if (action) {
      sendJson(response, 404, {
        error: "Monitoring target action not found.",
      });
      return true;
    }

    if (request.method !== "DELETE") {
      sendMethodNotAllowed(response, ["GET", "DELETE"]);
      return true;
    }

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
    sendRepositoryUnavailable(response, error, action === "run" ? "run_monitoring_target" : "access_monitoring_target");
  }

  return true;
}
