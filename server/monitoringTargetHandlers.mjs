import { API_VERSION } from "./scanDtos.mjs";

function clampLimit(value, fallback = 50, max = 100) {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(1, Math.floor(parsed)));
}

function recordMatchesMonitoringTarget(record, target) {
  if (!record || !target) {
    return false;
  }

  return (
    record.url === target.url
    || record.result?.finalUrl === target.url
    || record.result?.normalizedUrl === target.url
  );
}

async function listMonitoringTargetRecords(scanRepository, ownerId, target, limit) {
  const records = await scanRepository.listPersistedRecords({
    ownerId,
    limit: Math.max(limit * 4, 20),
  });

  return records
    .filter((record) => recordMatchesMonitoringTarget(record, target))
    .slice(0, limit);
}

export async function handleMonitoringSummaryRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  buildMonitoringSummaryPayload,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
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
    const limit = clampLimit(requestUrl.searchParams.get("limit"), 100, 250);
    const targets = await scanRepository.listMonitoringTargets({
      ownerId: authState.ownerId,
      limit,
    });
    const entries = await Promise.all(
      targets.map(async (target) => ({
        target,
        records: await listMonitoringTargetRecords(scanRepository, authState.ownerId, target, 5),
      })),
    );

    sendJson(response, 200, buildMonitoringSummaryPayload(entries));
  } catch (error) {
    sendRepositoryUnavailable(response, error, "monitoring_summary");
  }

  return true;
}

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
        limit: clampLimit(requestUrl.searchParams.get("limit")),
      });

      const enriched = await Promise.all(
        targets.map(async (target) => {
          const records = await listMonitoringTargetRecords(scanRepository, authState.ownerId, target, 5);
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
      apiVersion: API_VERSION,
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
  buildScanTelemetryContext = null,
  checkTargetQuota,
  runScanAnalysis,
  enqueueScan,
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
      const records = await listMonitoringTargetRecords(
        scanRepository,
        authState.ownerId,
        target,
        clampLimit(requestUrl.searchParams.get("limit"), 10),
      );

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
      const telemetryContext = typeof buildScanTelemetryContext === "function"
        ? buildScanTelemetryContext({ request, body, authState, channel: "monitoring_manual" })
        : { channel: "monitoring_manual" };
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
          apiVersion: API_VERSION,
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

      enqueueScan({
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
          telemetryContext,
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
      apiVersion: API_VERSION,
      ok: true,
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, action === "run" ? "run_monitoring_target" : "access_monitoring_target");
  }

  return true;
}
