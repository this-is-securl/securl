export function parseScanResourcePath(requestPath) {
  const match = requestPath.match(/^\/api\/scans\/([^/]+)(?:\/([^/]+))?$/);
  if (!match) {
    return null;
  }
  return {
    scanId: match[1],
    resource: match[2] || null,
  };
}

async function runQueuedScan({
  scan,
  validatedTarget,
  mode,
  authState,
  scanRepository,
  runScanAnalysis,
  telemetry,
  classifyScanFailure,
  normalizeScanErrorMessage,
  formatErrorMessage,
  log,
}) {
  try {
    await scanRepository.markRunning(scan.id);
  } catch (error) {
    telemetry.recordFailure("scan_repository_failure");
    log("error", "scan_resource_state_failed", {
      stage: "mark_running",
      message: formatErrorMessage(error),
      clientIp: authState.clientIp,
      target: validatedTarget.toString(),
      scanId: scan.id,
    });
    return;
  }

  let result;
  try {
    result = await runScanAnalysis({
      validatedTarget,
      mode,
      clientIp: authState.clientIp,
      requesterScope: authState.requesterScope,
    });
  } catch (error) {
    const failureClass = classifyScanFailure(error);
    telemetry.recordFailure(failureClass);
    try {
      await scanRepository.markFailed(scan.id, failureClass, normalizeScanErrorMessage(error));
    } catch (repositoryError) {
      telemetry.recordFailure("scan_repository_failure");
      log("error", "scan_resource_state_failed", {
        stage: "mark_failed",
        message: formatErrorMessage(repositoryError),
        clientIp: authState.clientIp,
        target: validatedTarget.toString(),
        scanId: scan.id,
      });
    }
    log("warn", "scan_resource_failed", {
      message: formatErrorMessage(error),
      clientIp: authState.clientIp,
      target: validatedTarget.toString(),
      scanId: scan.id,
    });
    return;
  }

  try {
    await scanRepository.markCompleted(scan.id, result);
  } catch (error) {
    telemetry.recordFailure("scan_repository_failure");
    log("error", "scan_resource_state_failed", {
      stage: "mark_completed",
      message: formatErrorMessage(error),
      clientIp: authState.clientIp,
      target: validatedTarget.toString(),
      scanId: scan.id,
    });
  }
}

export async function handleScanCollectionRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  readJsonBody,
  getRequestedScanMode,
  checkTargetQuota,
  assertPublicHttpUrl,
  sendJson,
  sendRepositoryUnavailable,
  telemetry,
  classifyScanFailure,
  normalizeScanErrorMessage,
  runScanAnalysis,
  formatErrorMessage,
  log,
}) {
  if (request.method === "GET") {
    try {
      const scans = await scanRepository.listScans({
        limit: Number(requestUrl.searchParams.get("limit") || 20),
      });
      sendJson(response, 200, { scans });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "list_scans");
    }
    return true;
  }

  if (request.method !== "POST") {
    return false;
  }

  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
  });
  if (!authState) {
    return true;
  }

  try {
    const body = await readJsonBody(request);
    const target = typeof body.url === "string" ? body.url : "";
    const mode = getRequestedScanMode(body.mode);

    const targetQuota = await checkTargetQuota({
      requesterScope: authState.requesterScope,
      target,
      clientIp: authState.clientIp,
      requestPath: requestUrl.pathname,
      response,
    });
    if (!targetQuota.ok) {
      return true;
    }

    const validatedTarget = await assertPublicHttpUrl(target);
    let scan;
    try {
      scan = await scanRepository.createScan({
        url: validatedTarget.toString(),
        mode,
        requesterScope: authState.requesterScope,
        clientIp: authState.clientIp,
      });

      sendJson(response, 202, {
        scan: (await scanRepository.getScan(scan.id)).summary,
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "create_scan");
      return true;
    }

    queueMicrotask(() => {
      void runQueuedScan({
        scan,
        validatedTarget,
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
  } catch (error) {
    telemetry.recordFailure(classifyScanFailure(error));
    sendJson(response, 400, {
      error: normalizeScanErrorMessage(error),
    });
  }

  return true;
}

export async function handleScanResourceRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  buildScanSummaryPayload,
  buildScanFindingsPayload,
  buildScanEvidencePayload,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
}) {
  if (request.method !== "GET") {
    sendMethodNotAllowed(response, ["GET"]);
    return true;
  }

  const parsed = parseScanResourcePath(requestUrl.pathname);
  if (!parsed) {
    sendJson(response, 404, {
      error: "Scan not found.",
    });
    return true;
  }

  try {
    const { scanId, resource } = parsed;
    const scan = await scanRepository.getScan(scanId);
    if (!scan) {
      sendJson(response, 404, {
        error: "Scan not found.",
      });
      return true;
    }

    if (!resource) {
      sendJson(response, 200, { scan });
      return true;
    }

    if (resource === "summary") {
      sendJson(response, 200, buildScanSummaryPayload(scan));
      return true;
    }

    if (resource === "findings") {
      sendJson(response, 200, buildScanFindingsPayload(scan));
      return true;
    }

    if (resource === "evidence") {
      sendJson(response, 200, buildScanEvidencePayload(scan));
      return true;
    }

    sendJson(response, 404, {
      error: "Scan resource not found.",
    });
  } catch (error) {
    sendRepositoryUnavailable(response, error, "get_scan_resource");
  }

  return true;
}
