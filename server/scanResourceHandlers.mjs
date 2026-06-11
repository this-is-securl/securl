import { API_VERSION } from "./scanDtos.mjs";
import { hashClientIp, redactRequesterScope, targetForPrivacy } from "./privacy.mjs";

export const RESULT_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const RESULT_CACHE_STARTED_AT_MS = Date.now();

export function getDeploymentScopedResultCacheAgeMs(
  nowMs = Date.now(),
  startedAtMs = RESULT_CACHE_STARTED_AT_MS,
) {
  return Math.max(0, Math.min(RESULT_CACHE_TTL_MS, nowMs - startedAtMs));
}

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

function clampLimit(value, fallback = 20, max = 100) {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(1, Math.floor(parsed)));
}

export async function runQueuedScan({
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
  const safeTarget = targetForPrivacy(validatedTarget);
  const safeClientIp = hashClientIp(authState.clientIp);
  const safeRequesterScope = redactRequesterScope(authState.requesterScope);

  try {
    await scanRepository.markRunning(scan.id);
  } catch (error) {
    telemetry.recordFailure("scan_repository_failure", {
      target: safeTarget,
      message: formatErrorMessage(error),
      source: "scan_state_mark_running",
    });
    log("error", "scan_resource_state_failed", {
      stage: "mark_running",
      message: formatErrorMessage(error),
      clientIpHash: safeClientIp,
      requesterScope: safeRequesterScope,
      targetOrigin: safeTarget,
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
    telemetry.recordFailure(failureClass, {
      target: safeTarget,
      message: normalizeScanErrorMessage(error),
      source: "scan_analysis",
    });
    try {
      await scanRepository.markFailed(scan.id, failureClass, normalizeScanErrorMessage(error));
    } catch (repositoryError) {
      telemetry.recordFailure("scan_repository_failure", {
        target: safeTarget,
        message: formatErrorMessage(repositoryError),
        source: "scan_state_mark_failed",
      });
      log("error", "scan_resource_state_failed", {
        stage: "mark_failed",
        message: formatErrorMessage(repositoryError),
        clientIpHash: safeClientIp,
        requesterScope: safeRequesterScope,
        targetOrigin: safeTarget,
        scanId: scan.id,
      });
    }
    log("warn", "scan_resource_failed", {
      message: formatErrorMessage(error),
      clientIpHash: safeClientIp,
      requesterScope: safeRequesterScope,
      targetOrigin: safeTarget,
      scanId: scan.id,
    });
    return;
  }

  try {
    await scanRepository.markCompleted(scan.id, result);
  } catch (error) {
    telemetry.recordFailure("scan_repository_failure", {
      target: safeTarget,
      message: formatErrorMessage(error),
      source: "scan_state_mark_completed",
    });
    log("error", "scan_resource_state_failed", {
      stage: "mark_completed",
      message: formatErrorMessage(error),
      clientIpHash: safeClientIp,
      requesterScope: safeRequesterScope,
      targetOrigin: safeTarget,
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
  buildTargetHistoryPayload,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  telemetry,
  classifyScanFailure,
  normalizeScanErrorMessage,
  runScanAnalysis,
  enqueueScan,
  formatErrorMessage,
  log,
  requireScanOwner = false,
}) {
  if (request.method === "GET") {
    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
      enforceRateLimit: false,
      requireScanOwner,
    });
    if (!authState) {
      return true;
    }

    const historyTarget = requestUrl.searchParams.get("url");

    try {
      if (historyTarget) {
        let validatedTarget;
        try {
          validatedTarget = await assertPublicHttpUrl(historyTarget);
        } catch (error) {
          telemetry.recordFailure(classifyScanFailure(error));
          sendJson(response, 400, {
            error: normalizeScanErrorMessage(error),
          });
          return true;
        }

        const scans = await scanRepository.listPersistedRecords({
          limit: clampLimit(requestUrl.searchParams.get("limit")),
          ownerId: authState.ownerId,
          url: validatedTarget.toString(),
        });
        sendJson(response, 200, buildTargetHistoryPayload(validatedTarget.toString(), scans));
        return true;
      }

      const scans = await scanRepository.listScans({
        limit: clampLimit(requestUrl.searchParams.get("limit")),
        ownerId: authState.ownerId,
      });
      sendJson(response, 200, { apiVersion: API_VERSION, scans });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "list_scans");
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
    requireScanOwner,
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

    // Result TTL cache — serve a recent successful scan rather than re-hitting a target
    // that may block repeated scanner requests (CDN/WAF bot protection). Scope it to
    // the current server process so scoring releases cannot reuse pre-deploy results.
    const resultCacheMaxAgeMs = getDeploymentScopedResultCacheAgeMs();
    const cachedScan = mode === "deep-passive"
      ? null
      : await scanRepository
        .getRecentSuccessfulScan({ url: validatedTarget.toString(), mode, maxAgeMs: resultCacheMaxAgeMs })
        .catch(() => null); // cache miss on error — fall through to live scan
    if (cachedScan?.result) {
      try {
        const scan = await scanRepository.createScan({
          url: validatedTarget.toString(),
          mode,
          requesterScope: authState.requesterScope,
          ownerId: authState.ownerId,
          clientIp: authState.clientIp,
        });
        const completedScan = await scanRepository.markCompleted(scan.id, cachedScan.result);
        log("info", "scan_result_cache_hit", {
          targetOrigin: targetForPrivacy(validatedTarget),
          cachedScanId: cachedScan.id,
          newScanId: scan.id,
          clientIpHash: hashClientIp(authState.clientIp),
          requesterScope: redactRequesterScope(authState.requesterScope),
          cacheMaxAgeMs: resultCacheMaxAgeMs,
        });
        sendJson(response, 202, {
          apiVersion: API_VERSION,
          fromCache: true,
          scan: completedScan.summary,
        });
      } catch (error) {
        sendRepositoryUnavailable(response, error, "create_cached_scan");
      }
      return true;
    }

    let scan;
    try {
      scan = await scanRepository.createScan({
        url: validatedTarget.toString(),
        mode,
        requesterScope: authState.requesterScope,
        ownerId: authState.ownerId,
        clientIp: authState.clientIp,
      });

      sendJson(response, 202, {
        apiVersion: API_VERSION,
        scan: (await scanRepository.getScan(scan.id, { ownerId: authState.ownerId })).summary,
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "create_scan");
      return true;
    }

    enqueueScan({
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
  authorizeAnalysisRequest,
  buildScanDetailPayload,
  buildScanExportResponse,
  buildScanSummaryPayload,
  buildScanFindingsPayload,
  buildScanDigestPayload,
  buildScanEvidencePayload,
  buildScanHistoryPayload,
  buildScanComparisonPayload,
  buildScanDriftPayload,
  sendBody,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  requireScanOwner = false,
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

  // Public share endpoint — no auth required
  if (parsed.resource === "share") {
    try {
      const scan = await scanRepository.getScanById(parsed.scanId);
      if (!scan || scan.status !== "completed" || !scan.result) {
        sendJson(response, 404, { error: "not_found" });
        return true;
      }
      sendJson(response, 200, {
        scan: {
          id: scan.id,
          url: scan.url,
          completedAt: scan.completedAt,
          result: scan.result,
        },
      });
    } catch (error) {
      sendRepositoryUnavailable(response, error, "get_shared_scan");
    }
    return true;
  }

  try {
    const { scanId, resource } = parsed;
    const authState = await authorizeAnalysisRequest({
      request,
      response,
      requestPath: requestUrl.pathname,
      enforceRateLimit: false,
      requireScanOwner,
    });
    if (!authState) {
      return true;
    }

    const scan = await scanRepository.getScan(scanId, {
      ownerId: authState.ownerId,
    });
    if (!scan) {
      sendJson(response, 404, {
        error: "Scan not found.",
      });
      return true;
    }

    if (!resource) {
      sendJson(response, 200, buildScanDetailPayload(scan));
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

    if (resource === "digest") {
      sendJson(response, 200, buildScanDigestPayload(scan));
      return true;
    }

    if (resource === "evidence") {
      sendJson(response, 200, buildScanEvidencePayload(scan));
      return true;
    }

    if (resource === "history") {
      const events = await scanRepository.listScanEvents(scanId, {
        ownerId: authState.ownerId,
      });
      sendJson(response, 200, buildScanHistoryPayload(scan, events));
      return true;
    }

    if (resource === "comparison") {
      if (scan.status !== "completed" || !scan.result) {
        sendJson(response, 409, {
          error: "Scan comparison is only available once the scan has completed.",
        });
        return true;
      }

      const records = await scanRepository.listPersistedRecords({
        limit: clampLimit(requestUrl.searchParams.get("limit"), 20, 100),
        ownerId: authState.ownerId,
        url: scan.url,
      });
      sendJson(response, 200, buildScanComparisonPayload(scan, records));
      return true;
    }

    if (resource === "drift") {
      if (scan.status !== "completed" || !scan.result) {
        sendJson(response, 409, {
          error: "Scan drift is only available once the scan has completed.",
        });
        return true;
      }

      const records = await scanRepository.listPersistedRecords({
        limit: clampLimit(requestUrl.searchParams.get("limit"), 20, 100),
        ownerId: authState.ownerId,
        url: scan.url,
      });
      sendJson(response, 200, buildScanDriftPayload(scan, records));
      return true;
    }

    if (resource === "export") {
      const requestedFormat = requestUrl.searchParams.get("format") || "json";
      const exportResponse = buildScanExportResponse(scan, requestedFormat);
      if (!exportResponse) {
        sendJson(response, 400, {
          error: "Unsupported export format. Use json, markdown, sarif, or ci-json.",
        });
        return true;
      }
      if (exportResponse.notReady) {
        sendJson(response, 409, {
          error: "Scan export is only available once the scan has completed.",
        });
        return true;
      }
      sendBody(response, 200, exportResponse.body, {
        "Content-Type": exportResponse.contentType,
        "Content-Disposition": `attachment; filename="${exportResponse.filename}"`,
      });
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
