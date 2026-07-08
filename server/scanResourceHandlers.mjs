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

function writeSse(response, event, data) {
  response.write(`event: ${event}\n`);
  response.write(`data: ${JSON.stringify(data)}\n\n`);
}

export function buildScanResourceLinks(scanId) {
  const basePath = `/api/scans/${scanId}`;
  return {
    detail: basePath,
    summary: `${basePath}/summary`,
    findings: `${basePath}/findings`,
    digest: `${basePath}/digest`,
    insights: `${basePath}/insights`,
    mobileSummary: `${basePath}/mobile-summary`,
    brief: `${basePath}/brief`,
    vendors: `${basePath}/vendors`,
    actionPlan: `${basePath}/action-plan`,
    events: `${basePath}/events`,
    evidence: `${basePath}/evidence`,
    observations: `${basePath}/observations`,
    observationDrift: `${basePath}/observation-drift`,
    policyEvaluation: `${basePath}/policy-evaluation`,
    manifest: `${basePath}/manifest`,
    history: `${basePath}/history`,
    comparison: `${basePath}/comparison`,
    drift: `${basePath}/drift`,
    share: `${basePath}/share`,
    shareCard: `${basePath}/share-card`,
  };
}

async function streamScanEvents({
  request,
  response,
  scanRepository,
  scan,
  ownerId,
  requesterScope,
  intervalMs = 1500,
}) {
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  response.write(": connected\n\n");

  const sent = new Set();
  let closed = false;
  let timer = null;
  const close = () => {
    closed = true;
    if (timer) {
      clearInterval(timer);
    }
    response.end();
  };

  request.once("close", () => {
    closed = true;
    if (timer) {
      clearInterval(timer);
    }
  });

  const sendPending = async () => {
    if (closed) {
      return;
    }
    const events = await scanRepository.listScanEvents(scan.id, {
      ownerId,
      requesterScope,
    });
    for (const event of [...events].reverse()) {
      if (sent.has(event.id)) {
        continue;
      }
      sent.add(event.id);
      writeSse(response, event.eventType || "scan_event", event);
    }

    const latest = await scanRepository.getScan(scan.id, {
      ownerId,
      requesterScope,
    });
    if (latest?.status === "completed" || latest?.status === "failed") {
      writeSse(response, "scan_terminal", {
        id: latest.id,
        status: latest.status,
        completedAt: latest.completedAt,
        grade: latest.summary?.grade ?? null,
        score: latest.summary?.score ?? null,
        failureClass: latest.failureClass ?? null,
      });
      close();
    }
  };

  timer = setInterval(() => {
    void sendPending().catch(() => close());
  }, intervalMs);
  timer.unref?.();
  await sendPending().catch(() => close());
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
  telemetryContext = {},
  notificationService = null,
  alertDeliveryService = null,
  scanLeaseOwner = null,
}) {
  const safeTarget = targetForPrivacy(validatedTarget);
  const safeClientIp = hashClientIp(authState.clientIp);
  const safeRequesterScope = redactRequesterScope(authState.requesterScope);

  try {
    const runningScan = await scanRepository.markRunning(scan.id, { workerId: scanLeaseOwner });
    if (!runningScan) {
      log("warn", "scan_resource_lease_lost", {
        scanId: scan.id,
        targetOrigin: safeTarget,
      });
      return;
    }
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
      telemetryContext,
    });
  } catch (error) {
    const failureClass = classifyScanFailure(error);
    telemetry.recordFailure(failureClass, {
      target: safeTarget,
      message: normalizeScanErrorMessage(error),
      source: "scan_analysis",
    });
    try {
      await scanRepository.markFailed(
        scan.id,
        failureClass,
        normalizeScanErrorMessage(error),
        { workerId: scanLeaseOwner },
      );
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

  let completedScan = null;
  try {
    completedScan = await scanRepository.markCompleted(scan.id, result, { workerId: scanLeaseOwner });
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

  let policyAlert = null;
  if (completedScan && alertDeliveryService) {
    try {
      policyAlert = await alertDeliveryService.processMonitoringScan({ completedScan, result, telemetryContext });
    } catch (error) {
      telemetry.recordFailure("alert_delivery_failure", {
        target: safeTarget,
        message: formatErrorMessage(error),
        source: "policy_alert_delivery",
      });
      log("error", "policy_alert_delivery_failed", {
        scanId: scan.id,
        targetOrigin: safeTarget,
        message: formatErrorMessage(error),
      });
    }
  }

  if (completedScan && notificationService && !policyAlert?.violations) {
    try {
      await notificationService.notifyMonitoringScanCompleted({ completedScan, result, telemetryContext });
    } catch (error) {
      telemetry.recordFailure("notification_delivery_failure", {
        target: safeTarget,
        message: formatErrorMessage(error),
        source: "monitoring_notification_delivery",
      });
      log("error", "monitoring_notification_delivery_failed", {
        scanId: scan.id,
        targetOrigin: safeTarget,
        message: formatErrorMessage(error),
      });
    }
  }
}

export async function handleScanCollectionRequest({
  request,
  response,
  requestUrl,
  scanRepository,
  authorizeAnalysisRequest,
  readJsonBody,
  buildScanTelemetryContext = null,
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
  notificationService = null,
  alertDeliveryService = null,
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
    const telemetryContext = typeof buildScanTelemetryContext === "function"
      ? buildScanTelemetryContext({ request, body, authState })
      : {};

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
        telemetry.recordScanRequested({
          mode,
          target: validatedTarget,
          requesterKey: authState.requesterScope,
          clientKey: telemetryContext.clientKey || authState.clientIp,
          source: telemetryContext.source,
          channel: telemetryContext.channel,
          client: telemetryContext.client,
          clientVersion: telemetryContext.clientVersion,
        });
        telemetry.recordScanCompleted(cachedScan.result);
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
          resources: buildScanResourceLinks(completedScan.id),
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
        resources: buildScanResourceLinks(scan.id),
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
        telemetryContext,
        notificationService,
        alertDeliveryService,
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
  buildScanBriefPayload,
  buildScanVendorsPayload,
  buildScanActionPlanPayload,
  buildScanInsightsPayload,
  buildScanMobileSummaryPayload,
  buildScanObservationsPayload,
  buildScanEvidencePayload,
  buildScanHistoryPayload,
  buildScanComparisonPayload,
  buildScanDriftPayload,
  buildScanObservationDriftPayload,
  buildScanPolicyEvaluationPayload,
  buildScanManifestPayload,
  buildScanShareCardPayload,
  sendBody,
  sendJson,
  sendMethodNotAllowed,
  sendRepositoryUnavailable,
  telemetry = null,
  readClientMetadata = null,
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

  if (parsed.resource === "share-card") {
    try {
      const scan = await scanRepository.getScanById(parsed.scanId);
      if (!scan) {
        sendJson(response, 404, { error: "not_found" });
        return true;
      }
      const payload = buildScanShareCardPayload(scan);
      if (!payload.ready) {
        sendJson(response, 409, payload);
        return true;
      }
      const clientMetadata = readClientMetadata?.(request) || {};
      telemetry?.recordFunnelEvent?.({
        event: "share_card_read",
        source: "backend_api",
        target: scan.url,
        scanId: scan.id,
        mode: clientMetadata.appId,
        client: clientMetadata.client,
        clientVersion: clientMetadata.version,
        clientChannel: clientMetadata.channel,
      });
      sendJson(response, 200, payload);
    } catch (error) {
      sendRepositoryUnavailable(response, error, "get_shared_scan_card");
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

    if (resource === "brief") {
      sendJson(response, 200, buildScanBriefPayload(scan));
      return true;
    }

    if (resource === "vendors") {
      sendJson(response, 200, buildScanVendorsPayload(scan));
      return true;
    }

    if (resource === "events") {
      await streamScanEvents({
        request,
        response,
        scanRepository,
        scan,
        ownerId: authState.ownerId,
        requesterScope: authState.ownerId ? null : authState.requesterScope,
      });
      return true;
    }

    if (resource === "action-plan") {
      sendJson(response, 200, buildScanActionPlanPayload(scan));
      return true;
    }

    if (resource === "insights") {
      sendJson(response, 200, buildScanInsightsPayload(scan));
      return true;
    }

    if (resource === "mobile-summary") {
      sendJson(response, 200, {
        ...buildScanMobileSummaryPayload(scan),
        resources: buildScanResourceLinks(scan.id),
      });
      return true;
    }

    if (resource === "observations") {
      sendJson(response, 200, buildScanObservationsPayload(scan));
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

    if (resource === "observation-drift") {
      if (scan.status !== "completed" || !scan.result) {
        sendJson(response, 409, {
          error: "Observation drift is only available once the scan has completed.",
        });
        return true;
      }
      const records = await scanRepository.listPersistedRecords({
        limit: clampLimit(requestUrl.searchParams.get("limit"), 20, 100),
        ownerId: authState.ownerId,
        url: scan.url,
      });
      sendJson(response, 200, buildScanObservationDriftPayload(scan, records));
      return true;
    }

    if (resource === "policy-evaluation") {
      if (scan.status !== "completed" || !scan.result) {
        sendJson(response, 409, {
          error: "Policy evaluation is only available once the scan has completed.",
        });
        return true;
      }
      const [records, targets] = await Promise.all([
        scanRepository.listPersistedRecords({
          limit: clampLimit(requestUrl.searchParams.get("limit"), 20, 100),
          ownerId: authState.ownerId,
          url: scan.url,
        }),
        scanRepository.listMonitoringTargets({ ownerId: authState.ownerId, limit: 250 }),
      ]);
      const target = targets.find((candidate) => (candidate.kind ?? "posture") === "posture"
        && (candidate.url === scan.url || candidate.url === scan.result.finalUrl));
      sendJson(response, 200, buildScanPolicyEvaluationPayload(
        scan,
        records,
        target?.observationPolicy ?? null,
        target?.observationPolicy ? "monitoring_target" : "default",
      ));
      return true;
    }

    if (resource === "manifest") {
      if (scan.status !== "completed" || !scan.result) {
        sendJson(response, 409, {
          error: "Posture manifest is only available once the scan has completed.",
        });
        return true;
      }
      const [records, targets] = await Promise.all([
        scanRepository.listPersistedRecords({
          limit: clampLimit(requestUrl.searchParams.get("limit"), 20, 100),
          ownerId: authState.ownerId,
          url: scan.url,
        }),
        scanRepository.listMonitoringTargets({ ownerId: authState.ownerId, limit: 250 }),
      ]);
      const target = targets.find((candidate) => (candidate.kind ?? "posture") === "posture"
        && (candidate.url === scan.url || candidate.url === scan.result.finalUrl));
      sendJson(response, 200, buildScanManifestPayload(
        scan,
        records,
        target?.observationPolicy ?? null,
        target?.observationPolicy ? "monitoring_target" : "default",
      ));
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
