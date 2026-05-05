export async function handleAnalyzeRequest({
  request,
  response,
  requestUrl,
  authorizeAnalysisRequest,
  getRequestedScanMode,
  checkTargetQuota,
  assertPublicHttpUrl,
  runScanAnalysis,
  telemetry,
  classifyScanFailure,
  formatErrorMessage,
  sendJson,
  sendMethodNotAllowed,
  log,
}) {
  if (request.method !== "GET") {
    sendMethodNotAllowed(response, ["GET"]);
    return true;
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
    const target = requestUrl.searchParams.get("url") || "";
    const mode = getRequestedScanMode(requestUrl.searchParams.get("mode"));
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
    const result = await runScanAnalysis({
      validatedTarget,
      mode,
      clientIp: authState.clientIp,
      requesterScope: authState.requesterScope,
    });
    sendJson(response, 200, result);
  } catch (error) {
    telemetry.recordFailure(classifyScanFailure(error));
    log("warn", "analysis_failed", {
      message: formatErrorMessage(error),
      clientIp: authState.clientIp,
      target: requestUrl.searchParams.get("url") || "",
    });
    sendJson(response, 400, {
      error: "Unable to analyze that target. Please check the URL and try again.",
    });
  }

  return true;
}
