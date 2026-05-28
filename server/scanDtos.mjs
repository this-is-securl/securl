import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";

export const API_VERSION = "2026-05-14";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function buildStoredTargetDiff(records) {
  const completedWithResults = normalizeArray(records).filter((scan) => scan?.status === "completed" && scan?.result);
  if (completedWithResults.length < 2) {
    return null;
  }

  const [current, previous] = completedWithResults;
  return {
    currentScanId: current.id,
    previousScanId: previous.id,
    diff: buildHistoryDiffFromSnapshots(
      snapshotFromAnalysis(current.result),
      snapshotFromAnalysis(previous.result),
    ),
  };
}

function cadenceWindowMs(cadence) {
  return cadence === "weekly" ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
}

export function buildMonitoringTargetView(target, records = []) {
  const baseTime = target.lastScannedAt ? new Date(target.lastScannedAt).getTime() : new Date(target.addedAt).getTime();
  const nextDueAt = new Date(baseTime + cadenceWindowMs(target.cadence)).toISOString();
  const scans = normalizeArray(records).map((record) => record.summary).filter(Boolean);
  const completedScans = scans.filter((scan) => scan.status === "completed");
  const latestScan = completedScans[0] ?? null;
  const previousScan = completedScans[1] ?? null;

  return {
    ...target,
    nextDueAt,
    due: Date.now() >= new Date(nextDueAt).getTime(),
    latestScan,
    previousScan,
    scoreDelta:
      latestScan && previousScan && typeof latestScan.score === "number" && typeof previousScan.score === "number"
        ? latestScan.score - previousScan.score
        : null,
  };
}

export function buildScanSummaryPayload(scan) {
  return {
    apiVersion: API_VERSION,
    summary: scan.summary,
  };
}

export function buildScanFindingsPayload(scan) {
  const result = scan.result;
  if (!result) {
    return {
      findings: [],
      strengths: [],
      priorityActions: [],
    };
  }

  return {
    apiVersion: API_VERSION,
    findings: normalizeArray(result.issues),
    strengths: normalizeArray(result.strengths),
    priorityActions: normalizeArray(result.executiveSummary?.takeaways),
  };
}

export function buildScanEvidencePayload(scan) {
  const result = scan.result;
  if (!result) {
    return {
      evidence: null,
    };
  }

  return {
    apiVersion: API_VERSION,
    evidence: {
      headers: normalizeArray(result.headers),
      rawHeaders: result.rawHeaders ?? {},
      cookies: normalizeArray(result.cookies),
      redirects: normalizeArray(result.redirects),
      certificate: result.certificate ?? null,
      exposure: result.exposure ?? null,
      apiSurface: result.apiSurface ?? null,
      corsSecurity: result.corsSecurity ?? null,
      htmlSecurity: result.htmlSecurity ?? null,
      domainSecurity: result.domainSecurity ?? null,
      securityTxt: result.securityTxt ?? null,
      publicSignals: result.publicSignals ?? null,
      infrastructure: result.infrastructure ?? null,
      passiveIntelligence: result.passiveIntelligence ?? null,
      compromiseSignals: result.compromiseSignals ?? null,
      identityProvider: result.identityProvider ?? null,
      thirdPartyTrust: result.thirdPartyTrust ?? null,
      aiSurface: result.aiSurface ?? null,
      technologies: normalizeArray(result.technologies),
      ctDiscovery: result.ctDiscovery ?? null,
      wafFingerprint: result.wafFingerprint ?? null,
      crawl: result.crawl ?? null,
    },
  };
}

export function buildScanHistoryPayload(scan, events) {
  return {
    apiVersion: API_VERSION,
    scan: {
      id: scan.id,
      status: scan.status,
      requestedAt: scan.requestedAt,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
    },
    events: normalizeArray(events),
  };
}

export function buildTargetHistoryPayload(url, records) {
  return {
    apiVersion: API_VERSION,
    target: {
      url,
    },
    scans: normalizeArray(records).map((record) => record.summary).filter(Boolean),
    comparison: buildStoredTargetDiff(records),
  };
}

export function buildMonitoringTargetsPayload(targets) {
  return {
    apiVersion: API_VERSION,
    targets: normalizeArray(targets),
  };
}

export function buildMonitoringTargetDetailPayload(target, records = [], events = []) {
  const view = buildMonitoringTargetView(target, records);

  return {
    apiVersion: API_VERSION,
    target: view,
    scans: normalizeArray(records).map((record) => record.summary).filter(Boolean),
    comparison: buildStoredTargetDiff(records),
    events: normalizeArray(events),
  };
}
