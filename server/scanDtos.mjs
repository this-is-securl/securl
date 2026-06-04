import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";
import { buildPostureDigest } from "../packages/core/dist/postureDigest.js";
import { buildPostureRiskEventsFromSnapshots } from "../packages/core/dist/riskEvents.js";

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
  const currentSnapshot = snapshotFromAnalysis(current.result);
  const previousSnapshot = snapshotFromAnalysis(previous.result);
  const diff = buildHistoryDiffFromSnapshots(currentSnapshot, previousSnapshot);

  return {
    currentScanId: current.id,
    previousScanId: previous.id,
    diff,
    riskEvents: buildPostureRiskEventsFromSnapshots(currentSnapshot, previousSnapshot, diff),
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

export function buildScanDigestPayload(scan) {
  const result = scan.result;
  return {
    apiVersion: API_VERSION,
    scan: {
      id: scan.id,
      status: scan.status,
      url: scan.url,
      mode: scan.mode,
      requestedAt: scan.requestedAt,
      completedAt: scan.completedAt,
    },
    digest: result ? buildPostureDigest(result) : null,
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

function incrementCount(counts, key) {
  counts[key] = (counts[key] ?? 0) + 1;
}

export function buildMonitoringSummaryPayload(targetEntries = []) {
  const entries = normalizeArray(targetEntries);
  const targets = entries.map(({ target, records }) => {
    const view = buildMonitoringTargetView(target, records);
    const comparison = buildStoredTargetDiff(records);
    return {
      ...view,
      latestRiskEvents: comparison?.riskEvents ?? [],
    };
  });
  const gradeDistribution = {};
  const riskEventCounts = {
    critical: 0,
    warning: 0,
    info: 0,
  };
  const topRiskEvents = [];

  for (const target of targets) {
    if (target.latestScan?.grade) {
      incrementCount(gradeDistribution, target.latestScan.grade);
    }

    for (const event of target.latestRiskEvents) {
      if (event.severity in riskEventCounts) {
        riskEventCounts[event.severity] += 1;
      }
      topRiskEvents.push({
        targetId: target.id,
        targetUrl: target.url,
        targetLabel: target.label,
        eventType: event.eventType,
        severity: event.severity,
        title: event.title,
        detail: event.detail,
      });
    }
  }

  topRiskEvents.sort((left, right) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    const severityDelta = severityOrder[left.severity] - severityOrder[right.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return String(left.targetLabel).localeCompare(String(right.targetLabel));
  });

  return {
    apiVersion: API_VERSION,
    summary: {
      totalTargets: targets.length,
      dueTargets: targets.filter((target) => target.due).length,
      targetsWithCompletedScans: targets.filter((target) => target.latestScan).length,
      gradeDistribution,
      riskEventCounts,
      topRiskEvents: topRiskEvents.slice(0, 20),
    },
    targets,
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
