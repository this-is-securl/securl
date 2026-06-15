import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";
import { buildActionPlan } from "../packages/core/dist/actionPlan.js";
import { buildExposureBrief } from "../packages/core/dist/exposureBrief.js";
import { buildPostureDigest } from "../packages/core/dist/postureDigest.js";
import { buildPostureDriftReportFromDiff } from "../packages/core/dist/postureDrift.js";
import { buildVendorExposureBrief } from "../packages/core/dist/vendorExposure.js";

export const API_VERSION = "2026-05-14";
export const SCAN_EXPORT_FORMATS = ["json", "markdown", "sarif", "ci-json"];

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function buildPublicScanEvent(event) {
  const metadata = event?.metadata && typeof event.metadata === "object" ? event.metadata : {};
  return {
    id: event.id,
    scanId: event.scanId,
    eventType: event.eventType,
    occurredAt: event.occurredAt,
    status: event.status,
    failureClass: event.failureClass ?? null,
    message: event.message ?? null,
    metadata: {
      ...(Object.hasOwn(metadata, "url") ? { url: metadata.url } : {}),
      ...(Object.hasOwn(metadata, "mode") ? { mode: metadata.mode } : {}),
      ...(Object.hasOwn(metadata, "score") ? { score: metadata.score } : {}),
      ...(Object.hasOwn(metadata, "grade") ? { grade: metadata.grade } : {}),
      ...(Object.hasOwn(metadata, "limited") ? { limited: metadata.limited } : {}),
      ...(Object.hasOwn(metadata, "limitedKind") ? { limitedKind: metadata.limitedKind } : {}),
    },
  };
}

function safeExportName(value) {
  return String(value || "scan")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "scan";
}

function countIssuesBySeverity(issues) {
  return normalizeArray(issues).reduce((counts, issue) => {
    const severity = issue?.severity || "unknown";
    counts[severity] = (counts[severity] ?? 0) + 1;
    return counts;
  }, {});
}

function sarifLevel(severity) {
  if (severity === "critical") return "error";
  if (severity === "warning") return "warning";
  return "note";
}

function ruleIdForIssue(issue) {
  return safeExportName(issue?.title || "external-posture-finding") || "external-posture-finding";
}

function buildMarkdownExport(scan) {
  const result = scan.result;
  return [
    `# SecURL Scan: ${result.host || scan.url}`,
    "",
    `- URL: ${result.finalUrl || scan.url}`,
    `- Scan ID: ${scan.id}`,
    `- Mode: ${scan.mode}`,
    `- Completed: ${scan.completedAt}`,
    `- Score: ${result.score}/100`,
    `- Grade: ${result.grade}`,
    "",
    "## Summary",
    "",
    result.executiveSummary?.overview || result.summary || "No summary recorded.",
    "",
    "## Key Findings",
    "",
    ...(normalizeArray(result.issues).length
      ? normalizeArray(result.issues).slice(0, 20).map((issue) => `- [${issue.severity}] ${issue.title}: ${issue.detail}`)
      : ["- No findings recorded."]),
    "",
    "## Score Drivers",
    "",
    ...(normalizeArray(result.scoreDrivers).length
      ? normalizeArray(result.scoreDrivers).map((driver) => `- ${driver.label}: ${driver.impact} (${driver.detail})`)
      : ["- No score drivers recorded."]),
  ].join("\n");
}

function buildSarifExport(scan) {
  const result = scan.result;
  const rules = new Map();
  const results = [];

  for (const issue of normalizeArray(result.issues)) {
    const ruleId = ruleIdForIssue(issue);
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: issue.title,
        shortDescription: { text: issue.title },
        fullDescription: { text: issue.detail },
        help: { text: issue.detail },
        properties: {
          tags: [
            ...normalizeArray(issue.owasp),
            ...normalizeArray(issue.mitre),
            issue.area,
            issue.source,
            issue.confidence,
          ].filter(Boolean),
        },
      });
    }

    results.push({
      ruleId,
      level: sarifLevel(issue.severity),
      message: { text: issue.detail },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: result.finalUrl || scan.url },
          },
        },
      ],
      properties: {
        scanId: scan.id,
        host: result.host,
        score: result.score,
        grade: result.grade,
        severity: issue.severity,
        area: issue.area,
        confidence: issue.confidence,
        source: issue.source,
      },
    });
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "SecURL",
            informationUri: "https://securl.online",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}

function buildCiJsonExport(scan) {
  const result = scan.result;
  const criticalIssues = normalizeArray(result.issues).filter((issue) => issue.severity === "critical");
  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    target: {
      inputUrl: result.inputUrl,
      finalUrl: result.finalUrl,
      host: result.host,
    },
    posture: {
      score: result.score,
      grade: result.grade,
      summary: result.summary,
      mainRisk: result.executiveSummary?.mainRisk ?? null,
      issueCounts: countIssuesBySeverity(result.issues),
      criticalIssueCount: criticalIssues.length,
      passed: criticalIssues.length === 0,
    },
    findings: normalizeArray(result.issues).map((issue) => ({
      severity: issue.severity,
      area: issue.area,
      title: issue.title,
      detail: issue.detail,
      confidence: issue.confidence,
      source: issue.source,
    })),
  };
}

export function buildScanExportResponse(scan, format = "json") {
  if (!SCAN_EXPORT_FORMATS.includes(format)) {
    return null;
  }

  if (scan.status !== "completed" || !scan.result) {
    return {
      notReady: true,
    };
  }

  const baseName = safeExportName(scan.result.host || scan.url || scan.id);
  if (format === "markdown") {
    return {
      body: `${buildMarkdownExport(scan)}\n`,
      contentType: "text/markdown; charset=utf-8",
      filename: `${baseName}-securl-report.md`,
    };
  }

  if (format === "sarif") {
    return {
      body: `${JSON.stringify(buildSarifExport(scan), null, 2)}\n`,
      contentType: "application/sarif+json; charset=utf-8",
      filename: `${baseName}-securl.sarif`,
    };
  }

  if (format === "ci-json") {
    return {
      body: `${JSON.stringify(buildCiJsonExport(scan), null, 2)}\n`,
      contentType: "application/json; charset=utf-8",
      filename: `${baseName}-securl-ci.json`,
    };
  }

  return {
    body: `${JSON.stringify({ apiVersion: API_VERSION, scan: scan.summary, result: scan.result }, null, 2)}\n`,
    contentType: "application/json; charset=utf-8",
    filename: `${baseName}-securl-report.json`,
  };
}

function buildStoredTargetDrift(records) {
  const completedWithResults = normalizeArray(records).filter((scan) => scan?.status === "completed" && scan?.result);
  if (completedWithResults.length < 2) {
    return null;
  }

  const [current, previous] = completedWithResults;
  const currentSnapshot = snapshotFromAnalysis(current.result);
  const previousSnapshot = snapshotFromAnalysis(previous.result);
  const diff = buildHistoryDiffFromSnapshots(currentSnapshot, previousSnapshot);
  const report = buildPostureDriftReportFromDiff(currentSnapshot, previousSnapshot, diff);

  return {
    currentScanId: current.id,
    previousScanId: previous.id,
    report,
  };
}

function buildStoredTargetDiff(records) {
  const drift = buildStoredTargetDrift(records);
  if (!drift) {
    return null;
  }

  return {
    currentScanId: drift.currentScanId,
    previousScanId: drift.previousScanId,
    diff: drift.report.diff,
    riskEvents: drift.report.riskEvents,
    drift: drift.report.summary,
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
    id: target.id,
    url: target.url,
    label: target.label,
    cadence: target.cadence,
    addedAt: target.addedAt,
    lastScannedAt: target.lastScannedAt ?? null,
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
    remediationPlan: result.remediationPlan ?? null,
    evidenceSummary: result.evidenceSummary ?? null,
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

export function buildScanBriefPayload(scan) {
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
    brief: result ? result.exposureBrief ?? buildExposureBrief(result) : null,
  };
}

export function buildScanVendorsPayload(scan) {
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
    vendors: result ? result.vendorExposure ?? buildVendorExposureBrief(result) : null,
  };
}

export function buildScanActionPlanPayload(scan) {
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
    actionPlan: result ? result.actionPlan ?? buildActionPlan(result) : null,
  };
}

export function buildScanDetailPayload(scan) {
  return {
    apiVersion: API_VERSION,
    scan: {
      ...scan.summary,
      result: scan.result ?? null,
    },
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
      evidenceSummary: result.evidenceSummary ?? null,
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
    events: normalizeArray(events).map(buildPublicScanEvent),
  };
}

export function buildScanComparisonPayload(scan, records) {
  const completedRecords = normalizeArray(records).filter((record) => record?.status === "completed" && record?.result);
  const currentIndex = completedRecords.findIndex((record) => record.id === scan.id);
  const comparisonRecords = currentIndex >= 0
    ? completedRecords.slice(currentIndex, currentIndex + 2)
    : completedRecords.slice(0, 2);

  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    scans: comparisonRecords.map((record) => record.summary).filter(Boolean),
    comparison: buildStoredTargetDiff(comparisonRecords),
  };
}

export function buildScanDriftPayload(scan, records) {
  const completedRecords = normalizeArray(records).filter((record) => record?.status === "completed" && record?.result);
  const currentIndex = completedRecords.findIndex((record) => record.id === scan.id);
  const comparisonRecords = currentIndex >= 0
    ? completedRecords.slice(currentIndex, currentIndex + 2)
    : completedRecords.slice(0, 2);
  const drift = buildStoredTargetDrift(comparisonRecords);

  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    scans: comparisonRecords.map((record) => record.summary).filter(Boolean),
    drift: drift ? {
      currentScanId: drift.currentScanId,
      previousScanId: drift.previousScanId,
      ...drift.report,
    } : null,
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
    events: normalizeArray(events).map(buildPublicScanEvent),
  };
}
