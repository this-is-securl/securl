import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";
import { buildActionPlan } from "../packages/core/dist/actionPlan.js";
import { buildExposureBrief } from "../packages/core/dist/exposureBrief.js";
import { buildPostureInsights } from "../packages/core/dist/postureInsights.js";
import { buildPostureDigest } from "../packages/core/dist/postureDigest.js";
import { buildPostureDriftReportFromDiff } from "../packages/core/dist/postureDrift.js";
import { buildVendorExposureBrief } from "../packages/core/dist/vendorExposure.js";
import { buildObservationLedger } from "../packages/core/dist/observations.js";
import { diffObservationLedgers } from "../packages/core/dist/observationDrift.js";
import { DEFAULT_OBSERVATION_POLICY, evaluateObservationPolicy } from "../packages/core/dist/observationPolicy.js";

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

function buildMobilePostureDriftSummary(comparison) {
  if (!comparison?.drift) {
    return null;
  }

  return {
    currentScanId: comparison.currentScanId,
    previousScanId: comparison.previousScanId,
    direction: comparison.drift.direction,
    severity: comparison.drift.severity,
    scoreDelta: comparison.drift.scoreDelta,
    gradeChanged: comparison.drift.gradeChanged,
    hasRegression: comparison.drift.hasRegression,
    hasImprovement: comparison.drift.hasImprovement,
    changedAreas: normalizeArray(comparison.drift.changedAreas).slice(0, 8),
    eventCounts: comparison.drift.eventCounts ?? {
      critical: 0,
      warning: 0,
      info: 0,
    },
    summary: normalizeArray(comparison.drift.summary).slice(0, 3),
    topEvents: normalizeArray(comparison.drift.topEvents).slice(0, 3).map((event) => ({
      eventType: event.eventType,
      severity: event.severity,
      title: event.title,
      detail: event.detail,
    })),
  };
}

function severityRank(severity) {
  return { critical: 3, warning: 2, info: 1 }[severity] ?? 0;
}

function strongestSeverity(values) {
  return normalizeArray(values)
    .filter(Boolean)
    .sort((left, right) => severityRank(right) - severityRank(left))[0] ?? null;
}

function secondsUntil(isoDate) {
  const time = isoDate ? new Date(isoDate).getTime() : NaN;
  if (!Number.isFinite(time)) {
    return null;
  }
  return Math.max(0, Math.ceil((time - Date.now()) / 1000));
}

function buildMobileNextCheck(view) {
  return {
    cadence: view.cadence,
    scheduledAt: view.nextDueAt,
    due: view.due,
    secondsUntilDue: secondsUntil(view.nextDueAt),
    lastCheckedAt: view.lastCheckedAt,
  };
}

function buildCertChangeSummary(view, certEventCount) {
  if (!view.cert) {
    return null;
  }

  const latestEvent = normalizeArray(view.cert.history).find((entry) => entry?.eventType) ?? null;
  const attention = view.cert.attention ?? null;
  const type = latestEvent?.eventType ?? attention?.type ?? null;
  const severity = strongestSeverity([attention?.severity, latestEvent?.eventSeverity, latestEvent ? "info" : null]);

  return {
    type,
    severity,
    changed: Boolean(type),
    eventCount: certEventCount,
    title: attention?.title ?? latestEvent?.eventTitle ?? (type ? `Certificate changed: ${view.cert.host ?? view.label}` : null),
    detail: attention?.body ?? latestEvent?.eventDetail ?? null,
    occurredAt: latestEvent?.checkedAt ?? view.cert.checkedAt ?? view.lastCheckedAt,
  };
}

function buildPostureChangeSummary(posture, riskEventCount) {
  if (!posture) {
    return {
      type: null,
      severity: null,
      changed: false,
      eventCount: 0,
      title: null,
      detail: null,
      occurredAt: null,
    };
  }

  const topEvent = normalizeArray(posture.topEvents)[0] ?? null;
  const type = posture.hasRegression
    ? "posture_regressed"
    : posture.hasImprovement
      ? "posture_improved"
      : posture.direction === "changed"
        ? "posture_changed"
        : null;

  return {
    type,
    severity: posture.severity ?? topEvent?.severity ?? null,
    changed: Boolean(type),
    eventCount: riskEventCount,
    title: topEvent?.title ?? (type ? "Posture changed" : null),
    detail: topEvent?.detail ?? normalizeArray(posture.summary)[0] ?? null,
    occurredAt: null,
  };
}

function buildMobileTargetStatus({ view, posture, certChange, postureChange, latestRecord }) {
  const certAttention = view.cert?.attention ?? null;
  if (certAttention?.severity === "critical") {
    return { state: "needs_attention", severity: "critical", reason: certAttention.type };
  }
  if (posture?.hasRegression) {
    return { state: "needs_attention", severity: posture.severity ?? "warning", reason: "posture_regressed" };
  }
  if (certAttention) {
    return { state: "needs_attention", severity: certAttention.severity ?? "warning", reason: certAttention.type };
  }
  if (certChange?.changed || postureChange?.changed) {
    return {
      state: "changed",
      severity: strongestSeverity([certChange?.severity, postureChange?.severity]) ?? "info",
      reason: certChange?.type ?? postureChange?.type,
    };
  }
  if (view.due) {
    return { state: "due", severity: "info", reason: "scheduled_check_due" };
  }
  if (view.kind === "posture" && !latestRecord) {
    return { state: "pending", severity: "info", reason: "no_completed_scan" };
  }
  if (view.kind === "cert" && !view.cert) {
    return { state: "pending", severity: "info", reason: "no_certificate_check" };
  }
  return { state: "stable", severity: null, reason: null };
}

function buildMobileTargetActions({ view, status, posture, certChange, latestRecord }) {
  const actions = [];
  if (view.kind === "posture" && !latestRecord) {
    actions.push({
      id: "run_initial_scan",
      label: "Run first check",
      priority: "high",
    });
  }
  if (status.reason === "posture_regressed") {
    actions.push({
      id: "review_posture_regression",
      label: "Review posture regression",
      priority: posture?.severity === "critical" ? "critical" : "high",
    });
  }
  if (view.cert?.attention) {
    actions.push({
      id: view.cert.attention.type === "unreachable" ? "check_tls_endpoint" : "review_certificate",
      label: view.cert.attention.type === "unreachable" ? "Check TLS endpoint" : "Review certificate",
      priority: view.cert.attention.severity === "critical" ? "critical" : "high",
    });
  }
  if (certChange?.type === "cert_renewed") {
    actions.push({
      id: "confirm_certificate_renewal",
      label: "Confirm renewal",
      priority: "normal",
    });
  }
  if (view.due && actions.every((action) => action.id !== "run_initial_scan")) {
    actions.push({
      id: "run_scheduled_check",
      label: "Run scheduled check",
      priority: "normal",
    });
  }
  return actions.slice(0, 4);
}

function buildMobileDigestPreview(record) {
  if (!record?.result) {
    return null;
  }

  const digest = buildPostureDigest(record.result, { findingLimit: 3 });
  return {
    scanId: record.id,
    generatedAt: digest.generatedAt,
    target: {
      host: digest.target.host,
      finalUrl: digest.target.finalUrl,
      scannedAt: digest.target.scannedAt,
      statusCode: digest.target.statusCode,
      responseTimeMs: digest.target.responseTimeMs,
    },
    posture: {
      score: digest.posture.score,
      grade: digest.posture.grade,
      summary: digest.posture.summary,
      overview: digest.posture.overview,
      mainRisk: digest.posture.mainRisk,
      limited: digest.posture.limited,
      limitedKind: digest.posture.limitedKind,
      scoreDrivers: normalizeArray(digest.posture.scoreDrivers).slice(0, 3),
    },
    findings: {
      total: digest.findings.total,
      bySeverity: digest.findings.bySeverity,
      top: normalizeArray(digest.findings.top).slice(0, 3),
    },
    signalClarity: digest.signalClarity ? {
      headline: digest.signalClarity.headline,
      verdict: digest.signalClarity.verdict,
      summary: digest.signalClarity.summary,
      confidence: digest.signalClarity.confidence,
      topNegativeDrivers: normalizeArray(digest.signalClarity.topNegativeDrivers).slice(0, 3),
      topPositiveSignals: normalizeArray(digest.signalClarity.topPositiveSignals).slice(0, 3),
      nextBestAction: digest.signalClarity.nextBestAction,
      caveats: normalizeArray(digest.signalClarity.caveats).slice(0, 3),
    } : null,
    controls: {
      headers: digest.controls.headers,
      tls: {
        available: digest.controls.tls.available,
        valid: digest.controls.tls.valid,
        authorized: digest.controls.tls.authorized,
        issuer: digest.controls.tls.issuer,
        daysRemaining: digest.controls.tls.daysRemaining,
      },
    },
    trust: {
      securityTxtStatus: digest.trust.securityTxt.status,
      thirdPartyProviders: normalizeArray(digest.trust.thirdParty.providers).slice(0, 5),
      highRiskThirdPartyProviders: digest.trust.thirdParty.highRiskProviders,
      identityProvider: digest.trust.identityProvider,
      wafProviders: normalizeArray(digest.trust.wafProviders).slice(0, 5),
      infrastructureProviders: normalizeArray(digest.trust.infrastructureProviders).slice(0, 5),
    },
    intelligence: {
      compromisePosture: digest.intelligence.compromisePosture,
      riskIndicators: normalizeArray(digest.intelligence.riskIndicators).slice(0, 3),
      ctPriorityHosts: normalizeArray(digest.intelligence.ctPriorityHosts).slice(0, 5),
      aiVendors: normalizeArray(digest.intelligence.aiVendors).slice(0, 5),
    },
  };
}

function cadenceWindowMs(cadence) {
  if (cadence === "hourly") return 60 * 60 * 1000;
  if (cadence === "6h") return 6 * 60 * 60 * 1000;
  if (cadence === "weekly") return 7 * 24 * 60 * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}

export function buildMonitoringTargetView(target, records = []) {
  const baseTime = target.lastCheckedAt
    ? new Date(target.lastCheckedAt).getTime()
    : target.lastScannedAt
      ? new Date(target.lastScannedAt).getTime()
      : new Date(target.addedAt).getTime();
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
    kind: target.kind ?? "posture",
    mode: target.mode ?? null,
    appId: target.appId ?? null,
    observationPolicy: target.observationPolicy ?? null,
    addedAt: target.addedAt,
    lastScannedAt: target.lastScannedAt ?? null,
    lastCheckedAt: target.lastCheckedAt ?? target.lastScannedAt ?? null,
    nextDueAt,
    due: Date.now() >= new Date(nextDueAt).getTime(),
    cert: target.certState ?? null,
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

export function buildScanInsightsPayload(scan) {
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
    insights: result ? result.postureInsights ?? buildPostureInsights(result) : null,
  };
}

export function buildScanMobileSummaryPayload(scan) {
  const digestPayload = buildScanDigestPayload(scan);
  const insightsPayload = buildScanInsightsPayload(scan);
  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    ready: scan.status === "completed" && Boolean(scan.result),
    digest: digestPayload.digest,
    insights: insightsPayload.insights,
  };
}

export function buildScanObservationsPayload(scan) {
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
    observationLedger: result ? result.observationLedger ?? buildObservationLedger(result) : null,
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

export function buildScanObservationDriftPayload(scan, records) {
  const completedRecords = normalizeArray(records).filter((record) => record?.status === "completed" && record?.result);
  const currentIndex = completedRecords.findIndex((record) => record.id === scan.id);
  const comparisonRecords = currentIndex >= 0
    ? completedRecords.slice(currentIndex, currentIndex + 2)
    : completedRecords.slice(0, 2);
  const [current, previous] = comparisonRecords;
  const observationDrift = current && previous
    ? diffObservationLedgers(
        current.result.observationLedger ?? buildObservationLedger(current.result),
        previous.result.observationLedger ?? buildObservationLedger(previous.result),
      )
    : null;

  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    scans: comparisonRecords.map((record) => record.summary).filter(Boolean),
    observationDrift: observationDrift ? {
      currentScanId: current.id,
      previousScanId: previous.id,
      ...observationDrift,
    } : null,
  };
}

function buildPolicyEvaluation(records, policy = null) {
  const completed = normalizeArray(records).filter((record) => record?.status === "completed" && record?.result);
  const [current, previous] = completed;
  if (!current) return null;
  const ledger = current.result.observationLedger ?? buildObservationLedger(current.result);
  const drift = previous
    ? diffObservationLedgers(
        ledger,
        previous.result.observationLedger ?? buildObservationLedger(previous.result),
      )
    : null;
  return evaluateObservationPolicy({ ledger, drift, policy: policy ?? DEFAULT_OBSERVATION_POLICY });
}

export function buildScanPolicyEvaluationPayload(scan, records, policy = null, policySource = "default") {
  const completedRecords = normalizeArray(records).filter((record) => record?.status === "completed" && record?.result);
  const currentIndex = completedRecords.findIndex((record) => record.id === scan.id);
  const comparisonRecords = currentIndex >= 0
    ? completedRecords.slice(currentIndex, currentIndex + 2)
    : completedRecords.slice(0, 2);
  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    policySource,
    policyEvaluation: buildPolicyEvaluation(comparisonRecords, policy),
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

function buildMobileTargetSummary(target, records = []) {
  const view = buildMonitoringTargetView(target, records);
  const comparison = buildStoredTargetDiff(records);
  const latestRecord = normalizeArray(records).find((record) => record?.status === "completed" && record?.result);
  const certHistory = Array.isArray(view.cert?.history) ? view.cert.history : [];
  const certEventCount = certHistory.filter((entry) => entry?.eventType).length;
  const posture = buildMobilePostureDriftSummary(comparison);
  const certChange = buildCertChangeSummary(view, certEventCount);
  const postureChange = buildPostureChangeSummary(posture, comparison?.riskEvents?.length ?? 0);
  const status = buildMobileTargetStatus({ view, posture, certChange, postureChange, latestRecord });

  return {
    id: view.id,
    kind: view.kind,
    url: view.url,
    label: view.label,
    cadence: view.cadence,
    mode: view.mode,
    appId: view.appId,
    addedAt: view.addedAt,
    lastCheckedAt: view.lastCheckedAt,
    nextDueAt: view.nextDueAt,
    due: view.due,
    nextCheck: buildMobileNextCheck(view),
    status,
    latestScan: view.latestScan
      ? {
          id: view.latestScan.id,
          status: view.latestScan.status,
          grade: view.latestScan.grade,
          score: view.latestScan.score,
          completedAt: view.latestScan.completedAt,
          findingsCount: view.latestScan.findingsCount,
          mainRisk: view.latestScan.mainRisk,
      }
      : null,
    scoreDelta: view.scoreDelta,
    latestDigest: view.kind === "posture" ? buildMobileDigestPreview(latestRecord) : null,
    cert: view.cert
      ? {
          reachable: view.cert.reachable ?? false,
          checkedAt: view.cert.checkedAt ?? null,
          host: view.cert.host ?? null,
          issuer: view.cert.issuer ?? null,
          validTo: view.cert.validTo ?? null,
          daysRemaining: view.cert.daysRemaining ?? null,
          serialNumber: view.cert.serialNumber ?? null,
          lastEventType: view.cert.lastEventType ?? null,
          lastWarnedBand: view.cert.lastWarnedBand ?? null,
          attention: view.cert.attention ?? null,
          issues: normalizeArray(view.cert.issues).slice(0, 5),
      }
      : null,
    posture,
    change: view.kind === "cert" ? certChange : postureChange,
    actions: buildMobileTargetActions({ view, status, posture, certChange, latestRecord }),
    changes: {
      postureRiskEvents: comparison?.riskEvents?.length ?? 0,
      certEvents: certEventCount,
    },
  };
}

export function buildMonitoringMobileSummaryPayload(targetEntries = []) {
  const targets = normalizeArray(targetEntries).map(({ target, records }) => buildMobileTargetSummary(target, records));
  const dueTargets = targets.filter((target) => target.due).length;
  const certTargets = targets.filter((target) => target.kind === "cert").length;
  const postureTargets = targets.filter((target) => target.kind !== "cert").length;

  return {
    apiVersion: API_VERSION,
    summary: {
      totalTargets: targets.length,
      dueTargets,
      postureTargets,
      certTargets,
      changes: targets.reduce((total, target) => total + target.changes.postureRiskEvents + target.changes.certEvents, 0),
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
    policyEvaluation: target.kind === "posture" ? buildPolicyEvaluation(records, target.observationPolicy) : null,
    events: normalizeArray(events).map(buildPublicScanEvent),
  };
}
