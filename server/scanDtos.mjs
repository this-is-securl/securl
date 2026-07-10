import { createRequire } from "node:module";
import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";
import { buildActionPlan } from "../packages/core/dist/actionPlan.js";
import { buildExposureBrief } from "../packages/core/dist/exposureBrief.js";
import { buildPostureInsights } from "../packages/core/dist/postureInsights.js";
import { buildPostureDigest } from "../packages/core/dist/postureDigest.js";
import { buildPostureManifest } from "../packages/core/dist/postureManifest.js";
import { buildPostureDriftReportFromDiff } from "../packages/core/dist/postureDrift.js";
import {
  buildCertificateMonitoringEvents,
  buildMonitoringEventsFromSnapshots,
} from "../packages/core/dist/monitoringEvents.js";
import { buildVendorExposureBrief } from "../packages/core/dist/vendorExposure.js";
import { buildObservationLedger } from "../packages/core/dist/observations.js";
import { diffObservationLedgers } from "../packages/core/dist/observationDrift.js";
import { DEFAULT_OBSERVATION_POLICY, evaluateObservationPolicy } from "../packages/core/dist/observationPolicy.js";

const require = createRequire(import.meta.url);
const corePackage = require("../packages/core/package.json");
export const API_VERSION = "2026-05-14";
export const SCAN_EXPORT_FORMATS = ["json", "markdown", "sarif", "ci-json"];
const CORE_ENGINE_VERSION = corePackage.version;
const DEFAULT_WEB_APP_ORIGIN = "https://app.securl.online";

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

function webAppOrigin() {
  return String(process.env.SECURL_WEB_APP_ORIGIN || DEFAULT_WEB_APP_ORIGIN).replace(/\/+$/, "");
}

function webReportUrl(scanId, source = "api", campaign = "share_card") {
  const url = new URL(`/report/${scanId}`, webAppOrigin());
  url.searchParams.set("utm_source", source);
  url.searchParams.set("utm_medium", "share");
  url.searchParams.set("utm_campaign", campaign);
  return url.toString();
}

function scannerHandoffUrl(targetUrl, source = "share_card", campaign = "scan_handoff") {
  const url = new URL("/", webAppOrigin());
  url.searchParams.set("url", targetUrl);
  url.searchParams.set("utm_source", source);
  url.searchParams.set("utm_medium", "web");
  url.searchParams.set("utm_campaign", campaign);
  return url.toString();
}

function scanResourceLinks(scanId) {
  const basePath = `/api/scans/${scanId}`;
  return {
    detail: basePath,
    summary: `${basePath}/summary`,
    digest: `${basePath}/digest`,
    insights: `${basePath}/insights`,
    mobileSummary: `${basePath}/mobile-summary`,
    share: `${basePath}/share`,
    shareCard: `${basePath}/share-card`,
  };
}

function compactFinding(issue) {
  return {
    severity: issue?.severity ?? "info",
    title: issue?.title ?? "Posture finding",
    detail: issue?.detail ?? null,
    area: issue?.area ?? null,
    confidence: issue?.confidence ?? null,
  };
}

function compactScoreDriver(driver) {
  return {
    label: driver?.label ?? driver?.title ?? "Score driver",
    detail: driver?.detail ?? null,
    impact: typeof driver?.impact === "number" ? driver.impact : null,
    direction: driver?.direction ?? null,
  };
}

function actionLabel(action) {
  if (!action) {
    return null;
  }
  if (typeof action === "string") {
    return action;
  }
  return action.label ?? action.title ?? action.action ?? action.whyNow ?? null;
}

export function buildScanShareCardPayload(scan) {
  if (scan.status !== "completed" || !scan.result) {
    return {
      apiVersion: API_VERSION,
      ready: false,
      scan: scan.summary,
      shareCard: null,
      resources: scanResourceLinks(scan.id),
    };
  }

  const result = scan.result;
  const digest = result.postureDigest ?? buildPostureDigest(result, { findingLimit: 3 });
  const insights = result.postureInsights ?? buildPostureInsights(result);
  const actionPlan = result.actionPlan ?? buildActionPlan(result);
  const finalUrl = result.finalUrl || result.normalizedUrl || scan.url;
  const host = result.host || new URL(finalUrl).hostname;
  const topIssues = normalizeArray(digest.findings?.top).slice(0, 3).map(compactFinding);
  const scoreDrivers = normalizeArray(digest.posture?.scoreDrivers).slice(0, 3).map(compactScoreDriver);
  const nextBestAction =
    actionLabel(normalizeArray(insights.nextBestActions)[0])
    ?? actionLabel(normalizeArray(actionPlan.items)[0])
    ?? actionLabel(digest.signalClarity?.nextBestAction)
    ?? null;
  const grade = result.grade ?? digest.posture?.grade ?? "U";
  const score = typeof result.score === "number" ? result.score : digest.posture?.score ?? null;
  const reportUrl = webReportUrl(scan.id);
  const scannerUrl = scannerHandoffUrl(finalUrl);
  const title = `SecURL report for ${host}: ${grade}${typeof score === "number" ? ` (${score}/100)` : ""}`;
  const summary = digest.signalClarity?.headline
    ?? digest.posture?.summary
    ?? result.executiveSummary?.overview
    ?? result.summary
    ?? "External security posture report generated by SecURL.";
  const shareText = `${title}\n${summary}\n${reportUrl}`;

  return {
    apiVersion: API_VERSION,
    ready: true,
    scan: {
      id: scan.id,
      status: scan.status,
      url: scan.url,
      mode: scan.mode,
      completedAt: scan.completedAt,
      grade,
      score,
    },
    shareCard: {
      title,
      summary,
      target: {
        host,
        finalUrl,
      },
      posture: {
        grade,
        score,
        mainRisk: digest.posture?.mainRisk ?? result.executiveSummary?.mainRisk ?? null,
        signalClarity: digest.signalClarity ? {
          headline: digest.signalClarity.headline,
          verdict: digest.signalClarity.verdict,
          confidence: digest.signalClarity.confidence,
        } : null,
      },
      topIssues,
      scoreDrivers,
      nextBestAction,
      share: {
        text: shareText,
        shortText: title,
        reportUrl,
        scannerUrl,
      },
      links: {
        report: `/report/${scan.id}`,
        webReport: reportUrl,
        scannerHandoff: scannerUrl,
        apiShare: `/api/scans/${scan.id}/share`,
      },
      generatedAt: new Date().toISOString(),
    },
    resources: scanResourceLinks(scan.id),
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
  const monitoringEvents = buildMonitoringEventsFromSnapshots(currentSnapshot, previousSnapshot, diff);

  return {
    currentScanId: current.id,
    previousScanId: previous.id,
    report,
    monitoringEvents,
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
    monitoringEvents: drift.monitoringEvents,
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
    monitoringEvents: normalizeArray(comparison.monitoringEvents).slice(0, 5),
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

function certResultFromState(state) {
  if (!state) {
    return null;
  }
  return {
    host: state.host ?? "unknown",
    port: state.port ?? 443,
    checkedAt: state.checkedAt ?? new Date().toISOString(),
    available: state.reachable ?? false,
    valid: state.valid ?? (state.reachable ?? false),
    authorized: state.authorized ?? (state.reachable ?? false),
    issuer: state.issuer ?? null,
    subject: state.subject ?? null,
    validFrom: state.validFrom ?? null,
    validTo: state.validTo ?? null,
    daysRemaining: typeof state.daysRemaining === "number" ? state.daysRemaining : null,
    protocol: state.protocol ?? null,
    cipher: state.cipher ?? null,
    fingerprint: state.fingerprint ?? null,
    serialNumber: state.serialNumber ?? null,
    keyBits: typeof state.keyBits === "number" ? state.keyBits : null,
    keyType: state.keyType ?? null,
    subjectAltName: [],
    issues: normalizeArray(state.issues),
    chain: normalizeArray(state.chain),
  };
}

function certPolicyExpiryDays(policy) {
  if (policy === "production") return 14;
  if (policy === "strict" || policy === "renewal-watch") return 30;
  return null;
}

function filterCertMonitoringEventsForPolicy(events, view) {
  const expiryDays = certPolicyExpiryDays(view.certPolicy ?? view.cert?.policyProfile ?? null);
  if (expiryDays === null) {
    return events;
  }
  return normalizeArray(events).filter((event) => (
    event?.eventType !== "certificate_expiring"
    || (
      typeof view.cert?.daysRemaining === "number"
      && view.cert.daysRemaining <= expiryDays
    )
  ));
}

function buildCertMonitoringEventsFromView(view) {
  if (Array.isArray(view.cert?.monitoringEvents) && view.cert.monitoringEvents.length) {
    return filterCertMonitoringEventsForPolicy(view.cert.monitoringEvents, view);
  }
  const current = certResultFromState(view.cert);
  if (!current) {
    return [];
  }
  const latestPrevious = normalizeArray(view.cert?.history)
    .find((entry) => entry?.previousDaysRemaining !== null || entry?.previousIssuer || entry?.previousSerialNumber);
  const previous = latestPrevious
    ? certResultFromState({
        ...view.cert,
        checkedAt: latestPrevious.checkedAt ?? null,
        reachable: latestPrevious.previousReachable ?? null,
        issuer: latestPrevious.previousIssuer ?? null,
        serialNumber: latestPrevious.previousSerialNumber ?? null,
        validTo: latestPrevious.previousValidTo ?? null,
        daysRemaining: latestPrevious.previousDaysRemaining ?? null,
      })
    : null;
  return filterCertMonitoringEventsForPolicy(buildCertificateMonitoringEvents(current, previous), view);
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
    certPolicy: target.certPolicy ?? target.certState?.policyProfile ?? null,
    policy: (target.kind ?? "posture") === "cert" ? target.certPolicy ?? target.certState?.policyProfile ?? null : null,
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
  const vendors = result
    ? result.vendorExposure?.schemaVersion === "1.0"
      ? result.vendorExposure
      : buildVendorExposureBrief(result)
    : null;
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
    vendors,
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
      monitoringEvents: drift.monitoringEvents,
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

export function buildScanManifestPayload(scan, records, policy = null, policySource = "default") {
  if (scan.status !== "completed" || !scan.result) {
    return {
      apiVersion: API_VERSION,
      scan: scan.summary,
      postureManifest: null,
    };
  }
  const policyEvaluation = buildScanPolicyEvaluationPayload(scan, records, policy, policySource).policyEvaluation;
  return {
    apiVersion: API_VERSION,
    scan: scan.summary,
    postureManifest: buildPostureManifest(scan.result, {
      engineVersion: CORE_ENGINE_VERSION,
      scanMode: scan.mode,
      policySource,
      policyEvaluation,
    }),
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
  const certMonitoringEvents = buildCertMonitoringEventsFromView(view);
  const storedCertMonitoringEvents = filterCertMonitoringEventsForPolicy(
    normalizeArray(view.cert?.monitoringEvents),
    view,
  );
  const monitoringEvents = view.kind === "cert"
    ? certMonitoringEvents
    : normalizeArray(posture?.monitoringEvents);
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
    policy: view.kind === "cert" ? view.certPolicy : null,
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
          policyProfile: view.cert.policyProfile ?? view.certPolicy ?? null,
          attention: view.cert.attention ?? null,
          monitoringEvents: storedCertMonitoringEvents.slice(0, 5),
          issues: normalizeArray(view.cert.issues).slice(0, 5),
      }
      : null,
    posture,
    events: monitoringEvents.slice(0, 5),
    change: view.kind === "cert" ? certChange : postureChange,
    actions: buildMobileTargetActions({ view, status, posture, certChange, latestRecord }),
    changes: {
      postureRiskEvents: comparison?.riskEvents?.length ?? 0,
      certEvents: certEventCount,
      monitoringEvents: monitoringEvents.length,
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

function classifyCertWatchHealth(target) {
  const cert = target.cert ?? null;
  if (!cert) return { state: "unknown", severity: "info", reason: "not_checked" };
  if (cert.reachable === false) return { state: "unreachable", severity: "critical", reason: "cert_unreachable" };
  const attention = cert.attention ?? null;
  if (attention?.type === "cert_expired" || Number(cert.daysRemaining) < 0) {
    return { state: "expired", severity: "critical", reason: "cert_expired" };
  }
  if (attention?.type === "cert_expiring" || Number(cert.daysRemaining) <= 30) {
    return {
      state: "expiring",
      severity: attention?.severity ?? (Number(cert.daysRemaining) <= 7 ? "critical" : "warning"),
      reason: "cert_expiring",
    };
  }
  if (cert.reachable === true) return { state: "healthy", severity: "info", reason: null };
  return { state: "unknown", severity: "info", reason: "not_checked" };
}

function compareIsoDates(left, right) {
  return new Date(left || 0).getTime() - new Date(right || 0).getTime();
}

function buildPushHealthSummary(pushDevices = []) {
  const devices = normalizeArray(pushDevices);
  const active = devices.filter((device) => !device.disabledAt);
  const byStatus = {
    ready: 0,
    stale: 0,
    push_failed: 0,
    rejected: 0,
    disabled: devices.length - active.length,
  };
  for (const device of active) {
    const status = device.health?.status || device.status || "unknown";
    if (status in byStatus) byStatus[status] += 1;
  }
  const lastSeenAt = active
    .map((device) => device.lastSeenAt)
    .filter(Boolean)
    .sort(compareIsoDates)
    .at(-1) ?? null;
  const lastPushSentAt = active
    .map((device) => device.lastPushSentAt)
    .filter(Boolean)
    .sort(compareIsoDates)
    .at(-1) ?? null;
  return {
    configured: active.length > 0,
    registeredDevices: devices.length,
    activeDevices: active.length,
    readyDevices: byStatus.ready,
    devicesNeedingRegistration: active.filter((device) => (
      device.health?.needsRegistration ?? device.needsRegistration ?? false
    )).length,
    byStatus,
    lastSeenAt,
    lastPushSentAt,
  };
}

export function buildMonitoringCertSummaryPayload(targetEntries = [], pushDevices = []) {
  const targets = normalizeArray(targetEntries)
    .filter(({ target }) => (target?.kind ?? "posture") === "cert")
    .map(({ target, records }) => buildMobileTargetSummary(target, records));
  const healthCounts = {
    healthy: 0,
    expiring: 0,
    expired: 0,
    unreachable: 0,
    unknown: 0,
  };
  const recentChanges = [];

  for (const target of targets) {
    const health = classifyCertWatchHealth(target);
    if (health.state in healthCounts) healthCounts[health.state] += 1;
    target.health = health;
    if (target.change?.type && target.change.type !== "none") {
      recentChanges.push({
        targetId: target.id,
        targetUrl: target.url,
        targetLabel: target.label,
        checkedAt: target.cert?.checkedAt ?? target.lastCheckedAt ?? null,
        ...target.change,
      });
    }
  }

  const sortedTargets = targets.sort((left, right) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    const severityDelta = (severityOrder[left.health.severity] ?? 3) - (severityOrder[right.health.severity] ?? 3);
    if (severityDelta !== 0) return severityDelta;
    return compareIsoDates(left.nextDueAt, right.nextDueAt);
  });
  const nextDueTarget = sortedTargets
    .filter((target) => target.nextDueAt)
    .sort((left, right) => compareIsoDates(left.nextDueAt, right.nextDueAt))[0] ?? null;
  recentChanges.sort((left, right) => compareIsoDates(right.checkedAt, left.checkedAt));

  return {
    apiVersion: API_VERSION,
    summary: {
      totalCerts: targets.length,
      dueCerts: targets.filter((target) => target.due).length,
      healthyCerts: healthCounts.healthy,
      expiringCerts: healthCounts.expiring,
      expiredCerts: healthCounts.expired,
      unreachableCerts: healthCounts.unreachable,
      unknownCerts: healthCounts.unknown,
      needsAttention: healthCounts.expiring + healthCounts.expired + healthCounts.unreachable,
      changes: recentChanges.length,
      nextCheckAt: nextDueTarget?.nextDueAt ?? null,
      nextCheckTargetId: nextDueTarget?.id ?? null,
    },
    push: buildPushHealthSummary(pushDevices),
    recentChanges: recentChanges.slice(0, 10),
    targets: sortedTargets,
  };
}

function buildTargetHealthSummary(target, now = Date.now()) {
  const nextDueTime = new Date(target.nextDueAt || 0).getTime();
  const secondsUntilDue = Number.isFinite(nextDueTime)
    ? Math.ceil((nextDueTime - now) / 1000)
    : null;
  const overdueSeconds = secondsUntilDue !== null && secondsUntilDue < 0
    ? Math.abs(secondsUntilDue)
    : 0;
  const overdueThresholdSeconds = 15 * 60;
  const health = target.kind === "cert"
    ? classifyCertWatchHealth(target)
    : target.latestFailure
      ? { state: "failed", severity: "warning", reason: "latest_scan_failed" }
      : target.due
        ? { state: "due", severity: overdueSeconds > overdueThresholdSeconds ? "warning" : "info", reason: "check_due" }
        : { state: "healthy", severity: "info", reason: null };

  return {
    id: target.id,
    kind: target.kind,
    appId: target.appId,
    policy: target.kind === "cert" ? target.certPolicy : null,
    url: target.url,
    label: target.label,
    cadence: target.cadence,
    lastCheckedAt: target.lastCheckedAt,
    nextDueAt: target.nextDueAt,
    due: target.due,
    secondsUntilDue,
    overdueSeconds,
    health,
    latestGrade: target.latestScan?.grade ?? null,
    latestScore: target.latestScan?.score ?? null,
    latestFailure: target.latestFailure ?? null,
    certDaysRemaining: target.cert?.daysRemaining ?? null,
    certAttention: target.cert?.attention ?? null,
  };
}

function summarizeByApp({ targets = [], devices = [] } = {}) {
  const apps = {};
  const ensureApp = (appId) => {
    const key = appId || "unknown";
    apps[key] ||= {
      appId: key,
      targets: 0,
      postureTargets: 0,
      certTargets: 0,
      dueTargets: 0,
      needsAttention: 0,
      registeredDevices: 0,
      readyDevices: 0,
      devicesNeedingRegistration: 0,
    };
    return apps[key];
  };

  for (const target of targets) {
    const app = ensureApp(target.appId);
    app.targets += 1;
    if (target.kind === "cert") app.certTargets += 1;
    else app.postureTargets += 1;
    if (target.due) app.dueTargets += 1;
    if (["critical", "warning"].includes(target.health?.severity)) app.needsAttention += 1;
  }

  for (const device of devices) {
    const app = ensureApp(device.appId);
    app.registeredDevices += 1;
    if (device.health?.status === "ready") app.readyDevices += 1;
    if (device.health?.needsRegistration) app.devicesNeedingRegistration += 1;
  }

  return Object.fromEntries(
    Object.entries(apps)
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

export function buildMonitoringHealthPayload({
  targetEntries = [],
  pushDevices = [],
  scheduler = null,
  notifications = null,
  now = new Date(),
} = {}) {
  const nowMs = now.getTime();
  const targets = normalizeArray(targetEntries)
    .map(({ target, records }) => {
      const view = buildMonitoringTargetView(target, records);
      const latestFailure = normalizeArray(records).find((record) => record?.status === "failed");
      return {
        ...view,
        latestFailure: latestFailure?.summary
          ? {
              id: latestFailure.summary.id,
              status: latestFailure.summary.status,
              failedAt: latestFailure.summary.failedAt ?? latestFailure.summary.completedAt ?? null,
              error: latestFailure.summary.error ?? null,
            }
          : null,
      };
    })
    .map((target) => buildTargetHealthSummary(target, nowMs));
  const devices = normalizeArray(pushDevices);
  const deviceSummary = buildPushHealthSummary(devices);
  const attentionTargets = targets.filter((target) => ["critical", "warning"].includes(target.health?.severity));
  const overdueTargets = targets.filter((target) => target.overdueSeconds > 15 * 60);
  const dueTargets = targets.filter((target) => target.due);
  const certAttentionTargets = targets.filter((target) => target.kind === "cert" && target.health?.severity === "critical");
  const postureFailureTargets = targets.filter((target) => target.kind !== "cert" && target.health?.state === "failed");

  return {
    apiVersion: API_VERSION,
    generatedAt: now.toISOString(),
    summary: {
      totalTargets: targets.length,
      postureTargets: targets.filter((target) => target.kind !== "cert").length,
      certTargets: targets.filter((target) => target.kind === "cert").length,
      dueTargets: dueTargets.length,
      overdueTargets: overdueTargets.length,
      targetsNeedingAttention: attentionTargets.length,
      certAttentionTargets: certAttentionTargets.length,
      postureFailureTargets: postureFailureTargets.length,
      pushDevicesNeedingRegistration: deviceSummary.devicesNeedingRegistration,
    },
    scheduler: {
      enabled: Boolean(scheduler?.enabled),
      running: Boolean(scheduler?.running),
      mode: scheduler?.mode ?? null,
      intervalMs: scheduler?.intervalMs ?? null,
      limit: scheduler?.limit ?? null,
      lastSweep: scheduler?.lastSweep ?? null,
      lastSweepHealthy: scheduler?.lastSweep
        ? Number(scheduler.lastSweep.failed || 0) === 0
        : null,
    },
    notifications: {
      enabled: Boolean(notifications?.enabled),
      provider: notifications?.provider ?? "apns",
      credentialsConfigured: Boolean(notifications?.credentialsConfigured),
      topicConfigured: Boolean(notifications?.topicConfigured),
      outbox: notifications?.outbox ?? null,
      devices: deviceSummary,
    },
    apps: summarizeByApp({ targets, devices }),
    attention: {
      dueTargets: dueTargets.slice(0, 10),
      overdueTargets: overdueTargets.slice(0, 10),
      certTargets: certAttentionTargets.slice(0, 10),
      postureFailures: postureFailureTargets.slice(0, 10),
      pushDevices: devices
        .filter((device) => device.health?.needsRegistration)
        .slice(0, 10)
        .map((device) => ({
          id: device.id,
          appId: device.appId,
          platform: device.platform,
          environment: device.environment,
          lastSeenAt: device.lastSeenAt,
          lastPushStatus: device.lastPushStatus,
          health: device.health,
        })),
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
