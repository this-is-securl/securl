import { buildHistoryDiffFromSnapshots } from "./historyDiff.js";
import { buildPostureRiskEventsFromSnapshots } from "./riskEvents.js";
import type {
  HistoryDiff,
  HistorySnapshot,
  PostureDriftArea,
  PostureDriftDirection,
  PostureDriftReport,
  PostureDriftSeverity,
  PostureRiskEvent,
  PostureRiskEventSeverity,
} from "./types.js";

const SEVERITY_ORDER: Record<PostureDriftSeverity, number> = {
  none: 0,
  info: 1,
  warning: 2,
  critical: 3,
};

function snapshotSummary(snapshot: HistorySnapshot) {
  return {
    finalUrl: snapshot.finalUrl,
    host: snapshot.host,
    scannedAt: snapshot.scannedAt,
    score: snapshot.score,
    grade: snapshot.grade,
    statusCode: snapshot.statusCode,
  };
}

function highestSeverity(events: PostureRiskEvent[]): PostureDriftSeverity {
  return events.reduce<PostureDriftSeverity>((highest, event) => (
    SEVERITY_ORDER[event.severity] > SEVERITY_ORDER[highest] ? event.severity : highest
  ), "none");
}

function countEvents(events: PostureRiskEvent[]) {
  return events.reduce<Record<PostureRiskEventSeverity, number>>((counts, event) => {
    counts[event.severity] += 1;
    return counts;
  }, {
    critical: 0,
    warning: 0,
    info: 0,
  });
}

function sortEventsBySeverity(events: PostureRiskEvent[]) {
  return [...events].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return left.eventType.localeCompare(right.eventType);
  });
}

function addArea(areas: Set<PostureDriftArea>, condition: boolean, area: PostureDriftArea) {
  if (condition) {
    areas.add(area);
  }
}

function changedAreas(diff: HistoryDiff): PostureDriftArea[] {
  const areas = new Set<PostureDriftArea>();
  addArea(areas, typeof diff.scoreDelta === "number" && diff.scoreDelta !== 0, "score");
  addArea(areas, diff.previousGrade !== diff.currentGrade, "grade");
  addArea(areas, Boolean(diff.statusCodeDelta && diff.statusCodeDelta.from !== diff.statusCodeDelta.to), "status");
  addArea(areas, Boolean(diff.certificateDaysRemainingDelta?.delta), "certificate");
  addArea(areas, diff.headerChanges.length > 0, "headers");
  addArea(areas, diff.newIssues.length > 0 || diff.resolvedIssues.length > 0, "findings");
  addArea(areas, diff.newThirdPartyProviders.length > 0 || diff.removedThirdPartyProviders.length > 0, "third_party");
  addArea(areas, diff.newAiVendors.length > 0 || diff.removedAiVendors.length > 0, "ai");
  addArea(areas, Boolean(diff.identityProviderChange), "identity");
  addArea(
    areas,
    diff.wafProviderChanges.newProviders.length > 0 || diff.wafProviderChanges.removedProviders.length > 0,
    "waf",
  );
  addArea(
    areas,
    diff.ctPriorityHostChanges.newHosts.length > 0 || diff.ctPriorityHostChanges.removedHosts.length > 0,
    "ct",
  );
  return [...areas];
}

function hasPositiveChange(diff: HistoryDiff) {
  return (
    (typeof diff.scoreDelta === "number" && diff.scoreDelta > 0) ||
    diff.resolvedIssues.length > 0 ||
    diff.wafProviderChanges.newProviders.length > 0
  );
}

function hasNegativeChange(diff: HistoryDiff, events: PostureRiskEvent[]) {
  return (
    events.some((event) => event.severity === "warning" || event.severity === "critical") ||
    (typeof diff.scoreDelta === "number" && diff.scoreDelta < 0) ||
    diff.newIssues.length > 0 ||
    diff.wafProviderChanges.removedProviders.length > 0
  );
}

function buildDirection(diff: HistoryDiff, events: PostureRiskEvent[]): PostureDriftDirection {
  const negative = hasNegativeChange(diff, events);
  const positive = hasPositiveChange(diff);
  if (negative) {
    return "regressed";
  }
  if (positive) {
    return "improved";
  }
  if (changedAreas(diff).length > 0) {
    return "changed";
  }
  return "unchanged";
}

export function buildPostureDriftReportFromDiff(
  current: HistorySnapshot,
  previous: HistorySnapshot,
  diff: HistoryDiff,
  riskEvents = buildPostureRiskEventsFromSnapshots(current, previous, diff),
): PostureDriftReport {
  const summaryItems = diff.summary.length ? diff.summary : ["No posture drift detected."];
  const eventCounts = countEvents(riskEvents);
  const topEvents = sortEventsBySeverity(riskEvents).slice(0, 5);

  return {
    current: snapshotSummary(current),
    previous: snapshotSummary(previous),
    diff,
    riskEvents,
    summary: {
      direction: buildDirection(diff, riskEvents),
      severity: highestSeverity(riskEvents),
      scoreDelta: typeof diff.scoreDelta === "number" ? diff.scoreDelta : null,
      gradeChanged: diff.previousGrade !== diff.currentGrade,
      hasRegression: hasNegativeChange(diff, riskEvents),
      hasImprovement: hasPositiveChange(diff),
      eventCounts,
      changedAreas: changedAreas(diff),
      topEvents,
      summary: summaryItems,
    },
  };
}

export function buildPostureDriftReportFromSnapshots(
  current: HistorySnapshot,
  previous: HistorySnapshot,
): PostureDriftReport {
  const diff = buildHistoryDiffFromSnapshots(current, previous);
  return buildPostureDriftReportFromDiff(current, previous, diff);
}

export function buildPostureDriftReport(history: HistorySnapshot[]): PostureDriftReport | null {
  if (history.length < 2) {
    return null;
  }
  return buildPostureDriftReportFromSnapshots(history[0], history[1]);
}
