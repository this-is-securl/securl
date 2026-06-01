import type { HistoryDiff, HistorySnapshot, PostureRiskEvent, PostureRiskEventSeverity } from "./types.js";

const GRADE_ORDER = new Map([
  ["A", 0],
  ["B", 1],
  ["C", 2],
  ["D", 3],
  ["E", 4],
  ["F", 5],
]);

function normalizeGrade(grade: string | null | undefined): string | null {
  if (!grade) {
    return null;
  }
  const normalized = grade.trim().toUpperCase().slice(0, 1);
  return GRADE_ORDER.has(normalized) ? normalized : null;
}

function compareGrades(currentGrade: string | null | undefined, previousGrade: string | null | undefined) {
  const current = normalizeGrade(currentGrade);
  const previous = normalizeGrade(previousGrade);
  if (!current || !previous) {
    return null;
  }
  return (GRADE_ORDER.get(current) ?? 0) - (GRADE_ORDER.get(previous) ?? 0);
}

function scoreRegressionSeverity(delta: number): PostureRiskEventSeverity {
  if (delta <= -25) {
    return "critical";
  }
  if (delta <= -10) {
    return "warning";
  }
  return "info";
}

function pushEvent(events: PostureRiskEvent[], event: PostureRiskEvent) {
  events.push(event);
}

export function buildPostureRiskEventsFromDiff(diff: HistoryDiff | null | undefined): PostureRiskEvent[] {
  if (!diff) {
    return [];
  }

  const events: PostureRiskEvent[] = [];
  const scoreDelta = typeof diff.scoreDelta === "number" ? diff.scoreDelta : null;
  if (scoreDelta !== null && scoreDelta < 0) {
    pushEvent(events, {
      eventType: "score_regressed",
      severity: scoreRegressionSeverity(scoreDelta),
      title: "Score regressed",
      detail: `The posture score dropped by ${Math.abs(scoreDelta)} point${Math.abs(scoreDelta) === 1 ? "" : "s"}.`,
      metadata: {
        previousScore: diff.previousScore,
        scoreDelta,
      },
    });
  }

  const gradeDelta = compareGrades(diff.currentGrade, diff.previousGrade);
  if (gradeDelta !== null && gradeDelta > 0) {
    pushEvent(events, {
      eventType: "grade_dropped",
      severity: gradeDelta >= 2 ? "critical" : "warning",
      title: "Grade dropped",
      detail: `The posture grade changed from ${diff.previousGrade} to ${diff.currentGrade}.`,
      metadata: {
        previousGrade: diff.previousGrade,
        currentGrade: diff.currentGrade,
      },
    });
  }

  if (diff.statusCodeDelta && diff.statusCodeDelta.from !== diff.statusCodeDelta.to) {
    pushEvent(events, {
      eventType: "status_code_changed",
      severity: "info",
      title: "HTTP status changed",
      detail: `The HTTP status changed from ${diff.statusCodeDelta.from} to ${diff.statusCodeDelta.to}.`,
      metadata: diff.statusCodeDelta,
    });
  }

  const certDelta = diff.certificateDaysRemainingDelta;
  if (certDelta && typeof certDelta.to === "number" && certDelta.to <= 14) {
    pushEvent(events, {
      eventType: "certificate_expiring_soon",
      severity: certDelta.to <= 7 ? "critical" : "warning",
      title: "Certificate expires soon",
      detail: `The certificate has ${certDelta.to} day${certDelta.to === 1 ? "" : "s"} remaining.`,
      metadata: certDelta,
    });
  } else if (certDelta && typeof certDelta.delta === "number" && certDelta.delta <= -30) {
    pushEvent(events, {
      eventType: "certificate_window_shortened",
      severity: "warning",
      title: "Certificate window shortened",
      detail: `The certificate validity window shortened by ${Math.abs(certDelta.delta)} days.`,
      metadata: certDelta,
    });
  }

  const removedHeaders = diff.headerChanges.filter((change) =>
    ["pass", "present"].includes(change.from) && change.to !== change.from,
  );
  if (removedHeaders.length) {
    pushEvent(events, {
      eventType: "security_header_regressed",
      severity: "warning",
      title: "Security headers regressed",
      detail: `${removedHeaders.length} security header${removedHeaders.length === 1 ? "" : "s"} moved away from a passing state.`,
      metadata: {
        headers: removedHeaders,
      },
    });
  }

  if (diff.wafProviderChanges.removedProviders.length) {
    pushEvent(events, {
      eventType: "waf_signal_removed",
      severity: "warning",
      title: "WAF or edge signal disappeared",
      detail: `Previously observed WAF or edge signals disappeared: ${diff.wafProviderChanges.removedProviders.join(", ")}.`,
      metadata: {
        removedProviders: diff.wafProviderChanges.removedProviders,
      },
    });
  }

  if (diff.ctPriorityHostChanges.newHosts.length) {
    pushEvent(events, {
      eventType: "new_ct_priority_hosts",
      severity: "info",
      title: "New CT hosts observed",
      detail: `New high-priority certificate transparency hosts appeared: ${diff.ctPriorityHostChanges.newHosts.join(", ")}.`,
      metadata: {
        newHosts: diff.ctPriorityHostChanges.newHosts,
      },
    });
  }

  if (diff.identityProviderChange) {
    pushEvent(events, {
      eventType: "identity_provider_changed",
      severity: "info",
      title: "Identity provider changed",
      detail: `Identity provider changed from ${diff.identityProviderChange.from ?? "none"} to ${diff.identityProviderChange.to ?? "none"}.`,
      metadata: diff.identityProviderChange,
    });
  }

  if (diff.newThirdPartyProviders.length) {
    pushEvent(events, {
      eventType: "new_third_party_providers",
      severity: "info",
      title: "New third-party providers observed",
      detail: `New third-party providers were observed: ${diff.newThirdPartyProviders.join(", ")}.`,
      metadata: {
        newProviders: diff.newThirdPartyProviders,
      },
    });
  }

  if (diff.newAiVendors.length) {
    pushEvent(events, {
      eventType: "new_ai_vendors",
      severity: "info",
      title: "New AI vendors observed",
      detail: `New AI vendors were observed: ${diff.newAiVendors.join(", ")}.`,
      metadata: {
        newVendors: diff.newAiVendors,
      },
    });
  }

  return events;
}

export function buildPostureRiskEventsFromSnapshots(
  current: HistorySnapshot,
  previous: HistorySnapshot,
  diff: HistoryDiff,
): PostureRiskEvent[] {
  const events = buildPostureRiskEventsFromDiff(diff);
  const previousCriticalIssues = new Set(
    previous.issues
      .filter((issue) => issue.severity === "critical")
      .map((issue) => issue.title),
  );
  const newCriticalIssues = current.issues
    .filter((issue) => issue.severity === "critical" && !previousCriticalIssues.has(issue.title))
    .map((issue) => ({
      title: issue.title,
      detail: issue.detail,
      confidence: issue.confidence,
      source: issue.source,
    }));

  if (newCriticalIssues.length) {
    events.unshift({
      eventType: "new_critical_findings",
      severity: "critical",
      title: "New critical findings",
      detail: `${newCriticalIssues.length} new critical finding${newCriticalIssues.length === 1 ? "" : "s"} appeared.`,
      metadata: {
        issues: newCriticalIssues,
      },
    });
  }

  return events;
}
