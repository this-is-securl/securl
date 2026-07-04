import { buildHistoryDiffFromSnapshots } from "./historyDiff.js";
import { buildPostureRiskEventsFromSnapshots } from "./riskEvents.js";
import type {
  HistoryDiff,
  HistorySnapshot,
  LiveCertificateResult,
  MonitoringEvent,
  MonitoringEventEvidence,
  MonitoringEventSeverity,
  PostureRiskEvent,
} from "./types.js";

const severityRank: Record<MonitoringEventSeverity, number> = {
  info: 1,
  warning: 2,
  critical: 3,
};

const slug = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "event";

const sortBySeverity = (events: MonitoringEvent[]) =>
  [...events].sort((left, right) => severityRank[right.severity] - severityRank[left.severity]);

const formatScore = (score: number | null | undefined) =>
  typeof score === "number" ? `${score}/100` : "unknown";

const formatGrade = (grade: string | null | undefined) => grade ?? "unknown";

const compactMessage = (message: string, maxLength = 160) =>
  message.length <= maxLength ? message : `${message.slice(0, maxLength - 1).trimEnd()}.`;

const postureNextAction = (event: PostureRiskEvent) => {
  switch (event.eventType) {
    case "new_critical_findings":
      return "Review the new critical finding and confirm whether the exposure is expected.";
    case "score_regressed":
    case "grade_dropped":
      return "Review the score drivers and restore the control that changed.";
    case "certificate_expiring_soon":
    case "certificate_window_shortened":
      return "Renew or replace the served certificate, then rescan the target.";
    case "security_header_regressed":
      return "Compare the latest response headers with the previous passing response.";
    case "waf_signal_removed":
      return "Confirm whether the edge or WAF configuration changed intentionally.";
    case "new_ct_priority_hosts":
      return "Review the newly observed certificate transparency hostnames.";
    case "identity_provider_changed":
      return "Confirm whether the identity provider change was planned.";
    case "new_third_party_providers":
    case "new_ai_vendors":
      return "Review the newly observed third-party surface and data-flow implications.";
    default:
      return "Review the changed evidence and rescan after remediation.";
  }
};

const postureEvidence = (event: PostureRiskEvent, diff: HistoryDiff): MonitoringEventEvidence[] => {
  switch (event.eventType) {
    case "score_regressed":
      return [
        {
          label: "Score",
          previous: diff.previousScore,
          current: diff.previousScore !== null && diff.scoreDelta !== null ? diff.previousScore + diff.scoreDelta : null,
        },
      ];
    case "grade_dropped":
      return [{ label: "Grade", previous: diff.previousGrade, current: diff.currentGrade }];
    case "status_code_changed":
      return [{ label: "HTTP status", previous: diff.statusCodeDelta?.from ?? null, current: diff.statusCodeDelta?.to ?? null }];
    case "certificate_expiring_soon":
    case "certificate_window_shortened":
      return [
        {
          label: "Certificate days remaining",
          previous: diff.certificateDaysRemainingDelta?.from ?? null,
          current: diff.certificateDaysRemainingDelta?.to ?? null,
        },
      ];
    case "security_header_regressed":
      return diff.headerChanges.slice(0, 5).map((change) => ({
        label: change.label,
        previous: change.from,
        current: change.to,
      }));
    case "waf_signal_removed":
      return [{ label: "Removed WAF/edge signals", previous: diff.wafProviderChanges.removedProviders.join(", "), current: null }];
    case "new_ct_priority_hosts":
      return [{ label: "New CT priority hosts", previous: null, current: diff.ctPriorityHostChanges.newHosts.join(", ") }];
    case "identity_provider_changed":
      return [
        {
          label: "Identity provider",
          previous: diff.identityProviderChange?.from ?? null,
          current: diff.identityProviderChange?.to ?? null,
        },
      ];
    case "new_third_party_providers":
      return [{ label: "New third-party providers", previous: null, current: diff.newThirdPartyProviders.join(", ") }];
    case "new_ai_vendors":
      return [{ label: "New AI vendors", previous: null, current: diff.newAiVendors.join(", ") }];
    default:
      return diff.summary.slice(0, 3).map((summary, index) => ({
        label: `Change ${index + 1}`,
        previous: null,
        current: summary,
      }));
  }
};

const fromPostureRiskEvent = (
  event: PostureRiskEvent,
  current: HistorySnapshot,
  previous: HistorySnapshot,
  diff: HistoryDiff,
): MonitoringEvent => {
  const scoreLine = `Score ${formatScore(previous.score)} -> ${formatScore(current.score)}; grade ${formatGrade(previous.grade)} -> ${formatGrade(current.grade)}.`;
  const message = compactMessage(`${event.title}: ${event.detail}`);
  const evidence = postureEvidence(event, diff);

  return {
    id: `${current.host}:${current.scannedAt}:${event.eventType}`,
    source: "posture",
    eventType: event.eventType,
    severity: event.severity,
    title: event.title,
    message,
    detail: `${event.detail} ${scoreLine}`,
    target: {
      host: current.host,
      finalUrl: current.finalUrl,
    },
    current: {
      observedAt: current.scannedAt,
      score: current.score,
      grade: current.grade,
      statusCode: current.statusCode,
      certificateDaysRemaining: current.certificateDaysRemaining,
    },
    previous: {
      observedAt: previous.scannedAt,
      score: previous.score,
      grade: previous.grade,
      statusCode: previous.statusCode,
      certificateDaysRemaining: previous.certificateDaysRemaining,
    },
    changedEvidence: evidence,
    nextAction: postureNextAction(event),
    push: {
      title: `SecURL: ${event.title}`,
      body: compactMessage(`${current.host}: ${event.detail}`, 140),
    },
    dedupeKey: `posture:${current.host}:${event.eventType}:${slug(evidence.map((item) => item.label).join("-"))}`,
    metadata: event.metadata,
  };
};

export const buildMonitoringEventsFromSnapshots = (
  current: HistorySnapshot,
  previous: HistorySnapshot,
  diff = buildHistoryDiffFromSnapshots(current, previous),
): MonitoringEvent[] =>
  sortBySeverity(
    buildPostureRiskEventsFromSnapshots(current, previous, diff).map((event) =>
      fromPostureRiskEvent(event, current, previous, diff),
    ),
  );

const certTarget = (certificate: LiveCertificateResult) => ({
  host: certificate.host,
  finalUrl: `https://${certificate.host}${certificate.port === 443 ? "" : `:${certificate.port}`}/`,
});

const certificateSeverity = (certificate: LiveCertificateResult): MonitoringEventSeverity => {
  if (!certificate.available || !certificate.valid || !certificate.authorized) {
    return "critical";
  }
  if (typeof certificate.daysRemaining === "number" && certificate.daysRemaining <= 7) {
    return "critical";
  }
  if (typeof certificate.daysRemaining === "number" && certificate.daysRemaining <= 30) {
    return "warning";
  }
  return "info";
};

const certificateNextAction = (certificate: LiveCertificateResult) => {
  if (!certificate.available) {
    return "Check the target is serving TLS correctly, then rescan.";
  }
  if (!certificate.valid || !certificate.authorized) {
    return "Replace or reissue the served certificate, then rescan.";
  }
  if (typeof certificate.daysRemaining === "number" && certificate.daysRemaining <= 30) {
    return "Renew the certificate before the expiry window closes.";
  }
  return "Record the certificate change if it was expected.";
};

const certificateEventType = (certificate: LiveCertificateResult, previous: LiveCertificateResult | null) => {
  if (!certificate.available || !certificate.valid || !certificate.authorized) {
    return "certificate_invalid";
  }
  if (typeof certificate.daysRemaining === "number" && certificate.daysRemaining <= 30) {
    return "certificate_expiring";
  }
  if (previous?.fingerprint && certificate.fingerprint && previous.fingerprint !== certificate.fingerprint) {
    return "certificate_rotated";
  }
  if (previous?.issuer && certificate.issuer && previous.issuer !== certificate.issuer) {
    return "certificate_issuer_changed";
  }
  return null;
};

export const buildCertificateMonitoringEvents = (
  current: LiveCertificateResult,
  previous: LiveCertificateResult | null = null,
): MonitoringEvent[] => {
  const eventType = certificateEventType(current, previous);
  if (!eventType) {
    return [];
  }

  const severity = certificateSeverity(current);
  const titleByType: Record<string, string> = {
    certificate_invalid: "Certificate needs attention",
    certificate_expiring: "Certificate expires soon",
    certificate_rotated: "Certificate changed",
    certificate_issuer_changed: "Certificate issuer changed",
  };
  const messageByType: Record<string, string> = {
    certificate_invalid: current.issues[0] ?? "The served certificate is unavailable, invalid, or unauthorized.",
    certificate_expiring: `The served certificate has ${current.daysRemaining} day${current.daysRemaining === 1 ? "" : "s"} remaining.`,
    certificate_rotated: "The served certificate fingerprint changed.",
    certificate_issuer_changed: `The served certificate issuer changed from ${previous?.issuer ?? "unknown"} to ${current.issuer ?? "unknown"}.`,
  };
  const changedEvidence: MonitoringEventEvidence[] = [
    { label: "Available", previous: previous?.available ?? null, current: current.available },
    { label: "Valid", previous: previous?.valid ?? null, current: current.valid },
    { label: "Authorized", previous: previous?.authorized ?? null, current: current.authorized },
    { label: "Days remaining", previous: previous?.daysRemaining ?? null, current: current.daysRemaining },
    { label: "Issuer", previous: previous?.issuer ?? null, current: current.issuer },
  ];
  const message = messageByType[eventType];

  return [
    {
      id: `${current.host}:${current.port}:${current.checkedAt}:${eventType}`,
      source: "certificate",
      eventType,
      severity,
      title: titleByType[eventType],
      message,
      detail: `${message} Protocol: ${current.protocol ?? "not negotiated"}. Issuer: ${current.issuer ?? "not observed"}.`,
      target: certTarget(current),
      current: {
        observedAt: current.checkedAt,
        certificateDaysRemaining: current.daysRemaining,
      },
      previous: {
        observedAt: previous?.checkedAt ?? null,
        certificateDaysRemaining: previous?.daysRemaining ?? null,
      },
      changedEvidence,
      nextAction: certificateNextAction(current),
      push: {
        title: `SecURL: ${titleByType[eventType]}`,
        body: compactMessage(`${current.host}: ${message}`, 140),
      },
      dedupeKey: `certificate:${current.host}:${current.port}:${eventType}`,
      metadata: {
        fingerprintChanged: Boolean(previous?.fingerprint && current.fingerprint && previous.fingerprint !== current.fingerprint),
        issuerChanged: Boolean(previous?.issuer && current.issuer && previous.issuer !== current.issuer),
        issues: current.issues,
      },
    },
  ];
};
