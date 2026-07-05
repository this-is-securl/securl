import { scanLiveCertificate } from "../packages/core/dist/certificate.js";
import { buildCertificateMonitoringEvents } from "../packages/core/dist/monitoringEvents.js";

const EXPIRY_WARNING_BANDS = [30, 14, 7, 1];
const APP_ID_ALIASES = {
  securl: "com.ktbatterham.securl",
  "header-watch": "com.ktbatterham.headerwatch",
  "cert-watch": "com.ktbatterham.certwatch",
};

export function normalizeMonitoringAppId(value) {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  return APP_ID_ALIASES[normalized] ?? normalized;
}

export function normalizeMonitoringKind(value) {
  return value === "cert" ? "cert" : "posture";
}

export function normalizeMonitoringMode(value, fallback = "quiet") {
  return ["standard", "quiet", "deep-passive"].includes(value) ? value : fallback;
}

export function normalizeMonitoringCadence(value, fallback = "daily") {
  return ["hourly", "6h", "daily", "weekly"].includes(value) ? value : fallback;
}

function normalizeSerialNumber(value) {
  const normalized = String(value || "").replace(/[^a-f0-9]/gi, "").toUpperCase();
  return normalized || null;
}

function certHostFromTarget(target) {
  try {
    return new URL(target.url).hostname;
  } catch {
    return target.label || target.url;
  }
}

function certSnapshotFromResult(target, certificate) {
  return {
    reachable: Boolean(certificate?.available),
    checkedAt: certificate?.checkedAt || new Date().toISOString(),
    host: certificate?.host || certHostFromTarget(target),
    port: certificate?.port ?? 443,
    valid: certificate?.valid ?? false,
    authorized: certificate?.authorized ?? false,
    issuer: certificate?.issuer ?? null,
    subject: certificate?.subject ?? null,
    validFrom: certificate?.validFrom ?? null,
    validTo: certificate?.validTo ?? null,
    daysRemaining: typeof certificate?.daysRemaining === "number" ? certificate.daysRemaining : null,
    protocol: certificate?.protocol ?? null,
    cipher: certificate?.cipher ?? null,
    fingerprint: certificate?.fingerprint ?? null,
    serialNumber: normalizeSerialNumber(certificate?.serialNumber),
    keyBits: typeof certificate?.keyBits === "number" ? certificate.keyBits : null,
    keyType: certificate?.keyType ?? null,
    issues: Array.isArray(certificate?.issues) ? certificate.issues : [],
    chain: Array.isArray(certificate?.chain) ? certificate.chain : [],
  };
}

function liveCertificateFromCertState(state) {
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
    issues: Array.isArray(state.issues) ? state.issues : [],
    chain: Array.isArray(state.chain) ? state.chain : [],
  };
}

function unreachableSnapshot(target, error) {
  return {
    reachable: false,
    checkedAt: new Date().toISOString(),
    host: certHostFromTarget(target),
    port: 443,
    valid: false,
    authorized: false,
    issuer: null,
    subject: null,
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    protocol: null,
    cipher: null,
    fingerprint: null,
    serialNumber: null,
    keyBits: null,
    keyType: null,
    issues: [error instanceof Error ? error.message : String(error)],
    chain: [],
  };
}

function expiryBandForDays(daysRemaining) {
  if (typeof daysRemaining !== "number" || !Number.isFinite(daysRemaining) || daysRemaining <= 0) {
    return null;
  }
  return [...EXPIRY_WARNING_BANDS].reverse().find((band) => daysRemaining <= band) ?? null;
}

function numericDelta(current, previous) {
  return typeof current === "number" && typeof previous === "number" ? current - previous : null;
}

function daysUntilValidTo(validTo) {
  const time = validTo ? new Date(validTo).getTime() : NaN;
  if (!Number.isFinite(time)) {
    return null;
  }
  return Math.ceil((time - Date.now()) / (24 * 60 * 60 * 1000));
}

export function buildCertAttention(state) {
  if (!state) {
    return null;
  }

  if (!state.reachable) {
    return {
      type: "unreachable",
      severity: "critical",
      title: `Certificate check failed: ${state.host ?? "unknown host"}`,
      body: state.issues?.[0] || "The TLS endpoint could not be reached.",
    };
  }

  if (typeof state.daysRemaining === "number" && state.daysRemaining <= 0) {
    return {
      type: "cert_expired",
      severity: "critical",
      title: `Certificate expired: ${state.host ?? "unknown host"}`,
      body: "The served certificate is no longer within its validity window.",
    };
  }

  const warningBand = expiryBandForDays(state.daysRemaining);
  if (warningBand !== null) {
    const severity = warningBand <= 7 ? "critical" : "warning";
    return {
      type: "cert_expiring",
      severity,
      warningBand,
      title: `Certificate expiring: ${state.host ?? "unknown host"}`,
      body: `${state.daysRemaining} day${state.daysRemaining === 1 ? "" : "s"} remaining.`,
    };
  }

  return null;
}

export function detectCertMonitoringEvent(previousState, nextState) {
  if (!nextState) {
    return null;
  }

  if (!nextState.reachable) {
    if (previousState?.reachable === true) {
      return { type: "unreachable", severity: "critical" };
    }
    return null;
  }

  if (!previousState?.reachable) {
    return null;
  }

  if (previousState.serialNumber && nextState.serialNumber && previousState.serialNumber !== nextState.serialNumber) {
    return { type: "cert_renewed", severity: "info", resetWarningBand: true };
  }

  if (previousState.issuer && nextState.issuer && previousState.issuer !== nextState.issuer) {
    return { type: "issuer_changed", severity: "warning" };
  }

  if (typeof nextState.daysRemaining === "number" && nextState.daysRemaining <= 0) {
    if (previousState.lastEventType !== "cert_expired") {
      return { type: "cert_expired", severity: "critical", warningBand: 0 };
    }
    return null;
  }

  const nextBand = expiryBandForDays(nextState.daysRemaining);
  const previousBand = previousState.lastWarnedBand ?? null;
  if (nextBand !== null && (previousBand === null || nextBand < previousBand)) {
    return { type: "cert_expiring", severity: nextBand <= 7 ? "critical" : "warning", warningBand: nextBand };
  }

  return null;
}

export function certEventTitle(type, host) {
  switch (type) {
    case "cert_expiring":
      return `Certificate expiring: ${host}`;
    case "cert_expired":
      return `Certificate expired: ${host}`;
    case "cert_renewed":
      return `Certificate renewed: ${host}`;
    case "issuer_changed":
      return `Certificate issuer changed: ${host}`;
    case "unreachable":
      return `Certificate check failed: ${host}`;
    default:
      return `Certificate changed: ${host}`;
  }
}

export function certEventBody(type, state) {
  switch (type) {
    case "cert_expiring":
      return `${state.daysRemaining} day${state.daysRemaining === 1 ? "" : "s"} remaining.`;
    case "cert_expired":
      return "The served certificate is no longer within its validity window.";
    case "cert_renewed":
      return state.issuer ? `New certificate from ${state.issuer}.` : "The served certificate serial changed.";
    case "issuer_changed":
      return state.issuer ? `New issuer: ${state.issuer}.` : "The served certificate issuer changed.";
    case "unreachable":
      return state.issues?.[0] || "The TLS endpoint could not be reached.";
    default:
      return "The served certificate changed.";
  }
}

export function buildCertMonitoringEventDetails(event, previousState, nextState) {
  if (!event || !nextState) {
    return null;
  }

  const host = nextState.host ?? previousState?.host ?? "unknown host";
  return {
    type: event.type,
    severity: event.severity,
    title: event.title ?? certEventTitle(event.type, host),
    body: event.body ?? certEventBody(event.type, nextState),
    warningBand: event.warningBand ?? null,
    resetWarningBand: Boolean(event.resetWarningBand),
    previous: previousState ? {
      reachable: previousState.reachable ?? null,
      issuer: previousState.issuer ?? null,
      serialNumber: previousState.serialNumber ?? null,
      validTo: previousState.validTo ?? null,
      daysRemaining: previousState.daysRemaining ?? null,
      lastWarnedBand: previousState.lastWarnedBand ?? null,
    } : null,
    current: {
      reachable: nextState.reachable ?? false,
      issuer: nextState.issuer ?? null,
      serialNumber: nextState.serialNumber ?? null,
      validTo: nextState.validTo ?? null,
      daysRemaining: nextState.daysRemaining ?? null,
      warningBand: expiryBandForDays(nextState.daysRemaining),
    },
    delta: {
      daysRemaining: numericDelta(nextState.daysRemaining, previousState?.daysRemaining),
      validToDays: numericDelta(daysUntilValidTo(nextState.validTo), daysUntilValidTo(previousState?.validTo)),
    },
  };
}

function firstSeenAttentionType(previousState, nextState, attention) {
  if (previousState || !attention) {
    return null;
  }
  return attention.type;
}

function appendCertHistory(previousState, nextState, event, attention) {
  const history = Array.isArray(previousState?.history) ? previousState.history : [];
  const eventDetails = buildCertMonitoringEventDetails(event, previousState, nextState);
  const entry = {
    checkedAt: nextState.checkedAt,
    eventType: event?.type ?? null,
    eventSeverity: eventDetails?.severity ?? null,
    eventTitle: eventDetails?.title ?? null,
    eventDetail: eventDetails?.body ?? null,
    warningBand: eventDetails?.warningBand ?? null,
    firstSeenAttentionType: firstSeenAttentionType(previousState, nextState, attention),
    reachable: nextState.reachable,
    valid: nextState.valid,
    authorized: nextState.authorized,
    issuer: nextState.issuer,
    previousIssuer: eventDetails?.previous?.issuer ?? null,
    serialNumber: nextState.serialNumber,
    previousSerialNumber: eventDetails?.previous?.serialNumber ?? null,
    validTo: nextState.validTo,
    previousValidTo: eventDetails?.previous?.validTo ?? null,
    daysRemaining: nextState.daysRemaining,
    previousDaysRemaining: eventDetails?.previous?.daysRemaining ?? null,
    daysRemainingDelta: eventDetails?.delta?.daysRemaining ?? null,
    issues: nextState.issues,
    monitoringEvent: eventDetails?.monitoringEvent ?? null,
  };
  return [entry, ...history].slice(0, 50);
}

export async function runCertificateMonitorCheck({
  target,
  scanRepository,
  notificationService = null,
  log = () => {},
}) {
  const previousState = target.certState ?? null;
  let nextState;

  try {
    const certificate = await scanLiveCertificate(new URL(target.url));
    nextState = certSnapshotFromResult(target, certificate);
  } catch (error) {
    nextState = unreachableSnapshot(target, error);
  }

  const event = detectCertMonitoringEvent(previousState, nextState);
  const monitoringEvents = buildCertificateMonitoringEvents(
    liveCertificateFromCertState(nextState),
    liveCertificateFromCertState(previousState),
  );
  const eventDetails = buildCertMonitoringEventDetails(event, previousState, nextState);
  if (eventDetails && monitoringEvents[0]) {
    eventDetails.monitoringEvent = monitoringEvents[0];
  }
  const lastWarnedBand = event?.resetWarningBand
    ? null
    : event?.warningBand ?? previousState?.lastWarnedBand ?? null;
  const attention = buildCertAttention(nextState);
  const nextCertState = {
    ...nextState,
    attention,
    lastWarnedBand,
    lastEventType: event?.type ?? previousState?.lastEventType ?? null,
    monitoringEvents: monitoringEvents.slice(0, 5),
    history: appendCertHistory(previousState, nextState, eventDetails, attention),
  };

  const updatedTarget = await scanRepository.updateMonitoringTargetCertState(target.id, {
    ownerId: target.ownerId,
    requesterScope: target.ownerId ? null : target.requesterScope,
    certState: nextCertState,
    lastCheckedAt: nextCertState.checkedAt,
  });

  let notification = { attempted: 0, sent: 0, failed: 0, skipped: event ? "notification_service_unavailable" : "no_event" };
  if (event && notificationService?.notifyCertMonitoringEvent) {
    notification = await notificationService.notifyCertMonitoringEvent({
      target: updatedTarget ?? { ...target, certState: nextCertState, lastCheckedAt: nextCertState.checkedAt },
      event: eventDetails,
      certState: nextCertState,
    });
  }

  log("info", "cert_monitoring_checked", {
    targetId: target.id,
    ownerId: target.ownerId,
    host: nextCertState.host,
    eventType: event?.type ?? null,
  });

  return {
    target: updatedTarget ?? { ...target, certState: nextCertState, lastCheckedAt: nextCertState.checkedAt },
    event,
    certState: nextCertState,
    notification,
  };
}
