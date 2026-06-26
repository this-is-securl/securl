import crypto from "node:crypto";
import https from "node:https";
import { createPinnedLookup, assertPublicRequestTarget } from "../packages/core/dist/network-validation.js";
import { buildObservationLedger } from "../packages/core/dist/observations.js";
import { diffObservationLedgers } from "../packages/core/dist/observationDrift.js";
import { DEFAULT_OBSERVATION_POLICY, evaluateObservationPolicy } from "../packages/core/dist/observationPolicy.js";

const MAX_ATTEMPTS = 5;
const SEVERITY_RANK = { critical: 3, warning: 2, info: 1 };

function highestSeverity(violations = []) {
  return violations.reduce((highest, violation) => (
    (SEVERITY_RANK[violation.severity] || 0) > (SEVERITY_RANK[highest] || 0) ? violation.severity : highest
  ), "info");
}

function categoryForViolation(violation) {
  const kind = String(violation.kind || "");
  if (kind.startsWith("tls.certificate") || kind.startsWith("certificate.")) return "certificate";
  if (kind.startsWith("http.header") || kind.startsWith("header.")) return "headers";
  if (kind.startsWith("dns.") || kind.startsWith("email.")) return "dns";
  if (kind.startsWith("web.") || kind.startsWith("html.")) return "web";
  if (kind.startsWith("vendor.") || kind.startsWith("third_party.")) return "vendors";
  if (kind.startsWith("delivery.")) return "delivery";
  return "posture";
}

function actionForViolation(violation) {
  const category = categoryForViolation(violation);
  const templates = {
    certificate: ["review_certificate", "Review certificate renewal"],
    headers: ["review_security_headers", "Review security header configuration"],
    dns: ["review_dns_trust", "Review DNS and email trust records"],
    web: ["review_public_web_surface", "Review public web surface"],
    vendors: ["review_third_party_surface", "Review third-party exposure"],
    delivery: ["review_alert_delivery", "Review alert delivery"],
    posture: ["review_posture_policy", "Review posture policy finding"],
  };
  const [id, label] = templates[category] ?? templates.posture;
  return {
    id,
    label,
    priority: violation.severity || "warning",
    category,
    ruleId: violation.ruleId,
    violationId: violation.id,
  };
}

function countBySeverity(violations = []) {
  return violations.reduce((counts, violation) => {
    const severity = violation.severity || "info";
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, { critical: 0, warning: 0, info: 0 });
}

function buildPolicyAlertBrief({ target, evaluation, violations }) {
  const severity = highestSeverity(violations);
  const first = violations[0];
  const count = violations.length;
  const host = target.label || target.url;
  const noun = `policy violation${count === 1 ? "" : "s"}`;
  const firstTitle = first?.title || "Monitoring policy failed";
  return {
    title: `${host}: ${count} ${severity} ${noun}`,
    body: count > 1 ? `${firstTitle} and ${count - 1} more.` : firstTitle,
    detail: `${evaluation.policy.name} found ${count} newly introduced ${noun}.`,
    highestSeverity: severity,
    primaryViolationId: first?.id ?? null,
    primaryActionId: first ? actionForViolation(first).id : null,
  };
}

function buildPolicyAlertActions(violations = []) {
  const actionsById = new Map();
  for (const violation of violations) {
    const action = actionForViolation(violation);
    const existing = actionsById.get(action.id);
    if (!existing || (SEVERITY_RANK[action.priority] || 0) > (SEVERITY_RANK[existing.priority] || 0)) {
      actionsById.set(action.id, { ...action, count: 1 });
    } else {
      existing.count += 1;
    }
  }
  return [...actionsById.values()].sort((a, b) => (SEVERITY_RANK[b.priority] || 0) - (SEVERITY_RANK[a.priority] || 0));
}

function matchesTarget(record, target) {
  return record?.url === target.url || record?.result?.finalUrl === target.url || record?.result?.normalizedUrl === target.url;
}

function buildEvaluation(result, previousResult, policy) {
  const ledger = result.observationLedger ?? buildObservationLedger(result);
  const drift = previousResult
    ? diffObservationLedgers(ledger, previousResult.observationLedger ?? buildObservationLedger(previousResult))
    : null;
  return evaluateObservationPolicy({ ledger, drift, policy: policy ?? DEFAULT_OBSERVATION_POLICY });
}

function buildPolicyAlert({ completedScan, target, evaluation, violations }) {
  const severityCounts = countBySeverity(violations);
  const brief = buildPolicyAlertBrief({ target, evaluation, violations });
  const actions = buildPolicyAlertActions(violations);
  return {
    type: "observation_policy_violation",
    version: "1.0",
    eventId: crypto.createHash("sha256").update(`${completedScan.id}:${evaluation.policy.id}`).digest("hex").slice(0, 24),
    occurredAt: evaluation.evaluatedAt,
    target: { id: target.id, url: target.url, label: target.label },
    scan: { id: completedScan.id, grade: completedScan.result?.grade ?? null, score: completedScan.result?.score ?? null },
    policy: evaluation.policy,
    summary: {
      ...evaluation.summary,
      newViolations: violations.length,
      newBySeverity: severityCounts,
      highestSeverity: brief.highestSeverity,
    },
    brief,
    actions,
    violations: violations.slice(0, 10).map((violation) => ({
      id: violation.id,
      ruleId: violation.ruleId,
      title: violation.title,
      severity: violation.severity,
      category: categoryForViolation(violation),
      kind: violation.kind,
      subject: violation.subject,
      actual: violation.actual,
      expected: violation.expected,
      summary: violation.summary,
      action: actionForViolation(violation),
    })),
  };
}

export function buildWebhookSignature(secret, timestamp, body) {
  return crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

async function sendWebhook(destination, payload, timeoutMs = 10_000) {
  const url = new URL(destination.endpoint);
  const addresses = await assertPublicRequestTarget(url);
  const body = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = buildWebhookSignature(destination.signingSecret, timestamp, body);
  return await new Promise((resolve) => {
    const request = https.request(url, {
      method: "POST",
      lookup: createPinnedLookup(addresses),
      timeout: timeoutMs,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": "SecURL-Alerts/1.0",
        "X-SecURL-Event": payload.type,
        "X-SecURL-Timestamp": timestamp,
        "X-SecURL-Signature": `sha256=${signature}`,
      },
    }, (response) => {
      response.resume();
      response.on("end", () => resolve({
        ok: response.statusCode >= 200 && response.statusCode < 300,
        statusCode: response.statusCode || 0,
        retryable: response.statusCode === 408 || response.statusCode === 429 || (response.statusCode || 0) >= 500,
      }));
    });
    request.on("timeout", () => request.destroy(new Error("Webhook delivery timed out.")));
    request.on("error", (error) => resolve({ ok: false, statusCode: 0, retryable: true, error: error.message }));
    request.end(body);
  });
}

async function sendEmail(destination, payload, config, timeoutMs = 10_000) {
  if (!config.resendApiKey || !config.emailFrom) {
    return { ok: false, statusCode: 0, retryable: true, error: "Email provider is not configured." };
  }
  const critical = payload.violations.filter((violation) => violation.severity === "critical").length;
  const subject = payload.brief?.title || `[SecURL] ${payload.target.label}: ${payload.violations.length} policy violation${payload.violations.length === 1 ? "" : "s"}`;
  const actionLines = Array.isArray(payload.actions) && payload.actions.length
    ? ["", "Suggested actions:", ...payload.actions.map((action) => `- ${action.label} (${action.count})`)]
    : [];
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    signal: AbortSignal.timeout(timeoutMs),
    headers: { Authorization: `Bearer ${config.resendApiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: config.emailFrom,
      to: [destination.email],
      subject: subject.startsWith("[SecURL]") ? subject : `[SecURL] ${subject}`,
      text: [
        `${payload.target.url} failed ${payload.policy.name}.`,
        payload.brief?.detail ?? null,
        `${critical} critical, ${payload.violations.length - critical} other new violation(s).`,
        "",
        ...payload.violations.map((violation) => `- [${violation.severity.toUpperCase()}] ${violation.title}${violation.action?.label ? ` - ${violation.action.label}` : ""}`),
        ...actionLines,
      ].filter(Boolean).join("\n"),
    }),
  }).catch((error) => ({ ok: false, status: 0, error }));
  const statusCode = response.status || 0;
  return {
    ok: response.ok,
    statusCode,
    retryable: statusCode === 0 || statusCode === 408 || statusCode === 429 || statusCode >= 500,
    error: response.error?.message,
  };
}

export function createAlertDeliveryService({
  scanRepository,
  notificationService = null,
  log = () => {},
  telemetry = null,
  config = {},
  webhookTransport = sendWebhook,
  emailTransport = sendEmail,
} = {}) {
  const resolvedConfig = {
    resendApiKey: config.resendApiKey ?? process.env.RESEND_API_KEY ?? "",
    emailFrom: config.emailFrom ?? process.env.ALERT_EMAIL_FROM ?? "",
  };
  const workerId = `alerts:${process.pid}:${crypto.randomUUID()}`;
  const enabled = Boolean(scanRepository?.enqueueAlertOutbox && scanRepository?.claimAlertOutbox);
  let timer = null;
  let running = false;
  let lastDrain = null;

  async function drain({ limit = 20 } = {}) {
    if (!enabled || running) return lastDrain;
    running = true;
    const summary = { claimed: 0, sent: 0, failed: 0, skipped: 0, retried: 0 };
    try {
      const entries = await scanRepository.claimAlertOutbox({ workerId, limit, leaseMs: 60_000 });
      summary.claimed = entries.length;
      for (const entry of entries) {
        const destination = await scanRepository.getAlertDestination(entry.destinationId, {
          ownerId: entry.ownerId,
          requesterScope: entry.ownerId ? null : entry.requesterScope,
          includeSecrets: true,
        });
        if (!destination) {
          await scanRepository.completeAlertOutbox(entry.id, { status: "skipped", error: "Destination unavailable.", workerId });
          summary.skipped += 1;
          continue;
        }
        let outcome;
        try {
          outcome = destination.type === "webhook"
            ? await webhookTransport(destination, entry.payload)
            : await emailTransport(destination, entry.payload, resolvedConfig);
        } catch (error) {
          outcome = { ok: false, statusCode: 0, retryable: true, error: error instanceof Error ? error.message : String(error) };
        }
        const retry = !outcome.ok && outcome.retryable && entry.attempts < MAX_ATTEMPTS;
        await scanRepository.completeAlertOutbox(entry.id, {
          status: outcome.ok ? "sent" : retry ? "queued" : "failed",
          error: outcome.ok ? null : String(outcome.error || `HTTP ${outcome.statusCode || 0}`).slice(0, 500),
          availableAt: retry ? new Date(Date.now() + Math.min(15 * 60_000, entry.attempts * 30_000)).toISOString() : null,
          workerId,
        });
        if (outcome.ok) summary.sent += 1;
        else if (retry) summary.retried += 1;
        else summary.failed += 1;
        telemetry?.recordNotificationDelivery?.({
          channel: `alert_${destination.type}`,
          attempted: 1,
          attempts: 1,
          sent: outcome.ok ? 1 : 0,
          failed: outcome.ok || retry ? 0 : 1,
          disabled: 0,
          retried: retry ? 1 : 0,
          skipped: null,
        });
      }
      summary.pruned = Number(await scanRepository.pruneAlertOutbox?.() || 0);
      summary.stats = await scanRepository.getAlertOutboxStats?.();
      lastDrain = { ...summary, completedAt: new Date().toISOString() };
      return lastDrain;
    } finally {
      running = false;
    }
  }

  async function processMonitoringScan({ completedScan, result, telemetryContext = {} }) {
    if (!["monitoring_scheduler", "monitoring_manual"].includes(telemetryContext.channel)) {
      return { queued: 0, skipped: "not_monitoring_scan" };
    }
    const targets = await scanRepository.listMonitoringTargets({
      ownerId: completedScan.ownerId,
      requesterScope: completedScan.ownerId ? null : completedScan.requesterScope,
      limit: 250,
    });
    const target = targets.find((candidate) => (candidate.kind ?? "posture") === "posture"
      && (candidate.url === completedScan.url || candidate.url === result.finalUrl || candidate.url === result.normalizedUrl));
    if (!target) return { queued: 0, skipped: "no_monitoring_target" };
    const records = (await scanRepository.listPersistedRecords({
      ownerId: completedScan.ownerId,
      requesterScope: completedScan.ownerId ? null : completedScan.requesterScope,
      limit: 20,
    })).filter((record) => matchesTarget(record, target) && record.status === "completed" && record.result);
    const currentEvaluation = buildEvaluation(result, records[1]?.result ?? null, target.observationPolicy);
    const previousEvaluation = records[1]
      ? buildEvaluation(records[1].result, records[2]?.result ?? null, target.observationPolicy)
      : null;
    const previousIds = new Set(previousEvaluation?.violations.map((violation) => violation.id) ?? []);
    const violations = currentEvaluation.violations.filter((violation) => !previousIds.has(violation.id));
    if (!violations.length) return { queued: 0, skipped: "no_new_violations", evaluation: currentEvaluation };

    const payload = buildPolicyAlert({ completedScan: { ...completedScan, result }, target, evaluation: currentEvaluation, violations });
    const push = await notificationService?.sendPolicyAlert?.({ completedScan, target, payload }) ?? { attempted: 0, sent: 0, skipped: "push_unavailable" };
    const destinations = await scanRepository.listAlertDestinations({
      ownerId: target.ownerId,
      requesterScope: target.ownerId ? null : target.requesterScope,
      limit: 50,
      includeSecrets: true,
    });
    const entries = await scanRepository.enqueueAlertOutbox({
      destinations,
      payload,
      referenceId: `${completedScan.id}:${currentEvaluation.policy.id}`,
      channel: "monitoring_policy",
    });
    if (entries.length) await drain({ limit: entries.length });
    log("info", "policy_alert_routed", {
      scanId: completedScan.id,
      targetId: target.id,
      policyId: currentEvaluation.policy.id,
      violations: violations.length,
      pushSent: push.sent || 0,
      destinations: entries.length,
    });
    return { queued: entries.length, push, violations: violations.length, evaluation: currentEvaluation };
  }

  async function sendTestDestination(destination) {
    const violation = {
      id: "test",
      ruleId: "test",
      title: "Alert delivery is configured",
      severity: "info",
      kind: "delivery.test",
      subject: "SecURL",
      actual: true,
      expected: { field: "value", operator: "eq", value: true },
      summary: "This synthetic alert confirms the destination can receive SecURL payloads.",
    };
    const policy = { id: "test", name: "Delivery test", version: "1" };
    const target = { id: null, url: "https://securl.online/", label: "SecURL test" };
    const payload = {
      type: "alert_destination_test",
      version: "1.0",
      eventId: crypto.randomUUID(),
      occurredAt: new Date().toISOString(),
      target,
      scan: { id: null, grade: null, score: null },
      policy,
      summary: {
        rulesEvaluated: 0,
        violations: 1,
        bySeverity: { info: 1, warning: 0, critical: 0 },
        highestSeverity: "info",
        newViolations: 1,
        newBySeverity: { info: 1, warning: 0, critical: 0 },
      },
      brief: buildPolicyAlertBrief({ target, evaluation: { policy }, violations: [violation] }),
      actions: buildPolicyAlertActions([violation]),
      violations: [{
        ...violation,
        category: categoryForViolation(violation),
        action: actionForViolation(violation),
      }],
    };
    const entries = await scanRepository.enqueueAlertOutbox({
      destinations: [destination],
      payload,
      referenceId: `test:${destination.id}:${payload.eventId}`,
      channel: "destination_test",
    });
    const delivery = await drain({ limit: 1 });
    return { queued: entries.length, delivery };
  }

  function start() {
    if (!enabled || timer) return false;
    timer = setInterval(() => void drain().catch((error) => log("error", "alert_outbox_drain_failed", { message: error.message })), 15_000);
    timer.unref?.();
    queueMicrotask(() => void drain().catch(() => {}));
    return true;
  }

  function stop() {
    if (!timer) return false;
    clearInterval(timer);
    timer = null;
    return true;
  }

  return {
    enabled,
    processMonitoringScan,
    sendTestDestination,
    drain,
    start,
    stop,
    snapshot: () => ({
      enabled,
      channels: { apns: Boolean(notificationService), webhook: true, email: Boolean(resolvedConfig.resendApiKey && resolvedConfig.emailFrom) },
      running,
      lastDrain,
    }),
  };
}
