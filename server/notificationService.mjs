import crypto from "node:crypto";
import http2 from "node:http2";
import { buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "../packages/core/dist/historyDiff.js";
import { buildPostureRiskEventsFromDiff } from "../packages/core/dist/riskEvents.js";

function base64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function privateKeyFromEnv(value) {
  if (!value) {
    return "";
  }
  return String(value).includes("\\n") ? String(value).replace(/\\n/g, "\n") : String(value);
}

function buildApnsJwt({ teamId, keyId, privateKey }) {
  const header = base64Url(JSON.stringify({ alg: "ES256", kid: keyId }));
  const claims = base64Url(JSON.stringify({ iss: teamId, iat: Math.floor(Date.now() / 1000) }));
  const signingInput = `${header}.${claims}`;
  const signature = crypto.sign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${base64Url(signature)}`;
}

function apnsHost(environment) {
  return environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";
}

async function sendApns({ token, environment, topic, payload, config }) {
  const jwt = buildApnsJwt(config);
  const client = http2.connect(apnsHost(environment));

  try {
    await new Promise((resolve, reject) => {
      client.once("error", reject);
      client.once("connect", resolve);
    });

    return await new Promise((resolve, reject) => {
      const apnsRequest = client.request({
        ":method": "POST",
        ":path": `/3/device/${token}`,
        authorization: `bearer ${jwt}`,
        "apns-topic": topic,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "content-type": "application/json",
      });
      let body = "";
      let statusCode = 0;
      let apnsId = null;
      apnsRequest.setEncoding("utf8");
      apnsRequest.on("data", (chunk) => {
        body += chunk;
      });
      apnsRequest.on("response", (headers) => {
        statusCode = Number(headers[":status"] || 0);
        apnsId = headers["apns-id"] ?? null;
      });
      apnsRequest.on("error", reject);
      apnsRequest.on("end", () => {
        resolve({
          statusCode,
          apnsId,
          body: body ? JSON.parse(body) : null,
        });
      });
      apnsRequest.end(JSON.stringify(payload));
    });
  } finally {
    client.close();
  }
}

function buildNotificationChangeSummary(diff, riskEvents) {
  const changes = [];
  if (diff.previousGrade !== diff.currentGrade) {
    changes.push(`grade ${diff.previousGrade ?? "unknown"} to ${diff.currentGrade ?? "unknown"}`);
  }
  if (typeof diff.scoreDelta === "number" && diff.scoreDelta !== 0) {
    changes.push(`score ${diff.scoreDelta > 0 ? "+" : ""}${diff.scoreDelta}`);
  }
  if (diff.headerChanges?.length) {
    changes.push(`${diff.headerChanges.length} header change${diff.headerChanges.length === 1 ? "" : "s"}`);
  }
  if (diff.certificateDaysRemainingDelta?.delta) {
    changes.push("certificate window changed");
  }
  if (riskEvents?.length && changes.length === 0) {
    changes.push(riskEvents[0].title);
  }
  return changes;
}

async function buildMonitoringPushPayload({ scanRepository, completedScan, result }) {
  const records = await scanRepository.listPersistedRecords({
    ownerId: completedScan.ownerId,
    requesterScope: completedScan.ownerId ? null : completedScan.requesterScope,
    url: completedScan.url,
    limit: 5,
  });
  const completed = records.filter((record) => record.status === "completed" && record.result);
  if (completed.length < 2) {
    return null;
  }

  const [current, previous] = completed;
  const diff = buildHistoryDiffFromSnapshots(snapshotFromAnalysis(current.result), snapshotFromAnalysis(previous.result));
  const riskEvents = buildPostureRiskEventsFromDiff(diff);
  const changes = buildNotificationChangeSummary(diff, riskEvents);
  if (changes.length === 0) {
    return null;
  }

  const host = result.host || new URL(completedScan.url).hostname;
  return {
    aps: {
      alert: {
        title: `SecURL changed: ${host}`,
        body: changes.slice(0, 2).join(", "),
      },
      sound: "default",
      "thread-id": host,
    },
    type: "monitoring_drift",
    scanId: completedScan.id,
    url: completedScan.url,
    host,
    grade: result.grade,
    score: result.score,
    changes,
    riskEvents: riskEvents.slice(0, 5).map((event) => ({
      eventType: event.eventType,
      severity: event.severity,
      title: event.title,
    })),
  };
}

export function createNotificationService({
  scanRepository,
  log = () => {},
  apns = {},
} = {}) {
  const config = {
    teamId: apns.teamId || process.env.APNS_TEAM_ID || "",
    keyId: apns.keyId || process.env.APNS_KEY_ID || "",
    privateKey: privateKeyFromEnv(apns.privateKey || process.env.APNS_PRIVATE_KEY || ""),
    defaultTopic: apns.topic || process.env.APNS_BUNDLE_ID || "",
  };
  const enabled = Boolean(config.teamId && config.keyId && config.privateKey && config.defaultTopic);

  async function deliverPushPayload({ devices, payload, referenceId, logEventName = "push_delivery_result" }) {
    if (!devices.length) {
      return { attempted: 0, sent: 0, skipped: "no_devices" };
    }
    if (!enabled) {
      log("warn", "push_delivery_skipped", {
        reason: "apns_not_configured",
        referenceId,
        devices: devices.length,
      });
      return { attempted: devices.length, sent: 0, skipped: "apns_not_configured" };
    }

    let sent = 0;
    for (const device of devices) {
      try {
        const response = await sendApns({
          token: device.token,
          environment: device.environment,
          topic: device.appId || config.defaultTopic,
          payload,
          config,
        });
        if (response.statusCode >= 200 && response.statusCode < 300) {
          sent += 1;
        } else if (response.statusCode === 410 || response.statusCode === 400) {
          await scanRepository.disablePushDevice(device.id, {
            ownerId: device.ownerId,
            requesterScope: device.ownerId ? null : device.requesterScope,
          });
        }
        log(response.statusCode >= 200 && response.statusCode < 300 ? "info" : "warn", logEventName, {
          referenceId,
          deviceId: device.id,
          statusCode: response.statusCode,
          apnsId: response.apnsId,
        });
      } catch (error) {
        log("warn", "push_delivery_failed", {
          referenceId,
          deviceId: device.id,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return { attempted: devices.length, sent, skipped: null };
  }

  async function notifyMonitoringScanCompleted({ completedScan, result, telemetryContext = {} }) {
    if (telemetryContext.channel !== "monitoring_scheduler") {
      return { attempted: 0, sent: 0, skipped: "not_monitoring_scheduler" };
    }

    const payload = await buildMonitoringPushPayload({ scanRepository, completedScan, result });
    if (!payload) {
      return { attempted: 0, sent: 0, skipped: "no_drift" };
    }

    const devices = await scanRepository.listPushDeviceSecrets({
      ownerId: completedScan.ownerId,
      requesterScope: completedScan.ownerId ? null : completedScan.requesterScope,
      limit: 50,
    });
    if (!devices.length) {
      return { attempted: 0, sent: 0, skipped: "no_devices" };
    }

    return deliverPushPayload({
      devices,
      payload,
      referenceId: completedScan.id,
    });
  }

  async function notifyCertMonitoringEvent({ target, event, certState }) {
    if (!event || !target) {
      return { attempted: 0, sent: 0, skipped: "no_event" };
    }

    const devices = await scanRepository.listPushDeviceSecrets({
      ownerId: target.ownerId,
      requesterScope: target.ownerId ? null : target.requesterScope,
      appId: target.appId ?? null,
      limit: 50,
    });
    const host = certState?.host || target.label || target.url;
    const payload = {
      aps: {
        alert: {
          title: event.title,
          body: event.body,
        },
        sound: "default",
        "thread-id": host,
      },
      type: event.type,
      targetId: target.id,
      url: target.url,
      host,
      appId: target.appId ?? null,
      severity: event.severity,
      certificate: {
        issuer: certState?.issuer ?? null,
        serialNumber: certState?.serialNumber ?? null,
        validTo: certState?.validTo ?? null,
        daysRemaining: certState?.daysRemaining ?? null,
        reachable: certState?.reachable ?? false,
      },
    };

    return deliverPushPayload({
      devices,
      payload,
      referenceId: target.id,
      logEventName: "cert_push_delivery_result",
    });
  }

  return {
    enabled,
    notifyMonitoringScanCompleted,
    notifyCertMonitoringEvent,
    snapshot() {
      return {
        enabled,
        provider: "apns",
        topicConfigured: Boolean(config.defaultTopic),
      };
    },
  };
}
