const DAY_MS = 24 * 60 * 60 * 1000;
const CADENCE_MS = {
  hourly: 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  daily: DAY_MS,
  weekly: 7 * DAY_MS,
};

function cadenceWindowMs(cadence) {
  return CADENCE_MS[cadence] ?? CADENCE_MS.daily;
}

function isTargetDue(target, now = Date.now()) {
  const baseTime = target.lastCheckedAt
    ? new Date(target.lastCheckedAt).getTime()
    : target.lastScannedAt
    ? new Date(target.lastScannedAt).getTime()
    : new Date(target.addedAt).getTime();
  return Number.isFinite(baseTime) && now >= baseTime + cadenceWindowMs(target.cadence);
}

function hasActiveScan(records) {
  return records.some((record) => record?.status === "queued" || record?.status === "running");
}

function recordMatchesTarget(record, target) {
  return (
    record?.url === target.url
    || record?.result?.finalUrl === target.url
    || record?.result?.normalizedUrl === target.url
  );
}

export async function runMonitoringSweep({
  scanRepository,
  enqueueScan,
  runCertificateCheck = null,
  mode = "quiet",
  limit = 20,
  now = Date.now(),
  log = () => {},
}) {
  const targets = await scanRepository.listMonitoringTargets({
    limit: Math.max(limit * 4, limit),
  });
  const dueTargets = targets
    .filter((target) => isTargetDue(target, now))
    .slice(0, Math.max(1, limit));
  const result = {
    checked: targets.length,
    due: dueTargets.length,
    queued: 0,
    certChecked: 0,
    certNotified: 0,
    notificationAttempted: 0,
    notificationSent: 0,
    notificationFailed: 0,
    notificationSkipped: 0,
    skipped: 0,
    failed: 0,
  };

  for (const target of dueTargets) {
    try {
      if ((target.kind ?? "posture") === "cert") {
        if (typeof runCertificateCheck !== "function") {
          result.skipped += 1;
          log("warn", "monitoring_scheduler_skipped_cert_no_runner", {
            targetId: target.id,
            ownerId: target.ownerId,
            url: target.url,
          });
          continue;
        }

        const outcome = await runCertificateCheck(target);
        result.certChecked += 1;
        const notification = outcome?.notification || {};
        result.notificationAttempted += Number(notification.attempted || 0);
        result.notificationSent += Number(notification.sent || 0);
        result.notificationFailed += Number(notification.failed || 0);
        if (notification.skipped) result.notificationSkipped += 1;
        result.certNotified += Number(notification.sent || 0);
        log("info", "monitoring_scheduler_checked_cert", {
          targetId: target.id,
          ownerId: target.ownerId,
          url: target.url,
          eventType: outcome?.event?.type ?? null,
          notificationSent: Number(notification.sent || 0),
          notificationFailed: Number(notification.failed || 0),
          notificationSkipped: notification.skipped ?? null,
        });
        continue;
      }

      const records = await scanRepository.listPersistedRecords({
        ownerId: target.ownerId,
        requesterScope: target.ownerId ? null : target.requesterScope,
        limit: 10,
      });
      const targetRecords = records.filter((record) => recordMatchesTarget(record, target));
      if (hasActiveScan(targetRecords)) {
        result.skipped += 1;
        log("info", "monitoring_scheduler_skipped_active_scan", {
          targetId: target.id,
          ownerId: target.ownerId,
          url: target.url,
        });
        continue;
      }

      const scan = await scanRepository.createScan({
        url: target.url,
        mode: target.mode || mode,
        requesterScope: target.requesterScope,
        ownerId: target.ownerId,
        clientIp: "monitoring-scheduler",
      });

      enqueueScan({
        scan,
        validatedTarget: new URL(target.url),
        mode: target.mode || mode,
        authState: {
          clientIp: "monitoring-scheduler",
          requesterScope: target.requesterScope,
          ownerId: target.ownerId,
        },
      });
      result.queued += 1;
      log("info", "monitoring_scheduler_queued_scan", {
        targetId: target.id,
        scanId: scan.id,
        ownerId: target.ownerId,
        url: target.url,
        mode: target.mode || mode,
      });
    } catch (error) {
      result.failed += 1;
      log("warn", "monitoring_scheduler_target_failed", {
        targetId: target.id,
        ownerId: target.ownerId,
        url: target.url,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return result;
}

export function createMonitoringScheduler({
  enabled = false,
  intervalMs = 15 * 60 * 1000,
  scanRepository,
  enqueueScan,
  runCertificateCheck = null,
  mode = "quiet",
  limit = 20,
  log = () => {},
}) {
  const resolvedIntervalMs = Number.isFinite(intervalMs) && intervalMs >= 60_000
    ? Math.floor(intervalMs)
    : 15 * 60 * 1000;
  const resolvedLimit = Number.isFinite(limit) && limit > 0
    ? Math.floor(limit)
    : 20;
  let timer = null;
  let running = false;
  let lastSweep = null;

  async function sweep() {
    if (running) {
      return lastSweep;
    }
    running = true;
    try {
      lastSweep = await runMonitoringSweep({
        scanRepository,
        enqueueScan,
        runCertificateCheck,
        mode,
        limit: resolvedLimit,
        log,
      });
      log("info", "monitoring_scheduler_sweep_completed", lastSweep);
      return lastSweep;
    } finally {
      running = false;
    }
  }

  function start() {
    if (!enabled || timer) {
      return false;
    }
    timer = setInterval(() => {
      void sweep().catch((error) => {
        log("error", "monitoring_scheduler_sweep_failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      });
    }, resolvedIntervalMs);
    timer.unref?.();
    queueMicrotask(() => {
      void sweep().catch((error) => {
        log("error", "monitoring_scheduler_initial_sweep_failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      });
    });
    return true;
  }

  function stop() {
    if (!timer) {
      return false;
    }
    clearInterval(timer);
    timer = null;
    return true;
  }

  return {
    start,
    stop,
    sweep,
    snapshot() {
      return {
        enabled,
        running,
        intervalMs: resolvedIntervalMs,
        mode,
        limit: resolvedLimit,
        lastSweep,
      };
    },
  };
}
