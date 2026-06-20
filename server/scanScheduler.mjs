import crypto from "node:crypto";

export function createScanScheduler({
  concurrency = 2,
  staleRunningScanMs = 2 * 60 * 1000,
  recoveryIntervalMs = 15_000,
  maxJobAttempts = 3,
  scanRepository,
  runQueuedScan,
  jobFactory = null,
  log = () => {},
}) {
  const maxConcurrency = Number.isFinite(concurrency) && concurrency > 0
    ? Math.floor(concurrency)
    : 2;
  const staleMs = Number.isFinite(staleRunningScanMs) && staleRunningScanMs > 0
    ? Math.floor(staleRunningScanMs)
    : 2 * 60 * 1000;
  const recoveryMs = Number.isFinite(recoveryIntervalMs) && recoveryIntervalMs > 0
    ? Math.floor(recoveryIntervalMs)
    : 15_000;
  const leaseMs = Math.max(staleMs * 2, 5 * 60 * 1000);
  const workerId = `scan-worker:${crypto.randomUUID()}`;
  const queue = [];
  const queuedIds = new Set();
  let active = 0;
  let recoveryTimer = null;
  let recoveryRunning = false;
  let stopped = false;
  let lastRecovery = null;

  async function recoverPersistedJobs() {
    if (recoveryRunning || stopped) return { requeued: 0, failed: 0, queued: 0 };
    recoveryRunning = true;
    try {
      let stale = { requeued: 0, failed: 0 };
      if (typeof scanRepository.requeueStaleRunningScanJobs === "function") {
        stale = await scanRepository.requeueStaleRunningScanJobs({
          maxAgeMs: staleMs,
          maxAttempts: maxJobAttempts,
          limit: maxConcurrency * 4,
        });
      } else if (typeof scanRepository.recoverStaleRunningScans === "function") {
        const failed = await scanRepository.recoverStaleRunningScans({
          maxAgeMs: staleMs,
          limit: maxConcurrency * 4,
          failureClass: "scan_timeout",
          message: "Scan was marked failed during startup recovery because it was still running from a previous worker.",
        });
        stale = { requeued: 0, failed };
      }

      let recovered = [];
      if (jobFactory && typeof scanRepository.listClaimableScanJobs === "function") {
        recovered = await scanRepository.listClaimableScanJobs({ limit: maxConcurrency * 4 });
        for (const scan of recovered) {
          enqueue(jobFactory(scan));
        }
      }
      lastRecovery = new Date().toISOString();
      if (stale.requeued || stale.failed || recovered.length) {
        log("warn", "scan_scheduler_recovered", {
          ...stale,
          queued: recovered.length,
          staleRunningScanMs: staleMs,
        });
      }
      return { ...stale, queued: recovered.length };
    } finally {
      recoveryRunning = false;
    }
  }

  // Kept as a compatibility hook for callers and older repository implementations.
  async function recoverStaleRunningScans() {
    const recovered = await recoverPersistedJobs();
    return recovered.requeued + recovered.failed;
  }

  async function execute(job) {
    let claimedScan = job.scan;
    if (typeof scanRepository.claimScanJob === "function") {
      claimedScan = await scanRepository.claimScanJob(job.scan.id, { workerId, leaseMs });
      if (!claimedScan) {
        log("info", "scan_scheduler_claim_skipped", { scanId: job.scan.id });
        return;
      }
    }
    await runQueuedScan({
      ...job,
      scan: claimedScan,
      scanLeaseOwner: typeof scanRepository.claimScanJob === "function" ? workerId : null,
    });
  }

  function drain() {
    if (stopped) return;
    while (active < maxConcurrency && queue.length) {
      const job = queue.shift();
      queuedIds.delete(job.scan.id);
      active += 1;
      log("info", "scan_scheduler_started", {
        scanId: job.scan.id,
        active,
        queued: queue.length,
        concurrency: maxConcurrency,
      });
      void execute(job)
        .catch(async (error) => {
          if (typeof scanRepository.releaseScanJob === "function") {
            await scanRepository.releaseScanJob(job.scan.id, { workerId }).catch(() => {});
          }
          log("error", "scan_scheduler_job_failed", {
            scanId: job.scan.id,
            message: error instanceof Error ? error.message : String(error),
          });
        })
        .finally(() => {
          active = Math.max(0, active - 1);
          log("info", "scan_scheduler_finished", {
            scanId: job.scan.id,
            active,
            queued: queue.length,
            concurrency: maxConcurrency,
          });
          drain();
        });
    }
  }

  function enqueue(job) {
    if (stopped || !job?.scan?.id || queuedIds.has(job.scan.id)) return false;
    queuedIds.add(job.scan.id);
    queue.push(job);
    log("info", "scan_scheduler_queued", {
      scanId: job.scan.id,
      active,
      queued: queue.length,
      concurrency: maxConcurrency,
    });
    queueMicrotask(drain);
    return true;
  }

  function start() {
    if (recoveryTimer || stopped) return;
    recoveryTimer = setInterval(() => {
      void recoverPersistedJobs().catch((error) => {
        log("error", "scan_scheduler_recovery_failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      });
    }, recoveryMs);
    recoveryTimer.unref?.();
  }

  function stop() {
    stopped = true;
    if (recoveryTimer) clearInterval(recoveryTimer);
    recoveryTimer = null;
  }

  return {
    enqueue,
    start,
    stop,
    recoverPersistedJobs,
    recoverStaleRunningScans,
    snapshot() {
      return {
        active,
        queued: queue.length,
        concurrency: maxConcurrency,
        staleRunningScanMs: staleMs,
        recoveryIntervalMs: recoveryMs,
        maxJobAttempts,
        durable: typeof scanRepository.claimScanJob === "function",
        lastRecovery,
      };
    },
  };
}
