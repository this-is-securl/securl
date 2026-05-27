export function createScanScheduler({
  concurrency = 2,
  staleRunningScanMs = 2 * 60 * 1000,
  scanRepository,
  runQueuedScan,
  log = () => {},
}) {
  const maxConcurrency = Number.isFinite(concurrency) && concurrency > 0
    ? Math.floor(concurrency)
    : 2;
  const staleMs = Number.isFinite(staleRunningScanMs) && staleRunningScanMs > 0
    ? Math.floor(staleRunningScanMs)
    : 2 * 60 * 1000;
  const queue = [];
  let active = 0;

  async function recoverStaleRunningScans() {
    if (typeof scanRepository.recoverStaleRunningScans !== "function") {
      return 0;
    }
    const recovered = await scanRepository.recoverStaleRunningScans({
      maxAgeMs: staleMs,
      limit: maxConcurrency * 4,
      failureClass: "scan_timeout",
      message: "Scan was marked failed during startup recovery because it was still running from a previous worker.",
    });
    if (recovered > 0) {
      log("warn", "stale_running_scans_recovered", {
        recovered,
        staleRunningScanMs: staleMs,
      });
    }
    return recovered;
  }

  function drain() {
    while (active < maxConcurrency && queue.length) {
      const job = queue.shift();
      active += 1;
      log("info", "scan_scheduler_started", {
        scanId: job.scan.id,
        active,
        queued: queue.length,
        concurrency: maxConcurrency,
      });
      void Promise.resolve()
        .then(() => runQueuedScan(job))
        .catch((error) => {
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
    queue.push(job);
    log("info", "scan_scheduler_queued", {
      scanId: job.scan.id,
      active,
      queued: queue.length,
      concurrency: maxConcurrency,
    });
    queueMicrotask(drain);
  }

  return {
    enqueue,
    recoverStaleRunningScans,
    snapshot() {
      return {
        active,
        queued: queue.length,
        concurrency: maxConcurrency,
        staleRunningScanMs: staleMs,
      };
    },
  };
}
