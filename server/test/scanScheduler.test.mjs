import assert from "node:assert/strict";
import test from "node:test";
import { createScanScheduler } from "../scanScheduler.mjs";

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("scan scheduler enforces configured concurrency", async () => {
  let active = 0;
  let maxActive = 0;
  const completed = [];
  const scheduler = createScanScheduler({
    concurrency: 2,
    scanRepository: {},
    log: () => {},
    runQueuedScan: async ({ scan }) => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await wait(20);
      completed.push(scan.id);
      active -= 1;
    },
  });

  for (const id of ["one", "two", "three", "four"]) {
    scheduler.enqueue({ scan: { id } });
  }

  for (let attempt = 0; attempt < 20 && completed.length < 4; attempt += 1) {
    await wait(10);
  }

  assert.equal(completed.length, 4);
  assert.equal(maxActive, 2);
  assert.equal(scheduler.snapshot().active, 0);
  assert.equal(scheduler.snapshot().queued, 0);
});

test("scan scheduler recovers stale running scans through repository hook", async () => {
  const scheduler = createScanScheduler({
    concurrency: 2,
    staleRunningScanMs: 10_000,
    scanRepository: {
      async recoverStaleRunningScans(options) {
        assert.equal(options.maxAgeMs, 10_000);
        assert.equal(options.failureClass, "scan_timeout");
        return 3;
      },
    },
    log: () => {},
    runQueuedScan: async () => {},
  });

  assert.equal(await scheduler.recoverStaleRunningScans(), 3);
});

test("scan scheduler claims durable jobs once across competing workers", async () => {
  let claimed = false;
  let executions = 0;
  const repository = {
    async claimScanJob(_id, { workerId }) {
      if (claimed) return null;
      claimed = true;
      return { id: "durable-one", leaseOwner: workerId };
    },
  };
  const options = {
    concurrency: 1,
    scanRepository: repository,
    log: () => {},
    runQueuedScan: async ({ scanLeaseOwner }) => {
      assert.match(scanLeaseOwner, /^scan-worker:/);
      executions += 1;
    },
  };
  const first = createScanScheduler(options);
  const second = createScanScheduler(options);

  first.enqueue({ scan: { id: "durable-one" } });
  second.enqueue({ scan: { id: "durable-one" } });
  await wait(20);

  assert.equal(executions, 1);
  first.stop();
  second.stop();
});

test("scan scheduler reconstructs persisted queued jobs during recovery", async () => {
  const executed = [];
  const scheduler = createScanScheduler({
    concurrency: 1,
    scanRepository: {
      async requeueStaleRunningScanJobs() {
        return { requeued: 1, failed: 0 };
      },
      async listClaimableScanJobs() {
        return [{ id: "recovered-one", url: "https://example.com", mode: "standard" }];
      },
      async claimScanJob(_id, { workerId }) {
        return { id: "recovered-one", leaseOwner: workerId };
      },
    },
    jobFactory: (scan) => ({ scan, recovered: true }),
    log: () => {},
    runQueuedScan: async (job) => executed.push(job),
  });

  const recovered = await scheduler.recoverPersistedJobs();
  await wait(20);

  assert.deepEqual(recovered, { requeued: 1, failed: 0, queued: 1 });
  assert.equal(executed.length, 1);
  assert.equal(executed[0].recovered, true);
  scheduler.stop();
});
