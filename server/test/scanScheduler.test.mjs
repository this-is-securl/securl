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
