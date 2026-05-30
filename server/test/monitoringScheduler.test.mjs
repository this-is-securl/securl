import assert from "node:assert/strict";
import test from "node:test";
import { createMonitoringScheduler, runMonitoringSweep } from "../monitoringScheduler.mjs";

const NOW = Date.parse("2026-05-30T12:00:00.000Z");

function makeTarget(overrides = {}) {
  return {
    id: overrides.id ?? "target-1",
    ownerId: overrides.ownerId ?? "scan-owner:test",
    requesterScope: overrides.requesterScope ?? "owner:test",
    url: overrides.url ?? "https://example.com/",
    label: overrides.label ?? "example.com",
    cadence: overrides.cadence ?? "daily",
    addedAt: overrides.addedAt ?? "2026-05-28T12:00:00.000Z",
    lastScannedAt: overrides.lastScannedAt ?? null,
  };
}

function createFakeRepository({ targets = [], records = [] } = {}) {
  const createdScans = [];
  return {
    createdScans,
    async listMonitoringTargets() {
      return targets;
    },
    async listPersistedRecords() {
      return records;
    },
    async createScan({ url, mode, requesterScope, ownerId, clientIp }) {
      const scan = {
        id: `scan-${createdScans.length + 1}`,
        url,
        mode,
        requesterScope,
        ownerId,
        clientIp,
      };
      createdScans.push(scan);
      return scan;
    },
  };
}

test("monitoring sweep queues scans for due targets", async () => {
  const target = makeTarget();
  const repository = createFakeRepository({ targets: [target] });
  const enqueued = [];

  const result = await runMonitoringSweep({
    scanRepository: repository,
    enqueueScan: (job) => enqueued.push(job),
    mode: "quiet",
    now: NOW,
    log: () => {},
  });

  assert.deepEqual(result, {
    checked: 1,
    due: 1,
    queued: 1,
    skipped: 0,
    failed: 0,
  });
  assert.equal(repository.createdScans.length, 1);
  assert.equal(repository.createdScans[0].mode, "quiet");
  assert.equal(repository.createdScans[0].clientIp, "monitoring-scheduler");
  assert.equal(enqueued.length, 1);
  assert.equal(enqueued[0].validatedTarget.toString(), "https://example.com/");
  assert.equal(enqueued[0].authState.ownerId, "scan-owner:test");
});

test("monitoring sweep ignores targets that are not yet due", async () => {
  const target = makeTarget({
    addedAt: "2026-05-30T06:00:00.000Z",
  });
  const repository = createFakeRepository({ targets: [target] });
  const enqueued = [];

  const result = await runMonitoringSweep({
    scanRepository: repository,
    enqueueScan: (job) => enqueued.push(job),
    now: NOW,
    log: () => {},
  });

  assert.equal(result.checked, 1);
  assert.equal(result.due, 0);
  assert.equal(result.queued, 0);
  assert.equal(enqueued.length, 0);
});

test("monitoring sweep skips a due target with an active scan", async () => {
  const target = makeTarget();
  const repository = createFakeRepository({
    targets: [target],
    records: [
      {
        id: "scan-active",
        status: "running",
        url: "https://example.com/",
      },
    ],
  });
  const enqueued = [];

  const result = await runMonitoringSweep({
    scanRepository: repository,
    enqueueScan: (job) => enqueued.push(job),
    now: NOW,
    log: () => {},
  });

  assert.equal(result.due, 1);
  assert.equal(result.queued, 0);
  assert.equal(result.skipped, 1);
  assert.equal(repository.createdScans.length, 0);
  assert.equal(enqueued.length, 0);
});

test("monitoring scheduler remains idle when disabled", () => {
  const scheduler = createMonitoringScheduler({
    enabled: false,
    scanRepository: createFakeRepository(),
    enqueueScan: () => {},
    log: () => {},
  });

  assert.equal(scheduler.start(), false);
  assert.equal(scheduler.stop(), false);
  assert.equal(scheduler.snapshot().enabled, false);
});
