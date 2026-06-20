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
    kind: overrides.kind ?? "posture",
    mode: overrides.mode ?? null,
    appId: overrides.appId ?? null,
    addedAt: overrides.addedAt ?? "2026-05-28T12:00:00.000Z",
    lastScannedAt: overrides.lastScannedAt ?? null,
    lastCheckedAt: overrides.lastCheckedAt ?? null,
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
    certChecked: 0,
    certNotified: 0,
    notificationAttempted: 0,
    notificationSent: 0,
    notificationFailed: 0,
    notificationSkipped: 0,
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

test("monitoring sweep runs certificate checks for due cert targets", async () => {
  const target = makeTarget({
    kind: "cert",
    cadence: "hourly",
    appId: "com.ktbatterham.certwatch",
  });
  const repository = createFakeRepository({ targets: [target] });
  const enqueued = [];
  const checked = [];

  const result = await runMonitoringSweep({
    scanRepository: repository,
    enqueueScan: (job) => enqueued.push(job),
    runCertificateCheck: async (certTarget) => {
      checked.push(certTarget);
      return {
        event: { type: "cert_expiring" },
        notification: { attempted: 1, sent: 1, failed: 0, skipped: null },
      };
    },
    now: NOW,
    log: () => {},
  });

  assert.equal(result.due, 1);
  assert.equal(result.queued, 0);
  assert.equal(result.certChecked, 1);
  assert.equal(result.certNotified, 1);
  assert.equal(result.notificationAttempted, 1);
  assert.equal(result.notificationSent, 1);
  assert.equal(result.notificationFailed, 0);
  assert.equal(repository.createdScans.length, 0);
  assert.equal(enqueued.length, 0);
  assert.equal(checked[0].id, target.id);
});

test("monitoring sweep honors hourly cadence against last cert check", async () => {
  const target = makeTarget({
    kind: "cert",
    cadence: "hourly",
    lastCheckedAt: "2026-05-30T11:30:00.000Z",
  });
  const repository = createFakeRepository({ targets: [target] });
  const result = await runMonitoringSweep({
    scanRepository: repository,
    enqueueScan: () => {},
    runCertificateCheck: async () => ({ event: null }),
    now: NOW,
    log: () => {},
  });

  assert.equal(result.due, 0);
  assert.equal(result.certChecked, 0);
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
