import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPersistedScanRecord,
  buildScanRepositorySchemaStatements,
  createInMemoryScanRepository,
} from "../scanRepository.mjs";

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("scan repository tracks queued, running, and completed scans", async () => {
  const repository = createInMemoryScanRepository();
  const scan = await repository.createScan({
    url: "https://example.com",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  assert.equal(scan.status, "queued");

  await repository.markRunning(scan.id);
  await repository.markCompleted(scan.id, {
    score: 74,
    grade: "C",
    title: "Example title",
    assessmentLimitation: { limited: false },
    executiveSummary: { mainRisk: "Browser hardening gaps" },
    issues: [{ id: "one" }, { id: "two" }],
  });

  const saved = await repository.getScan(scan.id);
  const events = await repository.listScanEvents(scan.id);
  assert.equal(saved.status, "completed");
  assert.equal(saved.summary.score, 74);
  assert.equal(saved.summary.grade, "C");
  assert.equal(saved.summary.findingsCount, 2);
  assert.equal(saved.summary.mainRisk, "Browser hardening gaps");
  assert.deepEqual(
    events.map((event) => event.eventType),
    ["completed", "started", "queued"],
  );
});

test("scan repository summarizes failed scans and newest-first ordering", async () => {
  const repository = createInMemoryScanRepository();
  const first = await repository.createScan({
    url: "https://first.example",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });
  const second = await repository.createScan({
    url: "https://second.example",
    mode: "quiet",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  await repository.markFailed(first.id, "scan_runtime_failure", "Socket hang up");
  await repository.markFailed(second.id, "invalid_target_private", "Private targets are not allowed.");

  const list = await repository.listScans();
  assert.equal(list[0].id, second.id);
  assert.equal(list[0].status, "failed");
  assert.equal(list[0].failureClass, "invalid_target_private");
  assert.equal(list[1].id, first.id);
});

test("scan repository can filter summaries by target url", async () => {
  const repository = createInMemoryScanRepository();
  await repository.createScan({
    url: "https://example.com",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });
  await repository.createScan({
    url: "https://example.com",
    mode: "quiet",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });
  await repository.createScan({
    url: "https://other.example",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  const list = await repository.listScans({ url: "https://example.com" });
  assert.equal(list.length, 2);
  assert.ok(list.every((scan) => scan.url === "https://example.com"));
});

test("scan repository result cache is mode-aware", async () => {
  const repository = createInMemoryScanRepository();
  const standard = await repository.createScan({
    url: "https://example.com/",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });
  await repository.markCompleted(standard.id, {
    score: 74,
    grade: "C",
    assessmentLimitation: { limited: false },
    executiveSummary: { mainRisk: "Browser hardening gaps" },
    issues: [],
    scanTiming: { timeoutMs: 45000, timedOut: false },
  });

  assert.equal((await repository.getRecentSuccessfulScan({
    url: "https://example.com/",
    mode: "standard",
  })).id, standard.id);
  assert.equal(await repository.getRecentSuccessfulScan({
    url: "https://example.com/",
    mode: "deep-passive",
  }), null);

  const deepPassive = await repository.createScan({
    url: "https://example.com/",
    mode: "deep-passive",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });
  await repository.markCompleted(deepPassive.id, {
    score: 74,
    grade: "C",
    assessmentLimitation: { limited: false },
    executiveSummary: { mainRisk: "Browser hardening gaps" },
    issues: [],
    scanTiming: { timeoutMs: 75000, timedOut: false },
  });

  const cached = await repository.getRecentSuccessfulScan({
    url: "https://example.com/",
    mode: "deep-passive",
  });
  assert.equal(cached.id, deepPassive.id);
  assert.equal(cached.result.scanTiming.timeoutMs, 75000);
});

test("scan repository can expose a persisted record shape", async () => {
  const repository = createInMemoryScanRepository();
  const scan = await repository.createScan({
    url: "https://example.com",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  await repository.markCompleted(scan.id, {
    score: 81,
    grade: "B",
    title: "Example title",
    assessmentLimitation: { limited: false },
    executiveSummary: { mainRisk: "Transport posture is mostly sound." },
    issues: [],
  });

  const persisted = buildPersistedScanRecord(await repository.getScan(scan.id));
  assert.equal(persisted.id, scan.id);
  assert.equal(persisted.summary.score, 81);
  assert.equal(persisted.summary.grade, "B");
  assert.equal(persisted.result.grade, "B");
});

test("scan repository can upsert and delete monitoring targets", async () => {
  const repository = createInMemoryScanRepository();
  const first = await repository.upsertMonitoringTarget({
    url: "https://example.com/",
    label: "example.com",
    cadence: "daily",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
  });

  assert.equal(first.cadence, "daily");

  const updated = await repository.upsertMonitoringTarget({
    url: "https://example.com/",
    label: "example.com",
    cadence: "weekly",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
  });

  assert.equal(updated.id, first.id);
  assert.equal(updated.cadence, "weekly");

  const list = await repository.listMonitoringTargets({
    ownerId: "scan-owner:test",
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].id, first.id);

  const deleted = await repository.deleteMonitoringTarget(first.id, {
    ownerId: "scan-owner:test",
  });
  assert.equal(deleted, true);
  assert.equal((await repository.listMonitoringTargets({ ownerId: "scan-owner:test" })).length, 0);
});

test("completed scans sync matching monitoring targets", async () => {
  const repository = createInMemoryScanRepository();
  await repository.upsertMonitoringTarget({
    url: "https://example.com/",
    label: "example.com",
    cadence: "daily",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
  });

  const scan = await repository.createScan({
    url: "https://example.com/",
    mode: "standard",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
    clientIp: "127.0.0.1",
  });

  await repository.markCompleted(scan.id, {
    host: "www.example.com",
    finalUrl: "https://www.example.com/",
    normalizedUrl: "https://example.com/",
    scannedAt: "2026-05-08T10:00:00.000Z",
    score: 81,
    grade: "B",
    title: "Example title",
    assessmentLimitation: { limited: false },
    executiveSummary: { mainRisk: "Transport posture is mostly sound." },
    issues: [],
  });

  const [target] = await repository.listMonitoringTargets({
    ownerId: "scan-owner:test",
  });
  assert.equal(target.url, "https://www.example.com/");
  assert.equal(target.label, "www.example.com");
  assert.equal(target.lastScannedAt, "2026-05-08T10:00:00.000Z");
});

test("scan repository recovers stale running scans as failed", async () => {
  const repository = createInMemoryScanRepository();
  const scan = await repository.createScan({
    url: "https://example.com",
    mode: "deep-passive",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  await repository.markRunning(scan.id);
  await wait(5);

  const recovered = await repository.recoverStaleRunningScans({
    maxAgeMs: 1,
    failureClass: "scan_timeout",
    message: "Recovered from a stale worker.",
  });

  const saved = await repository.getScan(scan.id);
  const events = await repository.listScanEvents(scan.id);

  assert.equal(recovered, 1);
  assert.equal(saved.status, "failed");
  assert.equal(saved.failureClass, "scan_timeout");
  assert.equal(saved.error, "Recovered from a stale worker.");
  assert.deepEqual(
    events.map((event) => event.eventType),
    ["failed", "started", "queued"],
  );
});

test("scan repository schema statements create the scans table and scoped indexes", () => {
  const statements = buildScanRepositorySchemaStatements("public");

  assert.match(statements[0], /create schema if not exists public/i);
  assert.ok(statements.some((statement) => /create table if not exists public\.users/i.test(statement)));
  assert.ok(statements.some((statement) => /create table if not exists public\.auth_sessions/i.test(statement)));
  assert.ok(statements.some((statement) => /create table if not exists public\.api_keys/i.test(statement)));
  const scansStatement = statements.find((statement) => /create table if not exists public\.scans/i.test(statement));
  assert.ok(scansStatement);
  assert.match(scansStatement, /owner_id text null/i);
  assert.ok(statements.some((statement) => /create table if not exists public\.scan_events/i.test(statement)));
  assert.ok(statements.some((statement) => /create table if not exists public\.monitoring_targets/i.test(statement)));
  assert.ok(statements.some((statement) => /scans_requested_at_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /scans_owner_requested_at_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /scans_requester_requested_at_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /scan_events_scan_occurred_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /monitoring_targets_owner_added_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /monitoring_targets_requester_added_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /monitoring_targets_owner_url_uidx/i.test(statement)));
  assert.ok(statements.some((statement) => /auth_sessions_user_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /api_keys_user_created_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /api_keys_active_token_hash_idx/i.test(statement)));
});
