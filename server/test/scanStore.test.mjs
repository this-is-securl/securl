import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPersistedScanRecord,
  buildScanRepositorySchemaStatements,
  createInMemoryScanRepository,
} from "../scanRepository.mjs";
import { buildScanHistoryPayload } from "../scanDtos.mjs";
import { hashClientIp } from "../privacy.mjs";

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
  assert.equal(scan.clientIp, hashClientIp("127.0.0.1"));
  assert.notEqual(scan.clientIp, "127.0.0.1");

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

test("scan history payload allowlists public event metadata", () => {
  const payload = buildScanHistoryPayload(
    {
      id: "scan-1",
      status: "completed",
      requestedAt: "2026-06-05T00:00:00.000Z",
      startedAt: "2026-06-05T00:00:01.000Z",
      completedAt: "2026-06-05T00:00:02.000Z",
    },
    [
      {
        id: "event-1",
        scanId: "scan-1",
        eventType: "completed",
        occurredAt: "2026-06-05T00:00:02.000Z",
        status: "completed",
        failureClass: null,
        message: null,
        metadata: {
          grade: "A",
          score: 98,
          limited: false,
          clientIp: "203.0.113.10",
          requesterScope: "ip:203.0.113.10",
          ownerId: "scan-owner:secret",
        },
      },
    ],
  );

  assert.deepEqual(payload.events[0].metadata, {
    score: 98,
    grade: "A",
    limited: false,
  });
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

test("scan repository stores cert monitoring state separately from posture targets", async () => {
  const repository = createInMemoryScanRepository();
  const posture = await repository.upsertMonitoringTarget({
    url: "https://example.com/",
    label: "example.com",
    cadence: "daily",
    kind: "posture",
    mode: "quiet",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
  });
  const cert = await repository.upsertMonitoringTarget({
    url: "https://example.com/",
    label: "example.com cert",
    cadence: "hourly",
    kind: "cert",
    appId: "com.ktbatterham.certwatch",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
  });

  assert.notEqual(posture.id, cert.id);
  assert.equal(cert.kind, "cert");
  assert.equal(cert.appId, "com.ktbatterham.certwatch");

  const updated = await repository.updateMonitoringTargetCertState(cert.id, {
    ownerId: "scan-owner:test",
    certState: {
      reachable: true,
      host: "example.com",
      serialNumber: "ABC123",
      issuer: "Example CA",
      checkedAt: "2026-06-18T08:00:00.000Z",
      history: [{ checkedAt: "2026-06-18T08:00:00.000Z", eventType: null }],
    },
    lastCheckedAt: "2026-06-18T08:00:00.000Z",
  });

  assert.equal(updated.certState.serialNumber, "ABC123");
  assert.equal(updated.lastCheckedAt, "2026-06-18T08:00:00.000Z");
  assert.equal((await repository.listMonitoringTargets({ ownerId: "scan-owner:test" })).length, 2);
});

test("scan repository stores push devices without exposing raw tokens in public lists", async () => {
  const repository = createInMemoryScanRepository();
  const token = "a".repeat(64);

  const saved = await repository.upsertPushDevice({
    platform: "ios",
    token,
    appId: "online.securl.app",
    environment: "sandbox",
    requesterScope: "ip:test",
    ownerId: "scan-owner:test",
  });

  assert.equal(saved.platform, "ios");
  assert.equal(saved.token, undefined);
  assert.equal(saved.tokenPrefix, "aaaaaaaa...");

  const listed = await repository.listPushDevices({ ownerId: "scan-owner:test" });
  assert.equal(listed.length, 1);
  assert.equal(listed[0].token, undefined);
  assert.equal(listed[0].tokenPrefix, "aaaaaaaa...");

  const secrets = await repository.listPushDeviceSecrets({ ownerId: "scan-owner:test" });
  assert.equal(secrets.length, 1);
  assert.equal(secrets[0].token, token);
  assert.equal((await repository.listPushDeviceSecrets({
    ownerId: "scan-owner:test",
    appId: "com.ktbatterham.certwatch",
  })).length, 0);

  assert.equal(await repository.disablePushDevice(saved.id, { ownerId: "scan-owner:test" }), true);
  assert.equal((await repository.listPushDevices({ ownerId: "scan-owner:test" })).length, 0);
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
  assert.ok(statements.some((statement) => /create table if not exists public\.push_devices/i.test(statement)));
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
  assert.ok(statements.some((statement) => /monitoring_targets_owner_url_kind_uidx/i.test(statement)));
  assert.ok(statements.some((statement) => /cert_state jsonb null/i.test(statement)));
  assert.ok(statements.some((statement) => /auth_sessions_user_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /api_keys_user_created_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /api_keys_active_token_hash_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /push_devices_owner_updated_idx/i.test(statement)));
  assert.ok(statements.some((statement) => /push_devices_scope_token_uidx/i.test(statement)));
});
