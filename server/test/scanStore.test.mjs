import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPersistedScanRecord,
  buildScanRepositorySchemaStatements,
  createInMemoryScanRepository,
} from "../scanRepository.mjs";

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

test("scan repository schema statements create the scans table and scoped indexes", () => {
  const statements = buildScanRepositorySchemaStatements("public");

  assert.match(statements[0], /create schema if not exists public/i);
  assert.match(statements[1], /create table if not exists public\.scans/i);
  assert.match(statements[1], /owner_id text null/i);
  assert.match(statements[2], /create table if not exists public\.scan_events/i);
  assert.match(statements[3], /scans_requested_at_idx/i);
  assert.match(statements[4], /scans_owner_requested_at_idx/i);
  assert.match(statements[5], /scans_requester_requested_at_idx/i);
  assert.match(statements[6], /scan_events_scan_occurred_idx/i);
});
