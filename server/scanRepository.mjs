import crypto from "node:crypto";
import { Pool } from "pg";

export function buildScanSummary(scan) {
  const result = scan.result;
  const limitation = result?.assessmentLimitation;
  const findingsCount = Array.isArray(result?.issues) ? result.issues.length : 0;

  return {
    id: scan.id,
    status: scan.status,
    url: scan.url,
    mode: scan.mode,
    requestedAt: scan.requestedAt,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    failureClass: scan.failureClass,
    error: scan.error,
    score: result?.score ?? null,
    grade: result?.grade ?? null,
    limited: limitation?.limited ?? false,
    limitedKind: limitation?.kind ?? null,
    title: result?.title ?? null,
    mainRisk: result?.executiveSummary?.mainRisk ?? null,
    findingsCount,
  };
}

export function buildPersistedScanRecord(scan) {
  return {
    id: scan.id,
    ownerId: scan.ownerId ?? null,
    status: scan.status,
    url: scan.url,
    mode: scan.mode,
    requestedAt: scan.requestedAt,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    requesterScope: scan.requesterScope,
    clientIp: scan.clientIp,
    failureClass: scan.failureClass,
    error: scan.error,
    summary: buildScanSummary(scan),
    result: scan.result,
  };
}

function enrichScan(scan) {
  if (!scan) {
    return null;
  }
  return {
    ...scan,
    summary: buildScanSummary(scan),
  };
}

function hydrateScanFromRow(row) {
  if (!row) {
    return null;
  }

  return enrichScan({
    id: row.id,
    ownerId: row.owner_id,
    status: row.status,
    url: row.url,
    mode: row.mode,
    requestedAt: row.requested_at?.toISOString?.() ?? row.requested_at,
    startedAt: row.started_at?.toISOString?.() ?? row.started_at,
    completedAt: row.completed_at?.toISOString?.() ?? row.completed_at,
    requesterScope: row.requester_scope,
    clientIp: row.client_ip,
    failureClass: row.failure_class,
    error: row.error,
    result: row.result,
  });
}

export function createInMemoryScanRepository({ maxEntries = 200 } = {}) {
  const scans = new Map();
  const order = [];

  const touchOrder = (id) => {
    const index = order.indexOf(id);
    if (index >= 0) {
      order.splice(index, 1);
    }
    order.unshift(id);

    while (order.length > maxEntries) {
      const staleId = order.pop();
      if (staleId) {
        scans.delete(staleId);
      }
    }
  };

  return {
    kind: "memory",
    async ping() {
      return true;
    },
    async createScan({ url, mode, requesterScope, clientIp, ownerId = null }) {
      const scan = {
        id: crypto.randomUUID(),
        ownerId,
        status: "queued",
        url,
        mode,
        requesterScope,
        clientIp,
        requestedAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        failureClass: null,
        error: null,
        result: null,
      };
      scans.set(scan.id, scan);
      touchOrder(scan.id);
      return enrichScan(scan);
    },
    async markRunning(id) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "running";
      scan.startedAt = new Date().toISOString();
      touchOrder(id);
      return enrichScan(scan);
    },
    async markCompleted(id, result) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "completed";
      scan.completedAt = new Date().toISOString();
      scan.result = result;
      touchOrder(id);
      return enrichScan(scan);
    },
    async markFailed(id, failureClass, message) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "failed";
      scan.completedAt = new Date().toISOString();
      scan.failureClass = failureClass;
      scan.error = message;
      touchOrder(id);
      return enrichScan(scan);
    },
    async getScan(id) {
      return enrichScan(scans.get(id));
    },
    async listScans({ limit = 20 } = {}) {
      return order
        .slice(0, Math.max(1, limit))
        .map((id) => enrichScan(scans.get(id))?.summary)
        .filter(Boolean);
    },
    async listPersistedRecords({ limit = 20 } = {}) {
      return order
        .slice(0, Math.max(1, limit))
        .map((id) => scans.get(id))
        .filter(Boolean)
        .map((scan) => buildPersistedScanRecord(scan));
    },
    async close() {
      return undefined;
    },
  };
}

export function createPostgresScanRepository({
  connectionString,
  maxConnections = 5,
  schema = "public",
  log = () => {},
}) {
  const pool = new Pool({
    connectionString,
    max: maxConnections,
    ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
  });

  const table = `${schema}.scans`;

  const repository = {
    kind: "postgres",
    async ping() {
      await pool.query("SELECT 1");
      await pool.query(`select 1 from ${table} limit 1`);
      return true;
    },
    async createScan({ url, mode, requesterScope, clientIp, ownerId = null }) {
      const scan = {
        id: crypto.randomUUID(),
        ownerId,
        status: "queued",
        url,
        mode,
        requesterScope,
        clientIp,
        requestedAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        failureClass: null,
        error: null,
        result: null,
      };
      const record = buildPersistedScanRecord(scan);
      await pool.query(
        `insert into ${table}
          (id, owner_id, status, url, mode, requested_at, started_at, completed_at, requester_scope, client_ip, failure_class, error, summary, result)
         values
          ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::timestamptz, $9, $10, $11, $12, $13::jsonb, $14::jsonb)`,
        [
          record.id,
          record.ownerId,
          record.status,
          record.url,
          record.mode,
          record.requestedAt,
          record.startedAt,
          record.completedAt,
          record.requesterScope,
          record.clientIp,
          record.failureClass,
          record.error,
          JSON.stringify(record.summary),
          record.result ? JSON.stringify(record.result) : null,
        ],
      );
      return scan;
    },
    async markRunning(id) {
      const startedAt = new Date().toISOString();
      const { rows } = await pool.query(
        `update ${table}
         set status = 'running', started_at = $2::timestamptz
         where id = $1
         returning *`,
        [id, startedAt],
      );
      return hydrateScanFromRow(rows[0]);
    },
    async markCompleted(id, result) {
      const completedAt = new Date().toISOString();
      const summary = buildScanSummary({
        id,
        status: "completed",
        requestedAt: null,
        startedAt: null,
        completedAt,
        failureClass: null,
        error: null,
        url: "",
        mode: "standard",
        result,
      });
      const { rows } = await pool.query(
        `update ${table}
         set status = 'completed',
             completed_at = $2::timestamptz,
             failure_class = null,
             error = null,
             summary = $3::jsonb,
             result = $4::jsonb
         where id = $1
         returning *`,
        [id, completedAt, JSON.stringify(summary), JSON.stringify(result)],
      );
      return hydrateScanFromRow(rows[0]);
    },
    async markFailed(id, failureClass, message) {
      const completedAt = new Date().toISOString();
      const { rows } = await pool.query(
        `update ${table}
         set status = 'failed',
             completed_at = $2::timestamptz,
             failure_class = $3,
             error = $4,
             result = null
         where id = $1
         returning *`,
        [id, completedAt, failureClass, message],
      );
      return hydrateScanFromRow(rows[0]);
    },
    async getScan(id) {
      const { rows } = await pool.query(`select * from ${table} where id = $1`, [id]);
      return hydrateScanFromRow(rows[0]);
    },
    async listScans({ limit = 20 } = {}) {
      const { rows } = await pool.query(
        `select * from ${table} order by requested_at desc limit $1`,
        [Math.max(1, limit)],
      );
      return rows.map((row) => hydrateScanFromRow(row)?.summary).filter(Boolean);
    },
    async listPersistedRecords({ limit = 20 } = {}) {
      const { rows } = await pool.query(
        `select * from ${table} order by requested_at desc limit $1`,
        [Math.max(1, limit)],
      );
      return rows.map((row) => buildPersistedScanRecord(hydrateScanFromRow(row)));
    },
    async close() {
      await pool.end();
    },
  };

  log("info", "scan_repository_configured", {
    backend: "postgres",
    schema,
    table: "scans",
  });

  return repository;
}

export function createScanRepository({ backend = "memory", databaseUrl = "", log } = {}) {
  if (backend === "postgres") {
    return createPostgresScanRepository({
      connectionString: databaseUrl,
      log,
    });
  }

  return createInMemoryScanRepository();
}
