import crypto from "node:crypto";
import { Pool } from "pg";

export function buildScanRepositorySchemaStatements(schema = "public") {
  const qualifiedTable = `${schema}.scans`;
  const qualifiedEventsTable = `${schema}.scan_events`;
  const qualifiedTargetsTable = `${schema}.monitoring_targets`;
  const qualifiedUsersTable = `${schema}.users`;
  const qualifiedSessionsTable = `${schema}.auth_sessions`;
  const qualifiedApiKeysTable = `${schema}.api_keys`;
  return [
    `create schema if not exists ${schema}`,
    `create table if not exists ${qualifiedUsersTable} (
      id uuid primary key,
      email text not null unique,
      display_name text null,
      password_hash text not null,
      created_at timestamptz not null,
      updated_at timestamptz not null
    )`,
    `create table if not exists ${qualifiedSessionsTable} (
      id uuid primary key,
      user_id uuid not null references ${qualifiedUsersTable}(id) on delete cascade,
      token_hash text not null unique,
      created_at timestamptz not null,
      expires_at timestamptz not null,
      last_seen_at timestamptz not null
    )`,
    `create table if not exists ${qualifiedApiKeysTable} (
      id uuid primary key,
      user_id uuid not null references ${qualifiedUsersTable}(id) on delete cascade,
      name text not null,
      token_hash text not null unique,
      token_prefix text not null,
      created_at timestamptz not null,
      last_used_at timestamptz null,
      revoked_at timestamptz null
    )`,
    `create table if not exists ${qualifiedTable} (
      id uuid primary key,
      owner_id text null,
      status text not null,
      url text not null,
      mode text not null,
      requested_at timestamptz not null,
      started_at timestamptz null,
      completed_at timestamptz null,
      requester_scope text not null,
      client_ip text not null,
      failure_class text null,
      error text null,
      summary jsonb not null,
      result jsonb null
    )`,
    `create table if not exists ${qualifiedEventsTable} (
      id uuid primary key,
      scan_id uuid not null references ${qualifiedTable}(id) on delete cascade,
      event_type text not null,
      occurred_at timestamptz not null,
      status text not null,
      failure_class text null,
      message text null,
      metadata jsonb not null default '{}'::jsonb
    )`,
    `create table if not exists ${qualifiedTargetsTable} (
      id uuid primary key,
      owner_id text null,
      requester_scope text not null,
      url text not null,
      label text not null,
      cadence text not null,
      added_at timestamptz not null,
      last_scanned_at timestamptz null
    )`,
    `create index if not exists scans_requested_at_idx on ${qualifiedTable} (requested_at desc)`,
    `create index if not exists scans_owner_requested_at_idx on ${qualifiedTable} (owner_id, requested_at desc)`,
    `create index if not exists scans_requester_requested_at_idx on ${qualifiedTable} (requester_scope, requested_at desc)`,
    `create index if not exists scan_events_scan_occurred_idx on ${qualifiedEventsTable} (scan_id, occurred_at desc)`,
    `create index if not exists monitoring_targets_owner_added_idx on ${qualifiedTargetsTable} (owner_id, added_at desc)`,
    `create index if not exists monitoring_targets_requester_added_idx on ${qualifiedTargetsTable} (requester_scope, added_at desc)`,
    `create unique index if not exists monitoring_targets_owner_url_uidx on ${qualifiedTargetsTable} (owner_id, url)`,
    `create index if not exists auth_sessions_user_idx on ${qualifiedSessionsTable} (user_id, created_at desc)`,
    `create index if not exists auth_sessions_expires_idx on ${qualifiedSessionsTable} (expires_at)`,
    `create index if not exists api_keys_user_created_idx on ${qualifiedApiKeysTable} (user_id, created_at desc)`,
    `create index if not exists api_keys_active_token_hash_idx on ${qualifiedApiKeysTable} (token_hash) where revoked_at is null`,
  ];
}

function buildPostgresSslConfig() {
  if (process.env.PGSSLMODE === "disable") {
    return false;
  }

  return {
    rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED === "true",
  };
}

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
    scanTiming: result?.scanTiming ?? null,
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

export function buildScanEvent({
  scanId,
  eventType,
  status,
  occurredAt = new Date().toISOString(),
  failureClass = null,
  message = null,
  metadata = {},
}) {
  return {
    id: crypto.randomUUID(),
    scanId,
    eventType,
    occurredAt,
    status,
    failureClass,
    message,
    metadata,
  };
}

export function buildMonitoringTargetRecord({
  id = crypto.randomUUID(),
  ownerId = null,
  requesterScope,
  url,
  label,
  cadence,
  addedAt = new Date().toISOString(),
  lastScannedAt = null,
}) {
  return {
    id,
    ownerId,
    requesterScope,
    url,
    label,
    cadence,
    addedAt,
    lastScannedAt,
  };
}

export function buildUserRecord({
  id = crypto.randomUUID(),
  email,
  displayName = null,
  passwordHash,
  createdAt = new Date().toISOString(),
  updatedAt = createdAt,
}) {
  return {
    id,
    email,
    displayName,
    passwordHash,
    createdAt,
    updatedAt,
  };
}

export function buildAuthSessionRecord({
  id = crypto.randomUUID(),
  userId,
  tokenHash,
  createdAt = new Date().toISOString(),
  expiresAt,
  lastSeenAt = createdAt,
}) {
  return {
    id,
    userId,
    tokenHash,
    createdAt,
    expiresAt,
    lastSeenAt,
  };
}

export function buildApiKeyRecord({
  id = crypto.randomUUID(),
  userId,
  name,
  tokenHash,
  tokenPrefix,
  createdAt = new Date().toISOString(),
  lastUsedAt = null,
  revokedAt = null,
}) {
  return {
    id,
    userId,
    name,
    tokenHash,
    tokenPrefix,
    createdAt,
    lastUsedAt,
    revokedAt,
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

function hydrateScanEventFromRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    scanId: row.scan_id,
    eventType: row.event_type,
    occurredAt: row.occurred_at?.toISOString?.() ?? row.occurred_at,
    status: row.status,
    failureClass: row.failure_class,
    message: row.message,
    metadata: row.metadata ?? {},
  };
}

function hydrateMonitoringTargetFromRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    ownerId: row.owner_id,
    requesterScope: row.requester_scope,
    url: row.url,
    label: row.label,
    cadence: row.cadence,
    addedAt: row.added_at?.toISOString?.() ?? row.added_at,
    lastScannedAt: row.last_scanned_at?.toISOString?.() ?? row.last_scanned_at,
  };
}

function hydrateUserFromRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name ?? null,
    passwordHash: row.password_hash,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
  };
}

function hydrateAuthSessionFromRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    expiresAt: row.expires_at?.toISOString?.() ?? row.expires_at,
    lastSeenAt: row.last_seen_at?.toISOString?.() ?? row.last_seen_at,
  };
}

function hydrateApiKeyFromRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    tokenHash: row.token_hash,
    tokenPrefix: row.token_prefix,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    lastUsedAt: row.last_used_at?.toISOString?.() ?? row.last_used_at,
    revokedAt: row.revoked_at?.toISOString?.() ?? row.revoked_at,
  };
}

function matchesScope(scan, { requesterScope = null, ownerId = null } = {}) {
  if (!scan) {
    return false;
  }
  if (ownerId && scan.ownerId !== ownerId) {
    return false;
  }
  if (requesterScope && scan.requesterScope !== requesterScope) {
    return false;
  }
  return true;
}

const MAX_MONITORING_TARGETS = 500;

export function createInMemoryScanRepository({ maxEntries = 200 } = {}) {
  const scans = new Map();
  const order = [];
  const events = new Map();
  const monitoringTargets = new Map();
  const monitoringOrder = [];
  const users = new Map();
  const usersByEmail = new Map();
  const authSessions = new Map();
  const authSessionsByTokenHash = new Map();
  const apiKeys = new Map();
  const apiKeysByTokenHash = new Map();

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

  const touchMonitoringOrder = (id) => {
    const index = monitoringOrder.indexOf(id);
    if (index >= 0) {
      monitoringOrder.splice(index, 1);
    }
    monitoringOrder.unshift(id);
  };

  return {
    kind: "memory",
    async initialize() {
      return true;
    },
    async ping() {
      return true;
    },
    async createUser({ email, displayName = null, passwordHash }) {
      const normalizedEmail = email.trim().toLowerCase();
      if (usersByEmail.has(normalizedEmail)) {
        return null;
      }
      const user = buildUserRecord({
        email: normalizedEmail,
        displayName,
        passwordHash,
      });
      users.set(user.id, user);
      usersByEmail.set(user.email, user.id);
      return { ...user };
    },
    async getUserByEmail(email) {
      const normalizedEmail = email.trim().toLowerCase();
      const userId = usersByEmail.get(normalizedEmail);
      if (!userId) {
        return null;
      }
      const user = users.get(userId);
      return user ? { ...user } : null;
    },
    async getUserById(id) {
      const user = users.get(id);
      return user ? { ...user } : null;
    },
    async createAuthSession({ userId, tokenHash, expiresAt }) {
      const session = buildAuthSessionRecord({
        userId,
        tokenHash,
        expiresAt,
      });
      authSessions.set(session.id, session);
      authSessionsByTokenHash.set(session.tokenHash, session.id);
      return { ...session };
    },
    async getAuthSessionByTokenHash(tokenHash) {
      const sessionId = authSessionsByTokenHash.get(tokenHash);
      if (!sessionId) {
        return null;
      }
      const session = authSessions.get(sessionId);
      return session ? { ...session } : null;
    },
    async touchAuthSession(id) {
      const session = authSessions.get(id);
      if (!session) {
        return null;
      }
      session.lastSeenAt = new Date().toISOString();
      return { ...session };
    },
    async deleteAuthSession(id) {
      const session = authSessions.get(id);
      if (!session) {
        return false;
      }
      authSessions.delete(id);
      authSessionsByTokenHash.delete(session.tokenHash);
      return true;
    },
    async createApiKey({ userId, name, tokenHash, tokenPrefix }) {
      const apiKey = buildApiKeyRecord({
        userId,
        name,
        tokenHash,
        tokenPrefix,
      });
      apiKeys.set(apiKey.id, apiKey);
      apiKeysByTokenHash.set(apiKey.tokenHash, apiKey.id);
      return { ...apiKey };
    },
    async listApiKeysByUser(userId) {
      return [...apiKeys.values()]
        .filter((apiKey) => apiKey.userId === userId && !apiKey.revokedAt)
        .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
        .map((apiKey) => ({ ...apiKey }));
    },
    async getApiKeyByTokenHash(tokenHash) {
      const apiKeyId = apiKeysByTokenHash.get(tokenHash);
      if (!apiKeyId) {
        return null;
      }
      const apiKey = apiKeys.get(apiKeyId);
      return apiKey && !apiKey.revokedAt ? { ...apiKey } : null;
    },
    async touchApiKey(id) {
      const apiKey = apiKeys.get(id);
      if (!apiKey || apiKey.revokedAt) {
        return null;
      }
      apiKey.lastUsedAt = new Date().toISOString();
      return { ...apiKey };
    },
    async revokeApiKey(id, { userId }) {
      const apiKey = apiKeys.get(id);
      if (!apiKey || apiKey.userId !== userId || apiKey.revokedAt) {
        return false;
      }
      apiKey.revokedAt = new Date().toISOString();
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
      events.set(scan.id, [
        buildScanEvent({
          scanId: scan.id,
          eventType: "queued",
          status: "queued",
          occurredAt: scan.requestedAt,
          metadata: {
            url: scan.url,
            mode: scan.mode,
          },
        }),
      ]);
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
      const scanEvents = events.get(id) ?? [];
      scanEvents.unshift(
        buildScanEvent({
          scanId: id,
          eventType: "started",
          status: "running",
          occurredAt: scan.startedAt,
        }),
      );
      events.set(id, scanEvents);
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
      const scanEvents = events.get(id) ?? [];
      scanEvents.unshift(
        buildScanEvent({
          scanId: id,
          eventType: "completed",
          status: "completed",
          occurredAt: scan.completedAt,
          metadata: {
            score: result?.score ?? null,
            grade: result?.grade ?? null,
            limited: result?.assessmentLimitation?.limited ?? false,
            limitedKind: result?.assessmentLimitation?.kind ?? null,
          },
        }),
      );
      events.set(id, scanEvents);
      touchOrder(id);
      for (const target of monitoringTargets.values()) {
        if (target.ownerId !== scan.ownerId) {
          continue;
        }
        if (target.url !== scan.url) {
          continue;
        }
        target.url = result?.finalUrl || scan.url;
        target.label = result?.host || target.label;
        target.lastScannedAt = result?.scannedAt || scan.completedAt;
        touchMonitoringOrder(target.id);
      }
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
      const scanEvents = events.get(id) ?? [];
      scanEvents.unshift(
        buildScanEvent({
          scanId: id,
          eventType: "failed",
          status: "failed",
          occurredAt: scan.completedAt,
          failureClass,
          message,
        }),
      );
      events.set(id, scanEvents);
      touchOrder(id);
      return enrichScan(scan);
    },
    async getScan(id, scope = {}) {
      const scan = scans.get(id);
      return matchesScope(scan, scope) ? enrichScan(scan) : null;
    },
    async getScanById(id) {
      const scan = scans.get(id);
      return scan ? enrichScan(scan) : null;
    },
    async getRecentSuccessfulScan({ url, maxAgeMs = 10 * 60 * 1000 } = {}) {
      const cutoff = Date.now() - maxAgeMs;
      for (const id of order) {
        const scan = scans.get(id);
        if (!scan) continue;
        if (scan.url !== url) continue;
        if (scan.status !== "completed") continue;
        if (!scan.result) continue;
        if (scan.result.assessmentLimitation?.limited) continue;
        const completedAt = scan.completedAt ? new Date(scan.completedAt).getTime() : 0;
        if (completedAt < cutoff) break; // order is newest-first; older entries won't qualify
        return enrichScan(scan);
      }
      return null;
    },
    async listScans({ limit = 20, requesterScope = null, ownerId = null, url = null } = {}) {
      const scopedOrder = ownerId
        ? order.filter((id) => scans.get(id)?.ownerId === ownerId)
        : requesterScope
          ? order.filter((id) => scans.get(id)?.requesterScope === requesterScope)
          : order;

      return scopedOrder
        .filter((id) => !url || scans.get(id)?.url === url)
        .slice(0, Math.max(1, limit))
        .map((id) => enrichScan(scans.get(id))?.summary)
        .filter(Boolean);
    },
    async listPersistedRecords({ limit = 20, requesterScope = null, ownerId = null, url = null } = {}) {
      const scopedOrder = ownerId
        ? order.filter((id) => scans.get(id)?.ownerId === ownerId)
        : requesterScope
          ? order.filter((id) => scans.get(id)?.requesterScope === requesterScope)
          : order;

      return scopedOrder
        .filter((id) => !url || scans.get(id)?.url === url)
        .slice(0, Math.max(1, limit))
        .map((id) => scans.get(id))
        .filter(Boolean)
        .map((scan) => buildPersistedScanRecord(scan));
    },
    async listScanEvents(id, scope = {}) {
      const scan = scans.get(id);
      if (!matchesScope(scan, scope)) {
        return [];
      }
      return [...(events.get(id) ?? [])];
    },
    async upsertMonitoringTarget({ url, label, cadence, requesterScope, ownerId = null, lastScannedAt = null }) {
      const existing = [...monitoringTargets.values()].find((target) =>
        target.url === url && target.ownerId === ownerId && target.requesterScope === requesterScope,
      );

      if (existing) {
        existing.label = label;
        existing.cadence = cadence;
        existing.lastScannedAt = lastScannedAt ?? existing.lastScannedAt;
        touchMonitoringOrder(existing.id);
        return { ...existing };
      }

      const target = buildMonitoringTargetRecord({
        ownerId,
        requesterScope,
        url,
        label,
        cadence,
        lastScannedAt,
      });
      if (monitoringTargets.size >= MAX_MONITORING_TARGETS) {
        const oldestKey = monitoringOrder[monitoringOrder.length - 1];
        if (oldestKey) {
          monitoringTargets.delete(oldestKey);
          monitoringOrder.splice(monitoringOrder.length - 1, 1);
        }
      }
      monitoringTargets.set(target.id, target);
      touchMonitoringOrder(target.id);
      return { ...target };
    },
    async listMonitoringTargets({ requesterScope = null, ownerId = null, limit = 50 } = {}) {
      const scopedOrder = ownerId
        ? monitoringOrder.filter((id) => monitoringTargets.get(id)?.ownerId === ownerId)
        : requesterScope
          ? monitoringOrder.filter((id) => monitoringTargets.get(id)?.requesterScope === requesterScope)
          : monitoringOrder;

      return scopedOrder
        .slice(0, Math.max(1, limit))
        .map((id) => monitoringTargets.get(id))
        .filter(Boolean)
        .map((target) => ({ ...target }));
    },
    async getMonitoringTarget(id, { requesterScope = null, ownerId = null } = {}) {
      const target = monitoringTargets.get(id);
      if (!target) {
        return null;
      }
      if (ownerId && target.ownerId !== ownerId) {
        return null;
      }
      if (!ownerId && requesterScope && target.requesterScope !== requesterScope) {
        return null;
      }
      return { ...target };
    },
    async deleteMonitoringTarget(id, { requesterScope = null, ownerId = null } = {}) {
      const target = monitoringTargets.get(id);
      if (!target) {
        return false;
      }
      if (ownerId && target.ownerId !== ownerId) {
        return false;
      }
      if (!ownerId && requesterScope && target.requesterScope !== requesterScope) {
        return false;
      }
      monitoringTargets.delete(id);
      const index = monitoringOrder.indexOf(id);
      if (index >= 0) {
        monitoringOrder.splice(index, 1);
      }
      return true;
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
    ssl: buildPostgresSslConfig(),
  });

  const table = `${schema}.scans`;
  const eventsTable = `${schema}.scan_events`;
  const targetsTable = `${schema}.monitoring_targets`;
  const usersTable = `${schema}.users`;
  const sessionsTable = `${schema}.auth_sessions`;
  const apiKeysTable = `${schema}.api_keys`;
  const schemaStatements = buildScanRepositorySchemaStatements(schema);

  const repository = {
    kind: "postgres",
    async initialize() {
      for (const statement of schemaStatements) {
        await pool.query(statement);
      }
      log("info", "scan_repository_initialized", {
        backend: "postgres",
        schema,
        table: "scans",
      });
      return true;
    },
    async ping() {
      await pool.query("SELECT 1");
      await pool.query(`select 1 from ${table} limit 1`);
      return true;
    },
    async createUser({ email, displayName = null, passwordHash }) {
      const user = buildUserRecord({
        email: email.trim().toLowerCase(),
        displayName,
        passwordHash,
      });
      const { rows } = await pool.query(
        `insert into ${usersTable}
          (id, email, display_name, password_hash, created_at, updated_at)
         values
          ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz)
         on conflict (email) do nothing
         returning *`,
        [
          user.id,
          user.email,
          user.displayName,
          user.passwordHash,
          user.createdAt,
          user.updatedAt,
        ],
      );
      return hydrateUserFromRow(rows[0]);
    },
    async getUserByEmail(email) {
      const normalizedEmail = email.trim().toLowerCase();
      const { rows } = await pool.query(
        `select * from ${usersTable} where email = $1 limit 1`,
        [normalizedEmail],
      );
      return hydrateUserFromRow(rows[0]);
    },
    async getUserById(id) {
      const { rows } = await pool.query(
        `select * from ${usersTable} where id = $1 limit 1`,
        [id],
      );
      return hydrateUserFromRow(rows[0]);
    },
    async createAuthSession({ userId, tokenHash, expiresAt }) {
      const session = buildAuthSessionRecord({
        userId,
        tokenHash,
        expiresAt,
      });
      const { rows } = await pool.query(
        `insert into ${sessionsTable}
          (id, user_id, token_hash, created_at, expires_at, last_seen_at)
         values
          ($1, $2, $3, $4::timestamptz, $5::timestamptz, $6::timestamptz)
         returning *`,
        [
          session.id,
          session.userId,
          session.tokenHash,
          session.createdAt,
          session.expiresAt,
          session.lastSeenAt,
        ],
      );
      return hydrateAuthSessionFromRow(rows[0]);
    },
    async getAuthSessionByTokenHash(tokenHash) {
      const { rows } = await pool.query(
        `select * from ${sessionsTable} where token_hash = $1 limit 1`,
        [tokenHash],
      );
      return hydrateAuthSessionFromRow(rows[0]);
    },
    async touchAuthSession(id) {
      const lastSeenAt = new Date().toISOString();
      const { rows } = await pool.query(
        `update ${sessionsTable}
         set last_seen_at = $2::timestamptz
         where id = $1
         returning *`,
        [id, lastSeenAt],
      );
      return hydrateAuthSessionFromRow(rows[0]);
    },
    async deleteAuthSession(id) {
      const result = await pool.query(
        `delete from ${sessionsTable} where id = $1`,
        [id],
      );
      return result.rowCount > 0;
    },
    async createApiKey({ userId, name, tokenHash, tokenPrefix }) {
      const apiKey = buildApiKeyRecord({
        userId,
        name,
        tokenHash,
        tokenPrefix,
      });
      const { rows } = await pool.query(
        `insert into ${apiKeysTable}
          (id, user_id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at)
         values
          ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::timestamptz)
         returning *`,
        [
          apiKey.id,
          apiKey.userId,
          apiKey.name,
          apiKey.tokenHash,
          apiKey.tokenPrefix,
          apiKey.createdAt,
          apiKey.lastUsedAt,
          apiKey.revokedAt,
        ],
      );
      return hydrateApiKeyFromRow(rows[0]);
    },
    async listApiKeysByUser(userId) {
      const { rows } = await pool.query(
        `select * from ${apiKeysTable}
         where user_id = $1 and revoked_at is null
         order by created_at desc`,
        [userId],
      );
      return rows.map(hydrateApiKeyFromRow).filter(Boolean);
    },
    async getApiKeyByTokenHash(tokenHash) {
      const { rows } = await pool.query(
        `select * from ${apiKeysTable}
         where token_hash = $1 and revoked_at is null
         limit 1`,
        [tokenHash],
      );
      return hydrateApiKeyFromRow(rows[0]);
    },
    async touchApiKey(id) {
      const lastUsedAt = new Date().toISOString();
      const { rows } = await pool.query(
        `update ${apiKeysTable}
         set last_used_at = $2::timestamptz
         where id = $1 and revoked_at is null
         returning *`,
        [id, lastUsedAt],
      );
      return hydrateApiKeyFromRow(rows[0]);
    },
    async revokeApiKey(id, { userId }) {
      const revokedAt = new Date().toISOString();
      const result = await pool.query(
        `update ${apiKeysTable}
         set revoked_at = $3::timestamptz
         where id = $1 and user_id = $2 and revoked_at is null`,
        [id, userId, revokedAt],
      );
      return result.rowCount > 0;
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
      const queuedEvent = buildScanEvent({
        scanId: record.id,
        eventType: "queued",
        status: "queued",
        occurredAt: record.requestedAt,
        metadata: {
          url: record.url,
          mode: record.mode,
        },
      });
      await pool.query(
        `insert into ${eventsTable}
          (id, scan_id, event_type, occurred_at, status, failure_class, message, metadata)
         values
          ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8::jsonb)`,
        [
          queuedEvent.id,
          queuedEvent.scanId,
          queuedEvent.eventType,
          queuedEvent.occurredAt,
          queuedEvent.status,
          queuedEvent.failureClass,
          queuedEvent.message,
          JSON.stringify(queuedEvent.metadata),
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
      const event = buildScanEvent({
        scanId: id,
        eventType: "started",
        status: "running",
        occurredAt: startedAt,
      });
      await pool.query(
        `insert into ${eventsTable}
          (id, scan_id, event_type, occurred_at, status, failure_class, message, metadata)
         values
          ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8::jsonb)`,
        [event.id, event.scanId, event.eventType, event.occurredAt, event.status, null, null, JSON.stringify({})],
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
      const event = buildScanEvent({
        scanId: id,
        eventType: "completed",
        status: "completed",
        occurredAt: completedAt,
        metadata: {
          score: result?.score ?? null,
          grade: result?.grade ?? null,
          limited: result?.assessmentLimitation?.limited ?? false,
          limitedKind: result?.assessmentLimitation?.kind ?? null,
        },
      });
      await pool.query(
        `insert into ${eventsTable}
          (id, scan_id, event_type, occurred_at, status, failure_class, message, metadata)
         values
          ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8::jsonb)`,
        [event.id, event.scanId, event.eventType, event.occurredAt, event.status, null, null, JSON.stringify(event.metadata)],
      );
      const finalUrl = result?.finalUrl || null;
      const finalHost = result?.host || null;
      const scannedAt = result?.scannedAt || completedAt;
      if (finalUrl || finalHost) {
        const matchUrls = [...new Set([rows[0]?.url, result?.normalizedUrl, finalUrl].filter(Boolean))];
        const filters = [];
        const params = [finalUrl || rows[0]?.url, finalHost, scannedAt];
        if (rows[0]?.owner_id) {
          params.push(rows[0].owner_id);
          filters.push(`owner_id = $${params.length}`);
        } else {
          params.push(rows[0]?.requester_scope);
          filters.push(`requester_scope = $${params.length}`);
        }
        if (matchUrls.length) {
          const placeholders = matchUrls.map((url) => {
            params.push(url);
            return `$${params.length}`;
          });
          filters.push(`url in (${placeholders.join(", ")})`);
        }
        if (filters.length >= 2) {
          await pool.query(
            `update ${targetsTable}
             set url = $1,
                 label = coalesce($2, label),
                 last_scanned_at = $3::timestamptz
             where ${filters.join(" and ")}`,
            params,
          );
        }
      }
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
      const event = buildScanEvent({
        scanId: id,
        eventType: "failed",
        status: "failed",
        occurredAt: completedAt,
        failureClass,
        message,
      });
      await pool.query(
        `insert into ${eventsTable}
          (id, scan_id, event_type, occurred_at, status, failure_class, message, metadata)
         values
          ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8::jsonb)`,
        [event.id, event.scanId, event.eventType, event.occurredAt, event.status, event.failureClass, event.message, JSON.stringify({})],
      );
      return hydrateScanFromRow(rows[0]);
    },
    async getScan(id, { requesterScope = null, ownerId = null } = {}) {
      const filters = ["id = $1"];
      const params = [id];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const { rows } = await pool.query(`select * from ${table} where ${filters.join(" and ")} limit 1`, params);
      return hydrateScanFromRow(rows[0]);
    },
    async getScanById(id) {
      const { rows } = await pool.query(`select * from ${table} where id = $1 limit 1`, [id]);
      return hydrateScanFromRow(rows[0]);
    },
    async getRecentSuccessfulScan({ url, maxAgeMs = 10 * 60 * 1000 } = {}) {
      const cutoffAt = new Date(Date.now() - maxAgeMs).toISOString();
      const { rows } = await pool.query(
        `select * from ${table}
         where url = $1
           and status = 'completed'
           and result is not null
           and (summary->>'limited')::boolean is not true
           and completed_at >= $2::timestamptz
         order by completed_at desc
         limit 1`,
        [url, cutoffAt],
      );
      return hydrateScanFromRow(rows[0]);
    },
    async listScans({ limit = 20, requesterScope = null, ownerId = null, url = null } = {}) {
      const filters = [];
      const params = [];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      if (url) {
        params.push(url);
        filters.push(`url = $${params.length}`);
      }
      params.push(Math.max(1, limit));
      const where = filters.length ? `where ${filters.join(" and ")}` : "";
      const { rows } = await pool.query(
        `select * from ${table} ${where} order by requested_at desc limit $${params.length}`,
        params,
      );
      return rows.map((row) => hydrateScanFromRow(row)?.summary).filter(Boolean);
    },
    async listPersistedRecords({ limit = 20, requesterScope = null, ownerId = null, url = null } = {}) {
      const filters = [];
      const params = [];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      if (url) {
        params.push(url);
        filters.push(`url = $${params.length}`);
      }
      params.push(Math.max(1, limit));
      const where = filters.length ? `where ${filters.join(" and ")}` : "";
      const { rows } = await pool.query(
        `select * from ${table} ${where} order by requested_at desc limit $${params.length}`,
        params,
      );
      return rows.map((row) => buildPersistedScanRecord(hydrateScanFromRow(row)));
    },
    async listScanEvents(id, { requesterScope = null, ownerId = null } = {}) {
      const filters = [`s.id = $1`];
      const params = [id];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`s.owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`s.requester_scope = $${params.length}`);
      }
      const { rows } = await pool.query(
        `select e.*
         from ${eventsTable} e
         join ${table} s on s.id = e.scan_id
         where ${filters.join(" and ")}
         order by e.occurred_at desc`,
        params,
      );
      return rows.map(hydrateScanEventFromRow).filter(Boolean);
    },
    async upsertMonitoringTarget({ url, label, cadence, requesterScope, ownerId = null, lastScannedAt = null }) {
      const existingFilters = [];
      const existingParams = [];
      if (ownerId) {
        existingParams.push(ownerId);
        existingFilters.push(`owner_id = $${existingParams.length}`);
      } else {
        existingParams.push(requesterScope);
        existingFilters.push(`requester_scope = $${existingParams.length}`);
      }
      existingParams.push(url);
      existingFilters.push(`url = $${existingParams.length}`);
      const existing = await pool.query(
        `select * from ${targetsTable} where ${existingFilters.join(" and ")} limit 1`,
        existingParams,
      );

      if (existing.rows[0]) {
        const { rows } = await pool.query(
          `update ${targetsTable}
           set label = $2,
               cadence = $3,
               last_scanned_at = coalesce($4::timestamptz, last_scanned_at)
           where id = $1
           returning *`,
          [existing.rows[0].id, label, cadence, lastScannedAt],
        );
        return hydrateMonitoringTargetFromRow(rows[0]);
      }

      const target = buildMonitoringTargetRecord({
        ownerId,
        requesterScope,
        url,
        label,
        cadence,
        lastScannedAt,
      });
      const { rows } = await pool.query(
        `insert into ${targetsTable}
          (id, owner_id, requester_scope, url, label, cadence, added_at, last_scanned_at)
         values
          ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz)
         returning *`,
        [
          target.id,
          target.ownerId,
          target.requesterScope,
          target.url,
          target.label,
          target.cadence,
          target.addedAt,
          target.lastScannedAt,
        ],
      );
      return hydrateMonitoringTargetFromRow(rows[0]);
    },
    async listMonitoringTargets({ requesterScope = null, ownerId = null, limit = 50 } = {}) {
      const filters = [];
      const params = [];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      params.push(Math.max(1, limit));
      const where = filters.length ? `where ${filters.join(" and ")}` : "";
      const { rows } = await pool.query(
        `select * from ${targetsTable} ${where} order by added_at desc limit $${params.length}`,
        params,
      );
      return rows.map(hydrateMonitoringTargetFromRow).filter(Boolean);
    },
    async getMonitoringTarget(id, { requesterScope = null, ownerId = null } = {}) {
      const filters = ["id = $1"];
      const params = [id];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const { rows } = await pool.query(
        `select * from ${targetsTable} where ${filters.join(" and ")} limit 1`,
        params,
      );
      return hydrateMonitoringTargetFromRow(rows[0]);
    },
    async deleteMonitoringTarget(id, { requesterScope = null, ownerId = null } = {}) {
      const filters = ["id = $1"];
      const params = [id];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const result = await pool.query(
        `delete from ${targetsTable} where ${filters.join(" and ")}`,
        params,
      );
      return result.rowCount > 0;
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
