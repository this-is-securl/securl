import crypto from "node:crypto";
import { Pool } from "pg";
import { hashClientIp } from "./privacy.mjs";

export function buildScanRepositorySchemaStatements(schema = "public") {
  const qualifiedTable = `${schema}.scans`;
  const qualifiedEventsTable = `${schema}.scan_events`;
  const qualifiedTargetsTable = `${schema}.monitoring_targets`;
  const qualifiedUsersTable = `${schema}.users`;
  const qualifiedSessionsTable = `${schema}.auth_sessions`;
  const qualifiedApiKeysTable = `${schema}.api_keys`;
  const qualifiedPushDevicesTable = `${schema}.push_devices`;
  const qualifiedNotificationOutboxTable = `${schema}.notification_outbox`;
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
    `create table if not exists ${qualifiedPushDevicesTable} (
      id uuid primary key,
      owner_id text null,
      requester_scope text not null,
      platform text not null,
      token text not null,
      token_hash text not null,
      app_id text null,
      environment text not null,
      created_at timestamptz not null,
      updated_at timestamptz not null,
      last_seen_at timestamptz not null,
      last_push_attempted_at timestamptz null,
      last_push_sent_at timestamptz null,
      last_push_status text null,
      last_push_error text null,
      disabled_at timestamptz null
    )`,
    `alter table if exists ${qualifiedPushDevicesTable} add column if not exists last_push_attempted_at timestamptz null`,
    `alter table if exists ${qualifiedPushDevicesTable} add column if not exists last_push_sent_at timestamptz null`,
    `alter table if exists ${qualifiedPushDevicesTable} add column if not exists last_push_status text null`,
    `alter table if exists ${qualifiedPushDevicesTable} add column if not exists last_push_error text null`,
    `create table if not exists ${qualifiedNotificationOutboxTable} (
      id uuid primary key,
      dedupe_key text not null unique,
      device_id uuid not null references ${qualifiedPushDevicesTable}(id) on delete cascade,
      owner_id text null,
      requester_scope text not null,
      channel text not null,
      reference_id text not null,
      payload jsonb not null,
      status text not null,
      attempts integer not null default 0,
      available_at timestamptz not null,
      leased_at timestamptz null,
      lease_owner text null,
      last_error text null,
      created_at timestamptz not null,
      updated_at timestamptz not null,
      completed_at timestamptz null
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
      job_attempts integer not null default 0,
      lease_owner text null,
      lease_expires_at timestamptz null,
      summary jsonb not null,
      result jsonb null
    )`,
    `alter table if exists ${qualifiedTable} add column if not exists job_attempts integer not null default 0`,
    `alter table if exists ${qualifiedTable} add column if not exists lease_owner text null`,
    `alter table if exists ${qualifiedTable} add column if not exists lease_expires_at timestamptz null`,
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
      kind text not null default 'posture',
      mode text null,
      app_id text null,
      cert_state jsonb null,
      added_at timestamptz not null,
      last_scanned_at timestamptz null,
      last_checked_at timestamptz null
    )`,
    `alter table if exists ${qualifiedTargetsTable} add column if not exists kind text not null default 'posture'`,
    `alter table if exists ${qualifiedTargetsTable} add column if not exists mode text null`,
    `alter table if exists ${qualifiedTargetsTable} add column if not exists app_id text null`,
    `alter table if exists ${qualifiedTargetsTable} add column if not exists cert_state jsonb null`,
    `alter table if exists ${qualifiedTargetsTable} add column if not exists last_checked_at timestamptz null`,
    `create index if not exists scans_requested_at_idx on ${qualifiedTable} (requested_at desc)`,
    `create index if not exists scans_owner_requested_at_idx on ${qualifiedTable} (owner_id, requested_at desc)`,
    `create index if not exists scans_requester_requested_at_idx on ${qualifiedTable} (requester_scope, requested_at desc)`,
    `create index if not exists scans_claimable_jobs_idx on ${qualifiedTable} (requested_at asc, lease_expires_at) where status = 'queued'`,
    `create index if not exists scan_events_scan_occurred_idx on ${qualifiedEventsTable} (scan_id, occurred_at desc)`,
    `create index if not exists monitoring_targets_owner_added_idx on ${qualifiedTargetsTable} (owner_id, added_at desc)`,
    `create index if not exists monitoring_targets_requester_added_idx on ${qualifiedTargetsTable} (requester_scope, added_at desc)`,
    `drop index if exists ${schema}.monitoring_targets_owner_url_uidx`,
    `create unique index if not exists monitoring_targets_owner_url_kind_uidx on ${qualifiedTargetsTable} (coalesce(owner_id, ''), requester_scope, url, kind, coalesce(app_id, ''))`,
    `create index if not exists auth_sessions_user_idx on ${qualifiedSessionsTable} (user_id, created_at desc)`,
    `create index if not exists auth_sessions_expires_idx on ${qualifiedSessionsTable} (expires_at)`,
    `create index if not exists api_keys_user_created_idx on ${qualifiedApiKeysTable} (user_id, created_at desc)`,
    `create index if not exists api_keys_active_token_hash_idx on ${qualifiedApiKeysTable} (token_hash) where revoked_at is null`,
    `create index if not exists push_devices_owner_updated_idx on ${qualifiedPushDevicesTable} (owner_id, updated_at desc) where disabled_at is null`,
    `create index if not exists push_devices_requester_updated_idx on ${qualifiedPushDevicesTable} (requester_scope, updated_at desc) where disabled_at is null`,
    `create unique index if not exists push_devices_scope_token_uidx on ${qualifiedPushDevicesTable} (coalesce(owner_id, ''), requester_scope, token_hash)`,
    `create index if not exists notification_outbox_pending_idx on ${qualifiedNotificationOutboxTable} (status, available_at) where status in ('queued', 'processing')`,
    `create index if not exists notification_outbox_device_created_idx on ${qualifiedNotificationOutboxTable} (device_id, created_at desc)`,
    `create index if not exists notification_outbox_completed_idx on ${qualifiedNotificationOutboxTable} (completed_at) where completed_at is not null`,
  ];
}

function buildPostgresSslConfig() {
  if (process.env.PGSSLMODE === "disable") {
    return false;
  }

  // Fail closed: verify the server certificate by default. Operators whose
  // managed Postgres provider presents a self-signed chain can opt out with
  // PGSSL_REJECT_UNAUTHORIZED=false (preferably alongside a pinned CA cert).
  return {
    rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED !== "false",
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
    jobAttempts: scan.jobAttempts ?? 0,
    leaseOwner: scan.leaseOwner ?? null,
    leaseExpiresAt: scan.leaseExpiresAt ?? null,
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
  kind = "posture",
  mode = null,
  appId = null,
  certState = null,
  addedAt = new Date().toISOString(),
  lastScannedAt = null,
  lastCheckedAt = null,
}) {
  return {
    id,
    ownerId,
    requesterScope,
    url,
    label,
    cadence,
    kind,
    mode,
    appId,
    certState,
    addedAt,
    lastScannedAt,
    lastCheckedAt,
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

export function buildPushDeviceRecord({
  id = crypto.randomUUID(),
  ownerId = null,
  requesterScope,
  platform = "ios",
  token,
  tokenHash,
  appId = null,
  environment = "production",
  createdAt = new Date().toISOString(),
  updatedAt = createdAt,
  lastSeenAt = createdAt,
  lastPushAttemptedAt = null,
  lastPushSentAt = null,
  lastPushStatus = null,
  lastPushError = null,
  disabledAt = null,
}) {
  return {
    id,
    ownerId,
    requesterScope,
    platform,
    token,
    tokenHash,
    appId,
    environment,
    createdAt,
    updatedAt,
    lastSeenAt,
    lastPushAttemptedAt,
    lastPushSentAt,
    lastPushStatus,
    lastPushError,
    disabledAt,
  };
}

export function hashPushToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function buildNotificationOutboxRecord({
  id = crypto.randomUUID(),
  dedupeKey,
  device,
  channel,
  referenceId,
  payload,
  status = "queued",
  attempts = 0,
  availableAt = new Date().toISOString(),
  leasedAt = null,
  leaseOwner = null,
  lastError = null,
  createdAt = new Date().toISOString(),
  updatedAt = createdAt,
  completedAt = null,
}) {
  return {
    id,
    dedupeKey,
    deviceId: device.id,
    ownerId: device.ownerId ?? null,
    requesterScope: device.requesterScope,
    channel,
    referenceId,
    payload,
    status,
    attempts,
    availableAt,
    leasedAt,
    leaseOwner,
    lastError,
    createdAt,
    updatedAt,
    completedAt,
  };
}

function hydrateNotificationOutboxFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    dedupeKey: row.dedupe_key,
    deviceId: row.device_id,
    ownerId: row.owner_id,
    requesterScope: row.requester_scope,
    channel: row.channel,
    referenceId: row.reference_id,
    payload: row.payload,
    status: row.status,
    attempts: Number(row.attempts || 0),
    availableAt: row.available_at?.toISOString?.() ?? row.available_at,
    leasedAt: row.leased_at?.toISOString?.() ?? row.leased_at ?? null,
    leaseOwner: row.lease_owner ?? null,
    lastError: row.last_error ?? null,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    completedAt: row.completed_at?.toISOString?.() ?? row.completed_at ?? null,
  };
}

function notificationDedupeKey(deviceId, channel, referenceId) {
  return crypto
    .createHash("sha256")
    .update(`${deviceId}:${channel}:${referenceId}`)
    .digest("hex");
}

function buildApiKeyUsageSummary(scans = []) {
  const counters = {
    queued: 0,
    running: 0,
    completed: 0,
    failed: 0,
  };
  let limitedReads = 0;
  let fullReads = 0;

  const ordered = [...scans].sort((left, right) =>
    new Date(right.requestedAt || 0).getTime() - new Date(left.requestedAt || 0).getTime(),
  );

  for (const scan of ordered) {
    if (scan?.status in counters) {
      counters[scan.status] += 1;
    }
    if (scan?.status === "completed") {
      if (scan.result?.assessmentLimitation?.limited || scan.summary?.limited) {
        limitedReads += 1;
      } else {
        fullReads += 1;
      }
    }
  }

  const latest = ordered[0] ?? null;

  return {
    scansRequested: ordered.length,
    scansCompleted: counters.completed,
    scansFailed: counters.failed,
    scansQueued: counters.queued,
    scansRunning: counters.running,
    fullReads,
    limitedReads,
    latestScanAt: latest?.requestedAt ?? null,
    latestScanId: latest?.id ?? null,
    latestTarget: latest?.url ?? null,
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
    jobAttempts: Number(row.job_attempts || 0),
    leaseOwner: row.lease_owner ?? null,
    leaseExpiresAt: row.lease_expires_at?.toISOString?.() ?? row.lease_expires_at ?? null,
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
    kind: row.kind ?? "posture",
    mode: row.mode ?? null,
    appId: row.app_id ?? null,
    certState: row.cert_state ?? null,
    addedAt: row.added_at?.toISOString?.() ?? row.added_at,
    lastScannedAt: row.last_scanned_at?.toISOString?.() ?? row.last_scanned_at,
    lastCheckedAt: row.last_checked_at?.toISOString?.() ?? row.last_checked_at,
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

function hydratePushDeviceFromRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    ownerId: row.owner_id,
    requesterScope: row.requester_scope,
    platform: row.platform,
    token: row.token,
    tokenHash: row.token_hash,
    appId: row.app_id,
    environment: row.environment,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    lastSeenAt: row.last_seen_at?.toISOString?.() ?? row.last_seen_at,
    lastPushAttemptedAt: row.last_push_attempted_at?.toISOString?.() ?? row.last_push_attempted_at ?? null,
    lastPushSentAt: row.last_push_sent_at?.toISOString?.() ?? row.last_push_sent_at ?? null,
    lastPushStatus: row.last_push_status ?? null,
    lastPushError: row.last_push_error ?? null,
    disabledAt: row.disabled_at?.toISOString?.() ?? row.disabled_at,
  };
}

function publicPushDevice(device) {
  if (!device) {
    return null;
  }
  return {
    id: device.id,
    ownerId: device.ownerId,
    requesterScope: device.requesterScope,
    platform: device.platform,
    tokenPrefix: `${String(device.token || "").slice(0, 8)}...`,
    appId: device.appId,
    environment: device.environment,
    createdAt: device.createdAt,
    updatedAt: device.updatedAt,
    lastSeenAt: device.lastSeenAt,
    lastPushAttemptedAt: device.lastPushAttemptedAt ?? null,
    lastPushSentAt: device.lastPushSentAt ?? null,
    lastPushStatus: device.lastPushStatus ?? null,
    lastPushError: device.lastPushError ?? null,
    disabledAt: device.disabledAt,
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
  const pushDevices = new Map();
  const pushDeviceOrder = [];
  const notificationOutbox = new Map();
  const notificationOutboxByDedupeKey = new Map();

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

  const touchPushDeviceOrder = (id) => {
    const index = pushDeviceOrder.indexOf(id);
    if (index >= 0) {
      pushDeviceOrder.splice(index, 1);
    }
    pushDeviceOrder.unshift(id);
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
    async getApiKeyUsageSummary(id, { userId }) {
      const apiKey = apiKeys.get(id);
      if (!apiKey || apiKey.userId !== userId) {
        return buildApiKeyUsageSummary([]);
      }
      const ownerId = `user:${userId}`;
      const requesterScope = `api-key:${id}`;
      return buildApiKeyUsageSummary(
        [...scans.values()].filter((scan) => scan.ownerId === ownerId && scan.requesterScope === requesterScope),
      );
    },
    async upsertPushDevice({ platform = "ios", token, appId = null, environment = "production", requesterScope, ownerId = null }) {
      const tokenHash = hashPushToken(token);
      const existing = [...pushDevices.values()].find((device) =>
        device.tokenHash === tokenHash && device.ownerId === ownerId && device.requesterScope === requesterScope,
      );
      const now = new Date().toISOString();
      if (existing) {
        existing.platform = platform;
        existing.token = token;
        existing.appId = appId;
        existing.environment = environment;
        existing.updatedAt = now;
        existing.lastSeenAt = now;
        existing.disabledAt = null;
        touchPushDeviceOrder(existing.id);
        return publicPushDevice(existing);
      }
      const device = buildPushDeviceRecord({
        ownerId,
        requesterScope,
        platform,
        token,
        tokenHash,
        appId,
        environment,
      });
      pushDevices.set(device.id, device);
      touchPushDeviceOrder(device.id);
      return publicPushDevice(device);
    },
    async listPushDevices({ requesterScope = null, ownerId = null, appId = null, includeDisabled = false, limit = 50 } = {}) {
      const scoped = pushDeviceOrder
        .map((id) => pushDevices.get(id))
        .filter((device) => {
          if (!device) return false;
          if (!includeDisabled && device.disabledAt) return false;
          if (ownerId && device.ownerId !== ownerId) return false;
          if (!ownerId && requesterScope && device.requesterScope !== requesterScope) return false;
          if (appId && device.appId !== appId) return false;
          return true;
        })
        .slice(0, Math.max(1, limit));
      return scoped.map(publicPushDevice);
    },
    async listPushDeviceSecrets({ requesterScope = null, ownerId = null, appId = null, limit = 50 } = {}) {
      return pushDeviceOrder
        .map((id) => pushDevices.get(id))
        .filter((device) => {
          if (!device || device.disabledAt) return false;
          if (ownerId && device.ownerId !== ownerId) return false;
          if (!ownerId && requesterScope && device.requesterScope !== requesterScope) return false;
          if (appId && device.appId !== appId) return false;
          return true;
        })
        .slice(0, Math.max(1, limit))
        .map((device) => ({ ...device }));
    },
    async getPushDeviceSecret(id, { requesterScope = null, ownerId = null } = {}) {
      const device = pushDevices.get(id);
      if (!device || device.disabledAt) return null;
      if (ownerId && device.ownerId !== ownerId) return null;
      if (!ownerId && requesterScope && device.requesterScope !== requesterScope) return null;
      return { ...device };
    },
    async disablePushDevice(id, { requesterScope = null, ownerId = null } = {}) {
      const device = pushDevices.get(id);
      if (!device) return false;
      if (ownerId && device.ownerId !== ownerId) return false;
      if (!ownerId && requesterScope && device.requesterScope !== requesterScope) return false;
      device.disabledAt = new Date().toISOString();
      touchPushDeviceOrder(id);
      return true;
    },
    async recordPushDeliveryAttempt(id, {
      requesterScope = null,
      ownerId = null,
      attemptedAt = new Date().toISOString(),
      sentAt = null,
      status = null,
      error = null,
    } = {}) {
      const device = pushDevices.get(id);
      if (!device) return null;
      if (ownerId && device.ownerId !== ownerId) return null;
      if (!ownerId && requesterScope && device.requesterScope !== requesterScope) return null;
      device.lastPushAttemptedAt = attemptedAt;
      device.lastPushSentAt = sentAt ?? device.lastPushSentAt ?? null;
      device.lastPushStatus = status;
      device.lastPushError = error;
      touchPushDeviceOrder(id);
      return publicPushDevice(device);
    },
    async enqueueNotificationOutbox({ devices = [], payload, referenceId, channel = "monitoring" } = {}) {
      const entries = [];
      for (const device of devices) {
        const dedupeKey = notificationDedupeKey(device.id, channel, referenceId);
        const existingId = notificationOutboxByDedupeKey.get(dedupeKey);
        if (existingId) {
          entries.push({ ...notificationOutbox.get(existingId) });
          continue;
        }
        const entry = buildNotificationOutboxRecord({
          dedupeKey,
          device,
          channel,
          referenceId,
          payload: structuredClone(payload),
        });
        notificationOutbox.set(entry.id, entry);
        notificationOutboxByDedupeKey.set(dedupeKey, entry.id);
        entries.push({ ...entry });
      }
      return entries;
    },
    async claimNotificationOutbox({ workerId, limit = 20, leaseMs = 60_000, ids = null, now = new Date() } = {}) {
      const nowMs = now.getTime();
      const allowedIds = Array.isArray(ids) ? new Set(ids) : null;
      const entries = [...notificationOutbox.values()]
        .filter((entry) => {
          if (allowedIds && !allowedIds.has(entry.id)) return false;
          const available = new Date(entry.availableAt).getTime() <= nowMs;
          const staleLease = entry.status === "processing"
            && new Date(entry.leasedAt || 0).getTime() <= nowMs - leaseMs;
          return available && (entry.status === "queued" || staleLease);
        })
        .sort((left, right) => String(left.createdAt).localeCompare(String(right.createdAt)))
        .slice(0, Math.max(1, limit));
      for (const entry of entries) {
        entry.status = "processing";
        entry.attempts += 1;
        entry.leasedAt = now.toISOString();
        entry.leaseOwner = workerId;
        entry.updatedAt = now.toISOString();
      }
      return entries.map((entry) => ({ ...entry, payload: structuredClone(entry.payload) }));
    },
    async completeNotificationOutbox(id, {
      status,
      error = null,
      availableAt = null,
      workerId = null,
      now = new Date(),
    } = {}) {
      const entry = notificationOutbox.get(id);
      if (!entry || (workerId && entry.leaseOwner !== workerId)) return null;
      entry.status = status;
      entry.lastError = error;
      entry.updatedAt = now.toISOString();
      entry.availableAt = availableAt || entry.availableAt;
      entry.completedAt = ["sent", "failed", "skipped"].includes(status) ? now.toISOString() : null;
      entry.leasedAt = null;
      entry.leaseOwner = null;
      return { ...entry, payload: structuredClone(entry.payload) };
    },
    async getNotificationOutboxStats() {
      const byStatus = {};
      for (const entry of notificationOutbox.values()) {
        byStatus[entry.status] = (byStatus[entry.status] || 0) + 1;
      }
      return { total: notificationOutbox.size, byStatus };
    },
    async pruneNotificationOutbox({ olderThanMs = 7 * 24 * 60 * 60 * 1000, limit = 500, now = new Date() } = {}) {
      const cutoff = now.getTime() - olderThanMs;
      const stale = [...notificationOutbox.values()]
        .filter((entry) => entry.completedAt && new Date(entry.completedAt).getTime() <= cutoff)
        .slice(0, Math.max(1, limit));
      for (const entry of stale) {
        notificationOutbox.delete(entry.id);
        notificationOutboxByDedupeKey.delete(entry.dedupeKey);
      }
      return stale.length;
    },
    async createScan({ url, mode, requesterScope, clientIp, ownerId = null }) {
      const clientIpHash = hashClientIp(clientIp);
      const scan = {
        id: crypto.randomUUID(),
        ownerId,
        status: "queued",
        url,
        mode,
        requesterScope,
        clientIp: clientIpHash,
        requestedAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        failureClass: null,
        error: null,
        jobAttempts: 0,
        leaseOwner: null,
        leaseExpiresAt: null,
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
    async claimScanJob(id, { workerId, leaseMs = 5 * 60 * 1000, now = new Date() } = {}) {
      const scan = scans.get(id);
      if (!scan || scan.status !== "queued" || !workerId) return null;
      const leaseExpiresAt = scan.leaseExpiresAt ? new Date(scan.leaseExpiresAt).getTime() : 0;
      if (scan.leaseOwner && leaseExpiresAt > now.getTime()) return null;
      scan.jobAttempts = (scan.jobAttempts ?? 0) + 1;
      scan.leaseOwner = workerId;
      scan.leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
      return enrichScan(scan);
    },
    async listClaimableScanJobs({ limit = 20, now = new Date() } = {}) {
      return order
        .map((id) => scans.get(id))
        .filter((scan) => scan?.status === "queued"
          && (!scan.leaseExpiresAt || new Date(scan.leaseExpiresAt).getTime() <= now.getTime()))
        .sort((left, right) => String(left.requestedAt).localeCompare(String(right.requestedAt)))
        .slice(0, Math.max(1, limit))
        .map(enrichScan);
    },
    async releaseScanJob(id, { workerId, now = new Date() } = {}) {
      const scan = scans.get(id);
      if (!scan || scan.status !== "queued" || (workerId && scan.leaseOwner !== workerId)) return null;
      scan.leaseOwner = null;
      scan.leaseExpiresAt = null;
      scan.requestedAt = scan.requestedAt || now.toISOString();
      return enrichScan(scan);
    },
    async markRunning(id, { workerId = null } = {}) {
      const scan = scans.get(id);
      if (!scan || scan.status !== "queued" || (workerId && scan.leaseOwner !== workerId)) {
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
    async markCompleted(id, result, { workerId = null } = {}) {
      const scan = scans.get(id);
      if (!scan || (workerId && (scan.status !== "running" || scan.leaseOwner !== workerId))) {
        return null;
      }
      scan.status = "completed";
      scan.completedAt = new Date().toISOString();
      scan.leaseOwner = null;
      scan.leaseExpiresAt = null;
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
        if ((target.kind ?? "posture") !== "posture") {
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
    async markFailed(id, failureClass, message, { workerId = null } = {}) {
      const scan = scans.get(id);
      if (!scan || (workerId && (scan.status !== "running" || scan.leaseOwner !== workerId))) {
        return null;
      }
      scan.status = "failed";
      scan.completedAt = new Date().toISOString();
      scan.leaseOwner = null;
      scan.leaseExpiresAt = null;
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
    async recoverStaleRunningScans({
      maxAgeMs = 2 * 60 * 1000,
      limit = 20,
      failureClass = "scan_timeout",
      message = "Scan was marked failed because it was still running after the recovery window.",
    } = {}) {
      const cutoff = Date.now() - maxAgeMs;
      const staleIds = order
        .map((id) => scans.get(id))
        .filter((scan) => {
          if (!scan || scan.status !== "running") return false;
          const startedAt = scan.startedAt ? new Date(scan.startedAt).getTime() : 0;
          return !startedAt || startedAt <= cutoff;
        })
        .slice(0, Math.max(1, limit))
        .map((scan) => scan.id);

      for (const id of staleIds) {
        await this.markFailed(id, failureClass, message);
      }

      return staleIds.length;
    },
    async requeueStaleRunningScanJobs({
      maxAgeMs = 2 * 60 * 1000,
      maxAttempts = 3,
      limit = 20,
      failureClass = "scan_timeout",
      message = "Scan exhausted its recovery attempts after a worker stopped responding.",
    } = {}) {
      const cutoff = Date.now() - maxAgeMs;
      const stale = order
        .map((id) => scans.get(id))
        .filter((scan) => scan?.status === "running"
          && (!scan.startedAt || new Date(scan.startedAt).getTime() <= cutoff))
        .slice(0, Math.max(1, limit));
      let requeued = 0;
      let failed = 0;
      for (const scan of stale) {
        if ((scan.jobAttempts ?? 0) >= maxAttempts) {
          await this.markFailed(scan.id, failureClass, message);
          failed += 1;
          continue;
        }
        scan.status = "queued";
        scan.startedAt = null;
        scan.leaseOwner = null;
        scan.leaseExpiresAt = null;
        const scanEvents = events.get(scan.id) ?? [];
        scanEvents.unshift(buildScanEvent({
          scanId: scan.id,
          eventType: "requeued",
          status: "queued",
          message: "Scan was requeued after its previous worker stopped responding.",
          metadata: { previousAttempts: scan.jobAttempts ?? 0 },
        }));
        events.set(scan.id, scanEvents);
        requeued += 1;
      }
      return { requeued, failed };
    },
    async getScan(id, scope = {}) {
      const scan = scans.get(id);
      return matchesScope(scan, scope) ? enrichScan(scan) : null;
    },
    async getScanById(id) {
      const scan = scans.get(id);
      return scan ? enrichScan(scan) : null;
    },
    async getRecentSuccessfulScan({ url, mode = null, maxAgeMs = 10 * 60 * 1000 } = {}) {
      const cutoff = Date.now() - maxAgeMs;
      for (const id of order) {
        const scan = scans.get(id);
        if (!scan) continue;
        if (scan.url !== url) continue;
        if (mode && scan.mode !== mode) continue;
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
    async upsertMonitoringTarget({
      url,
      label,
      cadence,
      requesterScope,
      ownerId = null,
      kind = "posture",
      mode = null,
      appId = null,
      certState = null,
      lastScannedAt = null,
      lastCheckedAt = null,
    }) {
      const existing = [...monitoringTargets.values()].find((target) =>
        target.url === url
          && target.ownerId === ownerId
          && target.requesterScope === requesterScope
          && (target.kind ?? "posture") === kind
          && (target.appId ?? null) === (appId ?? null),
      );

      if (existing) {
        existing.label = label;
        existing.cadence = cadence;
        existing.kind = kind;
        existing.mode = mode;
        existing.appId = appId;
        existing.certState = certState ?? existing.certState ?? null;
        existing.lastScannedAt = lastScannedAt ?? existing.lastScannedAt;
        existing.lastCheckedAt = lastCheckedAt ?? existing.lastCheckedAt ?? null;
        touchMonitoringOrder(existing.id);
        return { ...existing };
      }

      const target = buildMonitoringTargetRecord({
        ownerId,
        requesterScope,
        url,
        label,
        cadence,
        kind,
        mode,
        appId,
        certState,
        lastScannedAt,
        lastCheckedAt,
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
    async updateMonitoringTargetCertState(id, { certState, lastCheckedAt = null, requesterScope = null, ownerId = null } = {}) {
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
      target.certState = certState ?? null;
      target.lastCheckedAt = lastCheckedAt ?? certState?.checkedAt ?? new Date().toISOString();
      touchMonitoringOrder(id);
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
  const pushDevicesTable = `${schema}.push_devices`;
  const notificationOutboxTable = `${schema}.notification_outbox`;
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
    async getApiKeyUsageSummary(id, { userId }) {
      const ownerId = `user:${userId}`;
      const requesterScope = `api-key:${id}`;
      const { rows } = await pool.query(
        `select id, url, status, requested_at, completed_at, summary
         from ${table}
         where owner_id = $1 and requester_scope = $2
         order by requested_at desc`,
        [ownerId, requesterScope],
      );
      return buildApiKeyUsageSummary(rows.map((row) => ({
        id: row.id,
        url: row.url,
        status: row.status,
        requestedAt: row.requested_at?.toISOString?.() ?? row.requested_at,
        completedAt: row.completed_at?.toISOString?.() ?? row.completed_at,
        summary: row.summary ?? null,
      })));
    },
    async upsertPushDevice({ platform = "ios", token, appId = null, environment = "production", requesterScope, ownerId = null }) {
      const tokenHash = hashPushToken(token);
      const now = new Date().toISOString();
      const existingFilters = [];
      const existingParams = [];
      if (ownerId) {
        existingParams.push(ownerId);
        existingFilters.push(`owner_id = $${existingParams.length}`);
      } else {
        existingParams.push(requesterScope);
        existingFilters.push(`requester_scope = $${existingParams.length}`);
      }
      existingParams.push(tokenHash);
      existingFilters.push(`token_hash = $${existingParams.length}`);
      const existing = await pool.query(
        `select * from ${pushDevicesTable} where ${existingFilters.join(" and ")} limit 1`,
        existingParams,
      );
      if (existing.rows[0]) {
        const { rows } = await pool.query(
          `update ${pushDevicesTable}
           set platform = $2,
               token = $3,
               app_id = $4,
               environment = $5,
               updated_at = $6::timestamptz,
               last_seen_at = $6::timestamptz,
               disabled_at = null
           where id = $1
           returning *`,
          [existing.rows[0].id, platform, token, appId, environment, now],
        );
        return publicPushDevice(hydratePushDeviceFromRow(rows[0]));
      }

      const device = buildPushDeviceRecord({
        ownerId,
        requesterScope,
        platform,
        token,
        tokenHash,
        appId,
        environment,
        createdAt: now,
        updatedAt: now,
        lastSeenAt: now,
      });
      const { rows } = await pool.query(
        `insert into ${pushDevicesTable}
          (id, owner_id, requester_scope, platform, token, token_hash, app_id, environment, created_at, updated_at, last_seen_at, disabled_at)
         values
          ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10::timestamptz, $11::timestamptz, $12::timestamptz)
         returning *`,
        [
          device.id,
          device.ownerId,
          device.requesterScope,
          device.platform,
          device.token,
          device.tokenHash,
          device.appId,
          device.environment,
          device.createdAt,
          device.updatedAt,
          device.lastSeenAt,
          device.disabledAt,
        ],
      );
      return publicPushDevice(hydratePushDeviceFromRow(rows[0]));
    },
    async listPushDevices({ requesterScope = null, ownerId = null, appId = null, includeDisabled = false, limit = 50 } = {}) {
      const filters = [];
      const params = [];
      if (!includeDisabled) {
        filters.push("disabled_at is null");
      }
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      if (appId) {
        params.push(appId);
        filters.push(`app_id = $${params.length}`);
      }
      params.push(Math.max(1, limit));
      const where = filters.length ? `where ${filters.join(" and ")}` : "";
      const { rows } = await pool.query(
        `select * from ${pushDevicesTable} ${where} order by updated_at desc limit $${params.length}`,
        params,
      );
      return rows.map(hydratePushDeviceFromRow).filter(Boolean).map(publicPushDevice);
    },
    async listPushDeviceSecrets({ requesterScope = null, ownerId = null, appId = null, limit = 50 } = {}) {
      const filters = ["disabled_at is null"];
      const params = [];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      if (appId) {
        params.push(appId);
        filters.push(`app_id = $${params.length}`);
      }
      params.push(Math.max(1, limit));
      const { rows } = await pool.query(
        `select * from ${pushDevicesTable} where ${filters.join(" and ")} order by updated_at desc limit $${params.length}`,
        params,
      );
      return rows.map(hydratePushDeviceFromRow).filter(Boolean);
    },
    async getPushDeviceSecret(id, { requesterScope = null, ownerId = null } = {}) {
      const filters = ["id = $1", "disabled_at is null"];
      const params = [id];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const { rows } = await pool.query(
        `select * from ${pushDevicesTable} where ${filters.join(" and ")} limit 1`,
        params,
      );
      return hydratePushDeviceFromRow(rows[0]);
    },
    async disablePushDevice(id, { requesterScope = null, ownerId = null } = {}) {
      const filters = ["id = $1"];
      const params = [id, new Date().toISOString()];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const result = await pool.query(
        `update ${pushDevicesTable}
         set disabled_at = $2::timestamptz
         where ${filters.join(" and ")}`,
        params,
      );
      return result.rowCount > 0;
    },
    async recordPushDeliveryAttempt(id, {
      requesterScope = null,
      ownerId = null,
      attemptedAt = new Date().toISOString(),
      sentAt = null,
      status = null,
      error = null,
    } = {}) {
      const filters = ["id = $1"];
      const params = [id, attemptedAt, sentAt, status, error];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const { rows } = await pool.query(
        `update ${pushDevicesTable}
         set last_push_attempted_at = $2::timestamptz,
             last_push_sent_at = coalesce($3::timestamptz, last_push_sent_at),
             last_push_status = $4,
             last_push_error = $5
         where ${filters.join(" and ")}
         returning *`,
        params,
      );
      return publicPushDevice(hydratePushDeviceFromRow(rows[0]));
    },
    async enqueueNotificationOutbox({ devices = [], payload, referenceId, channel = "monitoring" } = {}) {
      const entries = [];
      for (const device of devices) {
        const entry = buildNotificationOutboxRecord({
          dedupeKey: notificationDedupeKey(device.id, channel, referenceId),
          device,
          channel,
          referenceId,
          payload,
        });
        const { rows } = await pool.query(
          `insert into ${notificationOutboxTable}
            (id, dedupe_key, device_id, owner_id, requester_scope, channel, reference_id, payload, status,
             attempts, available_at, leased_at, lease_owner, last_error, created_at, updated_at, completed_at)
           values
            ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11::timestamptz, $12::timestamptz,
             $13, $14, $15::timestamptz, $16::timestamptz, $17::timestamptz)
           on conflict (dedupe_key) do update set dedupe_key = excluded.dedupe_key
           returning *`,
          [
            entry.id,
            entry.dedupeKey,
            entry.deviceId,
            entry.ownerId,
            entry.requesterScope,
            entry.channel,
            entry.referenceId,
            JSON.stringify(entry.payload),
            entry.status,
            entry.attempts,
            entry.availableAt,
            entry.leasedAt,
            entry.leaseOwner,
            entry.lastError,
            entry.createdAt,
            entry.updatedAt,
            entry.completedAt,
          ],
        );
        entries.push(hydrateNotificationOutboxFromRow(rows[0]));
      }
      return entries;
    },
    async claimNotificationOutbox({ workerId, limit = 20, leaseMs = 60_000, ids = null, now = new Date() } = {}) {
      const params = [now.toISOString(), new Date(now.getTime() - leaseMs).toISOString(), workerId];
      const idFilter = Array.isArray(ids) && ids.length
        ? (() => {
            params.push(ids);
            return `and id = any($${params.length}::uuid[])`;
          })()
        : "";
      params.push(Math.max(1, limit));
      const { rows } = await pool.query(
        `with candidates as (
           select id from ${notificationOutboxTable}
           where available_at <= $1::timestamptz
             and (status = 'queued' or (status = 'processing' and leased_at <= $2::timestamptz))
             ${idFilter}
           order by created_at asc
           for update skip locked
           limit $${params.length}
         )
         update ${notificationOutboxTable} as outbox
         set status = 'processing',
             attempts = outbox.attempts + 1,
             leased_at = $1::timestamptz,
             lease_owner = $3,
             updated_at = $1::timestamptz
         from candidates
         where outbox.id = candidates.id
         returning outbox.*`,
        params,
      );
      return rows.map(hydrateNotificationOutboxFromRow).filter(Boolean);
    },
    async completeNotificationOutbox(id, {
      status,
      error = null,
      availableAt = null,
      workerId = null,
      now = new Date(),
    } = {}) {
      const params = [id, status, error, availableAt, now.toISOString()];
      const leaseFilter = workerId
        ? (() => {
            params.push(workerId);
            return `and lease_owner = $${params.length}`;
          })()
        : "";
      const { rows } = await pool.query(
        `update ${notificationOutboxTable}
         set status = $2,
             last_error = $3,
             available_at = coalesce($4::timestamptz, available_at),
             leased_at = null,
             lease_owner = null,
             updated_at = $5::timestamptz,
             completed_at = case when $2 in ('sent', 'failed', 'skipped') then $5::timestamptz else null end
         where id = $1 ${leaseFilter}
         returning *`,
        params,
      );
      return hydrateNotificationOutboxFromRow(rows[0]);
    },
    async getNotificationOutboxStats() {
      const { rows } = await pool.query(
        `select status, count(*)::integer as count from ${notificationOutboxTable} group by status`,
      );
      const byStatus = Object.fromEntries(rows.map((row) => [row.status, Number(row.count)]));
      return {
        total: Object.values(byStatus).reduce((sum, count) => sum + count, 0),
        byStatus,
      };
    },
    async pruneNotificationOutbox({ olderThanMs = 7 * 24 * 60 * 60 * 1000, limit = 500, now = new Date() } = {}) {
      const cutoffAt = new Date(now.getTime() - olderThanMs).toISOString();
      const result = await pool.query(
        `delete from ${notificationOutboxTable}
         where id in (
           select id from ${notificationOutboxTable}
           where completed_at is not null and completed_at <= $1::timestamptz
           order by completed_at asc
           limit $2
         )`,
        [cutoffAt, Math.max(1, limit)],
      );
      return result.rowCount;
    },
    async createScan({ url, mode, requesterScope, clientIp, ownerId = null }) {
      const clientIpHash = hashClientIp(clientIp);
      const scan = {
        id: crypto.randomUUID(),
        ownerId,
        status: "queued",
        url,
        mode,
        requesterScope,
        clientIp: clientIpHash,
        requestedAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        failureClass: null,
        error: null,
        jobAttempts: 0,
        leaseOwner: null,
        leaseExpiresAt: null,
        result: null,
      };
      const record = buildPersistedScanRecord(scan);
      await pool.query(
        `insert into ${table}
          (id, owner_id, status, url, mode, requested_at, started_at, completed_at, requester_scope, client_ip, failure_class, error, job_attempts, lease_owner, lease_expires_at, summary, result)
         values
          ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::timestamptz, $9, $10, $11, $12, $13, $14, $15::timestamptz, $16::jsonb, $17::jsonb)`,
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
          record.jobAttempts,
          record.leaseOwner,
          record.leaseExpiresAt,
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
    async claimScanJob(id, { workerId, leaseMs = 5 * 60 * 1000, now = new Date() } = {}) {
      if (!workerId) return null;
      const leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
      const { rows } = await pool.query(
        `update ${table}
         set job_attempts = job_attempts + 1,
             lease_owner = $2,
             lease_expires_at = $3::timestamptz
         where id = $1
           and status = 'queued'
           and (lease_expires_at is null or lease_expires_at <= $4::timestamptz)
         returning *`,
        [id, workerId, leaseExpiresAt, now.toISOString()],
      );
      return hydrateScanFromRow(rows[0]);
    },
    async listClaimableScanJobs({ limit = 20, now = new Date() } = {}) {
      const { rows } = await pool.query(
        `select * from ${table}
         where status = 'queued'
           and (lease_expires_at is null or lease_expires_at <= $1::timestamptz)
         order by requested_at asc
         limit $2`,
        [now.toISOString(), Math.max(1, limit)],
      );
      return rows.map(hydrateScanFromRow).filter(Boolean);
    },
    async releaseScanJob(id, { workerId = null } = {}) {
      const params = [id];
      const ownerFilter = workerId
        ? (() => {
            params.push(workerId);
            return `and lease_owner = $${params.length}`;
          })()
        : "";
      const { rows } = await pool.query(
        `update ${table}
         set lease_owner = null, lease_expires_at = null
         where id = $1 and status = 'queued' ${ownerFilter}
         returning *`,
        params,
      );
      return hydrateScanFromRow(rows[0]);
    },
    async markRunning(id, { workerId = null } = {}) {
      const startedAt = new Date().toISOString();
      const params = [id, startedAt];
      const ownerFilter = workerId
        ? (() => {
            params.push(workerId);
            return `and lease_owner = $${params.length}`;
          })()
        : "";
      const { rows } = await pool.query(
        `update ${table}
         set status = 'running', started_at = $2::timestamptz
         where id = $1 and status = 'queued' ${ownerFilter}
         returning *`,
        params,
      );
      if (!rows[0]) return null;
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
    async markCompleted(id, result, { workerId = null } = {}) {
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
      const params = [id, completedAt, JSON.stringify(summary), JSON.stringify(result)];
      const ownerFilter = workerId
        ? (() => {
            params.push(workerId);
            return `and status = 'running' and lease_owner = $${params.length}`;
          })()
        : "";
      const { rows } = await pool.query(
        `update ${table}
         set status = 'completed',
             completed_at = $2::timestamptz,
             failure_class = null,
             error = null,
             lease_owner = null,
             lease_expires_at = null,
             summary = $3::jsonb,
             result = $4::jsonb
         where id = $1 ${ownerFilter}
         returning *`,
        params,
      );
      if (!rows[0]) return null;
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
             where kind = 'posture' and ${filters.join(" and ")}`,
            params,
          );
        }
      }
      return hydrateScanFromRow(rows[0]);
    },
    async markFailed(id, failureClass, message, { workerId = null } = {}) {
      const completedAt = new Date().toISOString();
      const params = [id, completedAt, failureClass, message];
      const ownerFilter = workerId
        ? (() => {
            params.push(workerId);
            return `and status = 'running' and lease_owner = $${params.length}`;
          })()
        : "";
      const { rows } = await pool.query(
        `update ${table}
         set status = 'failed',
             completed_at = $2::timestamptz,
             failure_class = $3,
             error = $4,
             lease_owner = null,
             lease_expires_at = null,
             result = null
         where id = $1 ${ownerFilter}
         returning *`,
        params,
      );
      if (!rows[0]) return null;
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
    async recoverStaleRunningScans({
      maxAgeMs = 2 * 60 * 1000,
      limit = 20,
      failureClass = "scan_timeout",
      message = "Scan was marked failed because it was still running after the recovery window.",
    } = {}) {
      const cutoffAt = new Date(Date.now() - maxAgeMs).toISOString();
      const { rows } = await pool.query(
        `select id from ${table}
         where status = 'running'
           and (started_at is null or started_at < $1::timestamptz)
         order by coalesce(started_at, requested_at) asc
         limit $2`,
        [cutoffAt, Math.max(1, limit)],
      );

      for (const row of rows) {
        await this.markFailed(row.id, failureClass, message);
      }

      return rows.length;
    },
    async requeueStaleRunningScanJobs({
      maxAgeMs = 2 * 60 * 1000,
      maxAttempts = 3,
      limit = 20,
      failureClass = "scan_timeout",
      message = "Scan exhausted its recovery attempts after a worker stopped responding.",
    } = {}) {
      const cutoffAt = new Date(Date.now() - maxAgeMs).toISOString();
      const { rows } = await pool.query(
        `select id, job_attempts from ${table}
         where status = 'running'
           and (started_at is null or started_at < $1::timestamptz)
         order by coalesce(started_at, requested_at) asc
         limit $2`,
        [cutoffAt, Math.max(1, limit)],
      );
      let requeued = 0;
      let failed = 0;
      for (const row of rows) {
        if (Number(row.job_attempts || 0) >= maxAttempts) {
          const completedAt = new Date().toISOString();
          const exhausted = await pool.query(
            `update ${table}
             set status = 'failed',
                 completed_at = $3::timestamptz,
                 failure_class = $4,
                 error = $5,
                 lease_owner = null,
                 lease_expires_at = null,
                 result = null
             where id = $1
               and status = 'running'
               and (started_at is null or started_at < $2::timestamptz)
             returning id`,
            [row.id, cutoffAt, completedAt, failureClass, message],
          );
          if (!exhausted.rows[0]) continue;
          const event = buildScanEvent({
            scanId: row.id,
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
          failed += 1;
          continue;
        }
        const updated = await pool.query(
          `update ${table}
           set status = 'queued',
               started_at = null,
               lease_owner = null,
               lease_expires_at = null
           where id = $1
             and status = 'running'
             and (started_at is null or started_at < $2::timestamptz)
           returning id`,
          [row.id, cutoffAt],
        );
        if (!updated.rows[0]) continue;
        const event = buildScanEvent({
          scanId: row.id,
          eventType: "requeued",
          status: "queued",
          message: "Scan was requeued after its previous worker stopped responding.",
          metadata: { previousAttempts: Number(row.job_attempts || 0) },
        });
        await pool.query(
          `insert into ${eventsTable}
            (id, scan_id, event_type, occurred_at, status, failure_class, message, metadata)
           values
            ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8::jsonb)`,
          [event.id, event.scanId, event.eventType, event.occurredAt, event.status, null, event.message, JSON.stringify(event.metadata)],
        );
        requeued += 1;
      }
      return { requeued, failed };
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
    async getRecentSuccessfulScan({ url, mode = null, maxAgeMs = 10 * 60 * 1000 } = {}) {
      const cutoffAt = new Date(Date.now() - maxAgeMs).toISOString();
      const modeFilter = mode ? "and mode = $3" : "";
      const params = mode ? [url, cutoffAt, mode] : [url, cutoffAt];
      const { rows } = await pool.query(
        `select * from ${table}
         where url = $1
           and status = 'completed'
           and result is not null
           and (summary->>'limited')::boolean is not true
           and completed_at >= $2::timestamptz
           ${modeFilter}
         order by completed_at desc
         limit 1`,
        params,
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
    async upsertMonitoringTarget({
      url,
      label,
      cadence,
      requesterScope,
      ownerId = null,
      kind = "posture",
      mode = null,
      appId = null,
      certState = null,
      lastScannedAt = null,
      lastCheckedAt = null,
    }) {
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
      existingParams.push(kind);
      existingFilters.push(`kind = $${existingParams.length}`);
      if (appId) {
        existingParams.push(appId);
        existingFilters.push(`app_id = $${existingParams.length}`);
      } else {
        existingFilters.push("app_id is null");
      }
      const existing = await pool.query(
        `select * from ${targetsTable} where ${existingFilters.join(" and ")} limit 1`,
        existingParams,
      );

      if (existing.rows[0]) {
        const { rows } = await pool.query(
          `update ${targetsTable}
           set label = $2,
               cadence = $3,
               mode = $4,
               app_id = $5,
               cert_state = coalesce($6::jsonb, cert_state),
               last_scanned_at = coalesce($7::timestamptz, last_scanned_at),
               last_checked_at = coalesce($8::timestamptz, last_checked_at)
           where id = $1
           returning *`,
          [
            existing.rows[0].id,
            label,
            cadence,
            mode,
            appId,
            certState ? JSON.stringify(certState) : null,
            lastScannedAt,
            lastCheckedAt,
          ],
        );
        return hydrateMonitoringTargetFromRow(rows[0]);
      }

      const target = buildMonitoringTargetRecord({
        ownerId,
        requesterScope,
        url,
        label,
        cadence,
        kind,
        mode,
        appId,
        certState,
        lastScannedAt,
        lastCheckedAt,
      });
      const { rows } = await pool.query(
        `insert into ${targetsTable}
          (id, owner_id, requester_scope, url, label, cadence, kind, mode, app_id, cert_state, added_at, last_scanned_at, last_checked_at)
         values
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::timestamptz, $12::timestamptz, $13::timestamptz)
         returning *`,
        [
          target.id,
          target.ownerId,
          target.requesterScope,
          target.url,
          target.label,
          target.cadence,
          target.kind,
          target.mode,
          target.appId,
          target.certState ? JSON.stringify(target.certState) : null,
          target.addedAt,
          target.lastScannedAt,
          target.lastCheckedAt,
        ],
      );
      return hydrateMonitoringTargetFromRow(rows[0]);
    },
    async updateMonitoringTargetCertState(id, { certState, lastCheckedAt = null, requesterScope = null, ownerId = null } = {}) {
      const filters = ["id = $1"];
      const params = [
        id,
        certState ? JSON.stringify(certState) : null,
        lastCheckedAt ?? certState?.checkedAt ?? new Date().toISOString(),
      ];
      if (ownerId) {
        params.push(ownerId);
        filters.push(`owner_id = $${params.length}`);
      } else if (requesterScope) {
        params.push(requesterScope);
        filters.push(`requester_scope = $${params.length}`);
      }
      const { rows } = await pool.query(
        `update ${targetsTable}
         set cert_state = $2::jsonb,
             last_checked_at = $3::timestamptz
         where ${filters.join(" and ")}
         returning *`,
        params,
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
