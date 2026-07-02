import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { hashPrivacyValue, targetForPrivacy } from "./privacy.mjs";
import { normalizeClientId, normalizeClientVersion } from "./clientMetadata.mjs";

export function createTelemetryTracker({ storagePath = "" } = {}) {
  const persistence = storagePath ? "file" : "memory";
  const boundedBucketKey = (buckets, key, maxKeys) => {
    if (Object.hasOwn(buckets, key)) return key;
    return Object.keys(buckets).length < maxKeys - 1 ? key : "other";
  };

  const state = {
    startedAt: new Date().toISOString(),
    pageLoads: 0,
    visitorKeys: new Set(),
    visitorDays: {},
    sourceBuckets: {},
    scansRequested: 0,
    scansCompleted: 0,
    scanRequesterKeys: new Set(),
    scanClientKeys: new Set(),
    scanTargetOrigins: new Set(),
    scanSourceBuckets: {},
    scanChannelBuckets: {},
    scanProductBuckets: {},
    scanProductVersionBuckets: {},
    scanTargetBuckets: {},
    scanDays: {},
    recentScans: [],
    fullReads: 0,
    limitedReads: 0,
    quietModeScans: 0,
    timedOutScans: 0,
    scanDurationsMs: [],
    coreDurationsMs: [],
    enrichmentDurationsMs: [],
    limitedReadKinds: {},
    funnelEvents: {},
    funnelEventsBySource: {},
    funnelEventsByMode: {},
    funnelEventsByClient: {},
    funnelEventsByClientVersion: {},
    funnelClientKeysByClient: {},
    funnelClientKeysByClientVersion: {},
    funnelDays: {},
    recentFunnelEvents: [],
    notificationDeliveries: {
      batches: 0,
      attempted: 0,
      attempts: 0,
      sent: 0,
      failed: 0,
      disabled: 0,
      retried: 0,
    },
    notificationDeliverySkipped: {},
    notificationDeliveryChannels: {},
    notificationDeliveryDays: {},
    failureClasses: {},
    recentFailures: [],
    authRejected: 0,
    requesterRateLimited: 0,
    targetRateLimited: 0,
  };

  const serializeState = () => ({
    ...state,
    visitorKeys: [...state.visitorKeys],
    scanRequesterKeys: [...state.scanRequesterKeys],
    scanClientKeys: [...state.scanClientKeys],
    scanTargetOrigins: [...state.scanTargetOrigins],
    visitorDays: Object.fromEntries(
      Object.entries(state.visitorDays).map(([date, bucket]) => [
        date,
        {
          pageLoads: bucket.pageLoads,
          visitorKeys: [...bucket.visitorKeys],
          sourceBuckets: { ...(bucket.sourceBuckets || {}) },
        },
      ]),
    ),
    scanDays: Object.fromEntries(
      Object.entries(state.scanDays).map(([date, bucket]) => [
        date,
        {
          requested: bucket.requested,
          requesterKeys: [...bucket.requesterKeys],
          clientKeys: [...bucket.clientKeys],
          targetOrigins: [...bucket.targetOrigins],
          sourceBuckets: { ...(bucket.sourceBuckets || {}) },
          channelBuckets: { ...(bucket.channelBuckets || {}) },
        },
      ]),
    ),
    funnelClientKeysByClient: serializeSetBuckets(state.funnelClientKeysByClient),
    funnelClientKeysByClientVersion: serializeSetBuckets(state.funnelClientKeysByClientVersion),
    funnelDays: Object.fromEntries(
      Object.entries(state.funnelDays).map(([date, bucket]) => [
        date,
        {
          events: { ...(bucket.events || {}) },
          sources: { ...(bucket.sources || {}) },
          modes: { ...(bucket.modes || {}) },
          clients: { ...(bucket.clients || {}) },
          clientVersions: { ...(bucket.clientVersions || {}) },
          clientKeysByClient: serializeSetBuckets(bucket.clientKeysByClient || {}),
          clientKeysByClientVersion: serializeSetBuckets(bucket.clientKeysByClientVersion || {}),
        },
      ]),
    ),
  });

  const hydrateState = (value) => {
    if (!value || typeof value !== "object") {
      return;
    }

    state.startedAt = typeof value.startedAt === "string" ? value.startedAt : state.startedAt;
    state.pageLoads = Number.isFinite(value.pageLoads) ? value.pageLoads : state.pageLoads;
    state.visitorKeys = new Set(Array.isArray(value.visitorKeys) ? value.visitorKeys : []);
    state.visitorDays = Object.fromEntries(
      Object.entries(value.visitorDays || {}).map(([date, bucket]) => [
        date,
        {
          pageLoads: Number.isFinite(bucket?.pageLoads) ? bucket.pageLoads : 0,
          visitorKeys: new Set(Array.isArray(bucket?.visitorKeys) ? bucket.visitorKeys : []),
          sourceBuckets: { ...(bucket?.sourceBuckets || {}) },
        },
      ]),
    );
    state.sourceBuckets = { ...(value.sourceBuckets || {}) };
    state.scansRequested = Number.isFinite(value.scansRequested) ? value.scansRequested : state.scansRequested;
    state.scansCompleted = Number.isFinite(value.scansCompleted) ? value.scansCompleted : state.scansCompleted;
    state.scanRequesterKeys = new Set(Array.isArray(value.scanRequesterKeys) ? value.scanRequesterKeys : []);
    state.scanClientKeys = new Set(Array.isArray(value.scanClientKeys) ? value.scanClientKeys : []);
    state.scanTargetOrigins = new Set(Array.isArray(value.scanTargetOrigins) ? value.scanTargetOrigins : []);
    state.scanSourceBuckets = { ...(value.scanSourceBuckets || {}) };
    state.scanChannelBuckets = { ...(value.scanChannelBuckets || {}) };
    state.scanProductBuckets = { ...(value.scanProductBuckets || {}) };
    state.scanProductVersionBuckets = { ...(value.scanProductVersionBuckets || {}) };
    state.scanTargetBuckets = { ...(value.scanTargetBuckets || {}) };
    state.scanDays = Object.fromEntries(
      Object.entries(value.scanDays || {}).map(([date, bucket]) => [
        date,
        {
          requested: Number.isFinite(bucket?.requested) ? bucket.requested : 0,
          requesterKeys: new Set(Array.isArray(bucket?.requesterKeys) ? bucket.requesterKeys : []),
          clientKeys: new Set(Array.isArray(bucket?.clientKeys) ? bucket.clientKeys : []),
          targetOrigins: new Set(Array.isArray(bucket?.targetOrigins) ? bucket.targetOrigins : []),
          sourceBuckets: { ...(bucket?.sourceBuckets || {}) },
          channelBuckets: { ...(bucket?.channelBuckets || {}) },
        },
      ]),
    );
    state.recentScans = Array.isArray(value.recentScans)
      ? value.recentScans
        .map(sanitizeRecentScan)
        .filter(Boolean)
        .slice(-40)
      : state.recentScans;
    state.fullReads = Number.isFinite(value.fullReads) ? value.fullReads : state.fullReads;
    state.limitedReads = Number.isFinite(value.limitedReads) ? value.limitedReads : state.limitedReads;
    state.quietModeScans = Number.isFinite(value.quietModeScans) ? value.quietModeScans : state.quietModeScans;
    state.timedOutScans = Number.isFinite(value.timedOutScans) ? value.timedOutScans : state.timedOutScans;
    state.scanDurationsMs = Array.isArray(value.scanDurationsMs) ? value.scanDurationsMs.filter(Number.isFinite).slice(-200) : state.scanDurationsMs;
    state.coreDurationsMs = Array.isArray(value.coreDurationsMs) ? value.coreDurationsMs.filter(Number.isFinite).slice(-200) : state.coreDurationsMs;
    state.enrichmentDurationsMs = Array.isArray(value.enrichmentDurationsMs) ? value.enrichmentDurationsMs.filter(Number.isFinite).slice(-200) : state.enrichmentDurationsMs;
    state.limitedReadKinds = { ...(value.limitedReadKinds || {}) };
    state.funnelEvents = { ...(value.funnelEvents || {}) };
    state.funnelEventsBySource = { ...(value.funnelEventsBySource || {}) };
    state.funnelEventsByMode = { ...(value.funnelEventsByMode || {}) };
    state.funnelEventsByClient = { ...(value.funnelEventsByClient || {}) };
    state.funnelEventsByClientVersion = { ...(value.funnelEventsByClientVersion || {}) };
    state.funnelClientKeysByClient = hydrateSetBuckets(value.funnelClientKeysByClient);
    state.funnelClientKeysByClientVersion = hydrateSetBuckets(value.funnelClientKeysByClientVersion);
    state.funnelDays = Object.fromEntries(
      Object.entries(value.funnelDays || {}).map(([date, bucket]) => [
        date,
        {
          events: { ...(bucket?.events || {}) },
          sources: { ...(bucket?.sources || {}) },
          modes: { ...(bucket?.modes || {}) },
          clients: { ...(bucket?.clients || {}) },
          clientVersions: { ...(bucket?.clientVersions || {}) },
          clientKeysByClient: hydrateSetBuckets(bucket?.clientKeysByClient),
          clientKeysByClientVersion: hydrateSetBuckets(bucket?.clientKeysByClientVersion),
        },
      ]),
    );
    state.recentFunnelEvents = Array.isArray(value.recentFunnelEvents)
      ? value.recentFunnelEvents
        .map(sanitizeFunnelEvent)
        .filter(Boolean)
        .slice(-40)
      : state.recentFunnelEvents;
    state.notificationDeliveries = {
      ...state.notificationDeliveries,
      ...(value.notificationDeliveries || {}),
    };
    state.notificationDeliverySkipped = { ...(value.notificationDeliverySkipped || {}) };
    state.notificationDeliveryChannels = { ...(value.notificationDeliveryChannels || {}) };
    state.notificationDeliveryDays = { ...(value.notificationDeliveryDays || {}) };
    state.failureClasses = { ...(value.failureClasses || {}) };
    state.recentFailures = Array.isArray(value.recentFailures)
      ? value.recentFailures
        .map(sanitizeRecentFailure)
        .filter(Boolean)
        .slice(-20)
      : state.recentFailures;
    state.authRejected = Number.isFinite(value.authRejected) ? value.authRejected : state.authRejected;
    state.requesterRateLimited = Number.isFinite(value.requesterRateLimited) ? value.requesterRateLimited : state.requesterRateLimited;
    state.targetRateLimited = Number.isFinite(value.targetRateLimited) ? value.targetRateLimited : state.targetRateLimited;
  };

  const persist = () => {
    if (!storagePath) {
      return;
    }

    mkdirSync(dirname(storagePath), { recursive: true });
    const temporaryPath = `${storagePath}.${process.pid}.tmp`;
    writeFileSync(temporaryPath, `${JSON.stringify(serializeState())}\n`, "utf8");
    renameSync(temporaryPath, storagePath);
  };

  if (storagePath && existsSync(storagePath)) {
    try {
      hydrateState(JSON.parse(readFileSync(storagePath, "utf8")));
    } catch {
      // A corrupt telemetry file should not prevent the app starting.
    }
  }

  const incrementBucket = (bucket, key) => {
    bucket[key] = (bucket[key] ?? 0) + 1;
  };
  const nonNegativeCount = (value) => (
    Number.isFinite(Number(value)) ? Math.max(0, Math.floor(Number(value))) : 0
  );
  const incrementCounters = (bucket, counters) => {
    for (const [key, value] of Object.entries(counters)) {
      bucket[key] = nonNegativeCount(bucket[key]) + nonNegativeCount(value);
    }
  };
  const getDayBucket = (dateKey) => {
    if (!state.visitorDays[dateKey]) {
      state.visitorDays[dateKey] = {
        pageLoads: 0,
        visitorKeys: new Set(),
      };
    }
    return state.visitorDays[dateKey];
  };
  const getFunnelDayBucket = (dateKey) => {
    if (!state.funnelDays[dateKey]) {
      state.funnelDays[dateKey] = {
        events: {},
        sources: {},
        modes: {},
        clients: {},
        clientVersions: {},
        clientKeysByClient: {},
        clientKeysByClientVersion: {},
      };
    }
    state.funnelDays[dateKey].events ||= {};
    state.funnelDays[dateKey].sources ||= {};
    state.funnelDays[dateKey].modes ||= {};
    state.funnelDays[dateKey].clients ||= {};
    state.funnelDays[dateKey].clientVersions ||= {};
    state.funnelDays[dateKey].clientKeysByClient ||= {};
    state.funnelDays[dateKey].clientKeysByClientVersion ||= {};
    return state.funnelDays[dateKey];
  };
  const getScanDayBucket = (dateKey) => {
    if (!state.scanDays[dateKey]) {
      state.scanDays[dateKey] = {
        requested: 0,
        requesterKeys: new Set(),
        clientKeys: new Set(),
        targetOrigins: new Set(),
        sourceBuckets: {},
        channelBuckets: {},
      };
    }
    return state.scanDays[dateKey];
  };
  const serializeDayBucket = (date, bucket) => ({
    date,
    pageLoads: bucket.pageLoads,
    uniqueVisitors: bucket.visitorKeys.size,
  });
  const serializeScanDayBucket = (date, bucket) => ({
    date,
    requested: bucket.requested,
    uniqueRequesters: bucket.requesterKeys.size,
    uniqueClients: bucket.clientKeys.size,
    uniqueTargets: bucket.targetOrigins.size,
    sources: { ...(bucket.sourceBuckets || {}) },
    channels: { ...(bucket.channelBuckets || {}) },
  });
  const pushMetric = (values, value, maxValues = 200) => {
    if (!Number.isFinite(value) || value < 0) {
      return;
    }
    values.push(Math.round(value));
    if (values.length > maxValues) {
      values.splice(0, values.length - maxValues);
    }
  };
  const summarizeMetric = (values) => {
    if (!values.length) {
      return { count: 0, averageMs: 0, p50Ms: 0, p95Ms: 0, maxMs: 0 };
    }
    const sorted = [...values].sort((a, b) => a - b);
    const percentile = (fraction) => sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * fraction))];
    return {
      count: sorted.length,
      averageMs: Math.round(sorted.reduce((sum, value) => sum + value, 0) / sorted.length),
      p50Ms: percentile(0.5),
      p95Ms: percentile(0.95),
      maxMs: sorted[sorted.length - 1],
    };
  };
  const pushRecentFailure = (failureClass, details = {}) => {
    const failure = sanitizeRecentFailure({
      occurredAt: details.occurredAt || new Date().toISOString(),
      class: failureClass,
      target: details.target,
      message: details.message,
      source: details.source,
    });
    if (!failure) {
      return;
    }
    state.recentFailures.push(failure);
    if (state.recentFailures.length > 20) {
      state.recentFailures.splice(0, state.recentFailures.length - 20);
    }
  };
  const pushRecentFunnelEvent = (event) => {
    state.recentFunnelEvents.push(event);
    if (state.recentFunnelEvents.length > 40) {
      state.recentFunnelEvents.splice(0, state.recentFunnelEvents.length - 40);
    }
  };
  const pushRecentScan = (scan) => {
    state.recentScans.push(scan);
    if (state.recentScans.length > 40) {
      state.recentScans.splice(0, state.recentScans.length - 40);
    }
  };

  return {
    recordPageLoad({ visitorKey = null, now = new Date(), source = "unknown" } = {}) {
      const normalizedSource = normalizeTrafficSource(source);
      state.pageLoads += 1;
      incrementBucket(state.sourceBuckets, normalizedSource);
      const dateKey = now.toISOString().slice(0, 10);
      const dayBucket = getDayBucket(dateKey);
      dayBucket.pageLoads += 1;
      if (!dayBucket.sourceBuckets) {
        dayBucket.sourceBuckets = {};
      }
      incrementBucket(dayBucket.sourceBuckets, normalizedSource);
      if (visitorKey) {
        state.visitorKeys.add(visitorKey);
        dayBucket.visitorKeys.add(visitorKey);
      }
      persist();
    },
    recordFunnelEvent({
      event,
      source = "unknown",
      target = null,
      scanId = null,
      format = null,
      mode = null,
      client = null,
      clientVersion = null,
      clientKey = null,
      now = new Date(),
    } = {}) {
      const sanitized = sanitizeFunnelEvent({
        occurredAt: now.toISOString(),
        event,
        source: normalizeTrafficSource(source),
        target,
        scanId,
        format,
        mode,
        client,
        clientVersion,
      });
      if (!sanitized) {
        return false;
      }

      incrementBucket(state.funnelEvents, sanitized.event);
      if (!state.funnelEventsBySource[sanitized.source]) {
        state.funnelEventsBySource[sanitized.source] = {};
      }
      incrementBucket(state.funnelEventsBySource[sanitized.source], sanitized.event);
      if (sanitized.mode) {
        if (!state.funnelEventsByMode[sanitized.mode]) {
          state.funnelEventsByMode[sanitized.mode] = {};
        }
        incrementBucket(state.funnelEventsByMode[sanitized.mode], sanitized.event);
      }
      if (sanitized.client) {
        const clientBucketKey = boundedBucketKey(state.funnelEventsByClient, sanitized.client, 100);
        if (!state.funnelEventsByClient[clientBucketKey]) {
          state.funnelEventsByClient[clientBucketKey] = {};
        }
        incrementBucket(state.funnelEventsByClient[clientBucketKey], sanitized.event);
        if (sanitized.clientVersion) {
          const versionKey = `${sanitized.client}@${sanitized.clientVersion}`;
          const boundedVersionKey = boundedBucketKey(state.funnelEventsByClientVersion, versionKey, 200);
          if (!state.funnelEventsByClientVersion[boundedVersionKey]) {
            state.funnelEventsByClientVersion[boundedVersionKey] = {};
          }
          incrementBucket(state.funnelEventsByClientVersion[boundedVersionKey], sanitized.event);
        }
      }
      const safeBackendClientKey = hashPrivacyValue(clientKey, { prefix: "backend_client", length: 16 });
      if (sanitized.client && safeBackendClientKey !== "unknown") {
        const activeClientKey = boundedBucketKey(state.funnelClientKeysByClient, sanitized.client, 100);
        if (!state.funnelClientKeysByClient[activeClientKey]) {
          state.funnelClientKeysByClient[activeClientKey] = new Set();
        }
        state.funnelClientKeysByClient[activeClientKey].add(safeBackendClientKey);
        if (sanitized.clientVersion) {
          const versionKey = `${sanitized.client}@${sanitized.clientVersion}`;
          const activeVersionKey = boundedBucketKey(state.funnelClientKeysByClientVersion, versionKey, 200);
          if (!state.funnelClientKeysByClientVersion[activeVersionKey]) {
            state.funnelClientKeysByClientVersion[activeVersionKey] = new Set();
          }
          state.funnelClientKeysByClientVersion[activeVersionKey].add(safeBackendClientKey);
        }
      }
      const dateKey = now.toISOString().slice(0, 10);
      const dayBucket = getFunnelDayBucket(dateKey);
      incrementBucket(dayBucket.events, sanitized.event);
      if (!dayBucket.sources[sanitized.source]) {
        dayBucket.sources[sanitized.source] = {};
      }
      incrementBucket(dayBucket.sources[sanitized.source], sanitized.event);
      if (sanitized.mode) {
        if (!dayBucket.modes[sanitized.mode]) {
          dayBucket.modes[sanitized.mode] = {};
        }
        incrementBucket(dayBucket.modes[sanitized.mode], sanitized.event);
      }
      if (sanitized.client) {
        const dayClientKey = boundedBucketKey(dayBucket.clients, sanitized.client, 100);
        if (!dayBucket.clients[dayClientKey]) {
          dayBucket.clients[dayClientKey] = {};
        }
        incrementBucket(dayBucket.clients[dayClientKey], sanitized.event);
        if (safeBackendClientKey !== "unknown") {
          if (!dayBucket.clientKeysByClient[dayClientKey]) {
            dayBucket.clientKeysByClient[dayClientKey] = new Set();
          }
          dayBucket.clientKeysByClient[dayClientKey].add(safeBackendClientKey);
        }
        if (sanitized.clientVersion) {
          const versionKey = `${sanitized.client}@${sanitized.clientVersion}`;
          const dayVersionKey = boundedBucketKey(dayBucket.clientVersions, versionKey, 200);
          if (!dayBucket.clientVersions[dayVersionKey]) {
            dayBucket.clientVersions[dayVersionKey] = {};
          }
          incrementBucket(dayBucket.clientVersions[dayVersionKey], sanitized.event);
          if (safeBackendClientKey !== "unknown") {
            if (!dayBucket.clientKeysByClientVersion[dayVersionKey]) {
              dayBucket.clientKeysByClientVersion[dayVersionKey] = new Set();
            }
            dayBucket.clientKeysByClientVersion[dayVersionKey].add(safeBackendClientKey);
          }
        }
      }
      pushRecentFunnelEvent(sanitized);
      persist();
      return true;
    },
    recordScanRequested({
      mode,
      source = "unknown",
      channel = "unknown",
      requesterKey = null,
      clientKey = null,
      target = null,
      client = null,
      clientVersion = null,
      now = new Date(),
    } = {}) {
      const normalizedSource = normalizeTrafficSource(source);
      const normalizedChannel = normalizeScanChannel(channel);
      const targetOrigin = targetForPrivacy(target);
      const safeProduct = normalizeClientId(client);
      const safeProductVersion = safeProduct ? normalizeClientVersion(clientVersion) : null;
      const safeRequesterKey = hashPrivacyValue(requesterKey, { prefix: "req", length: 16 });
      const safeClientKey = hashPrivacyValue(clientKey, { prefix: "client", length: 16 });
      state.scansRequested += 1;
      if (mode === "quiet") {
        state.quietModeScans += 1;
      }
      incrementBucket(state.scanSourceBuckets, normalizedSource);
      incrementBucket(state.scanChannelBuckets, normalizedChannel);
      if (safeProduct) {
        incrementBucket(
          state.scanProductBuckets,
          boundedBucketKey(state.scanProductBuckets, safeProduct, 100),
        );
        if (safeProductVersion) {
          const versionKey = `${safeProduct}@${safeProductVersion}`;
          incrementBucket(
            state.scanProductVersionBuckets,
            boundedBucketKey(state.scanProductVersionBuckets, versionKey, 200),
          );
        }
      }
      if (targetOrigin) {
        state.scanTargetOrigins.add(targetOrigin);
        incrementBucket(state.scanTargetBuckets, targetOrigin);
      }
      if (safeRequesterKey !== "unknown") {
        state.scanRequesterKeys.add(safeRequesterKey);
      }
      if (safeClientKey !== "unknown") {
        state.scanClientKeys.add(safeClientKey);
      }
      const dateKey = now.toISOString().slice(0, 10);
      const dayBucket = getScanDayBucket(dateKey);
      dayBucket.requested += 1;
      incrementBucket(dayBucket.sourceBuckets, normalizedSource);
      incrementBucket(dayBucket.channelBuckets, normalizedChannel);
      if (targetOrigin) {
        dayBucket.targetOrigins.add(targetOrigin);
      }
      if (safeRequesterKey !== "unknown") {
        dayBucket.requesterKeys.add(safeRequesterKey);
      }
      if (safeClientKey !== "unknown") {
        dayBucket.clientKeys.add(safeClientKey);
      }
      pushRecentScan({
        occurredAt: now.toISOString(),
        target: targetOrigin,
        mode,
        source: normalizedSource,
        channel: normalizedChannel,
        requesterKey: safeRequesterKey,
        clientKey: safeClientKey,
        client: safeProduct,
        clientVersion: safeProductVersion,
      });
      persist();
    },
    recordScanCompleted(result) {
      state.scansCompleted += 1;
      if (result.scanTiming) {
        pushMetric(state.scanDurationsMs, result.scanTiming.totalMs);
        pushMetric(state.coreDurationsMs, result.scanTiming.coreMs);
        pushMetric(state.enrichmentDurationsMs, result.scanTiming.enrichmentMs);
        if (result.scanTiming.timedOut) {
          state.timedOutScans += 1;
        }
      }
      if (result.assessmentLimitation?.limited) {
        state.limitedReads += 1;
        incrementBucket(state.limitedReadKinds, result.assessmentLimitation.kind || "unknown");
      } else {
        state.fullReads += 1;
      }
      persist();
    },
    recordNotificationDelivery({
      channel = "unknown",
      attempted = 0,
      attempts = 0,
      sent = 0,
      failed = 0,
      disabled = 0,
      retried = 0,
      skipped = null,
      now = new Date(),
    } = {}) {
      const safeChannel = normalizeScanChannel(channel);
      const counters = {
        batches: 1,
        attempted: nonNegativeCount(attempted),
        attempts: nonNegativeCount(attempts),
        sent: nonNegativeCount(sent),
        failed: nonNegativeCount(failed),
        disabled: nonNegativeCount(disabled),
        retried: nonNegativeCount(retried),
      };
      incrementCounters(state.notificationDeliveries, counters);
      if (!state.notificationDeliveryChannels[safeChannel]) {
        state.notificationDeliveryChannels[safeChannel] = {};
      }
      incrementCounters(state.notificationDeliveryChannels[safeChannel], counters);
      const dateKey = now.toISOString().slice(0, 10);
      if (!state.notificationDeliveryDays[dateKey]) {
        state.notificationDeliveryDays[dateKey] = {};
      }
      incrementCounters(state.notificationDeliveryDays[dateKey], counters);
      const safeSkipped = sanitizeTelemetryText(skipped, 80);
      if (safeSkipped) incrementBucket(state.notificationDeliverySkipped, safeSkipped);
      persist();
    },
    recordFailure(failureClass, details = {}) {
      incrementBucket(state.failureClasses, failureClass);
      pushRecentFailure(failureClass, details);
      persist();
    },
    recordAuthRejected() {
      state.authRejected += 1;
      persist();
    },
    recordRequesterRateLimited() {
      state.requesterRateLimited += 1;
      persist();
    },
    recordTargetRateLimited() {
      state.targetRateLimited += 1;
      persist();
    },
    snapshot() {
      const todayKey = new Date().toISOString().slice(0, 10);
      const startedDate = state.startedAt.slice(0, 10);
      const recentDays = Object.entries(state.visitorDays)
        .sort(([left], [right]) => left.localeCompare(right))
        .slice(-14)
        .map(([date, bucket]) => serializeDayBucket(date, bucket));
      const recentScanDays = Object.entries(state.scanDays)
        .sort(([left], [right]) => left.localeCompare(right))
        .slice(-14)
        .map(([date, bucket]) => serializeScanDayBucket(date, bucket));
      const todayScanBucket = getScanDayBucket(todayKey);
      const todayFunnelBucket = getFunnelDayBucket(todayKey);
      const todayFunnelEvents = todayFunnelBucket.events || {};
      const clientConsumptionEvents = {
        monitoringTargetRegistrations: state.funnelEvents.monitoring_target_registered || 0,
        monitoringHealthReads: state.funnelEvents.monitoring_health_read || 0,
        monitoringMobileSummaryReads: state.funnelEvents.monitoring_mobile_summary_read || 0,
        notificationDeviceRegistrations: state.funnelEvents.notification_device_registered || 0,
        notificationDeviceHealthReads: state.funnelEvents.notification_device_health_read || 0,
        notificationTestRequests: state.funnelEvents.notification_test_requested || 0,
        liveCertificateReads: state.funnelEvents.live_certificate_read || 0,
        liveCertificateFailures: state.funnelEvents.live_certificate_failed || 0,
        certWatchlistSummaryReads: state.funnelEvents.cert_watchlist_summary_read || 0,
      };
      const todayClientConsumptionEvents = {
        monitoringTargetRegistrations: todayFunnelEvents.monitoring_target_registered || 0,
        monitoringHealthReads: todayFunnelEvents.monitoring_health_read || 0,
        monitoringMobileSummaryReads: todayFunnelEvents.monitoring_mobile_summary_read || 0,
        notificationDeviceRegistrations: todayFunnelEvents.notification_device_registered || 0,
        notificationDeviceHealthReads: todayFunnelEvents.notification_device_health_read || 0,
        notificationTestRequests: todayFunnelEvents.notification_test_requested || 0,
        liveCertificateReads: todayFunnelEvents.live_certificate_read || 0,
        liveCertificateFailures: todayFunnelEvents.live_certificate_failed || 0,
        certWatchlistSummaryReads: todayFunnelEvents.cert_watchlist_summary_read || 0,
      };
      const clientConsumptionTotal = Object.values(clientConsumptionEvents)
        .reduce((total, count) => total + count, 0);
      const todayClientConsumptionTotal = Object.values(todayClientConsumptionEvents)
        .reduce((total, count) => total + count, 0);
      return {
        startedAt: state.startedAt,
        persistence,
        pageLoads: state.pageLoads,
        visitors: {
          unique: state.visitorKeys.size,
          totalPageLoads: state.pageLoads,
          today: serializeDayBucket(todayKey, getDayBucket(todayKey)),
          sinceStart: serializeDayBucket(startedDate, {
            pageLoads: state.pageLoads,
            visitorKeys: state.visitorKeys,
          }),
          recentDays,
        },
        trafficSources: {
          pageLoads: { ...state.sourceBuckets },
          today: { ...(getDayBucket(todayKey).sourceBuckets || {}) },
        },
        funnel: {
          events: { ...state.funnelEvents },
          bySource: Object.fromEntries(
            Object.entries(state.funnelEventsBySource).map(([source, events]) => [
              source,
              { ...events },
            ]),
          ),
          byMode: Object.fromEntries(
            Object.entries(state.funnelEventsByMode).map(([mode, events]) => [
              mode,
              { ...events },
            ]),
          ),
          byClient: Object.fromEntries(
            Object.entries(state.funnelEventsByClient).map(([client, events]) => [
              client,
              { ...events },
            ]),
          ),
          byClientVersion: Object.fromEntries(
            Object.entries(state.funnelEventsByClientVersion).map(([clientVersion, events]) => [
              clientVersion,
              { ...events },
            ]),
          ),
          activeClientsByClient: countSetBuckets(state.funnelClientKeysByClient),
          activeClientsByClientVersion: countSetBuckets(state.funnelClientKeysByClientVersion),
          today: { ...(todayFunnelBucket.events || {}) },
          todayBySource: Object.fromEntries(
            Object.entries(todayFunnelBucket.sources || {}).map(([source, events]) => [
              source,
              { ...events },
            ]),
          ),
          todayByMode: Object.fromEntries(
            Object.entries(todayFunnelBucket.modes || {}).map(([mode, events]) => [
              mode,
              { ...events },
            ]),
          ),
          todayByClient: Object.fromEntries(
            Object.entries(todayFunnelBucket.clients || {}).map(([client, events]) => [
              client,
              { ...events },
            ]),
          ),
          todayByClientVersion: Object.fromEntries(
            Object.entries(todayFunnelBucket.clientVersions || {}).map(([clientVersion, events]) => [
              clientVersion,
              { ...events },
            ]),
          ),
          todayActiveClientsByClient: countSetBuckets(todayFunnelBucket.clientKeysByClient || {}),
          todayActiveClientsByClientVersion: countSetBuckets(todayFunnelBucket.clientKeysByClientVersion || {}),
          recentDays: Object.entries(state.funnelDays)
            .sort(([left], [right]) => left.localeCompare(right))
            .slice(-14)
            .map(([date, bucket]) => ({
              date,
              events: { ...bucket.events },
              sources: Object.fromEntries(
                Object.entries(bucket.sources || {}).map(([source, events]) => [
                  source,
                  { ...events },
                ]),
              ),
              modes: Object.fromEntries(
                Object.entries(bucket.modes || {}).map(([mode, events]) => [
                  mode,
                  { ...events },
                ]),
              ),
              clients: Object.fromEntries(
                Object.entries(bucket.clients || {}).map(([client, events]) => [
                  client,
                  { ...events },
                ]),
              ),
              clientVersions: Object.fromEntries(
                Object.entries(bucket.clientVersions || {}).map(([clientVersion, events]) => [
                  clientVersion,
                  { ...events },
                ]),
              ),
              activeClientsByClient: countSetBuckets(bucket.clientKeysByClient || {}),
              activeClientsByClientVersion: countSetBuckets(bucket.clientKeysByClientVersion || {}),
            })),
          recent: [...state.recentFunnelEvents].reverse(),
        },
        clients: {
          identity: {
            scanRequestsByClient: { ...state.scanProductBuckets },
            scanRequestsByClientVersion: { ...state.scanProductVersionBuckets },
            backendEventsByClient: Object.fromEntries(
              Object.entries(state.funnelEventsByClient).map(([client, events]) => [
                client,
                { ...events },
              ]),
            ),
            backendEventsByClientVersion: Object.fromEntries(
              Object.entries(state.funnelEventsByClientVersion).map(([clientVersion, events]) => [
                clientVersion,
                { ...events },
              ]),
            ),
            activeBackendClientsByClient: countSetBuckets(state.funnelClientKeysByClient),
            activeBackendClientsByClientVersion: countSetBuckets(state.funnelClientKeysByClientVersion),
            todayBackendEventsByClient: Object.fromEntries(
              Object.entries(todayFunnelBucket.clients || {}).map(([client, events]) => [
                client,
                { ...events },
              ]),
            ),
            todayBackendEventsByClientVersion: Object.fromEntries(
              Object.entries(todayFunnelBucket.clientVersions || {}).map(([clientVersion, events]) => [
                clientVersion,
                { ...events },
              ]),
            ),
            todayActiveBackendClientsByClient: countSetBuckets(todayFunnelBucket.clientKeysByClient || {}),
            todayActiveBackendClientsByClientVersion: countSetBuckets(todayFunnelBucket.clientKeysByClientVersion || {}),
          },
          consumption: {
            backendApiEvents: clientConsumptionTotal,
            todayBackendApiEvents: todayClientConsumptionTotal,
            ...clientConsumptionEvents,
            today: todayClientConsumptionEvents,
            byMode: Object.fromEntries(
              Object.entries(state.funnelEventsByMode)
                .filter(([, events]) => (
                  events.monitoring_mobile_summary_read
                  || events.monitoring_health_read
                  || events.monitoring_target_registered
                  || events.notification_device_registered
                  || events.notification_device_health_read
                  || events.notification_test_requested
                  || events.live_certificate_read
                  || events.live_certificate_failed
                  || events.cert_watchlist_summary_read
                ))
                .map(([mode, events]) => [
                  mode,
                  {
                    monitoringTargetRegistrations: events.monitoring_target_registered || 0,
                    monitoringHealthReads: events.monitoring_health_read || 0,
                    monitoringMobileSummaryReads: events.monitoring_mobile_summary_read || 0,
                    notificationDeviceRegistrations: events.notification_device_registered || 0,
                    notificationDeviceHealthReads: events.notification_device_health_read || 0,
                    notificationTestRequests: events.notification_test_requested || 0,
                    liveCertificateReads: events.live_certificate_read || 0,
                    liveCertificateFailures: events.live_certificate_failed || 0,
                    certWatchlistSummaryReads: events.cert_watchlist_summary_read || 0,
                  },
                ]),
            ),
            adoptionSignals: {
              monitoringRegistration: clientConsumptionEvents.monitoringTargetRegistrations > 0,
              monitoringHealth: clientConsumptionEvents.monitoringHealthReads > 0,
              mobileMonitoring: clientConsumptionEvents.monitoringMobileSummaryReads > 0,
              pushRegistration: clientConsumptionEvents.notificationDeviceRegistrations > 0,
              notificationHealth: clientConsumptionEvents.notificationDeviceHealthReads > 0,
              certWatch: clientConsumptionEvents.liveCertificateReads > 0
                || clientConsumptionEvents.liveCertificateFailures > 0
                || clientConsumptionEvents.certWatchlistSummaryReads > 0,
            },
          },
        },
        notifications: {
          delivery: {
            ...state.notificationDeliveries,
            skipped: { ...state.notificationDeliverySkipped },
            byChannel: Object.fromEntries(
              Object.entries(state.notificationDeliveryChannels).map(([channel, counters]) => [
                channel,
                { ...counters },
              ]),
            ),
            today: { ...(state.notificationDeliveryDays[todayKey] || {}) },
          },
        },
        scans: {
          requested: state.scansRequested,
          completed: state.scansCompleted,
          engagement: {
            sources: { ...state.scanSourceBuckets },
            channels: { ...state.scanChannelBuckets },
            clients: { ...state.scanProductBuckets },
            clientVersions: { ...state.scanProductVersionBuckets },
            uniqueRequesters: state.scanRequesterKeys.size,
            uniqueClients: state.scanClientKeys.size,
            uniqueTargets: state.scanTargetOrigins.size,
            today: serializeScanDayBucket(todayKey, todayScanBucket),
            recentDays: recentScanDays,
            repeatTargets: Object.entries(state.scanTargetBuckets)
              .sort(([, left], [, right]) => right - left)
              .slice(0, 10)
              .map(([target, count]) => ({ target, count })),
            recent: [...state.recentScans].reverse(),
          },
          fullReads: state.fullReads,
          limitedReads: state.limitedReads,
          quietMode: state.quietModeScans,
          timedOut: state.timedOutScans,
          limitedReadKinds: { ...state.limitedReadKinds },
          timing: {
            total: summarizeMetric(state.scanDurationsMs),
            core: summarizeMetric(state.coreDurationsMs),
            enrichment: summarizeMetric(state.enrichmentDurationsMs),
          },
        },
        failures: {
          classes: { ...state.failureClasses },
          recent: [...state.recentFailures].reverse(),
          authRejected: state.authRejected,
          requesterRateLimited: state.requesterRateLimited,
          targetRateLimited: state.targetRateLimited,
        },
      };
    },
  };
}

function serializeSetBuckets(buckets = {}) {
  return Object.fromEntries(
    Object.entries(buckets || {}).map(([key, values]) => [
      key,
      values instanceof Set ? [...values] : Array.isArray(values) ? values : [],
    ]),
  );
}

function hydrateSetBuckets(value = {}) {
  return Object.fromEntries(
    Object.entries(value || {}).map(([key, values]) => [
      key,
      new Set(Array.isArray(values) ? values : []),
    ]),
  );
}

function countSetBuckets(buckets = {}) {
  return Object.fromEntries(
    Object.entries(buckets || {}).map(([key, values]) => [
      key,
      values instanceof Set ? values.size : Array.isArray(values) ? values.length : 0,
    ]),
  );
}

function sanitizeTelemetryText(value, maxLength = 240) {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalized) {
    return null;
  }
  return normalized.slice(0, maxLength);
}

function sanitizeRecentFailure(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  const failureClass = sanitizeTelemetryText(value.class || value.failureClass, 80);
  if (!failureClass) {
    return null;
  }
  return {
    occurredAt: sanitizeTelemetryText(value.occurredAt, 40) || new Date().toISOString(),
    class: failureClass,
    target: sanitizeTelemetryText(targetForPrivacy(value.target), 240),
    message: sanitizeTelemetryText(value.message, 240),
    source: sanitizeTelemetryText(value.source, 80),
  };
}

function sanitizeRecentScan(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  const occurredAt = sanitizeTelemetryText(value.occurredAt, 40) || new Date().toISOString();
  const channel = normalizeScanChannel(value.channel);
  const source = normalizeTrafficSource(value.source);
  const client = normalizeClientId(value.client);
  return {
    occurredAt,
    target: sanitizeTelemetryText(targetForPrivacy(value.target), 240),
    mode: sanitizeTelemetryText(value.mode, 40) || "standard",
    source,
    channel,
    requesterKey: sanitizeTelemetryText(value.requesterKey, 80),
    clientKey: sanitizeTelemetryText(value.clientKey, 80),
    client,
    clientVersion: client ? normalizeClientVersion(value.clientVersion) : null,
  };
}

const FUNNEL_EVENT_NAMES = new Set([
  "scan_started",
  "handoff_started",
  "scan_completed",
  "scan_failed",
  "report_viewed",
  "shared_report_viewed",
  "share_link_copied",
  "export_clicked",
  "monitoring_saved",
  "monitoring_target_registered",
  "monitoring_health_read",
  "monitoring_mobile_summary_read",
  "notification_device_registered",
  "notification_device_health_read",
  "notification_test_requested",
  "live_certificate_read",
  "live_certificate_failed",
  "cert_watchlist_summary_read",
]);

function sanitizeFunnelEvent(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  const event = sanitizeTelemetryText(value.event, 80);
  if (!event || !FUNNEL_EVENT_NAMES.has(event)) {
    return null;
  }
  const client = normalizeClientId(value.client);
  return {
    occurredAt: sanitizeTelemetryText(value.occurredAt, 40) || new Date().toISOString(),
    event,
    source: normalizeTrafficSource(value.source),
    target: sanitizeTelemetryText(targetForPrivacy(value.target), 160),
    scanId: sanitizeTelemetryText(value.scanId, 80),
    format: sanitizeTelemetryText(value.format, 40),
    mode: sanitizeTelemetryText(value.mode, 40),
    client,
    clientVersion: client ? normalizeClientVersion(value.clientVersion) : null,
  };
}

export function normalizeTrafficSource(source) {
  const value = String(source || "unknown").trim().toLowerCase();
  return /^[a-z0-9_:-]{1,40}$/.test(value) ? value : "unknown";
}

export function normalizeScanChannel(channel) {
  const value = String(channel || "unknown").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  return /^[a-z0-9_-]{1,40}$/.test(value) ? value : "unknown";
}

export function classifyTrafficSource({ referrer = "", currentUrl = "" } = {}) {
  const explicitSource = readUtmSource(currentUrl);
  if (explicitSource) {
    return explicitSource;
  }

  if (!referrer) {
    return "direct";
  }

  let host = "";
  try {
    host = new URL(referrer).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "unknown";
  }

  if (!host || host === "securl.online" || host === "app.securl.online" || host.endsWith(".securl.online")) {
    return "internal";
  }
  if (host === "news.ycombinator.com" || host === "ycombinator.com") {
    return "hacker_news";
  }
  if (host === "reddit.com" || host.endsWith(".reddit.com")) {
    return "reddit";
  }
  if (host === "github.com" || host.endsWith(".github.com")) {
    return "github";
  }
  if (host === "google.com" || host.endsWith(".google.com")) {
    return "google";
  }
  if (host === "linkedin.com" || host.endsWith(".linkedin.com")) {
    return "linkedin";
  }
  if (host === "x.com" || host === "twitter.com" || host.endsWith(".twitter.com")) {
    return "social";
  }

  return "other_referrer";
}

function readUtmSource(currentUrl) {
  if (!currentUrl) {
    return null;
  }

  try {
    const url = new URL(currentUrl);
    const source = url.searchParams.get("utm_source");
    if (!source) {
      return null;
    }
    const normalized = normalizeTrafficSource(source.replace(/[^a-z0-9_-]/gi, "_"));
    return normalized === "unknown" ? null : `utm:${normalized}`;
  } catch {
    return null;
  }
}

export function classifyScanFailure(error) {
  const message = String(error?.message ?? error ?? "").toLowerCase();

  if (!message || message.includes("enter a url")) {
    return "invalid_target_empty";
  }
  if (message.includes("embedded credentials")) {
    return "invalid_target_credentials";
  }
  if (message.includes("localhost") || message.includes("private network") || message.includes("public ip")) {
    return "invalid_target_private";
  }
  if (message.includes("only http and https")) {
    return "invalid_target_protocol";
  }
  if (message.includes("resolve to a public ip")) {
    return "invalid_target_resolution";
  }

  return "scan_runtime_failure";
}
