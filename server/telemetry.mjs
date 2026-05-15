export function createTelemetryTracker() {
  const startedAt = new Date().toISOString();
  const startedDate = startedAt.slice(0, 10);

  const state = {
    pageLoads: 0,
    visitorKeys: new Set(),
    visitorDays: {},
    scansRequested: 0,
    scansCompleted: 0,
    fullReads: 0,
    limitedReads: 0,
    quietModeScans: 0,
    timedOutScans: 0,
    scanDurationsMs: [],
    coreDurationsMs: [],
    enrichmentDurationsMs: [],
    limitedReadKinds: {},
    failureClasses: {},
    authRejected: 0,
    requesterRateLimited: 0,
    targetRateLimited: 0,
  };

  const incrementBucket = (bucket, key) => {
    bucket[key] = (bucket[key] ?? 0) + 1;
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
  const serializeDayBucket = (date, bucket) => ({
    date,
    pageLoads: bucket.pageLoads,
    uniqueVisitors: bucket.visitorKeys.size,
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

  return {
    recordPageLoad({ visitorKey = null, now = new Date() } = {}) {
      state.pageLoads += 1;
      const dateKey = now.toISOString().slice(0, 10);
      const dayBucket = getDayBucket(dateKey);
      dayBucket.pageLoads += 1;
      if (visitorKey) {
        state.visitorKeys.add(visitorKey);
        dayBucket.visitorKeys.add(visitorKey);
      }
    },
    recordScanRequested({ mode }) {
      state.scansRequested += 1;
      if (mode === "quiet") {
        state.quietModeScans += 1;
      }
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
    },
    recordFailure(failureClass) {
      incrementBucket(state.failureClasses, failureClass);
    },
    recordAuthRejected() {
      state.authRejected += 1;
    },
    recordRequesterRateLimited() {
      state.requesterRateLimited += 1;
    },
    recordTargetRateLimited() {
      state.targetRateLimited += 1;
    },
    snapshot() {
      const todayKey = new Date().toISOString().slice(0, 10);
      const recentDays = Object.entries(state.visitorDays)
        .sort(([left], [right]) => left.localeCompare(right))
        .slice(-14)
        .map(([date, bucket]) => serializeDayBucket(date, bucket));
      return {
        startedAt,
        persistence: "memory",
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
        scans: {
          requested: state.scansRequested,
          completed: state.scansCompleted,
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
          authRejected: state.authRejected,
          requesterRateLimited: state.requesterRateLimited,
          targetRateLimited: state.targetRateLimited,
        },
      };
    },
  };
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
