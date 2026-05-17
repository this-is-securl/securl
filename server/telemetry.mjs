export function createTelemetryTracker() {
  const startedAt = new Date().toISOString();
  const startedDate = startedAt.slice(0, 10);

  const state = {
    pageLoads: 0,
    visitorKeys: new Set(),
    visitorDays: {},
    sourceBuckets: {},
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
        trafficSources: {
          pageLoads: { ...state.sourceBuckets },
          today: { ...(getDayBucket(todayKey).sourceBuckets || {}) },
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

export function normalizeTrafficSource(source) {
  const value = String(source || "unknown").trim().toLowerCase();
  return /^[a-z0-9_:-]{1,40}$/.test(value) ? value : "unknown";
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

  if (!host || host === "app.securl.online" || host.endsWith(".securl.online")) {
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
