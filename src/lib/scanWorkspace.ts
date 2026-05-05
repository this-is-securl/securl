import { buildHistoryDiff, snapshotFromAnalysis } from "@ktbatterham/external-posture-core/history-diff";
import type { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";

export const RECENT_SCANS_KEY = "secure-header-insight:recent-scans";
export const HISTORY_KEY = "secure-header-insight:history";
export const MONITORED_TARGETS_KEY = "secure-header-insight:monitored-targets";
export const SCAN_OWNER_KEY = "secure-header-insight:scan-owner";
export const STORAGE_SCHEMA_VERSION = 1;
export const MONITORED_TARGET_LIMIT = 12;

export interface RecentScan {
  url: string;
  grade: string;
  scannedAt: string;
}

export interface MonitoredTarget {
  url: string;
  label: string;
  cadence: "daily" | "weekly";
  addedAt: string;
  lastScannedAt: string | null;
}

export interface StoredHistoryAreaScore {
  key: string;
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
}

export type StoredHistorySnapshot = HistorySnapshot & {
  areaScores?: StoredHistoryAreaScore[];
};

export const buildRecentScans = (current: RecentScan[], scan: RecentScan) =>
  [scan, ...current.filter((item) => item.url !== scan.url)].slice(0, 6);

export const syncMonitoredTargetFromAnalysis = (targets: MonitoredTarget[], payload: AnalysisResult) => {
  let changed = false;
  const next = targets.map((target) => {
    const matchesTarget =
      target.url === payload.finalUrl || target.url === payload.normalizedUrl || target.label === payload.host;
    if (!matchesTarget) {
      return target;
    }

    const updatedTarget = {
      ...target,
      url: payload.finalUrl,
      label: payload.host,
      lastScannedAt: payload.scannedAt,
    };

    if (
      updatedTarget.url !== target.url ||
      updatedTarget.label !== target.label ||
      updatedTarget.lastScannedAt !== target.lastScannedAt
    ) {
      changed = true;
    }

    return updatedTarget;
  });

  return changed ? next : targets;
};

const cadenceMs: Record<MonitoredTarget["cadence"], number> = {
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
};

export const toMonitoredTargetView = (target: MonitoredTarget) => {
  const baseTime = target.lastScannedAt ? new Date(target.lastScannedAt).getTime() : new Date(target.addedAt).getTime();
  const nextDueAt = new Date(baseTime + cadenceMs[target.cadence]).toISOString();
  return {
    ...target,
    nextDueAt,
    due: Date.now() >= new Date(nextDueAt).getTime(),
  };
};

export const saveHistorySnapshot = (
  current: Record<string, StoredHistorySnapshot[]>,
  analysis: AnalysisResult,
  areaScores: StoredHistoryAreaScore[],
) => {
  const key = analysis.host;
  const snapshot: StoredHistorySnapshot = {
    ...snapshotFromAnalysis(analysis),
    areaScores,
  };
  const nextForHost = [snapshot, ...(current[key] || [])].slice(0, 10);
  const next = { ...current, [key]: nextForHost };
  return { next, nextForHost };
};

export const buildHistoryState = (history: StoredHistorySnapshot[]) => ({
  history,
  diff: buildHistoryDiff(history as HistorySnapshot[]) as HistoryDiff | null,
});

export const downloadFile = (filename: string, content: BlobPart, type: string) => {
  const blob = new Blob([content], { type });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(objectUrl);
};
