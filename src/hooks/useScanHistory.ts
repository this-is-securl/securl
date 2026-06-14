import { useState, useCallback, useRef } from "react";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import {
  HISTORY_KEY,
  STORAGE_SCHEMA_VERSION,
  saveHistorySnapshot as saveHistorySnapshotToDict,
  buildHistoryState,
  type StoredHistorySnapshot,
} from "@/lib/scanWorkspace";
import { getAreaScores } from "@/lib/posture";
import type { AnalysisResult, HistoryDiff } from "@/types/analysis";
import type { ApiScanSummary, ScanComparisonResponse } from "@/types/api";
import { snapshotFromAnalysis } from "securl/history-diff";

const hostFromUrl = (url: string) => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};

const summaryToHistorySnapshot = (summary: ApiScanSummary): StoredHistorySnapshot | null => {
  if (summary.status !== "completed" || typeof summary.score !== "number" || !summary.grade) {
    return null;
  }

  return {
    finalUrl: summary.url,
    host: hostFromUrl(summary.url),
    scannedAt: summary.completedAt ?? summary.requestedAt,
    score: summary.score,
    grade: summary.grade,
    statusCode: 0,
    responseTimeMs: summary.scanTiming?.totalMs ?? 0,
    certificateDaysRemaining: null,
    thirdPartyProviders: [],
    aiVendors: [],
    identityProvider: null,
    wafProviders: [],
    ctPriorityHosts: [],
    headers: [],
    issues: [],
  };
};

export const useScanHistory = () => {
  const [history, setHistory] = useState<StoredHistorySnapshot[]>([]);
  const [historyDiff, setHistoryDiff] = useState<HistoryDiff | null>(null);
  const historyByHostRef = useRef<Record<string, StoredHistorySnapshot[]>>({});

  const loadHistory = useCallback(async () => {
    const stored = await readBrowserStorage<Record<string, StoredHistorySnapshot[]>>(HISTORY_KEY, {}, STORAGE_SCHEMA_VERSION);
    historyByHostRef.current = stored;
    return stored;
  }, []);

  const addHistorySnapshot = useCallback((payload: AnalysisResult, setAsCurrent = true) => {
    const { next, nextForHost } = saveHistorySnapshotToDict(historyByHostRef.current, payload, getAreaScores(payload));
    historyByHostRef.current = next;
    void writeBrowserStorage(HISTORY_KEY, next, STORAGE_SCHEMA_VERSION);

    if (setAsCurrent) {
      const historyState = buildHistoryState(nextForHost);
      setHistory(historyState.history);
      setHistoryDiff(historyState.diff);
    }
  }, []);

  const applyServerComparison = useCallback((payload: ScanComparisonResponse, currentResult: AnalysisResult) => {
    const currentSnapshot: StoredHistorySnapshot = {
      ...snapshotFromAnalysis(currentResult),
      areaScores: getAreaScores(currentResult),
    };
    const serverHistory = payload.scans
      .map((summary) => (summary.id === payload.scan.id ? currentSnapshot : summaryToHistorySnapshot(summary)))
      .filter((snapshot): snapshot is StoredHistorySnapshot => Boolean(snapshot));
    const localHistory = historyByHostRef.current[currentResult.host] ?? [];
    const nextHistory = localHistory.length >= serverHistory.length ? localHistory : serverHistory;

    if (nextHistory.length) {
      setHistory(nextHistory);
    }
    setHistoryDiff(payload.comparison?.diff ?? null);
  }, []);

  const clearHistoryState = useCallback(() => {
    setHistory([]);
    setHistoryDiff(null);
  }, []);

  return {
    history,
    historyDiff,
    loadHistory,
    addHistorySnapshot,
    applyServerComparison,
    clearHistoryState,
  };
};
