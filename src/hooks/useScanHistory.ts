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

  const clearHistoryState = useCallback(() => {
    setHistory([]);
    setHistoryDiff(null);
  }, []);

  return {
    history,
    historyDiff,
    loadHistory,
    addHistorySnapshot,
    clearHistoryState,
  };
};
