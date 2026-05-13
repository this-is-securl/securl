import { useState, useCallback } from "react";
import { getRecentScanSummaries } from "@/lib/apiClient";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import {
  buildRecentScans,
  RECENT_SCANS_KEY,
  STORAGE_SCHEMA_VERSION,
  type RecentScan,
} from "@/lib/scanWorkspace";
import type { AnalysisResult } from "@/types/analysis";

export const useRecentScans = ({ accountOwned = false }: { accountOwned?: boolean } = {}) => {
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [activeRecentScanUrl, setActiveRecentScanUrl] = useState<string | null>(null);

  const loadRecentScans = useCallback(async () => {
    if (accountOwned) {
      const summaries = await getRecentScanSummaries(10);
      return summaries
        .filter((scan) => scan.status === "completed" && scan.grade)
        .map((scan) => ({
          url: scan.url,
          grade: scan.grade || "?",
          scannedAt: scan.completedAt || scan.requestedAt,
        }));
    }

    const stored = await readBrowserStorage<RecentScan[]>(RECENT_SCANS_KEY, [], STORAGE_SCHEMA_VERSION);
    setRecentScans(stored);
    return stored;
  }, [accountOwned]);

  const addRecentScan = useCallback((payload: AnalysisResult) => {
    setRecentScans((current) => {
      const next = buildRecentScans(current, {
        url: payload.finalUrl,
        grade: payload.grade,
        scannedAt: payload.scannedAt,
      });
      if (!accountOwned) {
        void writeBrowserStorage(RECENT_SCANS_KEY, next, STORAGE_SCHEMA_VERSION);
      }
      return next;
    });
  }, [accountOwned]);

  const clearRecentScans = useCallback(() => {
    setRecentScans([]);
  }, []);

  return {
    recentScans,
    setRecentScans,
    activeRecentScanUrl,
    setActiveRecentScanUrl,
    loadRecentScans,
    addRecentScan,
    clearRecentScans,
  };
};
