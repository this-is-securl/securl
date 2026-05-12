import { useState, useCallback } from "react";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import {
  buildRecentScans,
  RECENT_SCANS_KEY,
  STORAGE_SCHEMA_VERSION,
  type RecentScan,
} from "@/lib/scanWorkspace";
import type { AnalysisResult } from "@/types/analysis";

export const useRecentScans = () => {
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [activeRecentScanUrl, setActiveRecentScanUrl] = useState<string | null>(null);

  const loadRecentScans = useCallback(async () => {
    const stored = await readBrowserStorage<RecentScan[]>(RECENT_SCANS_KEY, [], STORAGE_SCHEMA_VERSION);
    setRecentScans(stored);
    return stored;
  }, []);

  const addRecentScan = useCallback((payload: AnalysisResult) => {
    setRecentScans((current) => {
      const next = buildRecentScans(current, {
        url: payload.finalUrl,
        grade: payload.grade,
        scannedAt: payload.scannedAt,
      });
      void writeBrowserStorage(RECENT_SCANS_KEY, next, STORAGE_SCHEMA_VERSION);
      return next;
    });
  }, []);

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
