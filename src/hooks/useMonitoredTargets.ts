import { useState, useCallback } from "react";
import { toast } from "sonner";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import {
  MONITORED_TARGETS_KEY,
  MONITORED_TARGET_LIMIT,
  STORAGE_SCHEMA_VERSION,
  syncMonitoredTargetFromAnalysis,
  toMonitoredTargetView,
  type MonitoredTarget,
} from "@/lib/scanWorkspace";
import type { AnalysisResult } from "@/types/analysis";

export const useMonitoredTargets = () => {
  const [monitoredTargets, setMonitoredTargets] = useState<MonitoredTarget[]>([]);

  const loadMonitoredTargets = useCallback(async () => {
    const stored = await readBrowserStorage<MonitoredTarget[]>(MONITORED_TARGETS_KEY, [], STORAGE_SCHEMA_VERSION);
    setMonitoredTargets(stored);
    return stored;
  }, []);

  const saveCurrentAsMonitored = useCallback((cadence: MonitoredTarget["cadence"], analysisData: AnalysisResult | null) => {
    if (!analysisData) {
      return;
    }

    setMonitoredTargets((current) => {
      const alreadyTracked = current.some((target) => target.url === analysisData.finalUrl);
      if (!alreadyTracked && current.length >= MONITORED_TARGET_LIMIT) {
        toast.error(`You can save up to ${MONITORED_TARGET_LIMIT} monitoring targets in this browser. Remove one first to add another.`);
        return current;
      }

      const next = [
        {
          url: analysisData.finalUrl,
          label: analysisData.host,
          cadence,
          addedAt: new Date().toISOString(),
          lastScannedAt: analysisData.scannedAt,
        },
        ...current.filter((target) => target.url !== analysisData.finalUrl),
      ].slice(0, MONITORED_TARGET_LIMIT);
      
      void writeBrowserStorage(MONITORED_TARGETS_KEY, next, STORAGE_SCHEMA_VERSION);
      toast.success(`Saved ${analysisData.host} as a ${cadence} monitoring target.`);
      return next;
    });
  }, []);

  const removeMonitoredTarget = useCallback((url: string) => {
    setMonitoredTargets((current) => {
      const next = current.filter((target) => target.url !== url);
      void writeBrowserStorage(MONITORED_TARGETS_KEY, next, STORAGE_SCHEMA_VERSION);
      return next;
    });
  }, []);

  const syncMonitoredTarget = useCallback((payload: AnalysisResult) => {
    setMonitoredTargets((current) => {
      const next = syncMonitoredTargetFromAnalysis(current, payload);
      if (next !== current) {
        void writeBrowserStorage(MONITORED_TARGETS_KEY, next, STORAGE_SCHEMA_VERSION);
      }
      return next;
    });
  }, []);

  return {
    monitoredTargets,
    setMonitoredTargets,
    monitoredViews: monitoredTargets.map(toMonitoredTargetView),
    loadMonitoredTargets,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    syncMonitoredTarget,
  };
};
